defmodule ChronoMesh.DHT do
  @moduledoc """
  Kademlia-style Distributed Hash Table for node discovery and lightweight KV.

  This implementation is self-contained and uses an in-VM transport via an ETS
  registry to allow multiple DHT nodes in the same BEAM VM to form a network.

  ## Features

  - **XOR metric**: Uses XOR distance over 256-bit node IDs for proximity routing
  - **K-buckets**: Maintains up to K=20 peers per distance bucket with LRU eviction
  - **RPC protocol**: Implements ping, find_node, find_value, and store operations
  - **Iterative lookups**: Finds keys/values through iterative queries to closest nodes
  - **Key/value store**: Distributed storage with configurable TTL (default 5 minutes)
  - **Cryptographic identifiers**: All node identification uses node_id (SHA256 of X25519 public key), never IP addresses
  - **Replay protection**: Nonce-based replay attack prevention with timestamp validation
  - **Introduction points**: Anonymous rendezvous for connection establishment

  ## Security Features

  - **Replay Protection**: Each announcement includes a unique 16-byte nonce. Duplicate nonces are rejected.
  - **Timestamp Validation**: Clock skew tolerance of ±5 minutes prevents replay of old announcements.
  - **Nonce Tracking**: Tracks seen nonces per node_id (last 100) with automatic cleanup.
  - **Signature Verification**: Announcements are cryptographically signed (currently HMAC-SHA256, Ed25519 support planned).

  ## Usage

      # Start two DHT nodes
      {:ok, node_a} = ChronoMesh.DHT.start_link(address: :node_a)
      {:ok, node_b} = ChronoMesh.DHT.start_link(address: :node_b)

      # Bootstrap node_b to know about node_a
      ChronoMesh.DHT.bootstrap(node_b, [:node_a])

      # Announce node with introduction points
      {public_key, private_key} = ChronoMesh.Keys.generate()
      introduction_points = [%{node_id: <<...>>, public_key: <<...>>}]
      :ok = ChronoMesh.DHT.announce_node(node_a, public_key, private_key, :timer.minutes(5), introduction_points)

      # Lookup node announcements
      node_id = ChronoMesh.Keys.node_id_from_public_key(public_key)
      announcements = ChronoMesh.DHT.lookup_nodes(node_a, node_id, 5)

      # Store a value
      ChronoMesh.DHT.put(node_a, "key1", "value1")

      # Retrieve it from another node (via DHT lookup)
      {:ok, "value1"} = ChronoMesh.DHT.get(node_b, "key1")

      # Find closest peers to a target ID
      target_id = :crypto.hash(:sha256, "target")
      peers = ChronoMesh.DHT.neighbors(node_a, target_id, 5)

  ## Implementation Details

  - **Node IDs**: 256-bit (32 bytes) derived from X25519 public key: `node_id = SHA256(public_key)`
  - **Bucket indexing**: Distance is XOR(id1, id2); bucket index is based on leading zeros
  - **Transport**: In-VM only via ETS registry; network transport is future work
  - **Concurrency**: α=3 (default); queries proceed sequentially for simplicity
  - **Expiration**: Store entries expire based on TTL; expired entries are cleaned on access
  - **Announcements**: Include `node_id`, `public_key`, `timestamp`, `expires_at`, `signature`, `nonce`, and `introduction_points`
  - **Nonce Management**: Tracks up to 100 nonces per node_id, expires after `ttl_ms * 1.5`

  ## Replay Protection Details

  Announcements include a 16-byte nonce to prevent replay attacks:
  - Each announcement has a unique nonce generated with `:crypto.strong_rand_bytes(16)`
  - Nonces are tracked per `node_id` in the `seen_nonces` state
  - Duplicate nonces are rejected during verification
  - Nonce window: Last 100 nonces per node_id, expires after `ttl_ms * 1.5` (buffer for clock skew)
  - Own announcements are always accepted (to allow refresh with same nonce)

  ## Future Work

  - Real network I/O (currently in-VM only via ETS registry)
  - Ed25519 signatures for proper public-key verification (currently HMAC-SHA256)
  - Trust policy integration
  - Parallel queries with proper α concurrency
  - See `docs/02_core_network/05_node_discovery_dht.md` for planned enhancements
  """

  use GenServer
  import Bitwise
  @dialyzer {:nowarn_function, do_find_value: 5}
  @dialyzer {:nowarn_function, iterative_find_value: 3}

  @registry_table :chrono_mesh_dht_registry

  @typedoc "Opaque node ID (256-bit)"
  @type node_id :: binary()

  @typedoc "Transport address for in-VM nodes (opaque term)"
  @type address :: term()

  @typedoc "Peer record"
  @type peer :: %{
          id: node_id(),
          address: address(),
          last_seen: non_neg_integer()
        }

  @typedoc "Introduction point for anonymous connection establishment.

  Introduction points are rendezvous nodes that act as relays.
  They contain ONLY cryptographic identifiers - NO IP addresses.
  To connect through an introduction point, you must:
  1. Recursively resolve the introduction point's connection (via DHT)
  2. Connect to the introduction point node
  3. Ask the introduction point to relay to the target node
  "
  @type introduction_point :: %{
          node_id: node_id(),
          public_key: binary()
        }

  @typedoc "Node announcement record"
  @type announcement :: %{
          node_id: node_id(),
          public_key: binary(),
          timestamp: non_neg_integer(),
          expires_at: non_neg_integer(),
          signature: binary(),
          introduction_points: [introduction_point()],
          nonce: binary(),
          ed25519_public_key: binary() | nil
        }

  @typedoc "DHT state"
  @type state :: %{
          id: node_id(),
          address: address(),
          k: pos_integer(),
          alpha: pos_integer(),
          buckets: [[peer()]],
          store: %{optional(binary()) => {binary(), non_neg_integer()}},
          announcements: %{optional(node_id()) => announcement()},
          seen_nonces: %{optional(node_id()) => [nonce_entry()]},
          ttl_ms: non_neg_integer()
        }

  @type nonce_entry :: {binary(), non_neg_integer()}

  # Public API ----------------------------------------------------------------

  @doc """
  Start a DHT node.

  Options:
  - `:id` (binary 32 bytes). If missing, a random ID is generated.
  - `:address` (any term uniquely identifying this node). If missing, uses `self()`.
  - `:k` (bucket size, default 20)
  - `:alpha` (concurrency, default 3)
  - `:ttl_ms` (KV TTL in ms, default 5 minutes)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, [])
  end

  @doc """
  Bootstrap this node by contacting a list of `addresses` and updating buckets.
  """
  @spec bootstrap(pid(), [address()]) :: :ok
  def bootstrap(pid, addresses) when is_list(addresses) do
    GenServer.call(pid, {:bootstrap, addresses})
  end

  @doc """
  Put a key/value pair into the DHT (replicates to closest K peers).
  Uses the DHT's configured TTL.
  """
  @spec put(pid(), binary(), binary()) :: :ok
  def put(pid, key, value) when is_binary(key) and is_binary(value) do
    GenServer.call(pid, {:put, key, value})
  end

  @doc """
  Put a key/value pair into the DHT with a custom TTL.
  """
  @spec put(pid(), binary(), binary(), non_neg_integer()) :: :ok
  def put(pid, key, value, ttl_ms) when is_binary(key) and is_binary(value) and is_integer(ttl_ms) and ttl_ms > 0 do
    GenServer.call(pid, {:put, key, value, ttl_ms})
  end

  @doc """
  Get a key/value via iterative lookup. Returns `{:ok, value}` or `:not_found`.
  """
  @spec get(pid(), binary()) :: {:ok, binary()} | :not_found
  def get(pid, key) when is_binary(key) do
    GenServer.call(pid, {:get, key})
  end

  @doc """
  Return up to `n` nearest peers (from local view) to a target ID.
  """
  @spec neighbors(pid(), node_id(), pos_integer()) :: [peer()]
  def neighbors(pid, target_id, n) when is_binary(target_id) and is_integer(n) and n > 0 do
    GenServer.call(pid, {:neighbors, target_id, n})
  end

  @doc """
  Announce this node in the DHT with a signed announcement.

  The announcement includes: node_id, public_key, timestamp, signature, and optional introduction_points.
  It expires after `ttl_ms` (default 5 minutes).

  If Ed25519 keys are provided, they will be used for signing (proper public-key signatures).
  Otherwise, HMAC-SHA256 is used (requires private key to verify).

  No IP addresses are stored in the announcement itself - nodes are identified solely by cryptographic identifiers.
  Introduction points provide anonymous connection establishment via rendezvous nodes.
  """
  @spec announce_node(pid(), binary(), binary(), non_neg_integer(), [introduction_point()],
          keyword()) ::
          :ok | {:error, term()}
  def announce_node(
        pid,
        public_key,
        private_key,
        ttl_ms \\ :timer.minutes(5),
        introduction_points \\ [],
        opts \\ []
      ) do
    ed25519_public_key = Keyword.get(opts, :ed25519_public_key)
    ed25519_private_key = Keyword.get(opts, :ed25519_private_key)

    GenServer.call(
      pid,
      {:announce_node, public_key, private_key, ttl_ms, introduction_points,
       ed25519_public_key, ed25519_private_key}
    )
  end

  @doc """
  Lookup node announcements by node_id.
  Returns list of valid (non-expired, verified) announcements.
  """
  @spec lookup_nodes(pid(), node_id(), pos_integer()) :: [map()]
  def lookup_nodes(pid, node_id, n \\ 20) when is_binary(node_id) do
    GenServer.call(pid, {:lookup_nodes, node_id, n})
  end

  @doc """
  Refresh this node's announcement (updates expiry).
  """
  @spec refresh_announcement(pid(), binary(), binary(), non_neg_integer(), [introduction_point()]) ::
          :ok
  def refresh_announcement(
        pid,
        public_key,
        private_key,
        ttl_ms \\ :timer.minutes(5),
        introduction_points \\ []
      ) do
    announce_node(pid, public_key, private_key, ttl_ms, introduction_points)
  end

  # GenServer callbacks -------------------------------------------------------

  @impl true
  @spec init(keyword()) :: {:ok, state()}
  def init(opts) do
    ensure_registry()

    id = Keyword.get(opts, :id) || :crypto.strong_rand_bytes(32)
    address = Keyword.get(opts, :address, {:dht, self()})
    k = Keyword.get(opts, :k, 20)
    alpha = Keyword.get(opts, :alpha, 3)
    ttl_ms = Keyword.get(opts, :ttl_ms, :timer.minutes(5))

    # 256 buckets for 256-bit IDs (index 0..255)
    buckets = for _ <- 1..256, do: []

    state = %{
      id: id,
      address: address,
      k: k,
      alpha: alpha,
      buckets: buckets,
      store: %{},
      announcements: %{},
      seen_nonces: %{},
      ttl_ms: ttl_ms
    }

    register_node(address, self())
    {:ok, state}
  end

  @impl true
  def handle_call({:bootstrap, addresses}, _from, state) do
    state = contact_addresses(state, addresses)
    {:reply, :ok, state}
  end

  def handle_call({:put, key, value}, from, state) do
    handle_call({:put, key, value, state.ttl_ms}, from, state)
  end

  def handle_call({:put, key, value, ttl_ms}, _from, state) do
    now = now_ms()
    state = put_local(state, key, value, now + ttl_ms)

    target = hash_key(key)
    closest = closest_peers(state, target, state.k)

    Enum.each(closest, fn peer ->
      rpc(peer.address, {:store, peer_from_state(state), key, value, ttl_ms})
    end)

    {:reply, :ok, state}
  end

  def handle_call({:get, key}, _from, state) do
    now = now_ms()
    state = purge_expired_store(state, now)

    case state.store[key] do
      {value, exp} when exp > now ->
        {:reply, {:ok, value}, state}

      _ ->
        target = hash_key(key)
        {state, result} = iterative_find_value(state, key, target)
        {:reply, result, state}
    end
  end

  def handle_call({:neighbors, target_id, n}, _from, state) do
    {:reply, closest_peers(state, target_id, n), state}
  end

  def handle_call(
        {:announce_node, public_key, private_key, ttl_ms, introduction_points,
         ed25519_public_key, ed25519_private_key},
        _from,
        state
      ) do
    node_id = ChronoMesh.Keys.node_id_from_public_key(public_key)
    now = now_ms()
    expires_at = now + ttl_ms
    nonce = :crypto.strong_rand_bytes(16)

    safe_intro_points =
      (introduction_points || [])
      |> Enum.take(10)
      |> Enum.filter(&valid_introduction_point?/1)

    announcement_data =
      encode_announcement(
        node_id,
        public_key,
        now,
        expires_at,
        safe_intro_points,
        nonce,
        ed25519_public_key
      )

    # Use Ed25519 if available, otherwise fall back to HMAC-SHA256
    {signature, ed25519_pub} =
      if ed25519_public_key != nil and ed25519_private_key != nil do
        try do
          sig = ChronoMesh.Keys.ed25519_sign(announcement_data, ed25519_private_key)
          {sig, ed25519_public_key}
        rescue
          _ ->
            # Fallback to HMAC if Ed25519 fails
            sig = ChronoMesh.Keys.sign(announcement_data, private_key)
            {sig, nil}
        end
      else
        sig = ChronoMesh.Keys.sign(announcement_data, private_key)
        {sig, nil}
      end

    announcement = %{
      node_id: node_id,
      public_key: public_key,
      timestamp: now,
      expires_at: expires_at,
      signature: signature,
      introduction_points: safe_intro_points,
      nonce: nonce,
      ed25519_public_key: ed25519_pub
    }

    # Store announcement in DHT using node_id as key
    key = <<"node:", node_id::binary>>
    value = :erlang.term_to_binary(announcement)
    state = put_local(state, key, value, expires_at)

    # Replicate to closest K peers
    closest = closest_peers(state, node_id, state.k)

    Enum.each(closest, fn peer ->
      rpc(peer.address, {:store, peer_from_state(state), key, value, ttl_ms})
    end)

    # Update announcements cache and record nonce
    announcements = Map.put(state.announcements, node_id, announcement)
    state = %{state | announcements: announcements}
    state = record_nonce(state, node_id, nonce, now)

    {:reply, :ok, state}
  end

  def handle_call({:lookup_nodes, node_id, n}, _from, state) do
    now = now_ms()
    state = purge_expired_announcements(state, now)

    # First check local announcements cache
    local_announcements =
      state.announcements
      |> Map.values()
      |> Enum.filter(fn ann -> ann.expires_at > now end)
      |> Enum.filter(fn ann -> ann.node_id == node_id end)

    # Also try DHT lookup
    key = <<"node:", node_id::binary>>

    dht_results =
      case state.store[key] do
        {value, exp} when exp > now ->
          try do
            announcement = :erlang.binary_to_term(value, [:safe])

            if valid_announcement?(announcement) and
                 announcement.expires_at > now and
                 announcement.timestamp <= now do
              [announcement]
            else
              []
            end
          catch
            _ -> []
          end

        _ ->
          target = hash_key(key)
          {_updated_state, result} = iterative_find_value(state, key, target)

          case result do
            {:ok, value} ->
              try do
                announcement = :erlang.binary_to_term(value, [:safe])

                if valid_announcement?(announcement) do
                  [announcement]
                else
                  []
                end
              catch
                _ -> []
              end

            _ ->
              []
          end
      end

    # Merge all announcements
    all_announcements = local_announcements ++ dht_results

    # Verify signatures with replay protection
    {verified, updated_state} =
      Enum.reduce(all_announcements, {[], state}, fn announcement, {acc, st} ->
        {is_valid, new_st} = verify_announcement_with_state(st, announcement)

        if is_valid and length(acc) < n do
          {[announcement | acc], new_st}
        else
          {acc, new_st}
        end
      end)

    {:reply, Enum.reverse(verified), updated_state}
  end

  # RPC entry points ----------------------------------------------------------

  @impl true
  def handle_call({:rpc, {:ping, from_peer}}, _from, state) do
    {:reply, {:pong, peer_from_state(state)}, touch_peer(state, from_peer)}
  end

  def handle_call({:rpc, {:find_node, from_peer, target_id}}, _from, state) do
    peers = closest_peers(state, target_id, state.k)
    {:reply, {:nodes, peer_from_state(state), peers}, touch_peer(state, from_peer)}
  end

  def handle_call({:rpc, {:find_value, from_peer, key}}, _from, state) do
    now = now_ms()
    state = purge_expired_store(state, now)

    reply =
      case state.store[key] do
        {value, exp} when exp > now -> {:value, peer_from_state(state), value}
        _ -> {:nodes, peer_from_state(state), closest_peers(state, hash_key(key), state.k)}
      end

    {:reply, reply, touch_peer(state, from_peer)}
  end

  def handle_call({:rpc, {:store, from_peer, key, value, ttl_ms}}, _from, state) do
    now = now_ms()
    state = put_local(state, key, value, now + ttl_ms)
    {:reply, :ok, touch_peer(state, from_peer)}
  end

  # Internal logic ------------------------------------------------------------

  @spec iterative_find_value(state(), binary(), node_id()) ::
          {state(), {:ok, binary()} | :not_found}
  defp iterative_find_value(state, key, target) do
    queried = MapSet.new()
    queue = closest_peers(state, target, state.k)

    do_find_value(state, key, target, queried, queue)
  end

  defp do_find_value(state, _key, _target, _queried, []), do: {state, :not_found}

  defp do_find_value(state, key, target, queried, [peer | rest]) do
    if MapSet.member?(queried, peer.id) do
      do_find_value(state, key, target, queried, rest)
    else
      case rpc(peer.address, {:find_value, peer_from_state(state), key}) do
        {:value, _from, value} ->
          {state, {:ok, value}}

        {:nodes, _from, peers} ->
          merged = merge_peers(rest, peers)
          sorted = sort_by_distance(merged, target)

          do_find_value(
            touch_peer(state, peer),
            key,
            target,
            MapSet.put(queried, peer.id),
            sorted
          )

        _ ->
          do_find_value(state, key, target, MapSet.put(queried, peer.id), rest)
      end
    end
  end

  @spec closest_peers(state(), node_id(), pos_integer()) :: [peer()]
  defp closest_peers(state, target_id, n) do
    state.buckets
    |> List.flatten()
    |> Enum.reject(&(&1.id == state.id))
    |> sort_by_distance(target_id)
    |> Enum.take(n)
  end

  defp sort_by_distance(peers, target_id) do
    Enum.sort_by(peers, fn p -> distance(p.id, target_id) end)
  end

  defp merge_peers(a, b) do
    (a ++ b)
    |> Enum.uniq_by(& &1.id)
  end

  @spec contact_addresses(state(), [address()]) :: state()
  defp contact_addresses(state, []), do: state

  defp contact_addresses(state, [addr | rest]) do
    state =
      case rpc(addr, {:ping, peer_from_state(state)}) do
        {:pong, peer} -> insert_peer(state, peer)
        _ -> state
      end

    contact_addresses(state, rest)
  end

  @spec put_local(state(), binary(), binary(), non_neg_integer()) :: state()
  defp put_local(state, key, value, expires_at) do
    %{state | store: Map.put(state.store, key, {value, expires_at})}
  end

  @spec purge_expired_store(state(), non_neg_integer()) :: state()
  defp purge_expired_store(state, now) do
    store =
      state.store
      |> Enum.reject(fn {_key, {_value, exp}} -> exp <= now end)
      |> Enum.into(%{})

    %{state | store: store}
  end

  @spec touch_peer(state(), peer()) :: state()
  defp touch_peer(state, %{} = peer) do
    insert_peer(state, %{peer | last_seen: now_ms()})
  end

  @spec insert_peer(state(), peer()) :: state()
  defp insert_peer(state, %{} = peer) do
    idx = bucket_index(state.id, peer.id)
    buckets = state.buckets
    bucket = Enum.at(buckets, idx)

    bucket =
      bucket
      |> Enum.reject(&(&1.id == peer.id))
      |> Kernel.++([peer])
      |> lru_trim(state.k)

    %{state | buckets: List.replace_at(buckets, idx, bucket)}
  end

  defp lru_trim(list, k) do
    if length(list) <= k, do: list, else: Enum.drop(list, length(list) - k)
  end

  @spec peer_from_state(state()) :: peer()
  defp peer_from_state(state) do
    %{id: state.id, address: state.address, last_seen: now_ms()}
  end

  @spec bucket_index(node_id(), node_id()) :: non_neg_integer()
  defp bucket_index(id1, id2) do
    xor_result = xor_bin(id1, id2)
    # Count leading zeros in the 32-byte (256-bit) binary
    leading = count_leading_zeros_binary(xor_result)
    # For identical IDs (all zeros), place in the last bucket (index 255) though we filter self
    min(255, 255 - leading)
  end

  defp count_leading_zeros_binary(<<>>), do: 256

  defp count_leading_zeros_binary(bin) when byte_size(bin) == 32 do
    count_leading_zeros_binary_aux(bin, 0)
  end

  defp count_leading_zeros_binary_aux(<<0::8, rest::binary>>, count) when count < 256 do
    count_leading_zeros_binary_aux(rest, count + 8)
  end

  defp count_leading_zeros_binary_aux(<<byte::8, _rest::binary>>, count) do
    # Count leading zeros in this byte
    byte_leading = count_leading_zeros_byte(byte, 0)
    count + byte_leading
  end

  defp count_leading_zeros_byte(0, count), do: count

  defp count_leading_zeros_byte(byte, count) when count < 8 do
    if (byte &&& 0x80) == 0 do
      count_leading_zeros_byte(byte <<< 1, count + 1)
    else
      count
    end
  end

  defp count_leading_zeros_byte(_byte, count), do: count

  @spec xor_bin(binary(), binary()) :: binary()
  defp xor_bin(<<a::binary-size(32)>>, <<b::binary-size(32)>>) do
    :crypto.exor(a, b)
  end

  @spec distance(node_id(), node_id()) :: non_neg_integer()
  defp distance(a, b) do
    <<d::unsigned-size(256)>> = xor_bin(a, b)
    d
  end

  @spec hash_key(binary()) :: node_id()
  defp hash_key(key) do
    :crypto.hash(:sha256, key)
  end

  @spec now_ms() :: non_neg_integer()
  defp now_ms, do: System.system_time(:millisecond)

  # Announcement helpers --------------------------------------------------------

  @spec encode_announcement(node_id(), binary(), non_neg_integer(), non_neg_integer(), [
          introduction_point()
        ], binary(), binary() | nil) ::
          binary()
  defp encode_announcement(
         node_id,
         public_key,
         timestamp,
         expires_at,
         introduction_points,
         nonce,
         ed25519_public_key
       ) do
    intro_points = introduction_points || []
    ed25519_pub = ed25519_public_key || <<>>
    :erlang.term_to_binary(
      {node_id, public_key, timestamp, expires_at, intro_points, nonce, ed25519_pub}
    )
  end

  @spec verify_announcement(announcement()) :: boolean()
  defp verify_announcement(announcement) do
    now = now_ms()

    # Check timestamp validity (with clock skew tolerance)
    if not timestamp_valid?(announcement.timestamp, announcement.expires_at, now) do
      false
    else
      announcement_data =
        encode_announcement(
          announcement.node_id,
          announcement.public_key,
          announcement.timestamp,
          announcement.expires_at,
          announcement.introduction_points || [],
          announcement.nonce,
          Map.get(announcement, :ed25519_public_key)
        )

      # Use Ed25519 verification if ed25519_public_key is present, otherwise fall back to HMAC
      if Map.has_key?(announcement, :ed25519_public_key) and
           announcement.ed25519_public_key != nil and
           byte_size(announcement.ed25519_public_key) == 32 do
        # Ed25519 verification (proper public-key signature)
        try do
          ChronoMesh.Keys.ed25519_verify(
            announcement_data,
            announcement.signature,
            announcement.ed25519_public_key
          )
        rescue
          _ -> false
        catch
          _ -> false
        end
      else
        # HMAC-SHA256 verification (basic structure check)
        ChronoMesh.Keys.verify_public(
          announcement_data,
          announcement.signature,
          announcement.public_key
        )
      end
    end
  end

  @spec timestamp_valid?(non_neg_integer(), non_neg_integer(), non_neg_integer()) :: boolean()
  defp timestamp_valid?(timestamp, expires_at, now) do
    # Clock skew tolerance: ±5 minutes
    clock_skew_tolerance_ms = :timer.minutes(5)

    # Check expiration
    if expires_at <= now do
      false
    else
      # Reject future timestamps (beyond tolerance)
      if timestamp > now + clock_skew_tolerance_ms do
        false
      else
        # Reject too-old timestamps (older than expiry window)
        # Allow timestamps up to ttl_ms before now
        # For default 5-minute TTL, this means timestamps from 5 minutes ago are acceptable
        ttl_ms = expires_at - timestamp
        max_age = ttl_ms + clock_skew_tolerance_ms

        timestamp >= now - max_age
      end
    end
  end

  @spec verify_announcement_with_state(state(), announcement()) :: {boolean(), state()}
  defp verify_announcement_with_state(state, announcement) do
    now = now_ms()

    # First verify signature and timestamp
    if not verify_announcement(announcement) do
      {false, state}
    else
      # Check if this announcement is already in our local cache
      # (we announced it ourselves, so it's valid even if nonce was seen)
      is_own_announcement = Map.has_key?(state.announcements, announcement.node_id)

      if is_own_announcement and
           Map.get(state.announcements, announcement.node_id).nonce == announcement.nonce do
        # This is our own announcement - always accept
        {true, state}
      else
        # Check for replay attack (nonce already seen from another source)
        if seen_nonce?(state, announcement.node_id, announcement.nonce) do
          {false, state}
        else
          # Record nonce after successful verification
          updated_state = record_nonce(state, announcement.node_id, announcement.nonce, now)
          {true, updated_state}
        end
      end
    end
  end

  @spec purge_expired_announcements(state(), non_neg_integer()) :: state()
  defp purge_expired_announcements(state, now) do
    announcements =
      state.announcements
      |> Enum.reject(fn {_node_id, ann} -> ann.expires_at <= now end)
      |> Enum.into(%{})

    state = %{state | announcements: announcements}
    purge_expired_nonces(state, now)
  end

  @spec valid_announcement?(term()) :: boolean()
  defp valid_announcement?(term) do
    case term do
      %{
        node_id: node_id,
        public_key: public_key,
        timestamp: timestamp,
        expires_at: expires_at,
        signature: signature,
        introduction_points: introduction_points,
        nonce: nonce
      } = announcement ->
        # Check if ed25519_public_key is present (optional field)
        ed25519_pub = Map.get(announcement, :ed25519_public_key)

        # Validate signature size based on type
        # Ed25519 signatures are 64 bytes, HMAC-SHA256 are 32 bytes
        valid_signature_size =
          if ed25519_pub != nil and byte_size(ed25519_pub) == 32 do
            # Ed25519 signature
            byte_size(signature) == 64
          else
            # HMAC-SHA256 signature
            byte_size(signature) == 32
          end

        if is_binary(node_id) and byte_size(node_id) == 32 and
             is_binary(public_key) and byte_size(public_key) == 32 and
             is_integer(timestamp) and timestamp > 0 and
             is_integer(expires_at) and expires_at > timestamp and
             is_binary(signature) and valid_signature_size and
             is_list(introduction_points) and length(introduction_points) <= 10 and
             is_binary(nonce) and byte_size(nonce) == 16 and
             (ed25519_pub == nil or (is_binary(ed25519_pub) and byte_size(ed25519_pub) == 32)) do
          Enum.all?(introduction_points, &valid_introduction_point?/1)
        else
          false
        end

      _ ->
        false
    end
  end

  @spec valid_introduction_point?(term()) :: boolean()
  defp valid_introduction_point?(term) do
    case term do
      %{node_id: node_id, public_key: public_key}
      when is_binary(node_id) and byte_size(node_id) == 32 and
             is_binary(public_key) and byte_size(public_key) == 32 ->
        true

      _ ->
        false
    end
  end

  # Nonce tracking functions -----------------------------------------------------

  @spec seen_nonce?(state(), node_id(), binary()) :: boolean()
  defp seen_nonce?(state, node_id, nonce) do
    case Map.get(state.seen_nonces, node_id, []) do
      [] ->
        false

      nonces ->
        Enum.any?(nonces, fn {seen_nonce, _timestamp} -> seen_nonce == nonce end)
    end
  end

  @spec record_nonce(state(), node_id(), binary(), non_neg_integer()) :: state()
  defp record_nonce(state, node_id, nonce, timestamp) do
    existing_nonces = Map.get(state.seen_nonces, node_id, [])

    # Add new nonce with timestamp
    new_entry = {nonce, timestamp}
    updated_nonces = [new_entry | existing_nonces]

    # Limit to last 100 nonces per node_id (FIFO eviction)
    trimmed_nonces =
      if length(updated_nonces) > 100 do
        updated_nonces
        |> Enum.sort_by(fn {_nonce, ts} -> ts end, :desc)
        |> Enum.take(100)
      else
        updated_nonces
      end

    updated_seen_nonces = Map.put(state.seen_nonces, node_id, trimmed_nonces)
    %{state | seen_nonces: updated_seen_nonces}
  end

  @spec purge_expired_nonces(state(), non_neg_integer()) :: state()
  defp purge_expired_nonces(state, now) do
    # Keep nonces for duration of ttl_ms * 1.5 (buffer for clock skew)
    expiry_window = div(state.ttl_ms * 3, 2)
    cutoff_time = now - expiry_window

    updated_seen_nonces =
      state.seen_nonces
      |> Enum.map(fn {node_id, nonces} ->
        # Filter out expired nonces
        active_nonces =
          Enum.filter(nonces, fn {_nonce, timestamp} -> timestamp >= cutoff_time end)

        {node_id, active_nonces}
      end)
      |> Enum.filter(fn {_node_id, nonces} -> length(nonces) > 0 end)
      |> Enum.into(%{})

    %{state | seen_nonces: updated_seen_nonces}
  end

  # Trust policy hooks -----------------------------------------------------------

  @doc """
  Callback for trust policy checks. Returns `true` by default.
  Can be overridden to implement custom trust logic.
  """
  @spec trust_policy_check(announcement(), keyword()) :: boolean()
  def trust_policy_check(announcement, _opts \\ []) do
    # Default: accept all verified announcements
    # Can be extended with trust scoring, blacklists, etc.
    # Note: Replay protection is handled in verify_announcement_with_state
    verify_announcement(announcement)
  end

  # Transport (in-VM registry) -----------------------------------------------

  @spec ensure_registry() :: :ok
  defp ensure_registry do
    case :ets.info(@registry_table) do
      :undefined -> :ets.new(@registry_table, [:named_table, :public, read_concurrency: true])
      _ -> :ok
    end

    :ok
  end

  @spec register_node(address(), pid()) :: :ok
  defp register_node(address, pid) do
    :ets.insert(@registry_table, {address, pid})
    :ok
  end

  @spec rpc(address(), term()) :: term() | :nodedown
  defp rpc(address, message) do
    case :ets.lookup(@registry_table, address) do
      [{^address, pid}] when is_pid(pid) ->
        if Process.alive?(pid) do
          try do
            GenServer.call(pid, {:rpc, message}, 2_000)
          catch
            :exit, {:timeout, _} -> :nodedown
            :exit, _ -> :nodedown
          end
        else
          :nodedown
        end

      _ ->
        :nodedown
    end
  end
end
