defmodule ChronoMesh.Discovery do
  @moduledoc """
  Discovery service backed by DHT for decentralized peer discovery.

  - Maintains an ETS table of known peers for local caching: %{node_id => %{node_id, public_key, ts}}.
  - On start, publishes self to DHT (if identity present) and ingests bootstrap peers.
  - Provides random sampling for path building via DHT lookup.
  - Uses signed announcements with expiry for authenticity.
  - Supports trust policy hooks for future extensibility.
  - Automatically publishes subscription lists and aliases to DHT for distributed address book resolution.

  ## Address Book Integration

  Discovery automatically integrates with AddressBook subscriptions:

  - **Auto-Publish on Startup**: On initialization, publishes subscription list and all local aliases to DHT
  - **Periodic Refresh**: Refreshes subscription list and alias publishing at configurable intervals
  - **Distributed Resolution**: `lookup_peer/1` queries distributed address books when local resolution fails

  ### Subscription Publishing

  When a node starts, Discovery:
  1. Retrieves the node's subscription list from AddressBook
  2. Signs and publishes the subscription list to DHT (if subscriptions exist)
  3. Publishes all locally registered aliases to DHT (if subscriptions exist)

  The refresh interval is configurable via `address_book.subscriptions.refresh_interval_ms`
  (default: 30 minutes).

  ### Alias Resolution

  `lookup_peer/1` performs alias resolution in this order:
  1. Local AddressBook lookup
  2. Local cache of published aliases from DHT
  3. Distributed resolution via subscription lists (queries subscribed nodes' aliases from DHT)

  Integrates with ChronoMesh.DHT for decentralized discovery while maintaining
  local cache for performance.
  """

  use GenServer
  require Logger

  alias ChronoMesh.{AddressBook, DHT, Keys}

  @table :chrono_mesh_peers

  @type peer :: %{
          node_id: binary(),
          public_key: binary(),
          ts: non_neg_integer()
        }

  @type state :: %{
          config: map(),
          dht_pid: pid() | nil,
          private_key: binary() | nil,
          public_key: binary() | nil,
          ed25519_private_key: binary(),
          ed25519_public_key: binary(),
          announce_interval: non_neg_integer(),
          refresh_interval: non_neg_integer(),
          last_announce: non_neg_integer()
        }

  @doc """
  Starts the DHT-backed peer discovery process.
  """
  @spec start_link(map()) :: GenServer.on_start()
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @impl true
  @doc """
  Initializes the discovery process by creating the ETS table, starting DHT node,
  bootstrapping from config, and publishing the self-node entry to DHT.
  """
  @spec init(map()) :: {:ok, state()}
  def init(config) do
    ensure_table()

    # Start DHT node for this discovery instance
    dht_opts = [
      address: {:discovery_dht, self()},
      k: 20,
      alpha: 3,
      ttl_ms: :timer.minutes(5)
    ]

    {:ok, dht_pid} = DHT.start_link(dht_opts)

    # Load keys if available
    {private_key, public_key} = load_keys(config)
    {ed25519_private_key, ed25519_public_key} = load_ed25519_keys(config)

    # Bootstrap DHT
    bootstrap_from_config(config, dht_pid)

    # Publish self to DHT
    # Get refresh interval from config
    refresh_interval = AddressBook.subscription_refresh_interval_ms(config)

    state = %{
      config: config,
      dht_pid: dht_pid,
      private_key: private_key,
      public_key: public_key,
      ed25519_private_key: ed25519_private_key,
      ed25519_public_key: ed25519_public_key,
      # Refresh before expiry
      announce_interval: :timer.minutes(4),
      refresh_interval: refresh_interval,
      last_announce: 0
    }

    publish_self_to_dht(state)

    # Schedule periodic announcement refresh
    schedule_announce_refresh(state)

    {:ok, state}
  end

  @doc """
  Returns all known peers collected in the in-memory registry.
  """
  @spec list_peers() :: [peer()]
  def list_peers do
    case :ets.tab2list(@table) do
      [] -> []
      entries -> Enum.map(entries, fn {_pk, peer} -> peer end)
    end
  end

  @doc """
  Provides a shuffled subset of peers useful for path construction.
  Uses DHT lookup if local cache is insufficient.
  """
  @spec random_sample(non_neg_integer()) :: [peer()]
  def random_sample(n) when n > 0 do
    local_peers = list_peers()

    if length(local_peers) >= n do
      local_peers |> Enum.shuffle() |> Enum.take(n)
    else
      # Use DHT to find more peers
      case GenServer.whereis(__MODULE__) do
        nil ->
          local_peers |> Enum.shuffle() |> Enum.take(n)

        pid ->
          GenServer.call(pid, {:random_sample_from_dht, n})
      end
    end
  end

  @doc """
  Lookup peer by identifier (alias or node_id).

  Accepts:
  - Alias (e.g., `"alice.mesh"`) - resolves via AddressBook first
  - Node ID (hex string or binary) - queries DHT directly
  - Public key (binary) - derives node_id and queries DHT

  Returns `{:ok, node_id}` if found, `:not_found` otherwise.
  """
  @spec lookup_peer(String.t() | binary()) :: {:ok, binary()} | :not_found
  def lookup_peer(identifier) when is_binary(identifier) do
    cond do
      # Check if it's an alias (ends with .mesh)
      String.ends_with?(identifier, ".mesh") ->
        case AddressBook.resolve(identifier) do
          {:ok, node_id} ->
            {:ok, node_id}

          :not_found ->
            # Try DHT lookup if Discovery is available
            case GenServer.whereis(__MODULE__) do
              nil ->
                :not_found

              pid ->
                case GenServer.call(pid, {:get_state}, 5_000) do
                  %{dht_pid: dht_pid, public_key: public_key} when public_key != nil ->
                    node_id = Keys.node_id_from_public_key(public_key)
                    AddressBook.resolve_distributed(dht_pid, node_id, identifier)

                  _ ->
                    :not_found
                end
            end
        end

      # Check if it's a hex-encoded node_id (64 hex chars = 32 bytes)
      Regex.match?(~r/^[0-9a-fA-F]{64}$/i, identifier) ->
        try do
          node_id = Base.decode16!(identifier, case: :mixed)
          {:ok, node_id}
        rescue
          ArgumentError -> :not_found
        end

      # Check if it's a 32-byte binary (node_id)
      byte_size(identifier) == 32 ->
        {:ok, identifier}

      # Otherwise treat as public_key and derive node_id
      true ->
        node_id = Keys.node_id_from_public_key(identifier)

        case GenServer.whereis(__MODULE__) do
          nil ->
            # Fallback to local cache
            case :ets.lookup(@table, node_id) do
              [{^node_id, _peer}] -> {:ok, node_id}
              _ -> :not_found
            end

          pid ->
            case GenServer.call(pid, {:lookup_peer_dht, node_id}, 5_000) do
              [_announcement | _] -> {:ok, node_id}
              _ -> :not_found
            end
        end
    end
  end

  @doc """
  Lookup peer by public key using DHT (legacy function, kept for backward compatibility).
  """
  @spec lookup_peer_by_public_key(binary()) :: [peer()]
  def lookup_peer_by_public_key(public_key) when is_binary(public_key) do
    node_id = Keys.node_id_from_public_key(public_key)

    case GenServer.whereis(__MODULE__) do
      nil ->
        # Fallback to local cache
        case :ets.lookup(@table, public_key) do
          [{^public_key, peer}] -> [peer]
          _ -> []
        end

      pid ->
        GenServer.call(pid, {:lookup_peer_dht, node_id})
    end
  end

  @doc """
  Inserts or updates a peer in the discovery table.

  Takes a public_key and derives the node_id from it.
  Peers are identified solely by cryptographic identifiers (no IP addresses).
  """
  @spec upsert_peer(binary()) :: :ok
  def upsert_peer(public_key) when is_binary(public_key) do
    node_id = Keys.node_id_from_public_key(public_key)
    ts = System.os_time(:second)
    :ets.insert(@table, {node_id, %{node_id: node_id, public_key: public_key, ts: ts}})
    :ok
  end

  @spec ensure_table() :: :chrono_mesh_peers
  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined -> :ets.new(@table, [:set, :public, :named_table])
      _ -> @table
    end
  end

  @impl true
  def handle_call({:get_state}, _from, state) do
    {:reply, state, state}
  end

  def handle_call({:random_sample_from_dht, n}, _from, state) do
    # Generate random target IDs to sample DHT
    random_targets = for _ <- 1..min(n, 5), do: :crypto.strong_rand_bytes(32)

    dht_peers =
      random_targets
      |> Enum.flat_map(fn target_id ->
        DHT.neighbors(state.dht_pid, target_id, 10)
      end)
      |> Enum.uniq_by(& &1.id)

    # Convert DHT peers to discovery format
    peers = Enum.map(dht_peers, fn dht_peer -> convert_dht_peer(dht_peer) end)

    # Merge with local cache
    all_peers = (list_peers() ++ peers) |> Enum.uniq_by(& &1.node_id)
    result = all_peers |> Enum.shuffle() |> Enum.take(n)

    {:reply, result, state}
  end

  def handle_call({:lookup_peer_dht, node_id}, _from, state) do
    announcements = DHT.lookup_nodes(state.dht_pid, node_id, 5)

    peers =
      announcements
      |> Enum.filter(&trust_policy_check/1)
      |> Enum.map(&announcement_to_peer/1)

    # Update local cache
    Enum.each(peers, fn peer ->
      upsert_peer(peer.public_key)
    end)

    # Return announcements (not just peers) so introduction_points can be accessed
    verified_announcements =
      announcements
      |> Enum.filter(&trust_policy_check/1)
      |> Enum.take(1)

    {:reply, verified_announcements, state}
  end

  @impl true
  def handle_info(:refresh_announcement, state) do
    state = publish_self_to_dht(state)
    schedule_announce_refresh(state)
    {:noreply, state}
  end

  @spec bootstrap_from_config(map(), pid()) :: :ok
  defp bootstrap_from_config(%{"network" => net}, _dht_pid) do
    peers = Map.get(net, "bootstrap_peers", [])

    Enum.each(peers, fn peer ->
      case peer do
        %{"public_key" => pk} = peer_config ->
          case decode_pk(pk) do
            {:ok, pubkey} ->
              node_id = Keys.node_id_from_public_key(pubkey)
              upsert_peer(pubkey)

              if connection_hint = Map.get(peer_config, "connection_hint") do
                case parse_connection_hint(connection_hint) do
                  {host, port} ->
                    ChronoMesh.ControlClient.register_connection(node_id, host, port)

                  nil ->
                    Logger.warning("Discovery: invalid connection_hint for bootstrap peer")
                end
              end
          end

        %{"node_id" => node_id_hex} = peer_config ->
          case Base.decode16(node_id_hex, case: :mixed) do
            {:ok, node_id} when byte_size(node_id) == 32 ->
              public_key = node_id
              upsert_peer(public_key)

              if connection_hint = Map.get(peer_config, "connection_hint") do
                case parse_connection_hint(connection_hint) do
                  {host, port} when is_binary(host) and is_integer(port) and port > 0 ->
                    ChronoMesh.ControlClient.register_connection(node_id, host, port)

                  _ ->
                    Logger.warning("Discovery: invalid connection_hint for bootstrap peer")
                end
              end

            {:ok, node_id} ->
              Logger.warning(
                "Discovery: bootstrap peer node_id has invalid size #{byte_size(node_id)}, expected 32"
              )

            :error ->
              Logger.warning(
                "Discovery: invalid bootstrap peer node_id encoding #{inspect(peer)}"
              )
          end

        _ ->
          Logger.warning("Discovery: invalid bootstrap peer #{inspect(peer)}")
      end
    end)

    :ok
  end

  defp bootstrap_from_config(_, _), do: :ok

  @spec parse_connection_hint(String.t()) :: {String.t(), pos_integer()} | nil
  defp parse_connection_hint(hint) when is_binary(hint) do
    case String.split(hint, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, _} when port > 0 -> {host, port}
          _ -> nil
        end

      _ ->
        nil
    end
  end

  defp parse_connection_hint(_), do: nil

  @spec decode_pk(String.t()) :: {:ok, binary()}
  defp decode_pk(pk) when is_binary(pk) do
    pk = String.trim(pk)

    case Base.decode64(pk) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:ok, pk}
    end
  end

  @spec load_keys(map()) :: {binary() | nil, binary() | nil}
  defp load_keys(%{
         "identity" => %{"private_key_path" => priv_path, "public_key_path" => pub_path}
       }) do
    try do
      private_key = Keys.read_private_key!(priv_path)
      public_key = Keys.read_public_key!(pub_path)
      {private_key, public_key}
    rescue
      _ -> {nil, nil}
    end
  end

  defp load_keys(_), do: {nil, nil}

  @spec load_ed25519_keys(map()) :: {binary(), binary()}
  defp load_ed25519_keys(%{
         "identity" => %{
           "ed25519_private_key_path" => priv_path,
           "ed25519_public_key_path" => pub_path
         }
       }) do
    ed25519_private_key = Keys.read_private_key!(priv_path)
    ed25519_public_key = Keys.read_public_key!(pub_path)
    {ed25519_private_key, ed25519_public_key}
  end

  defp load_ed25519_keys(_) do
    raise ArgumentError,
          "ed25519_private_key_path and ed25519_public_key_path must be configured in config[\"identity\"]"
  end

  @spec publish_self_to_dht(state()) :: state()
  defp publish_self_to_dht(%{dht_pid: nil} = state), do: state
  defp publish_self_to_dht(%{private_key: nil} = state), do: state
  defp publish_self_to_dht(%{public_key: nil} = state), do: state

  defp publish_self_to_dht(
         %{
           dht_pid: dht_pid,
           private_key: private_key,
           public_key: public_key,
           ed25519_private_key: ed25519_private_key,
           ed25519_public_key: ed25519_public_key,
           config: config
         } = state
       ) do
    introduction_points = build_introduction_points(config)

    # Build options for Ed25519 keys (required)
    opts = [
      ed25519_private_key: ed25519_private_key,
      ed25519_public_key: ed25519_public_key
    ]

    case DHT.announce_node(
           dht_pid,
           public_key,
           private_key,
           :timer.minutes(5),
           introduction_points,
           opts
         ) do
      :ok ->
        node_id = Keys.node_id_from_public_key(public_key)
        sig_type = "Ed25519"

        Logger.info(
          "Discovery: announced self to DHT with node_id #{Base.encode16(node_id)} (#{length(introduction_points)} introduction points, #{sig_type})"
        )

        # Publish subscription list to DHT
        publish_subscription_list_to_dht(state)

        # Publish all aliases to DHT
        publish_all_aliases_to_dht(state)

        %{state | last_announce: System.system_time(:millisecond)}

      {:error, reason} ->
        Logger.warning("Discovery: failed to announce to DHT: #{inspect(reason)}")
        state
    end
  end

  @spec build_introduction_points(map()) :: [ChronoMesh.DHT.introduction_point()]
  defp build_introduction_points(_config) do
    known_peers = list_peers()
    selected_peers = known_peers |> Enum.shuffle() |> Enum.take(3)

    Enum.map(selected_peers, fn peer ->
      %{
        node_id: peer.node_id,
        public_key: peer.public_key
      }
    end)
  end

  defp publish_subscription_list_to_dht(%{
         dht_pid: dht_pid,
         public_key: public_key,
         private_key: private_key,
         ed25519_private_key: ed25519_private_key,
         ed25519_public_key: ed25519_public_key,
         config: config
       })
       when public_key != nil and private_key != nil do
    node_id = Keys.node_id_from_public_key(public_key)

    # Check if subscriptions exist
    subscriptions = AddressBook.list_subscriptions(node_id)

    if length(subscriptions) > 0 do
        case AddressBook.publish_subscription_list(
               dht_pid,
               node_id,
               private_key,
               ed25519_private_key,
               ed25519_public_key,
               config
             ) do
        :ok ->
          Logger.debug(
            "Discovery: published subscription list to DHT (#{length(subscriptions)} subscriptions)"
          )

        {:error, reason} ->
          Logger.warning(
            "Discovery: failed to publish subscription list to DHT: #{inspect(reason)}"
          )
      end
    end
  end

  defp publish_subscription_list_to_dht(_state) do
    :ok
  end

  defp publish_all_aliases_to_dht(%{
         dht_pid: dht_pid,
         public_key: public_key,
         private_key: private_key,
         ed25519_private_key: ed25519_private_key,
         ed25519_public_key: ed25519_public_key,
         config: config
       })
       when public_key != nil and private_key != nil do
    node_id = Keys.node_id_from_public_key(public_key)

    # Check if subscriptions exist (only publish if others are subscribed)
    subscriptions = AddressBook.list_subscriptions(node_id)

    if length(subscriptions) > 0 do
      # Get all registered aliases
      aliases = AddressBook.list()

      # Publish each alias
      Enum.each(aliases, fn {alias, _node_id} ->
        case AddressBook.publish_alias(
               dht_pid,
               alias,
               node_id,
               private_key,
               ed25519_private_key,
               ed25519_public_key,
               config
             ) do
          :ok ->
            Logger.debug("Discovery: published alias #{alias} to DHT")

          {:error, reason} ->
            Logger.warning(
              "Discovery: failed to publish alias #{alias} to DHT: #{inspect(reason)}"
            )
        end
      end)
    end
  end

  defp publish_all_aliases_to_dht(_state) do
    :ok
  end

  @spec schedule_announce_refresh(state()) :: reference()
  defp schedule_announce_refresh(%{refresh_interval: refresh_interval}) do
    Process.send_after(self(), :refresh_announcement, refresh_interval)
  end

  defp schedule_announce_refresh(_state) do
    # Fallback if refresh_interval not set
    Process.send_after(self(), :refresh_announcement, :timer.minutes(30))
  end

  @spec convert_dht_peer(ChronoMesh.DHT.peer()) :: peer()
  defp convert_dht_peer(dht_peer) do
    %{
      node_id: dht_peer.id,
      public_key: dht_peer.id,
      ts: dht_peer.last_seen
    }
  end

  @spec announcement_to_peer(map()) :: peer()
  defp announcement_to_peer(announcement) do
    %{
      node_id: announcement.node_id,
      public_key: announcement.public_key,
      ts: announcement.timestamp
    }
  end

  @spec trust_policy_check(map()) :: boolean()
  defp trust_policy_check(announcement) do
    DHT.trust_policy_check(announcement)
  end
end
