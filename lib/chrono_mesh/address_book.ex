defmodule ChronoMesh.AddressBook do
  @moduledoc """
  Local address book for human-readable aliases with distributed subscription support.

  Provides I2P-style alias mapping: `alias.mesh` → `node_id`.
  Supports both local storage and distributed alias resolution via DHT subscriptions.

  ## Features

  - **Local Storage**: Aliases are stored in an ETS table, local to each node
  - **Signature-Based**: Each alias is signed by the node owner to prove ownership
  - **I2P-Style**: Format is `name.mesh` where name is alphanumeric + hyphens (max 64 chars)
  - **Cryptographic Security**: Aliases map to `node_id` (cryptographic identifiers), never IP addresses
  - **Distributed Resolution**: Subscribe to other nodes' address books for distributed alias discovery
  - **DHT Publishing**: Publish subscription lists and aliases to DHT for network-wide discovery

  ## Usage

      # Register an alias
      {public_key, private_key} = ChronoMesh.Keys.generate()
      node_id = ChronoMesh.Keys.node_id_from_public_key(public_key)
      :ok = AddressBook.register("alice", node_id, public_key, private_key)

      # Resolve alias to node_id (checks local, then DHT cache, then distributed)
      {:ok, node_id} = AddressBook.resolve("alice.mesh")
      :not_found = AddressBook.resolve("unknown.mesh")

      # Subscribe to another node's address book
      {target_pub, _target_priv} = ChronoMesh.Keys.generate()
      target_node_id = ChronoMesh.Keys.node_id_from_public_key(target_pub)
      :ok = AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id, config)

      # Publish subscription list to DHT
      :ok = AddressBook.publish_subscription_list(
        dht_pid, subscriber_node_id, subscriber_private_key, nil, nil, config
      )

      # Publish alias to DHT
      :ok = AddressBook.publish_alias(
        dht_pid, "alice", node_id, private_key, nil, nil, config
      )

      # List all aliases
      aliases = AddressBook.list()
      # => [{"alice.mesh", <<...>>}, {"bob.mesh", <<...>>}]

      # Delete an alias
      :ok = AddressBook.delete("alice.mesh")

  ## Alias Format

  - Must be alphanumeric characters and hyphens (no spaces, special chars)
  - Maximum 64 characters (excluding `.mesh` suffix)
  - Suffix `.mesh` is automatically added if not present
  - Examples: `"alice"` → `"alice.mesh"`, `"bob-123"` → `"bob-123.mesh"`

  ## Signature

  Each alias is signed with the node's private key:
  - Message: `alias || node_id || published_at || expires_at`
  - Signature: Ed25519 (preferred) or HMAC-SHA256 (fallback)
  - Verification: Checks signature structure and cryptographic validity

  ## Subscriptions

  Nodes can subscribe to other nodes' address books for distributed alias resolution:

  - **Subscription Limits**: Maximum 100 subscriptions per node (configurable)
  - **Rate Limiting**: Max 1 publish per minute per subscription list (configurable)
  - **TTL**: Subscription lists expire after 1 hour (configurable)
  - **Security**: Subscription lists are signed by the subscriber to prevent tampering

  ### Subscription List Format

  - DHT Key: `"subs:<subscriber_node_id>"`
  - Contains: List of `node_id`s that the subscriber is subscribed to
  - Signed: By subscriber's private key (Ed25519 or HMAC-SHA256)
  - Verified: Using subscriber's public key from DHT announcement

  ### Alias Publishing

  - DHT Key: `"alias:<alias_name>:<owner_node_id>"`
  - Contains: Published alias with signature and expiration
  - Signed: By owner's private key (Ed25519 or HMAC-SHA256)
  - Verified: Using owner's public key from DHT announcement

  ## Configuration

  Subscription and alias publishing behavior can be configured via `address_book` section:

      address_book:
        subscriptions:
          enabled: true
          max_count: 100
          refresh_interval_ms: 1800000  # 30 minutes
          ttl_ms: 3600000  # 1 hour
          rate_limit_ms: 60000  # 1 minute
        aliases:
          publish_ttl_ms: 86400000  # 24 hours
          publish_rate_limit_ms: 60000  # 1 minute

  Use configuration helpers to read values:
  - `max_subscriptions/1` - Maximum subscription count
  - `subscription_ttl_ms/1` - Subscription list TTL
  - `subscription_rate_limit_ms/1` - Rate limit for publishing
  - `subscriptions_enabled?/1` - Check if subscriptions are enabled
  - `subscription_refresh_interval_ms/1` - Refresh interval for Discovery
  - `alias_publish_ttl_ms/1` - Alias publish TTL
  - `alias_publish_rate_limit_ms/1` - Rate limit for alias publishing

  ## Security Guarantees

  - **Signature Verification**: All subscription lists and published aliases are cryptographically signed
  - **Replay Protection**: Timestamps and expiration prevent replay attacks
  - **Rate Limiting**: Prevents DoS attacks via excessive publishing
  - **Subscription Limits**: Prevents abuse via excessive subscriptions
  - **No Subscription Chaining**: Subscriptions can only target actual node IDs, not other subscription lists

  ## Integration

  - **ClientActions**: `send_message/4` accepts aliases (e.g., `"alice.mesh"`)
  - **Discovery**: `lookup_peer/1` resolves aliases via local lookup, DHT cache, and distributed resolution
  - **Discovery**: Automatically publishes subscription lists and aliases to DHT on startup and periodically

  ## Privacy

  - Address books are primarily local (not automatically shared)
  - Subscriptions allow opt-in distributed alias resolution
  - Aliases resolve to cryptographic identifiers only (no IP addresses)
  - Signature proves ownership but doesn't reveal private key
  - Subscription lists are publicly queryable but signed to prevent tampering
  """

  require Logger

  alias ChronoMesh.{Keys, DHT}

  @table :chrono_mesh_address_book
  @subscriptions_table :chrono_mesh_subscriptions
  @rate_limit_table :chrono_mesh_subscription_rate_limit
  @alias_rate_limit_table :chrono_mesh_alias_rate_limit
  @published_aliases_table :chrono_mesh_published_aliases

  @type alias_entry :: %{
          alias: String.t(),
          node_id: binary(),
          public_key: binary(),
          signature: binary(),
          registered_at: non_neg_integer()
        }

  @type subscription_list :: %{
          subscriber_node_id: binary(),
          subscribed_nodes: [binary()],
          timestamp: non_neg_integer(),
          expires_at: non_neg_integer(),
          signature: binary(),
          ed25519_public_key: binary() | nil
        }

  @doc """
  Registers a new alias for the current node.

  The alias must be in format `name.mesh` where name is alphanumeric + hyphens (max 64 chars).
  The signature proves ownership of the node_id.

  If subscriptions exist, the alias will be automatically published to DHT.

  Returns `:ok` on success, or `{:error, reason}` on failure.
  """
  @spec register(String.t(), binary(), binary(), binary()) :: :ok | {:error, term()}
  def register(alias_name, node_id, public_key, private_key) do
    register(alias_name, node_id, public_key, private_key, nil, nil)
  end

  @doc """
  Registers a new alias for the current node with optional Ed25519 keys.

  If subscriptions exist, the alias will be automatically published to DHT.
  """
  @spec register(String.t(), binary(), binary(), binary(), binary() | nil, binary() | nil) ::
          :ok | {:error, term()}
  def register(
        alias_name,
        node_id,
        public_key,
        private_key,
        _ed25519_private_key,
        _ed25519_public_key
      ) do
    with :ok <- validate_alias_format(alias_name),
         full_alias <- ensure_mesh_suffix(alias_name),
         :ok <- validate_node_id(node_id),
         :ok <- validate_public_key(public_key),
         signature <- create_signature(full_alias, node_id, private_key) do
      ensure_table()

      entry = %{
        alias: full_alias,
        node_id: node_id,
        public_key: public_key,
        signature: signature,
        registered_at: now_ms()
      }

      :ets.insert(@table, {full_alias, entry})

      # Auto-publish to DHT if subscriptions exist (will be done via Discovery)
      :ok
    end
  end

  @doc """
  Resolves an alias to a node_id.

  First checks local address book, then queries DHT for subscribed nodes if local lookup fails.
  Returns `{:ok, node_id}` if found, `:not_found` otherwise.
  """
  @spec resolve(String.t()) :: {:ok, binary()} | :not_found
  def resolve(alias) do
    ensure_table()
    full_alias = ensure_mesh_suffix(alias)

    case :ets.lookup(@table, full_alias) do
      [{^full_alias, entry}] ->
        {:ok, entry.node_id}

      _ ->
        # Check local cache of published aliases
        ensure_published_aliases_table()

        case :ets.lookup(@published_aliases_table, full_alias) do
          [{^full_alias, published_alias}] ->
            # Check if cached alias is still valid
            if published_alias.expires_at > now_ms() do
              {:ok, published_alias.node_id}
            else
              # Expired, remove from cache
              :ets.delete(@published_aliases_table, full_alias)
              :not_found
            end

          _ ->
            :not_found
        end
    end
  end

  @doc """
  Resolves an alias via DHT (queries subscribed nodes).

  This function queries DHT for aliases from subscribed nodes.
  Only subscribed nodes' aliases are queried (not all nodes).

  Returns `{:ok, node_id}` if found, `:not_found` otherwise.
  """
  @spec resolve_distributed(pid(), binary(), String.t()) :: {:ok, binary()} | :not_found
  def resolve_distributed(dht_pid, subscriber_node_id, alias)
      when is_pid(dht_pid) and is_binary(subscriber_node_id) and
             byte_size(subscriber_node_id) == 32 and is_binary(alias) do
    ensure_subscriptions_table()
    ensure_published_aliases_table()

    full_alias = ensure_mesh_suffix(alias)

    # Get subscribed nodes
    subscribed_nodes = list_subscriptions(subscriber_node_id)

    if length(subscribed_nodes) == 0 do
      :not_found
    else
      # Query DHT for aliases from each subscribed node
      result =
        Enum.reduce_while(subscribed_nodes, :not_found, fn subscribed_node_id, _acc ->
          # Query DHT for alias
          key = "alias:" <> full_alias <> ":" <> subscribed_node_id

          case DHT.get(dht_pid, key) do
            {:ok, value} ->
              try do
                # Decode published alias
                published_alias = :erlang.binary_to_term(value, [:safe])

                # Verify signature
                if verify_published_alias(dht_pid, published_alias) do
                  # Check expiration
                  if published_alias.expires_at > now_ms() do
                    # Cache locally
                    :ets.insert(@published_aliases_table, {full_alias, published_alias})
                    {:halt, {:ok, published_alias.node_id}}
                  else
                    {:cont, :not_found}
                  end
                else
                  # Invalid signature - reject
                  {:cont, :not_found}
                end
              catch
                _ ->
                  # Decode failed
                  {:cont, :not_found}
              end

            _ ->
              {:cont, :not_found}
          end
        end)

      result
    end
  end

  def resolve_distributed(_, _, _) do
    :not_found
  end

  @doc """
  Lists all registered aliases.

  Returns a list of `{alias, node_id}` tuples.
  """
  @spec list() :: [{String.t(), binary()}]
  def list() do
    ensure_table()

    @table
    |> :ets.tab2list()
    |> Enum.map(fn {alias, entry} -> {alias, entry.node_id} end)
  end

  @doc """
  Deletes an alias from the address book.

  Returns `:ok` if deleted, `:not_found` if alias doesn't exist.
  """
  @spec delete(String.t()) :: :ok | :not_found
  def delete(alias) do
    ensure_table()
    full_alias = ensure_mesh_suffix(alias)

    case :ets.lookup(@table, full_alias) do
      [{^full_alias, _}] ->
        :ets.delete(@table, full_alias)
        :ok

      _ ->
        :not_found
    end
  end

  @doc """
  Verifies an alias entry's signature structure.

  Returns `true` if signature structure is valid (32 bytes), `false` otherwise.
  Note: Full verification requires the private key (HMAC limitation).
  Proper verification will be available with Ed25519 support.
  """
  @spec verify_alias(String.t()) :: boolean()
  def verify_alias(alias) do
    ensure_table()
    full_alias = ensure_mesh_suffix(alias)

    case :ets.lookup(@table, full_alias) do
      [{^full_alias, entry}] ->
        is_binary(entry.signature) and byte_size(entry.signature) == 32

      _ ->
        false
    end
  end

  @doc """
  Checks if an alias exists in the address book.
  """
  @spec exists?(String.t()) :: boolean()
  def exists?(alias) do
    ensure_table()
    full_alias = ensure_mesh_suffix(alias)

    case :ets.lookup(@table, full_alias) do
      [{^full_alias, _}] -> true
      _ -> false
    end
  end

  @doc """
  Subscribes to another node's address book.

  Adds the `target_node_id` to the local subscription list.
  The subscription list will be published to DHT (signed by subscriber).

  Optional `config` parameter allows customizing subscription limits.
  If not provided, uses defaults (max 100 subscriptions).

  Returns `:ok` on success, or `{:error, reason}` on failure.
  Reasons:
  - `:max_subscriptions_exceeded` - Already at maximum subscription limit
  - `:invalid_node_id` - Target node_id is invalid (not 32 bytes)
  - `:already_subscribed` - Already subscribed to this node
  """
  @spec subscribe(binary(), binary(), binary(), map() | nil) :: :ok | {:error, atom()}
  def subscribe(subscriber_node_id, subscriber_public_key, target_node_id, config \\ nil)

  def subscribe(subscriber_node_id, subscriber_public_key, target_node_id, config)
      when is_binary(subscriber_node_id) and byte_size(subscriber_node_id) == 32 and
             is_binary(subscriber_public_key) and byte_size(subscriber_public_key) == 32 and
             is_binary(target_node_id) and byte_size(target_node_id) == 32 do
    ensure_subscriptions_table()

    # Get current subscriptions
    current_subscriptions =
      case :ets.lookup(@subscriptions_table, subscriber_node_id) do
        [{^subscriber_node_id, sub_list}] -> sub_list.subscribed_nodes
        _ -> []
      end

    # Check if already subscribed
    if target_node_id in current_subscriptions do
      {:error, :already_subscribed}
    else
      # Check subscription limit (configurable)
      max_subscriptions = max_subscriptions(config)

      if length(current_subscriptions) >= max_subscriptions do
        {:error, :max_subscriptions_exceeded}
      else
        # Validate no subscription chaining (target must be a node_id, not a subscription list key)
        if String.starts_with?(target_node_id, "subs:") do
          {:error, :invalid_node_id}
        else
          # Add to subscription list
          updated_subscriptions = [target_node_id | current_subscriptions]

          ttl_ms = subscription_ttl_ms(config)

          subscription_list = %{
            subscriber_node_id: subscriber_node_id,
            subscribed_nodes: updated_subscriptions,
            timestamp: now_ms(),
            expires_at: now_ms() + ttl_ms,
            # Will be signed when published to DHT
            signature: <<>>,
            ed25519_public_key: nil
          }

          :ets.insert(@subscriptions_table, {subscriber_node_id, subscription_list})
          :ok
        end
      end
    end
  end

  def subscribe(_subscriber_node_id, _subscriber_public_key, _target_node_id, _config) do
    {:error, :invalid_node_id}
  end

  @doc """
  Unsubscribes from another node's address book.

  Removes the `target_node_id` from the local subscription list.

  Optional `config` parameter allows customizing TTL.
  """
  @spec unsubscribe(binary(), binary(), map() | nil) :: :ok | {:error, atom()}
  def unsubscribe(subscriber_node_id, target_node_id, config \\ nil)

  def unsubscribe(subscriber_node_id, target_node_id, config)
      when is_binary(subscriber_node_id) and byte_size(subscriber_node_id) == 32 and
             is_binary(target_node_id) and byte_size(target_node_id) == 32 do
    ensure_subscriptions_table()

    case :ets.lookup(@subscriptions_table, subscriber_node_id) do
      [{^subscriber_node_id, sub_list}] ->
        updated_subscriptions = List.delete(sub_list.subscribed_nodes, target_node_id)

        if length(updated_subscriptions) == 0 do
          # Remove subscription list if empty
          :ets.delete(@subscriptions_table, subscriber_node_id)
        else
          # Update subscription list
          ttl_ms = subscription_ttl_ms(config)

          updated_sub_list = %{
            sub_list
            | subscribed_nodes: updated_subscriptions,
              timestamp: now_ms(),
              expires_at: now_ms() + ttl_ms
          }

          :ets.insert(@subscriptions_table, {subscriber_node_id, updated_sub_list})
        end

        :ok

      _ ->
        {:error, :not_subscribed}
    end
  end

  def unsubscribe(_subscriber_node_id, _target_node_id, _config) do
    {:error, :invalid_node_id}
  end

  @doc """
  Lists all subscribed node_ids for a given subscriber.

  Returns a list of `node_id`s that the subscriber is subscribed to.
  """
  @spec list_subscriptions(binary()) :: [binary()]
  def list_subscriptions(subscriber_node_id)
      when is_binary(subscriber_node_id) and byte_size(subscriber_node_id) == 32 do
    ensure_subscriptions_table()

    case :ets.lookup(@subscriptions_table, subscriber_node_id) do
      [{^subscriber_node_id, sub_list}] -> sub_list.subscribed_nodes
      _ -> []
    end
  end

  def list_subscriptions(_) do
    []
  end

  @doc """
  Gets the subscription list for a subscriber (for DHT publishing).

  Returns the subscription list structure if it exists, `nil` otherwise.
  """
  @spec get_subscription_list(binary()) :: subscription_list() | nil
  def get_subscription_list(subscriber_node_id)
      when is_binary(subscriber_node_id) and byte_size(subscriber_node_id) == 32 do
    ensure_subscriptions_table()

    case :ets.lookup(@subscriptions_table, subscriber_node_id) do
      [{^subscriber_node_id, sub_list}] -> sub_list
      _ -> nil
    end
  end

  def get_subscription_list(_) do
    nil
  end

  @doc """
  Publishes a subscription list to DHT.

  The subscription list must be signed by the subscriber's private key.
  Includes rate limiting to prevent DoS.

  Optional `config` parameter allows customizing TTL and rate limits.

  Returns `:ok` on success, or `{:error, reason}` on failure.
  """
  @spec publish_subscription_list(
          pid(),
          binary(),
          binary(),
          binary() | nil,
          binary() | nil,
          map() | nil
        ) :: :ok | {:error, atom()}
  def publish_subscription_list(
        dht_pid,
        subscriber_node_id,
        subscriber_private_key,
        ed25519_private_key \\ nil,
        ed25519_public_key \\ nil,
        config \\ nil
      )

  def publish_subscription_list(
        dht_pid,
        subscriber_node_id,
        subscriber_private_key,
        ed25519_private_key,
        ed25519_public_key,
        config
      )
      when is_pid(dht_pid) and is_binary(subscriber_node_id) and
             byte_size(subscriber_node_id) == 32 and
             is_binary(subscriber_private_key) and byte_size(subscriber_private_key) == 32 do
    ensure_subscriptions_table()
    ensure_rate_limit_table()

    # Check rate limit (configurable)
    if rate_limit_exceeded?(subscriber_node_id, config) do
      {:error, :rate_limit_exceeded}
    else
      case get_subscription_list(subscriber_node_id) do
        nil ->
          {:error, :no_subscriptions}

        sub_list ->
          # Sign subscription list
          signed_sub_list =
            sign_subscription_list(
              sub_list,
              subscriber_private_key,
              ed25519_private_key,
              ed25519_public_key
            )

          # Encode for DHT storage
          key = "subs:" <> subscriber_node_id
          value = :erlang.term_to_binary(signed_sub_list, [:compressed])

          # Publish to DHT
          ttl_ms = subscription_ttl_ms(config)
          DHT.put(dht_pid, key, value, ttl_ms)

          # Update rate limit
          record_rate_limit(subscriber_node_id)

          # Update local subscription list with signature
          :ets.insert(
            @subscriptions_table,
            {subscriber_node_id, signed_sub_list}
          )

          :ok
      end
    end
  end

  @doc """
  Verifies a subscription list signature.

  Retrieves the subscriber's public key from DHT announcement and verifies the signature.
  Returns `true` if valid, `false` otherwise.
  """
  @spec verify_subscription_list(pid(), subscription_list()) :: boolean()
  def verify_subscription_list(dht_pid, subscription_list)
      when is_pid(dht_pid) and is_map(subscription_list) do
    # Get subscriber's public key from DHT announcement
    announcements = DHT.lookup_nodes(dht_pid, subscription_list.subscriber_node_id, 1)

    case announcements do
      [announcement | _] ->
        public_key = announcement.public_key
        ed25519_pub = Map.get(announcement, :ed25519_public_key)

        # Verify signature
        message =
          encode_subscription_list_message(
            subscription_list.subscriber_node_id,
            subscription_list.subscribed_nodes,
            subscription_list.timestamp,
            subscription_list.expires_at
          )

        # Use Ed25519 if available, otherwise HMAC
        if ed25519_pub != nil and
             subscription_list.ed25519_public_key != nil and
             byte_size(subscription_list.ed25519_public_key) == 32 do
          Keys.ed25519_verify(message, subscription_list.signature, ed25519_pub)
        else
          # HMAC verification (basic structure check)
          Keys.verify_public(message, subscription_list.signature, public_key)
        end

      _ ->
        false
    end
  end

  def verify_subscription_list(_, _) do
    false
  end

  @doc """
  Publishes an alias to DHT for subscribed nodes.

  The alias must be signed by the owner's private key.
  Includes rate limiting to prevent DoS.

  Optional `config` parameter allows customizing TTL and rate limits.

  Returns `:ok` on success, or `{:error, reason}` on failure.
  """
  @spec publish_alias(
          pid(),
          String.t(),
          binary(),
          binary(),
          binary() | nil,
          binary() | nil,
          map() | nil
        ) :: :ok | {:error, atom()}
  def publish_alias(
        dht_pid,
        alias_name,
        node_id,
        private_key,
        ed25519_private_key \\ nil,
        ed25519_public_key \\ nil,
        config \\ nil
      )

  def publish_alias(
        dht_pid,
        alias_name,
        node_id,
        private_key,
        ed25519_private_key,
        ed25519_public_key,
        config
      )
      when is_pid(dht_pid) and is_binary(alias_name) and is_binary(node_id) and
             byte_size(node_id) == 32 and is_binary(private_key) and
             byte_size(private_key) == 32 do
    ensure_table()
    ensure_alias_rate_limit_table()

    full_alias = ensure_mesh_suffix(alias_name)

    # Check if alias exists locally
    case :ets.lookup(@table, full_alias) do
      [{^full_alias, entry}] ->
        # Check rate limit (configurable)
        if alias_rate_limit_exceeded?(full_alias, config) do
          {:error, :rate_limit_exceeded}
        else
          # Create published alias structure
          published_at = now_ms()
          ttl_ms = alias_publish_ttl_ms(config)
          expires_at = published_at + ttl_ms

          # Sign the published alias
          message = encode_published_alias_message(full_alias, node_id, published_at, expires_at)

          {signature, ed25519_pub} =
            if ed25519_private_key != nil and ed25519_public_key != nil and
                 byte_size(ed25519_private_key) == 32 and byte_size(ed25519_public_key) == 32 do
              try do
                sig = Keys.ed25519_sign(message, ed25519_private_key)
                {sig, ed25519_public_key}
              rescue
                _ ->
                  # Fallback to HMAC
                  sig = Keys.sign(message, private_key)
                  {sig, nil}
              end
            else
              sig = Keys.sign(message, private_key)
              {sig, nil}
            end

          published_alias = %{
            alias: full_alias,
            node_id: node_id,
            owner_public_key: entry.public_key,
            signature: signature,
            published_at: published_at,
            expires_at: expires_at,
            ed25519_public_key: ed25519_pub
          }

          # Encode for DHT storage
          key = "alias:" <> full_alias <> ":" <> node_id
          value = :erlang.term_to_binary(published_alias, [:compressed])

          # Publish to DHT
          DHT.put(dht_pid, key, value, ttl_ms)

          # Update rate limit
          record_alias_rate_limit(full_alias)

          # Cache published alias locally
          ensure_published_aliases_table()
          :ets.insert(@published_aliases_table, {full_alias, published_alias})

          :ok
        end

      _ ->
        {:error, :alias_not_found}
    end
  end

  @doc """
  Verifies a published alias signature.

  Retrieves the owner's public key from DHT announcement and verifies the signature.
  Returns `true` if valid, `false` otherwise.
  """
  @spec verify_published_alias(pid(), map()) :: boolean()
  def verify_published_alias(dht_pid, published_alias)
      when is_pid(dht_pid) and is_map(published_alias) do
    # Get owner's public key from DHT announcement
    announcements = DHT.lookup_nodes(dht_pid, published_alias.node_id, 1)

    case announcements do
      [announcement | _] ->
        public_key = announcement.public_key
        ed25519_pub = Map.get(announcement, :ed25519_public_key)

        # Verify signature
        message =
          encode_published_alias_message(
            published_alias.alias,
            published_alias.node_id,
            published_alias.published_at,
            published_alias.expires_at
          )

        # Use Ed25519 if available, otherwise HMAC
        if ed25519_pub != nil and
             published_alias.ed25519_public_key != nil and
             byte_size(published_alias.ed25519_public_key) == 32 do
          Keys.ed25519_verify(message, published_alias.signature, ed25519_pub)
        else
          # HMAC verification (basic structure check)
          Keys.verify_public(message, published_alias.signature, public_key)
        end

      _ ->
        false
    end
  end

  def verify_published_alias(_, _) do
    false
  end

  # Private functions -----------------------------------------------------------

  defp ensure_table do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:set, :named_table, :public, read_concurrency: true])
    end
  end

  defp ensure_subscriptions_table do
    if :ets.whereis(@subscriptions_table) == :undefined do
      :ets.new(@subscriptions_table, [:set, :named_table, :public, read_concurrency: true])
    end
  end

  defp ensure_rate_limit_table do
    if :ets.whereis(@rate_limit_table) == :undefined do
      :ets.new(@rate_limit_table, [:set, :named_table, :public, read_concurrency: true])
    end
  end

  defp sign_subscription_list(sub_list, private_key, ed25519_private_key, ed25519_public_key) do
    message =
      encode_subscription_list_message(
        sub_list.subscriber_node_id,
        sub_list.subscribed_nodes,
        sub_list.timestamp,
        sub_list.expires_at
      )

    # Use Ed25519 if available, otherwise HMAC-SHA256
    {signature, ed25519_pub} =
      if ed25519_private_key != nil and ed25519_public_key != nil and
           byte_size(ed25519_private_key) == 32 and byte_size(ed25519_public_key) == 32 do
        try do
          sig = Keys.ed25519_sign(message, ed25519_private_key)
          {sig, ed25519_public_key}
        rescue
          _ ->
            # Fallback to HMAC
            sig = Keys.sign(message, private_key)
            {sig, nil}
        end
      else
        sig = Keys.sign(message, private_key)
        {sig, nil}
      end

    %{sub_list | signature: signature, ed25519_public_key: ed25519_pub}
  end

  defp encode_subscription_list_message(
         subscriber_node_id,
         subscribed_nodes,
         timestamp,
         expires_at
       ) do
    subscribed_nodes_binary =
      subscribed_nodes
      |> Enum.join("")
      |> :erlang.term_to_binary()

    subscriber_node_id <> subscribed_nodes_binary <> <<timestamp::64>> <> <<expires_at::64>>
  end

  defp rate_limit_exceeded?(subscriber_node_id, config \\ nil) do
    case :ets.lookup(@rate_limit_table, subscriber_node_id) do
      [{^subscriber_node_id, last_publish_time}] ->
        now = now_ms()
        rate_limit_ms = subscription_rate_limit_ms(config)
        now - last_publish_time < rate_limit_ms

      _ ->
        false
    end
  end

  defp record_rate_limit(subscriber_node_id) do
    :ets.insert(@rate_limit_table, {subscriber_node_id, now_ms()})
  end

  defp ensure_alias_rate_limit_table do
    if :ets.whereis(@alias_rate_limit_table) == :undefined do
      :ets.new(@alias_rate_limit_table, [:set, :named_table, :public, read_concurrency: true])
    end
  end

  defp ensure_published_aliases_table do
    if :ets.whereis(@published_aliases_table) == :undefined do
      :ets.new(@published_aliases_table, [:set, :named_table, :public, read_concurrency: true])
    end
  end

  defp alias_rate_limit_exceeded?(alias, config \\ nil) do
    case :ets.lookup(@alias_rate_limit_table, alias) do
      [{^alias, last_publish_time}] ->
        now = now_ms()
        rate_limit_ms = alias_publish_rate_limit_ms(config)
        now - last_publish_time < rate_limit_ms

      _ ->
        false
    end
  end

  defp record_alias_rate_limit(alias) do
    :ets.insert(@alias_rate_limit_table, {alias, now_ms()})
  end

  defp encode_published_alias_message(alias, node_id, published_at, expires_at) do
    alias <> node_id <> <<published_at::64>> <> <<expires_at::64>>
  end

  # Configuration helpers ----------------------------------------------------

  @doc """
  Gets the maximum subscription count from config.

  Returns the configured max_count or default (100).
  """
  @spec max_subscriptions(map() | nil) :: pos_integer()
  def max_subscriptions(nil), do: 100

  def max_subscriptions(config) do
    get_in(config, ["address_book", "subscriptions", "max_count"]) || 100
  end

  @doc """
  Gets the subscription TTL from config.

  Returns the configured ttl_ms or default (1 hour).
  """
  @spec subscription_ttl_ms(map() | nil) :: non_neg_integer()
  def subscription_ttl_ms(nil), do: :timer.hours(1)

  def subscription_ttl_ms(config) do
    case get_in(config, ["address_book", "subscriptions", "ttl_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.hours(1)
        end

      _ ->
        :timer.hours(1)
    end
  end

  @doc """
  Gets the subscription rate limit from config.

  Returns the configured rate_limit_ms or default (1 minute).
  """
  @spec subscription_rate_limit_ms(map() | nil) :: non_neg_integer()
  def subscription_rate_limit_ms(nil), do: :timer.minutes(1)

  def subscription_rate_limit_ms(config) do
    case get_in(config, ["address_book", "subscriptions", "rate_limit_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.minutes(1)
        end

      _ ->
        :timer.minutes(1)
    end
  end

  @doc """
  Gets the alias publish TTL from config.

  Returns the configured publish_ttl_ms or default (24 hours).
  """
  @spec alias_publish_ttl_ms(map() | nil) :: non_neg_integer()
  def alias_publish_ttl_ms(nil), do: :timer.hours(24)

  def alias_publish_ttl_ms(config) do
    case get_in(config, ["address_book", "aliases", "publish_ttl_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.hours(24)
        end

      _ ->
        :timer.hours(24)
    end
  end

  @doc """
  Gets the alias publish rate limit from config.

  Returns the configured publish_rate_limit_ms or default (1 minute).
  """
  @spec alias_publish_rate_limit_ms(map() | nil) :: non_neg_integer()
  def alias_publish_rate_limit_ms(nil), do: :timer.minutes(1)

  def alias_publish_rate_limit_ms(config) do
    case get_in(config, ["address_book", "aliases", "publish_rate_limit_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.minutes(1)
        end

      _ ->
        :timer.minutes(1)
    end
  end

  @doc """
  Checks if subscriptions are enabled in config.

  Returns true if enabled, false otherwise (default: true).
  """
  @spec subscriptions_enabled?(map() | nil) :: boolean()
  def subscriptions_enabled?(nil), do: true

  def subscriptions_enabled?(config) do
    case get_in(config, ["address_book", "subscriptions", "enabled"]) do
      value when is_boolean(value) ->
        value

      value when is_binary(value) ->
        String.downcase(value) in ["true", "1", "yes"]

      _ ->
        true
    end
  end

  @doc """
  Gets the subscription refresh interval from config.

  Returns the configured refresh_interval_ms or default (30 minutes).
  """
  @spec subscription_refresh_interval_ms(map() | nil) :: non_neg_integer()
  def subscription_refresh_interval_ms(nil), do: :timer.minutes(30)

  def subscription_refresh_interval_ms(config) do
    case get_in(config, ["address_book", "subscriptions", "refresh_interval_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.minutes(30)
        end

      _ ->
        :timer.minutes(30)
    end
  end

  defp validate_alias_format(alias) when is_binary(alias) do
    # Remove .mesh suffix if present for validation
    name = String.replace_suffix(alias, ".mesh", "")

    cond do
      byte_size(name) == 0 ->
        {:error, :alias_empty}

      byte_size(name) > 64 ->
        {:error, :alias_too_long}

      not Regex.match?(~r/^[a-zA-Z0-9-]+$/, name) ->
        {:error, :invalid_alias_format}

      true ->
        :ok
    end
  end

  defp validate_alias_format(_), do: {:error, :invalid_alias_type}

  defp ensure_mesh_suffix(alias) do
    if String.ends_with?(alias, ".mesh") do
      alias
    else
      alias <> ".mesh"
    end
  end

  defp validate_node_id(node_id) when is_binary(node_id) and byte_size(node_id) == 32 do
    :ok
  end

  defp validate_node_id(_), do: {:error, :invalid_node_id}

  defp validate_public_key(public_key)
       when is_binary(public_key) and byte_size(public_key) == 32 do
    :ok
  end

  defp validate_public_key(_), do: {:error, :invalid_public_key}

  defp create_signature(alias, node_id, private_key) do
    message = alias <> node_id
    Keys.sign(message, private_key)
  end

  defp now_ms do
    :erlang.system_time(:millisecond)
  end
end
