defmodule ChronoMesh.ClientActions do
  @moduledoc """
  Implements client-side actions such as path selection and message queuing.

  Enqueues pulses on the local node for forwarding across the network.
  Payload is encoded as UTF-8 and fragmented into shards.

  ## Forward Error Correction (FEC)

  Supports optional Forward Error Correction (FEC) for improved reliability:
  - When FEC is enabled, parity shards are generated from data shards
  - Parity shards allow recovery from lost data shards without retransmission
  - FEC can be enabled via configuration: `fec.enabled: true`
  - Parity ratio can be configured: `fec.parity_ratio: 0.25` (default: 1 parity per 4 data shards)
  - Minimum parity shards: `fec.min_parity_shards: 1` (default: 1)

  See `ChronoMesh.FEC` for details on FEC implementation.

  ## Path Failure Protocol (PFP)

  The module tracks failed paths and handles failure notices from intermediate nodes.
  When a path failure is detected, the failure is logged and can be used for path
  rerouting in future message sends.

  See `ChronoMesh.PFP` for details on path failure detection and handling.
  """

  alias ChronoMesh.{AddressBook, FEC, Pulse, Token, Keys}

  @failed_paths_table :chrono_mesh_failed_paths

  @doc """
  Queues a human-readable `message` for delivery to `recipient_name`.

  The recipient can be specified as:
  - An alias (e.g., `"alice.mesh"`) - will be resolved via AddressBook
  - A hex-encoded node_id (e.g., `"A1B2C3..."`) - will be decoded
  - A peer name from config - will use config peer

  Options:

    * `:path_length` — number of intermediate hops (defaults to configuration or `2`).
  """
  @spec send_message(map(), String.t(), String.t(), keyword()) ::
          :ok | {:error, String.t()}
  def send_message(config, recipient_name, message, opts) do
    peers = config["peers"] || []

    path_length = opts[:path_length] || default_path_length(config)

    with {:ok, recipient} <- resolve_recipient(peers, recipient_name),
         {:ok, path} <- build_path(peers, recipient, path_length) do
      frame_id = :crypto.strong_rand_bytes(16)

      # Check if FEC is enabled
      fec_enabled = fec_enabled?(config)
      parity_ratio = fec_parity_ratio(config)
      min_parity_shards = fec_min_parity_shards(config)

      # Check if AEAD is enabled
      aead_enabled = aead_enabled?(config)

      shard_size = shard_payload_size(config)
      plaintext = IO.iodata_to_binary(message <> "\n")
      data_chunks = chunk_binary(plaintext, shard_size)
      data_shard_count = max(length(data_chunks), 1)

      # Calculate FEC shard counts
      {data_shard_count, parity_count, total_shard_count} =
        if fec_enabled do
          FEC.calculate_fec_shard_count(data_shard_count, parity_ratio, min_parity_shards)
        else
          {data_shard_count, 0, data_shard_count}
        end

      # Generate parity shards if FEC enabled
      parity_chunks =
        if fec_enabled and parity_count > 0 do
          FEC.generate_parity_shards(data_chunks, parity_count)
        else
          []
        end

      # Create pulses for data shards
      data_pulses =
        Enum.with_index(data_chunks)
        |> Enum.map(fn {chunk, shard_index} ->
          {tokens, payload_secret} = build_tokens(path, frame_id, shard_index)
          payload_secret = payload_secret || raise "Failed to derive payload secret"

          # Use AEAD if enabled, otherwise standard encryption
          {payload_ciphertext, auth_tag} =
            if aead_enabled do
              Token.encrypt_aead(payload_secret, frame_id, shard_index, chunk)
            else
              {Token.encrypt_payload(payload_secret, frame_id, shard_index, chunk), nil}
            end

          %Pulse{
            frame_id: frame_id,
            shard_index: shard_index,
            shard_count: total_shard_count,
            token_chain: tokens,
            payload: payload_ciphertext,
            fec_enabled: fec_enabled,
            parity_count: parity_count,
            data_shard_count: data_shard_count,
            aead_enabled: aead_enabled,
            auth_tag: auth_tag
          }
        end)

      # Create pulses for parity shards
      parity_pulses =
        Enum.with_index(parity_chunks)
        |> Enum.map(fn {parity_chunk, parity_index} ->
          shard_index = data_shard_count + parity_index
          {tokens, payload_secret} = build_tokens(path, frame_id, shard_index)
          payload_secret = payload_secret || raise "Failed to derive payload secret"

          # Use AEAD if enabled, otherwise standard encryption
          {payload_ciphertext, auth_tag} =
            if aead_enabled do
              Token.encrypt_aead(payload_secret, frame_id, shard_index, parity_chunk)
            else
              {Token.encrypt_payload(payload_secret, frame_id, shard_index, parity_chunk), nil}
            end

          %Pulse{
            frame_id: frame_id,
            shard_index: shard_index,
            shard_count: total_shard_count,
            token_chain: tokens,
            payload: payload_ciphertext,
            fec_enabled: fec_enabled,
            parity_count: parity_count,
            data_shard_count: data_shard_count,
            aead_enabled: aead_enabled,
            auth_tag: auth_tag
          }
        end)

      # Combine all pulses
      pulses = data_pulses ++ parity_pulses

      send_with_retry(config, pulses, 3)
    else
      {:error, _} = error ->
        error
    end
  end

  @doc """
  Handles a path failure notice.

  Records the failed node and path for future path rerouting.
  """
  @spec handle_path_failure(binary(), binary()) :: :ok
  def handle_path_failure(frame_id, failed_node_id)
      when is_binary(frame_id) and byte_size(frame_id) == 16 and
             is_binary(failed_node_id) and byte_size(failed_node_id) == 32 do
    ensure_failed_paths_table()

    # Record failed node for this frame
    :ets.insert(@failed_paths_table, {frame_id, failed_node_id, System.system_time(:millisecond)})

    :ok
  end

  @doc """
  Gets a list of failed nodes for a given frame.

  Returns a list of node IDs that failed during transmission of this frame.
  """
  @spec get_failed_nodes(binary()) :: [binary()]
  def get_failed_nodes(frame_id) when is_binary(frame_id) and byte_size(frame_id) == 16 do
    ensure_failed_paths_table()

    @failed_paths_table
    |> :ets.match({{frame_id, :_, :_}})
    |> Enum.map(fn [{^frame_id, node_id, _timestamp}] -> node_id end)
  end

  @spec ensure_failed_paths_table() :: :ok
  defp ensure_failed_paths_table do
    case :ets.whereis(@failed_paths_table) do
      :undefined ->
        :ets.new(@failed_paths_table, [:set, :public, :named_table])
        :ok

      _ ->
        :ok
    end
  end

  @spec send_with_retry(map(), [Pulse.t()], pos_integer()) :: :ok | {:error, String.t()}
  defp send_with_retry(config, pulses, attempts_left) do
    case ChronoMesh.ControlClient.enqueue_local(config, pulses) do
      :ok ->
        :ok

      {:error, _reason} when attempts_left > 1 ->
        Process.sleep(100)
        send_with_retry(config, pulses, attempts_left - 1)

      {:error, _reason} ->
        {:error, "send failed after retries"}
    end
  end

  @spec shard_payload_size(map()) :: pos_integer()
  defp shard_payload_size(config) do
    total = get_in(config, ["network", "pulse_size_bytes"]) || 1024
    overhead = 128
    max(total - overhead, 1)
  end

  @spec chunk_binary(binary(), pos_integer()) :: [binary()]
  defp chunk_binary(bin, size) when is_binary(bin) and size > 0 do
    do_chunk(bin, size, []) |> Enum.reverse()
  end

  @spec do_chunk(binary(), pos_integer(), [binary()]) :: [binary()]
  defp do_chunk(<<>>, _size, acc), do: acc

  defp do_chunk(bin, size, acc) do
    {part, rest} = split_binary(bin, size)
    do_chunk(rest, size, [part | acc])
  end

  @spec split_binary(binary(), pos_integer()) :: {binary(), binary()}
  defp split_binary(bin, size) do
    if byte_size(bin) <= size do
      {bin, <<>>}
    else
      <<part::binary-size(size), rest::binary>> = bin
      {part, rest}
    end
  end

  @spec resolve_recipient([map()], String.t()) :: {:ok, map()} | {:error, String.t()}
  defp resolve_recipient(peers, identifier) do
    cond do
      # Check if it's an alias (ends with .mesh)
      String.ends_with?(identifier, ".mesh") ->
        case AddressBook.resolve(identifier) do
          {:ok, node_id} ->
            # Create peer map from alias resolution
            {:ok, %{"node_id" => Base.encode16(node_id, case: :lower), "name" => identifier}}

          :not_found ->
            {:error, "Unknown alias #{identifier}. Use `AddressBook.register/4` to register."}
        end

      # Check if it's a hex-encoded node_id (64 hex chars = 32 bytes)
      Regex.match?(~r/^[0-9a-fA-F]{64}$/, identifier) ->
        try do
          _node_id = Base.decode16!(identifier, case: :mixed)
          {:ok, %{"node_id" => identifier, "name" => identifier}}
        rescue
          ArgumentError ->
            {:error, "Invalid node_id format: #{identifier}"}
        end

      # Check if it's a config peer name
      true ->
        find_peer(peers, identifier)
    end
  end

  @spec find_peer([map()], String.t()) :: {:ok, map()} | {:error, String.t()}
  defp find_peer(peers, name) do
    case Enum.find(peers, &(&1["name"] == name)) do
      nil -> {:error, "Unknown peer #{name}. See `peers list`."}
      peer -> {:ok, peer}
    end
  end

  @spec build_path([map()], map(), pos_integer()) :: {:ok, [map()]} | {:error, String.t()}
  defp build_path(peers, recipient, path_length) do
    other_peers =
      peers
      |> Enum.reject(&(&1 == recipient))

    if length(other_peers) < max(path_length - 1, 0) do
      {:error, "Not enough peers to build a path of length #{path_length}"}
    else
      shuffled = Enum.shuffle(other_peers)
      intermediates = Enum.take(shuffled, max(path_length - 1, 0))
      {:ok, intermediates ++ [recipient]}
    end
  end

  @spec build_tokens([map()], binary(), non_neg_integer()) :: {[binary()], binary() | nil}
  defp build_tokens(path, frame_id, shard_index) do
    path_info = Enum.map(path, &prepare_peer/1)
    last_index = length(path_info) - 1

    Enum.map_reduce(Enum.with_index(path_info), nil, fn {peer_info, idx}, acc ->
      instruction =
        if idx == last_index do
          %{instruction: :deliver}
        else
          next_peer = Enum.at(path_info, idx + 1)
          %{instruction: :forward, node_id: next_peer.node_id}
        end

      {token, shared} =
        Token.encrypt_token(instruction, peer_info.public_key, frame_id, shard_index)

      new_acc = if idx == last_index, do: shared, else: acc
      {token, new_acc}
    end)
  end

  @spec prepare_peer(map()) :: %{node_id: binary(), public_key: binary()}
  defp prepare_peer(peer) do
    # Get node_id from config (either directly or derive from public_key)
    node_id =
      case peer do
        %{"node_id" => node_id_hex} ->
          # Node ID provided as hex string
          Base.decode16!(node_id_hex, case: :mixed)

        %{"public_key" => _} ->
          # Derive node_id from public_key
          public_key = load_public_key(peer["public_key"])
          ChronoMesh.Keys.node_id_from_public_key(public_key)

        _ ->
          raise "Peer config must have either node_id or public_key"
      end

    public_key =
      case peer do
        %{"public_key" => pk} -> load_public_key(pk)
        _ -> node_id
      end

    %{node_id: node_id, public_key: public_key}
  end

  @spec load_public_key(String.t()) :: binary()
  defp load_public_key(path) do
    cond do
      is_binary(path) and File.exists?(path) ->
        Keys.read_public_key!(path)

      is_binary(path) ->
        path
        |> String.trim()
        |> Base.decode64!()

      true ->
        raise "Invalid public key entry #{inspect(path)}"
    end
  end

  @spec default_path_length(map()) :: pos_integer()
  defp default_path_length(config) do
    config
    |> get_in(["network", "default_path_length"])
    |> case do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> 2
        end

      _ ->
        2
    end
  end

  @spec fec_enabled?(map()) :: boolean()
  defp fec_enabled?(config) do
    get_in(config, ["fec", "enabled"]) || false
  end

  @spec fec_parity_ratio(map()) :: float()
  defp fec_parity_ratio(config) do
    case get_in(config, ["fec", "parity_ratio"]) do
      ratio when is_float(ratio) and ratio > 0.0 -> ratio
      ratio when is_integer(ratio) and ratio > 0 -> ratio / 1.0
      ratio when is_binary(ratio) ->
        case Float.parse(ratio) do
          {float, _} when float > 0.0 -> float
          _ -> 0.25
        end
      _ -> 0.25
    end
  end

  @spec fec_min_parity_shards(map()) :: pos_integer()
  defp fec_min_parity_shards(config) do
    case get_in(config, ["fec", "min_parity_shards"]) do
      min when is_integer(min) and min > 0 -> min
      min when is_binary(min) ->
        case Integer.parse(min) do
          {int, _} when int > 0 -> int
          _ -> 1
        end
      _ -> 1
    end
  end

  @spec aead_enabled?(map()) :: boolean()
  defp aead_enabled?(config) do
    case get_in(config, ["network", "aead_enabled"]) do
      value when is_boolean(value) -> value
      value when is_binary(value) ->
        String.downcase(value) in ["true", "1", "yes"]
      _ -> false
    end
  end
end
