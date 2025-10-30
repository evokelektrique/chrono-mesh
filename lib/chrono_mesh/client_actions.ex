defmodule ChronoMesh.ClientActions do
  @moduledoc """
  Implements client-side actions such as path selection and message queuing.

  Enqueues pulses on the local node for forwarding across the network.
  Payload is encoded as UTF-8 and fragmented into shards.
  """

  alias ChronoMesh.{Pulse, Token, Keys}

  @doc """
  Queues a human-readable `message` for delivery to `recipient_name`.

  Options:

    * `:path_length` — number of intermediate hops (defaults to configuration or `2`).
  """
  @spec send_message(map(), String.t(), String.t(), keyword()) ::
          :ok | {:error, String.t()}
  def send_message(config, recipient_name, message, opts) do
    peers = config["peers"] || []

    path_length = opts[:path_length] || default_path_length(config)

    with {:ok, recipient} <- find_peer(peers, recipient_name),
         {:ok, path} <- build_path(peers, recipient, path_length) do
      frame_id = :crypto.strong_rand_bytes(16)

      shard_size = shard_payload_size(config)
      plaintext = IO.iodata_to_binary(message <> "\n")
      chunks = chunk_binary(plaintext, shard_size)
      shard_count = max(length(chunks), 1)

      pulses =
        Enum.with_index(chunks)
        |> Enum.map(fn {chunk, shard_index} ->
          {tokens, payload_secret} = build_tokens(path, frame_id, shard_index)
          payload_secret = payload_secret || raise "Failed to derive payload secret"
          payload_ciphertext = Token.encrypt_payload(payload_secret, frame_id, shard_index, chunk)

          %Pulse{
            frame_id: frame_id,
            shard_index: shard_index,
            shard_count: shard_count,
            token_chain: tokens,
            payload: payload_ciphertext
          }
        end)

      send_with_retry(config, pulses, 3)
    else
      {:error, _} = error ->
        error
    end
  end

  @doc false
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

  @doc false
  @spec shard_payload_size(map()) :: pos_integer()
  defp shard_payload_size(config) do
    total = get_in(config, ["network", "pulse_size_bytes"]) || 1024
    overhead = 128
    max(total - overhead, 1)
  end

  @doc false
  @spec chunk_binary(binary(), pos_integer()) :: [binary()]
  defp chunk_binary(bin, size) when is_binary(bin) and size > 0 do
    do_chunk(bin, size, []) |> Enum.reverse()
  end

  @doc false
  @spec do_chunk(binary(), pos_integer(), [binary()]) :: [binary()]
  defp do_chunk(<<>>, _size, acc), do: acc

  defp do_chunk(bin, size, acc) do
    {part, rest} = split_binary(bin, size)
    do_chunk(rest, size, [part | acc])
  end

  @doc false
  @spec split_binary(binary(), pos_integer()) :: {binary(), binary()}
  defp split_binary(bin, size) do
    if byte_size(bin) <= size do
      {bin, <<>>}
    else
      <<part::binary-size(size), rest::binary>> = bin
      {part, rest}
    end
  end

  @doc false
  @spec find_peer([map()], String.t()) :: {:ok, map()} | {:error, String.t()}
  defp find_peer(peers, name) do
    case Enum.find(peers, &(&1["name"] == name)) do
      nil -> {:error, "Unknown peer #{name}. See `peers list`."}
      peer -> {:ok, peer}
    end
  end

  @doc false
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

  @doc false
  @spec build_tokens([map()], binary(), non_neg_integer()) :: {[binary()], binary()}
  defp build_tokens(path, frame_id, shard_index) do
    path_info = Enum.map(path, &prepare_peer/1)
    last_index = length(path_info) - 1

    Enum.map_reduce(Enum.with_index(path_info), nil, fn {peer_info, idx}, acc ->
      instruction =
        if idx == last_index do
          %{instruction: :deliver}
        else
          next_peer = Enum.at(path_info, idx + 1)
          %{instruction: :forward, host: next_peer.host, port: next_peer.port}
        end

      {token, shared} =
        Token.encrypt_token(instruction, peer_info.public_key, frame_id, shard_index)

      new_acc = if idx == last_index, do: shared, else: acc
      {token, new_acc}
    end)
  end

  @doc false
  @spec prepare_peer(map()) :: %{host: String.t(), port: pos_integer(), public_key: binary()}
  defp prepare_peer(peer) do
    {host, port} = parse_address(peer["address"])
    public_key = load_public_key(peer["public_key"])

    %{host: host, port: port, public_key: public_key}
  end

  @doc false
  @spec parse_address(String.t()) :: {String.t(), pos_integer()}
  defp parse_address(address) do
    case String.split(address, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, _} when port > 0 -> {host, port}
          _ -> raise "Invalid peer address #{address}"
        end

      _ ->
        raise "Invalid peer address format #{address}"
    end
  end

  @doc false
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

  @doc false
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
end
