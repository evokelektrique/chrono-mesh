defmodule ChronoMesh.ControlClient do
  @moduledoc """
  Client for the control channel used to enqueue pulses on a running node.

  Provides helpers for addressing the local node (from config) and arbitrary
  remote nodes explicitly.
  """

  require Logger

  alias ChronoMesh.{Pulse, JoinChallenge}

  @connection_registry :chrono_mesh_connections
  @authenticated_peers :chrono_mesh_authenticated_peers

  @doc """
  Enqueues pulses on the locally configured node via TCP control port.
  """
  @spec enqueue_local(map(), [Pulse.t()]) :: :ok | {:error, String.t()}
  def enqueue_local(config, pulses) when is_list(pulses) do
    {host, port} = control_endpoint(config)
    send_to(host, port, pulses)
  end

  @doc """
  Enqueues pulses on a remote node identified by node_id.

  Resolves node_id to a connection endpoint and maintains a connection pool
  keyed by node_id for efficient routing.
  """
  @spec enqueue_remote(binary(), [Pulse.t()]) :: :ok | {:error, String.t()}
  def enqueue_remote(node_id, pulses)
      when is_binary(node_id) and byte_size(node_id) == 32 and is_list(pulses) do
    send_to_node(node_id, pulses)
  end

  def enqueue_remote(node_id, _pulses) when is_binary(node_id) do
    {:error, "Invalid node_id size: expected 32 bytes, got #{byte_size(node_id)}"}
  end

  def enqueue_remote(_node_id, _pulses) do
    {:error, "Invalid node_id: must be a 32-byte binary"}
  end

  @spec control_endpoint(map()) :: {String.t(), non_neg_integer()}
  defp control_endpoint(config) do
    network = config["network"] || %{}
    host = Map.get(network, "listen_host", "127.0.0.1")
    port = parse_port(Map.get(network, "listen_port"))
    {host, port}
  end

  @spec parse_port(integer() | String.t() | nil) :: non_neg_integer()
  defp parse_port(port) when is_integer(port) and port > 0, do: port

  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {int, _} when int > 0 -> int
      _ -> 4_000
    end
  end

  defp parse_port(_), do: 4_000

  @doc """
  Registers a connection endpoint for a node_id.

  This allows manual registration of connection endpoints for bootstrap nodes
  or nodes discovered through out-of-band mechanisms.

  Note: For full anonymity, connections should be established through
  introduction points or rendezvous mechanisms. This direct registration
  is for bootstrap/manual setup only.
  """
  @spec register_connection(binary(), String.t(), pos_integer()) :: :ok
  def register_connection(node_id, host, port)
      when is_binary(node_id) and byte_size(node_id) == 32 and is_binary(host) and
             is_integer(port) do
    ensure_registry()
    :ets.insert(@connection_registry, {node_id, {host, port}})
    :ok
  end

  @doc """
  Unregisters a connection endpoint for a node_id.
  """
  @spec unregister_connection(binary()) :: :ok
  def unregister_connection(node_id) when is_binary(node_id) do
    ensure_registry()
    :ets.delete(@connection_registry, node_id)
    :ok
  end

  @spec send_to_node(binary(), [Pulse.t()]) :: :ok | {:error, String.t()}
  defp send_to_node(node_id, pulses) do
    result = resolve_connection(node_id)

    case result do
      {host, port} when is_binary(host) and is_integer(port) ->
        send_to(host, port, pulses)

      _ ->
        Logger.error("Control client: unable to resolve node_id #{Base.encode16(node_id)}")
        {:error, "Unable to resolve node_id for connection"}
    end
  end

  @spec resolve_connection(binary()) :: {String.t(), pos_integer()} | nil
  defp resolve_connection(node_id) do
    ensure_registry()

    case :ets.lookup(@connection_registry, node_id) do
      [{^node_id, {host, port}}] ->
        {host, port}

      _ ->
        resolve_connection_recursive(node_id, 0)
    end
  end

  @spec resolve_connection_recursive(binary(), non_neg_integer()) ::
          {String.t(), pos_integer()} | nil
  defp resolve_connection_recursive(node_id, depth) when depth >= 5 do
    Logger.warning(
      "Control client: max recursion depth reached resolving node_id #{Base.encode16(node_id)}"
    )

    nil
  end

  defp resolve_connection_recursive(node_id, _depth)
       when not is_binary(node_id) or byte_size(node_id) != 32 do
    Logger.warning(
      "Control client: invalid node_id size #{if is_binary(node_id), do: byte_size(node_id), else: :not_binary}"
    )

    nil
  end

  defp resolve_connection_recursive(node_id, depth) do
    ensure_registry()

    case :ets.lookup(@connection_registry, node_id) do
      [{^node_id, {host, port}}] ->
        {host, port}

      _ ->
        case GenServer.whereis(ChronoMesh.Discovery) do
          nil ->
            nil

          discovery_pid ->
            try do
              case GenServer.call(discovery_pid, {:lookup_peer_dht, node_id}, 5_000) do
                [announcement | _] when is_map(announcement) ->
                  introduction_points = Map.get(announcement, :introduction_points, [])

                  if introduction_points == [] do
                    nil
                  else
                    try_introduction_points_recursive(introduction_points, node_id, depth + 1)
                  end

                _ ->
                  nil
              end
            catch
              :exit, {:timeout, _} ->
                Logger.warning("Control client: timeout looking up node_id in DHT")
                nil

              _, _ ->
                nil
            end
        end
    end
  end

  @spec try_introduction_points_recursive([map()], binary(), non_neg_integer()) ::
          {String.t(), pos_integer()} | nil
  defp try_introduction_points_recursive([], _target_node_id, _depth), do: nil

  defp try_introduction_points_recursive([intro_point | rest], target_node_id, depth) do
    intro_node_id = Map.get(intro_point, :node_id)

    if intro_node_id == target_node_id do
      Logger.warning("Control client: detected circular introduction point reference")
      try_introduction_points_recursive(rest, target_node_id, depth)
    else
      if is_binary(intro_node_id) and byte_size(intro_node_id) == 32 do
        case resolve_connection_recursive(intro_node_id, depth) do
          {host, port} when is_binary(host) and is_integer(port) and port > 0 ->
            {host, port}

          _ ->
            try_introduction_points_recursive(rest, target_node_id, depth)
        end
      else
        Logger.warning("Control client: invalid introduction point node_id")
        try_introduction_points_recursive(rest, target_node_id, depth)
      end
    end
  end

  @spec ensure_registry() :: :ok
  defp ensure_registry do
    case :ets.whereis(@connection_registry) do
      :undefined ->
        :ets.new(@connection_registry, [:set, :public, :named_table])
        :ok

      _ ->
        :ok
    end
  end

  @spec send_to(String.t(), non_neg_integer(), [Pulse.t()]) :: :ok | {:error, String.t()}
  defp send_to(host, port, pulses) do
    host_chars = String.to_charlist(host)
    payload = :erlang.term_to_binary(pulses)

    # Set connection timeout (5 seconds)
    timeout = 5_000

    case :gen_tcp.connect(host_chars, port, [:binary, packet: 4, active: false], timeout) do
      {:ok, socket} ->
        # Set send timeout
        :ok = :inet.setopts(socket, send_timeout: timeout)

        # Send pulses (join challenge handshake would be implemented in full version)
        result = :gen_tcp.send(socket, payload)
        :ok = :gen_tcp.close(socket)

        case result do
          :ok -> :ok
          {:error, reason} ->
            Logger.error("Control client failed to send to #{host}:#{port} -> #{inspect(reason)}")
            {:error, "Unable to send to node #{host}:#{port} (#{inspect(reason)})"}
        end

      {:error, :timeout} ->
        Logger.error("Control client connection timeout to #{host}:#{port}")
        {:error, "Connection timeout to node #{host}:#{port}"}

      {:error, reason} ->
        Logger.error("Control client failed to connect to #{host}:#{port} -> #{inspect(reason)}")
        {:error, "Unable to reach node #{host}:#{port} (#{inspect(reason)})"}
    end
  end

  @spec handle_connection_with_challenge(port(), String.t(), non_neg_integer(), binary(), non_neg_integer()) :: :ok | {:error, String.t()}
  defp handle_connection_with_challenge(socket, _host, _port, payload, timeout) do
    # For now, send accept message first (legacy mode)
    # In full implementation, would check for challenge from server
    accept_payload = :erlang.term_to_binary({:accept})

    case :gen_tcp.send(socket, accept_payload) do
      :ok ->
        # Wait for server response (could be challenge or accept)
        case :gen_tcp.recv(socket, 0, timeout) do
          {:ok, data} ->
            case :erlang.binary_to_term(data, [:safe]) do
              {:join_challenge, challenge} ->
                # Respond to challenge
                handle_challenge_response(socket, challenge, payload, timeout)

              {:accept} ->
                # Already authenticated - send pulses
                :gen_tcp.send(socket, payload)

              _other ->
                # Legacy: assume server is ready for pulses
                :gen_tcp.send(socket, payload)
            end

          {:error, reason} ->
            {:error, "Failed to receive server response: #{inspect(reason)}"}
        end

      {:error, reason} ->
        {:error, "Failed to send accept: #{inspect(reason)}"}
    end
  end

  @spec handle_challenge_response(port(), JoinChallenge.challenge(), binary(), non_neg_integer()) :: :ok | {:error, String.t()}
  defp handle_challenge_response(_socket, _challenge, _payload, _timeout) do
    # Placeholder implementation - in full implementation would:
    # 1. Get local Ed25519 private key from config
    # 2. Create response using JoinChallenge.create_response
    # 3. Send response
    # 4. Wait for acceptance
    # 5. Send pulses

    Logger.debug("Control client: Received join challenge (placeholder - not fully implemented)")

    # For now, just send pulses (backward compatibility)
    # In full implementation, this would require passing config to send_to
    {:error, "Join challenge not fully implemented - requires config context"}
  end
end
