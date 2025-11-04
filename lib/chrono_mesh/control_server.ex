defmodule ChronoMesh.ControlServer do
  @moduledoc """
  Local control channel for enqueuing pulses from external CLI processes.

  A single TCP listener accepts connections (packet: 4). Each payload is
  expected to be an erlang term representing a list of `%Pulse{}` structs.
  """

  use GenServer
  require Logger

  alias ChronoMesh.{Node, JoinChallenge, Config}

  @type state :: %{
          listen_socket: port(),
          port: non_neg_integer(),
          config: map() | nil
        }

  @doc """
  Starts the control server on the given port.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    port = Keyword.fetch!(opts, :port)
    config = Keyword.get(opts, :config, %{})
    GenServer.start_link(__MODULE__, {port, config}, name: __MODULE__)
  end

  @impl true
  @doc """
  Opens the listening socket and prepares for inbound control connections.
  """
  @spec init({non_neg_integer(), map()}) :: {:ok, state()} | {:stop, term()}
  def init({port, config}) when is_integer(port) do
    opts = [:binary, packet: 4, active: false, reuseaddr: true]

    case :gen_tcp.listen(port, opts) do
      {:ok, socket} ->
        Logger.info("Control server listening on port #{port}")
        send(self(), :accept)
        {:ok, %{listen_socket: socket, port: port, config: config}}

      {:error, reason} ->
        Logger.error("Unable to start control server on port #{port}: #{inspect(reason)}")
        {:stop, reason}
    end
  end

  @impl true
  @doc """
  Handles asynchronous messages, either accepting new control connections or
  ignoring unexpected notifications.
  """
  @spec handle_info(:accept | term(), state()) ::
          {:noreply, state()} | {:stop, term(), state()}
  def handle_info(:accept, %{listen_socket: socket} = state) do
    case :gen_tcp.accept(socket) do
      {:ok, client} ->
        Task.start(fn -> handle_client(client, state.config) end)
        send(self(), :accept)
        {:noreply, state}

      {:error, reason} ->
        Logger.error("Accept failed: #{inspect(reason)}")
        {:stop, reason, state}
    end
  end

  @impl true
  def handle_info(message, state) do
    Logger.debug("ControlServer received unexpected message #{inspect(message)}")
    {:noreply, state}
  end

  @impl true
  @doc """
  Closes the listening socket on shutdown to unblock any pending accept() calls.
  """
  @spec terminate(term(), state()) :: :ok
  def terminate(_reason, %{listen_socket: socket}) do
    try do
      :gen_tcp.close(socket)
    rescue
      _ -> :ok
    end
  end

  def terminate(_reason, _state) do
    :ok
  end

  @spec handle_client(port(), map() | nil) :: :ok
  defp handle_client(socket, config) do
    # Check if join challenge is enabled
    challenge_enabled = config != nil and Config.join_challenge_enabled?(config)

    if challenge_enabled do
      # Send challenge to new peer
      handle_client_with_challenge(socket, config)
    else
      # Legacy mode: accept pulses directly
      case :gen_tcp.recv(socket, 0) do
        {:ok, data} ->
          dispatch_payload(data)

        {:error, reason} ->
          Logger.error("Control client recv failed: #{inspect(reason)}")
      end
    end

    :gen_tcp.close(socket)
  end

  @spec handle_client_with_challenge(port(), map()) :: :ok
  defp handle_client_with_challenge(socket, config) do
    # Generate challenge for connecting peer
    # Note: We don't have node_id yet, so we'll use a placeholder
    # In a full implementation, we'd identify the peer from the connection
    # For now, we'll send a generic challenge

    # Get Ed25519 private key from config
    ed25519_private_key_path = get_in(config, ["identity", "ed25519_private_key_path"])

    if ed25519_private_key_path != nil do
      ed25519_private_key = ChronoMesh.Keys.read_private_key!(ed25519_private_key_path)

      # Generate challenge (using placeholder node_id - would need peer identification)
      placeholder_node_id = :crypto.strong_rand_bytes(32)

      case JoinChallenge.generate_challenge(placeholder_node_id, ed25519_private_key) do
        {:ok, challenge} ->
          challenge_payload = :erlang.term_to_binary({:join_challenge, challenge})

          case :gen_tcp.send(socket, challenge_payload) do
            :ok ->
              # Wait for response
              case :gen_tcp.recv(socket, 0, 30_000) do
                {:ok, response_data} ->
                  case safe_decode(response_data) do
                    {:ok, {:join_response, response}} ->
                      # Verify response (would need peer's public key)
                      # For now, accept if format is valid
                      # In full implementation, verify with peer's public key from DHT
                      accept_payload = :erlang.term_to_binary({:accept})
                      :gen_tcp.send(socket, accept_payload)

                      # Now accept pulses
                      case :gen_tcp.recv(socket, 0, 5_000) do
                        {:ok, pulse_data} ->
                          dispatch_payload(pulse_data)

                        {:error, reason} ->
                          Logger.error(
                            "Control client recv failed after challenge: #{inspect(reason)}"
                          )
                      end

                    {:ok, other} ->
                      Logger.warning(
                        "Control server: unexpected response after challenge: #{inspect(other)}"
                      )

                      reject_payload = :erlang.term_to_binary({:reject, :invalid_response})
                      :gen_tcp.send(socket, reject_payload)

                    {:error, reason} ->
                      Logger.error(
                        "Control server: failed to decode challenge response: #{inspect(reason)}"
                      )

                      reject_payload = :erlang.term_to_binary({:reject, :decode_error})
                      :gen_tcp.send(socket, reject_payload)
                  end

                {:error, reason} ->
                  Logger.error("Control server: challenge response timeout: #{inspect(reason)}")
              end

            {:error, reason} ->
              Logger.error("Control server: failed to send challenge: #{inspect(reason)}")
          end

        {:error, reason} ->
          Logger.error("Control server: failed to generate challenge: #{inspect(reason)}")
          # Fallback: accept without challenge
          case :gen_tcp.recv(socket, 0) do
            {:ok, data} -> dispatch_payload(data)
            {:error, reason} -> Logger.error("Control client recv failed: #{inspect(reason)}")
          end
      end
    else
      # No Ed25519 key - skip challenge
      case :gen_tcp.recv(socket, 0) do
        {:ok, data} -> dispatch_payload(data)
        {:error, reason} -> Logger.error("Control client recv failed: #{inspect(reason)}")
      end
    end
  end

  @spec dispatch_payload(binary()) :: :ok
  defp dispatch_payload(binary) do
    case safe_decode(binary) do
      {:ok, pulses} when is_list(pulses) ->
        ChronoMesh.Events.emit(:control_received, %{count: length(pulses)}, %{})
        Enum.each(pulses, &Node.enqueue/1)

      {:ok, _other} ->
        Logger.warning("Control server: received non-pulse payload")
        :ok

      {:error, reason} ->
        Logger.error("Control payload decode error: #{inspect(reason)}")
    end
  end

  @spec safe_decode(binary()) :: {:ok, [ChronoMesh.Pulse.t()]} | {:error, term()}
  defp safe_decode(binary) do
    try do
      case :erlang.binary_to_term(binary, [:safe]) do
        pulses when is_list(pulses) -> {:ok, pulses}
        other -> {:error, {:unexpected_payload, other}}
      end
    rescue
      ArgumentError -> {:error, :unsafe_term}
    catch
      :error, :badarg -> {:error, :bad_term}
      error -> {:error, error}
    end
  end
end
