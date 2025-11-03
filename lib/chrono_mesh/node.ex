defmodule ChronoMesh.Node do
  @moduledoc """
  Minimal node implementation that performs Time-Wave Relay (TWR) batching.

  Maintains an in-memory map of pulses indexed by their target wave.
  On each wave tick it shuffles the batch and forwards pulses to the next hop.
  """

  @dialyzer {:nowarn_function, handle_cast: 2}
  @dialyzer {:nowarn_function, process_token: 2}
  @dialyzer {:nowarn_function, deliver_pulse: 3}
  @dialyzer {:nowarn_function, store_payload: 2}
  @dialyzer {:nowarn_function, inbox_path: 0}

  use GenServer
  require Logger

  alias ChronoMesh.Pulse, as: Pulse
  alias ChronoMesh.Token, as: Token
  alias ChronoMesh.Keys, as: Keys
  alias ChronoMesh.FDP, as: FDP

  @type state :: %{
          wave_duration: pos_integer(),
          pulses: %{optional(non_neg_integer()) => [{Pulse.t(), binary()}]},
          config: map(),
          listen_host: String.t(),
          listen_port: non_neg_integer(),
          local_address: String.t(),
          private_key: binary(),
          fdp_pid: pid() | nil,
          active_paths: %{optional(binary()) => [binary()]}
        }

  # Public API ----------------------------------------------------------------

  @doc """
  Starts the node process responsible for forwarding pulses.
  """
  @spec start_link(map()) :: GenServer.on_start()
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @doc """
  Enqueues a pulse for processing by the running node.
  """
  @spec enqueue(Pulse.t()) :: :ok
  def enqueue(%Pulse{} = pulse) do
    case GenServer.whereis(__MODULE__) do
      nil ->
        Logger.warning("Node process not running; cannot enqueue pulse.")
        :ok

      pid ->
        GenServer.cast(pid, {:enqueue, pulse})
    end
  end

  # GenServer callbacks -------------------------------------------------------

  @impl true
  @doc """
  Prepares the node state, spawns supporting infrastructure and kicks off wave scheduling.
  """
  @spec init(map()) :: {:ok, state()} | {:stop, term()}
  def init(config) do
    wave_duration = parse_wave_duration(config)
    listen_port = parse_listen_port(config)
    listen_host = parse_listen_host(config)
    local_address = "#{listen_host}:#{listen_port}"

    # Start control server, handle already_started case
    control_server_result =
      case ChronoMesh.ControlServer.start_link(port: listen_port) do
        {:ok, _control_pid} -> :ok
        {:error, {:already_started, _pid}} -> :ok
        {:error, reason} -> {:stop, reason}
      end

    if match?({:stop, _}, control_server_result) do
      control_server_result
    else
      # Start FDP process for frame reassembly
      fdp_opts = [
        frame_timeout_ms: parse_fdp_timeout(config),
        cleanup_interval_ms: parse_fdp_cleanup_interval(config),
        max_frame_size: parse_fdp_max_size(config)
      ]

      {:ok, fdp_pid} = FDP.start_link(fdp_opts)

      Logger.info("Node started with wave duration #{wave_duration}s")
      schedule_wave(wave_duration)

      private_key =
        config
        |> get_in(["identity", "private_key_path"])
        |> Keys.read_private_key!()

      {:ok,
       %{
         wave_duration: wave_duration,
         pulses: %{},
         config: config,
         listen_port: listen_port,
         listen_host: listen_host,
         local_address: local_address,
         private_key: private_key,
         fdp_pid: fdp_pid,
         active_paths: %{}
       }}
    end
  end

  @impl true
  @doc false
  @spec handle_cast({:enqueue, Pulse.t()}, state()) :: {:noreply, state()}
  def handle_cast({:enqueue, %Pulse{} = pulse}, state) do
    case process_token(pulse, state) do
      {:ok, {:deliver, shared_secret, remaining_pulse}} ->
        updated_state = deliver_pulse(remaining_pulse, shared_secret, state)
        {:noreply, updated_state}

      {:ok, {:forward, node_id, updated_pulse}} ->
        next_wave = current_wave(state.wave_duration) + 1
        entry = {updated_pulse, node_id}
        updated_map = Map.update(state.pulses, next_wave, [entry], &[entry | &1])

        # Track active path for failure detection
        frame_id = updated_pulse.frame_id
        current_path = Map.get(state.active_paths, frame_id, [])
        updated_paths =
          if node_id not in current_path do
            Map.put(state.active_paths, frame_id, current_path ++ [node_id])
          else
            state.active_paths
          end

        ChronoMesh.Events.emit(:pulse_enqueued, %{count: 1}, %{pulse: updated_pulse})
        {:noreply, %{state | pulses: updated_map, active_paths: updated_paths}}

      {:error, reason} ->
        Logger.error("Dropping pulse due to #{inspect(reason)}")
        {:noreply, state}
    end
  end

  @impl true
  @doc false
  @spec handle_info(term(), state()) :: {:noreply, state()} | {:stop, term(), state()}
  def handle_info(:wave_tick, state) do
    wave = current_wave(state.wave_duration)
    {batch, pulses} = Map.pop(state.pulses, wave, [])

    if batch != [] do
      Logger.debug("Dispatching #{length(batch)} pulses for wave #{wave}")

      batch
      |> Enum.shuffle()
      |> Enum.each(fn {pulse, node_id} -> forward_pulse(pulse, node_id, state) end)
    else
      Logger.debug("No pulses scheduled for wave #{wave}")
    end

    schedule_wave(state.wave_duration)
    {:noreply, %{state | pulses: pulses}}
  end

  @impl true
  @doc false
  def handle_info({:retry_forward, %Pulse{} = pulse, node_id, attempt}, state) do
    max_attempts = 3

    case ChronoMesh.ControlClient.enqueue_remote(node_id, [pulse]) do
      :ok ->
        # Remove from active paths on success
        updated_paths = Map.delete(state.active_paths, pulse.frame_id)
        {:noreply, %{state | active_paths: updated_paths}}

      {:error, reason} when attempt < max_attempts ->
        Logger.warning(
          "Retry #{attempt}/#{max_attempts} forwarding to node_id #{Base.encode16(node_id)} failed: #{inspect(reason)}"
        )

        Process.send_after(self(), {:retry_forward, pulse, node_id, attempt + 1}, 200)
        {:noreply, state}

      {:error, reason} ->
        Logger.error("Giving up forwarding to node_id #{Base.encode16(node_id)}: #{inspect(reason)}")

        # Detect path failure after max retries
        path = Map.get(state.active_paths, pulse.frame_id, [])
        failure_notice = ChronoMesh.PFP.detect_failure(pulse.frame_id, node_id, :timeout, state.private_key)

        # Send failure notice upstream
        ChronoMesh.PFP.send_failure_notice(failure_notice, path, state.config)

        # Remove from active paths
        updated_paths = Map.delete(state.active_paths, pulse.frame_id)
        {:noreply, %{state | active_paths: updated_paths}}
    end
  end

  @doc false
  @impl true
  def handle_info(message, state) do
    Logger.debug("Unhandled message #{inspect(message)}")
    {:noreply, state}
  end

  # Internal helpers ----------------------------------------------------------

  @spec forward_pulse(Pulse.t(), binary(), state()) :: :ok
  defp forward_pulse(%Pulse{} = pulse, node_id, state) do
    Logger.debug("Forwarding pulse (#{byte_size(pulse.payload)} bytes) to node_id #{Base.encode16(node_id)}")
    ChronoMesh.Events.emit(:pulse_forwarded, %{}, %{pulse: pulse})

    case ChronoMesh.ControlClient.enqueue_remote(node_id, [pulse]) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to forward pulse to node_id #{Base.encode16(node_id)} -> #{reason}")

        # Detect path failure
        path = Map.get(state.active_paths, pulse.frame_id, [])
        failure_notice = ChronoMesh.PFP.detect_failure(pulse.frame_id, node_id, :connection_error, state.private_key)

        # Send failure notice upstream
        ChronoMesh.PFP.send_failure_notice(failure_notice, path, state.config)

        # Retry forwarding
        Process.send_after(self(), {:retry_forward, pulse, node_id, 1}, 100)
    end
  end

  @spec schedule_wave(pos_integer()) :: reference()
  defp schedule_wave(wave_duration) do
    now = System.os_time(:second)
    next_wave = current_wave(wave_duration) + 1

    millis_until =
      max(next_wave * wave_duration - now, 0) * 1000

    Process.send_after(self(), :wave_tick, millis_until)
  end

  @spec current_wave(pos_integer()) :: non_neg_integer()
  defp current_wave(wave_duration) do
    System.os_time(:second) |> div(wave_duration)
  end

  @spec parse_wave_duration(map()) :: pos_integer()
  defp parse_wave_duration(config) do
    case get_in(config, ["network", "wave_duration_secs"]) do
      value when is_integer(value) ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _rest} -> int
          :error -> 10
        end

      _ ->
        10
    end
  end

  @spec parse_listen_port(map()) :: pos_integer()
  defp parse_listen_port(config) do
    case get_in(config, ["network", "listen_port"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> 4_000
        end

      _ ->
        4_000
    end
  end

  @spec parse_listen_host(map()) :: String.t()
  defp parse_listen_host(config) do
    case get_in(config, ["network", "listen_host"]) do
      value when is_binary(value) and value != "" -> value
      _ -> "127.0.0.1"
    end
  end

  defp process_token(%Pulse{token_chain: []}, _state), do: {:error, :no_token}

  @spec process_token(Pulse.t(), map()) ::
          {:ok, {:forward, binary(), Pulse.t()}}
          | {:ok, {:deliver, binary(), Pulse.t()}}
          | {:error, term()}
  defp process_token(%Pulse{token_chain: [token | rest]} = pulse, state) do
    case Token.decrypt_token(token, state.private_key, pulse.frame_id, pulse.shard_index) do
      {:ok, {%{instruction: :forward, node_id: node_id}, _shared}} ->
        {:ok, {:forward, node_id, %{pulse | token_chain: rest}}}

      {:ok, {%{instruction: :deliver}, shared}} ->
        {:ok, {:deliver, shared, %{pulse | token_chain: rest}}}

      {:ok, {data, _shared}} ->
        {:error, {:unknown_instruction, data}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec deliver_pulse(Pulse.t(), binary(), state()) :: state()
  defp deliver_pulse(%Pulse{} = pulse, shared_secret, state) do
    # Check if AEAD is enabled and auth_tag is present
    decrypt_result =
      if pulse.aead_enabled && pulse.auth_tag != nil do
        # Verify auth_tag size (must be 16 bytes for Poly1305)
        if byte_size(pulse.auth_tag) == 16 do
          Token.decrypt_aead(
            shared_secret,
            pulse.frame_id,
            pulse.shard_index,
            pulse.payload,
            pulse.auth_tag
          )
        else
          {:error, :invalid_auth_tag}
        end
      else
        # Standard decryption (non-AEAD)
        Token.decrypt_payload(shared_secret, pulse.frame_id, pulse.shard_index, pulse.payload)
      end

    case decrypt_result do
      {:ok, plaintext} ->
        # Route through FDP for frame reassembly if multi-shard
        # Remove from active paths on successful delivery
        updated_paths = Map.delete(state.active_paths, pulse.frame_id)

        if pulse.shard_count == 1 do
          # Single shard - store immediately, no reassembly needed
          store_payload(state, plaintext)

          ChronoMesh.Events.emit(:pulse_delivered, %{bytes: byte_size(plaintext)}, %{pulse: pulse})
          %{state | active_paths: updated_paths}
        else
          # Multi-shard - route through FDP
          # Pass FEC metadata if available
          fec_opts = [
            fec_enabled: pulse.fec_enabled || false,
            parity_count: pulse.parity_count || 0,
            data_shard_count: pulse.data_shard_count || pulse.shard_count
          ]

          case FDP.register_shard(
                 pulse.frame_id,
                 pulse.shard_index,
                 pulse.shard_count,
                 plaintext,
                 fec_opts
               ) do
            {:ok, :complete} ->
              # Frame is complete - reassemble and store
              case FDP.reassemble(pulse.frame_id) do
                {:ok, reassembled} ->
                  store_payload(state, reassembled)

                  ChronoMesh.Events.emit(
                    :pulse_delivered,
                    %{
                      bytes: byte_size(reassembled),
                      frame_id: pulse.frame_id,
                      shard_count: pulse.shard_count
                    },
                    %{pulse: pulse}
                  )

                  # Return updated state with cleaned paths
                  %{state | active_paths: updated_paths}

                {:error, reason} ->
                  Logger.error(
                    "Failed to reassemble frame #{Base.encode16(pulse.frame_id)}: #{inspect(reason)}"
                  )

                  %{state | active_paths: updated_paths}
              end

            {:ok, :incomplete} ->
              # Frame incomplete - waiting for more shards
              Logger.debug(
                "Received shard #{pulse.shard_index + 1}/#{pulse.shard_count} of frame #{Base.encode16(pulse.frame_id)}"
              )

              %{state | active_paths: updated_paths}

            {:error, reason} ->
              Logger.error(
                "FDP error for shard #{pulse.shard_index} of frame #{Base.encode16(pulse.frame_id)}: #{inspect(reason)}"
              )

              %{state | active_paths: updated_paths}
          end
        end

      {:error, :invalid_auth_tag} ->
        Logger.error(
          "Invalid auth_tag for shard #{pulse.shard_index} of frame #{Base.encode16(pulse.frame_id)}"
        )

        state

      {:error, reason} ->
        Logger.error(
          "Failed to decrypt shard #{pulse.shard_index} of frame #{Base.encode16(pulse.frame_id)}: #{inspect(reason)}"
        )

        state
    end
  end

  @spec store_payload(state(), binary()) :: :ok
  defp store_payload(_state, payload) do
    path = inbox_path()
    :ok = File.mkdir_p(Path.dirname(path))
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
    message = payload |> IO.iodata_to_binary() |> String.trim_trailing()
    line = "#{timestamp} :: #{message}"
    File.write(path, line <> "\n", [:append])
    Logger.info("Stored incoming pulse (#{byte_size(payload)} bytes) -> #{path}")
  end

  @spec inbox_path() :: Path.t()
  defp inbox_path do
    base_dir = System.get_env("CHRONO_MESH_HOME") || System.user_home!()
    Path.join(base_dir, ".chrono_mesh/inbox.log")
  end

  @spec parse_fdp_timeout(map()) :: non_neg_integer()
  defp parse_fdp_timeout(config) do
    case get_in(config, ["fdp", "frame_timeout_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.minutes(5)
        end

      _ ->
        :timer.minutes(5)
    end
  end

  @spec parse_fdp_cleanup_interval(map()) :: non_neg_integer()
  defp parse_fdp_cleanup_interval(config) do
    case get_in(config, ["fdp", "cleanup_interval_ms"]) do
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

  @spec parse_fdp_max_size(map()) :: non_neg_integer()
  defp parse_fdp_max_size(config) do
    case get_in(config, ["fdp", "max_frame_size"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> 10 * 1024 * 1024
        end

      _ ->
        10 * 1024 * 1024
    end
  end
end
