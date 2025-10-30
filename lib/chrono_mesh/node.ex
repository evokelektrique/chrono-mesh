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

  @type state :: %{
          wave_duration: pos_integer(),
          pulses: %{optional(non_neg_integer()) => [{Pulse.t(), {String.t(), non_neg_integer()}}]},
          config: map(),
          listen_host: String.t(),
          listen_port: non_neg_integer(),
          local_address: String.t(),
          private_key: binary()
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
    {:ok, _control_pid} = ChronoMesh.ControlServer.start_link(port: listen_port)
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
       private_key: private_key
     }}
  end

  @impl true
  @doc false
  @spec handle_cast({:enqueue, Pulse.t()}, state()) :: {:noreply, state()}
  def handle_cast({:enqueue, %Pulse{} = pulse}, state) do
    case process_token(pulse, state) do
      {:ok, {:deliver, shared_secret, remaining_pulse}} ->
        deliver_pulse(remaining_pulse, shared_secret, state)
        {:noreply, state}

      {:ok, {:forward, {host, port}, updated_pulse}} ->
        next_wave = current_wave(state.wave_duration) + 1
        entry = {updated_pulse, {host, port}}
        updated_map = Map.update(state.pulses, next_wave, [entry], &[entry | &1])
        ChronoMesh.Events.emit(:pulse_enqueued, %{count: 1}, %{pulse: updated_pulse})
        {:noreply, %{state | pulses: updated_map}}

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
      |> Enum.each(fn {pulse, {host, port}} -> forward_pulse(pulse, host, port) end)
    else
      Logger.debug("No pulses scheduled for wave #{wave}")
    end

    schedule_wave(state.wave_duration)
    {:noreply, %{state | pulses: pulses}}
  end

  @impl true
  @doc false
  def handle_info({:retry_forward, %Pulse{} = pulse, host, port, attempt}, state) do
    max_attempts = 3

    case ChronoMesh.ControlClient.enqueue_remote(host, port, [pulse]) do
      :ok ->
        :ok

      {:error, reason} when attempt < max_attempts ->
        Logger.warning(
          "Retry #{attempt}/#{max_attempts} forwarding to #{host}:#{port} failed: #{inspect(reason)}"
        )

        Process.send_after(self(), {:retry_forward, pulse, host, port, attempt + 1}, 200)

      {:error, reason} ->
        Logger.error("Giving up forwarding to #{host}:#{port}: #{inspect(reason)}")
    end

    {:noreply, state}
  end

  @doc false
  @impl true
  def handle_info(message, state) do
    Logger.debug("Unhandled message #{inspect(message)}")
    {:noreply, state}
  end

  # Internal helpers ----------------------------------------------------------

  @doc false
  @spec forward_pulse(Pulse.t(), String.t(), non_neg_integer()) :: :ok
  defp forward_pulse(%Pulse{} = pulse, host, port) do
    Logger.debug("Forwarding pulse (#{byte_size(pulse.payload)} bytes) to #{host}:#{port}")
    ChronoMesh.Events.emit(:pulse_forwarded, %{}, %{pulse: pulse})

    case ChronoMesh.ControlClient.enqueue_remote(host, port, [pulse]) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to forward pulse to #{host}:#{port} -> #{reason}")
        Process.send_after(self(), {:retry_forward, pulse, host, port, 1}, 100)
    end
  end

  @doc false
  @spec schedule_wave(pos_integer()) :: :ok
  defp schedule_wave(wave_duration) do
    now = System.os_time(:second)
    next_wave = current_wave(wave_duration) + 1

    millis_until =
      max(next_wave * wave_duration - now, 0) * 1000

    Process.send_after(self(), :wave_tick, millis_until)
  end

  @doc false
  @spec current_wave(pos_integer()) :: non_neg_integer()
  defp current_wave(wave_duration) do
    System.os_time(:second) |> div(wave_duration)
  end

  @doc false
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

  @doc false
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

  @doc false
  @spec parse_listen_host(map()) :: String.t()
  defp parse_listen_host(config) do
    case get_in(config, ["network", "listen_host"]) do
      value when is_binary(value) and value != "" -> value
      _ -> "127.0.0.1"
    end
  end

  defp process_token(%Pulse{token_chain: []}, _state), do: {:error, :no_token}

  @doc false
  @spec process_token(Pulse.t(), map()) ::
          {:ok, {:forward, {String.t(), non_neg_integer()}, Pulse.t()}}
          | {:ok, {:deliver, binary(), Pulse.t()}}
          | {:error, term()}
  defp process_token(%Pulse{token_chain: [token | rest]} = pulse, state) do
    case Token.decrypt_token(token, state.private_key, pulse.frame_id, pulse.shard_index) do
      {:ok, {%{instruction: :forward, host: host, port: port}, _shared}} ->
        {:ok, {:forward, {host, port}, %{pulse | token_chain: rest}}}

      {:ok, {%{instruction: :deliver}, shared}} ->
        {:ok, {:deliver, shared, %{pulse | token_chain: rest}}}

      {:ok, {data, _shared}} ->
        {:error, {:unknown_instruction, data}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc false
  @spec deliver_pulse(Pulse.t(), binary(), state()) :: :ok
  defp deliver_pulse(%Pulse{} = pulse, shared_secret, state) do
    case Token.decrypt_payload(shared_secret, pulse.frame_id, pulse.shard_index, pulse.payload) do
      {:ok, plaintext} ->
        store_payload(state, plaintext)
        ChronoMesh.Events.emit(:pulse_delivered, %{bytes: byte_size(plaintext)}, %{pulse: pulse})
    end
  end

  @doc false
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

  @doc false
  @spec inbox_path() :: Path.t()
  defp inbox_path do
    base_dir = System.get_env("CHRONO_MESH_HOME") || System.user_home!()
    Path.join(base_dir, ".chrono_mesh/inbox.log")
  end
end
