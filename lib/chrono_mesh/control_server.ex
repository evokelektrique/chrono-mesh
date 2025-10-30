defmodule ChronoMesh.ControlServer do
  @moduledoc """
  Local control channel for enqueuing pulses from external CLI processes.

  A single TCP listener accepts connections (packet: 4). Each payload is
  expected to be an erlang term representing a list of `%Pulse{}` structs.
  """

  use GenServer
  require Logger

  alias ChronoMesh.Node

  @type state :: %{
          listen_socket: port(),
          port: non_neg_integer()
        }

  @doc """
  Starts the control server on the given port.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    port = Keyword.fetch!(opts, :port)
    GenServer.start_link(__MODULE__, port, name: __MODULE__)
  end

  @impl true
  @doc """
  Opens the listening socket and prepares for inbound control connections.
  """
  @spec init(non_neg_integer()) :: {:ok, state()} | {:stop, term()}
  def init(port) when is_integer(port) do
    opts = [:binary, packet: 4, active: false, reuseaddr: true]

    case :gen_tcp.listen(port, opts) do
      {:ok, socket} ->
        Logger.info("Control server listening on port #{port}")
        send(self(), :accept)
        {:ok, %{listen_socket: socket, port: port}}

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
        Task.start(fn -> handle_client(client) end)
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

  @doc false
  @spec handle_client(port()) :: :ok
  defp handle_client(socket) do
    case :gen_tcp.recv(socket, 0) do
      {:ok, data} ->
        dispatch_payload(data)

      {:error, reason} ->
        Logger.error("Control client recv failed: #{inspect(reason)}")
    end

    :gen_tcp.close(socket)
  end

  @doc false
  @spec dispatch_payload(binary()) :: :ok
  defp dispatch_payload(binary) do
    case safe_decode(binary) do
      {:ok, pulses} ->
        ChronoMesh.Events.emit(:control_received, %{count: length(pulses)}, %{})
        Enum.each(pulses, &Node.enqueue/1)

      {:error, reason} ->
        Logger.error("Control payload decode error: #{inspect(reason)}")
    end
  end

  @doc false
  @spec safe_decode(binary()) :: {:ok, [ChronoMesh.Pulse.t()]} | {:error, term()}
  defp safe_decode(binary) do
    try do
      case :erlang.binary_to_term(binary) do
        pulses when is_list(pulses) -> {:ok, pulses}
        other -> {:error, {:unexpected_payload, other}}
      end
    rescue
      error -> {:error, error}
    end
  end
end
