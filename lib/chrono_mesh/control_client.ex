defmodule ChronoMesh.ControlClient do
  @moduledoc """
  Client for the control channel used to enqueue pulses on a running node.

  Provides helpers for addressing the local node (from config) and arbitrary
  remote nodes explicitly.
  """

  require Logger

  alias ChronoMesh.Pulse

  @doc """
  Enqueues pulses on the locally configured node via TCP control port.
  """
  @spec enqueue_local(map(), [Pulse.t()]) :: :ok | {:error, String.t()}
  def enqueue_local(config, pulses) when is_list(pulses) do
    {host, port} = control_endpoint(config)
    send_to(host, port, pulses)
  end

  @doc """
  Enqueues pulses on a remote node identified by host and port.
  """
  @spec enqueue_remote(String.t(), non_neg_integer(), [Pulse.t()]) :: :ok | {:error, String.t()}
  def enqueue_remote(host, port, pulses) when is_list(pulses) do
    send_to(host, port, pulses)
  end

  @doc false
  @spec control_endpoint(map()) :: {String.t(), non_neg_integer()}
  defp control_endpoint(config) do
    network = config["network"] || %{}
    host = Map.get(network, "listen_host", "127.0.0.1")
    port = parse_port(Map.get(network, "listen_port"))
    {host, port}
  end

  @doc false
  @spec parse_port(integer() | String.t() | nil) :: non_neg_integer()
  defp parse_port(port) when is_integer(port) and port > 0, do: port

  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {int, _} when int > 0 -> int
      _ -> 4_000
    end
  end

  defp parse_port(_), do: 4_000

  @doc false
  @spec send_to(String.t(), non_neg_integer(), [Pulse.t()]) :: :ok | {:error, String.t()}
  defp send_to(host, port, pulses) do
    host_chars = String.to_charlist(host)
    payload = :erlang.term_to_binary(pulses)

    case :gen_tcp.connect(host_chars, port, [:binary, packet: 4]) do
      {:ok, socket} ->
        :ok = :gen_tcp.send(socket, payload)
        :ok = :gen_tcp.close(socket)
        :ok

      {:error, reason} ->
        Logger.error("Control client failed to connect to #{host}:#{port} -> #{inspect(reason)}")
        {:error, "Unable to reach node #{host}:#{port} (#{inspect(reason)})"}
    end
  end
end
