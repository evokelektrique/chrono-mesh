defmodule ChronoMesh.ClientShell do
  @moduledoc """
  Placeholder client process. For now it simply logs a banner and
  keeps running so that combined mode can stay alive.
  """

  use GenServer
  require Logger

  @doc """
  Starts the placeholder client process responsible for keeping combined mode alive.
  """
  @spec start_link(map()) :: GenServer.on_start()
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @impl true
  @doc """
  Logs an informational banner and stores the client configuration.
  """
  @spec init(map()) :: {:ok, map()}
  def init(config) do
    Logger.info("Client shell started for #{config["identity"]["display_name"]}")
    {:ok, config}
  end
end
