defmodule ChronoMesh.Runtime do
  @moduledoc """
  Boots the different runtime modes for ChronoMesh.
  """

  require Logger

  alias ChronoMesh.Node
  alias ChronoMesh.Discovery

  @doc """
  Starts an isolated supervision tree for the requested `mode`.
  """
  @spec start(keyword()) :: {:ok, pid()}
  def start(opts) do
    mode = Keyword.fetch!(opts, :mode)
    config = Keyword.fetch!(opts, :config)

    children =
      case mode do
        :server ->
          [discovery_child(config), node_child(config)]

        :client ->
          [client_child(config)]

        :combined ->
          [discovery_child(config), node_child(config), client_child(config)]
      end

    Supervisor.start_link(children,
      strategy: :one_for_one,
      name: ChronoMesh.RuntimeSupervisor
    )
  end

  @doc false
  @spec node_child(map()) :: Supervisor.child_spec()
  defp node_child(config) do
    Supervisor.child_spec({Node, config}, id: :node)
  end

  @doc false
  @spec client_child(map()) :: Supervisor.child_spec()
  defp client_child(config) do
    Supervisor.child_spec({ChronoMesh.ClientShell, config}, id: :client_shell)
  end

  @doc false
  @spec discovery_child(map()) :: Supervisor.child_spec()
  defp discovery_child(config) do
    Supervisor.child_spec({Discovery, config}, id: :discovery)
  end
end
