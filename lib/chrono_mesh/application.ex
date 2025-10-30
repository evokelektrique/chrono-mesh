defmodule ChronoMesh.Application do
  @moduledoc """
  OTP application callback responsible for bootstrapping the supervision tree.

  At the moment the application only starts a registry used by long-lived
  processes (nodes, clients, discovery). As additional subsystems are added,
  they should be wired into this callback so that `mix chrono_mesh` can start the
  full stack through OTP.
  """

  use Application

  @impl true
  @doc """
  Starts the top-level supervisor that hosts shared registries.
  """
  @spec start(Application.start_type(), term()) ::
          {:ok, pid()}
          | {:ok, pid(), term()}
          | {:error, term()}
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: ChronoMesh.Registry}
    ]

    Supervisor.start_link(children,
      strategy: :one_for_one,
      name: ChronoMesh.Supervisor
    )
  end
end
