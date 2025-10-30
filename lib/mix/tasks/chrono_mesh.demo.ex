defmodule Mix.Tasks.ChronoMesh.Demo do
  @moduledoc """
  Invokes the demo cluster automation used during development to spin up a
  small Cadence network locally.
  """

  use Mix.Task

  @shortdoc "Runs the ChronoMesh demo cluster script"

  @doc """
  Builds the escript and executes the shell script responsible for orchestrating
  the demo cluster. Returns the exit status from the shell script.
  """
  @spec run([String.t()]) :: integer()
  def run(_args) do
    Mix.shell().cmd("mix escript.build")
    Mix.shell().cmd("scripts/demo_cluster.sh", quiet: false)
  end
end
