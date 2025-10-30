defmodule ChronoMesh do
  @moduledoc """
  Core namespace for the Cadence protocol reference implementation.

  This module currently exposes helper utilities that are shared across the
  public API surface. As the network matures, the intention is to collect
  high-level convenience functions here for embedding Cadence into other
  applications.
  """

  @doc """
  Returns a sentinel atom that can be used to assert the library compiled.

  ## Examples

      iex> ChronoMesh.hello()
      :world

  """
  @spec hello() :: :world
  def hello do
    :world
  end
end
