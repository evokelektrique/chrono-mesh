defmodule ChronoMesh.Pulse do
  @moduledoc """
  Representation of a fixed-size Cadence pulse.
  """

  @enforce_keys [:frame_id, :shard_index, :shard_count, :token_chain, :payload]
  defstruct [:frame_id, :shard_index, :shard_count, :token_chain, :payload]

  @type t :: %__MODULE__{
          frame_id: binary(),
          shard_index: non_neg_integer(),
          shard_count: pos_integer(),
          token_chain: [binary()],
          payload: binary()
        }
end
