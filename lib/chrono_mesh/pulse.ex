defmodule ChronoMesh.Pulse do
  @moduledoc """
  Representation of a fixed-size Cadence pulse.

  Supports Forward Error Correction (FEC) with optional parity shards for
  recovery from lost shards.
  """

  @enforce_keys [:frame_id, :shard_index, :shard_count, :token_chain, :payload]
  defstruct [
    :frame_id,
    :shard_index,
    :shard_count,
    :token_chain,
    :payload,
    fec_enabled: false,
    parity_count: 0,
    data_shard_count: 0,
    aead_enabled: false,
    auth_tag: nil
  ]

  @type t :: %__MODULE__{
          frame_id: binary(),
          shard_index: non_neg_integer(),
          shard_count: pos_integer(),
          token_chain: [binary()],
          payload: binary(),
          fec_enabled: boolean(),
          parity_count: non_neg_integer(),
          data_shard_count: pos_integer(),
          aead_enabled: boolean(),
          auth_tag: binary() | nil
        }
end
