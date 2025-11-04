defmodule ChronoMesh.TrustPolicy do
  @moduledoc """
  Trust policy hooks for relay decisions based on node trust scores.

  Provides a pluggable interface for trust-based relay decisions. The default
  implementation allows all relays (backward compatible), but can be extended
  to implement custom trust scoring and filtering logic.
  """

  require Logger

  @typedoc "Node ID (32-byte binary)"
  @type node_id :: binary()

  @typedoc "Trust score (0.0 to 1.0, where 1.0 is fully trusted)"
  @type trust_score :: float()

  @typedoc "Pulse struct"
  @type pulse :: ChronoMesh.Pulse.t()

  @doc """
  Determines whether a pulse should be relayed to a given node_id.

  Returns `true` to allow relay, `false` to reject.

  Default implementation: allows all relays (backward compatible).
  """
  @spec should_relay?(node_id(), pulse()) :: boolean()
  def should_relay?(node_id, _pulse) when is_binary(node_id) and byte_size(node_id) == 32 do
    # Default: allow all relays
    true
  end

  @doc """
  Gets the trust score for a node_id.

  Returns a float between 0.0 (untrusted) and 1.0 (fully trusted).

  Default implementation: returns 0.5 (neutral trust).
  """
  @spec get_trust_score(node_id()) :: trust_score()
  def get_trust_score(node_id) when is_binary(node_id) and byte_size(node_id) == 32 do
    # Default: neutral trust
    0.5
  end

  @doc """
  Updates the trust score for a node_id.

  `delta` can be positive (increase trust) or negative (decrease trust).
  The score is clamped to [0.0, 1.0].

  Default implementation: no-op (does nothing).
  """
  @spec update_trust_score(node_id(), float()) :: :ok
  def update_trust_score(node_id, delta)
      when is_binary(node_id) and byte_size(node_id) == 32 and is_float(delta) do
    # Default: no-op
    :ok
  end

  defmodule Default do
    @moduledoc """
    Default trust policy implementation (allows all relays).
    """

    @behaviour ChronoMesh.TrustPolicy.Behaviour

    @impl true
    def should_relay?(_node_id, _pulse), do: true

    @impl true
    def get_trust_score(_node_id), do: 0.5

    @impl true
    def update_trust_score(_node_id, _delta), do: :ok
  end

  defmodule Behaviour do
    @moduledoc """
    Behaviour for trust policy implementations.
    """

    @type node_id :: binary()
    @type pulse :: ChronoMesh.Pulse.t()
    @type trust_score :: float()

    @callback should_relay?(node_id(), pulse()) :: boolean()
    @callback get_trust_score(node_id()) :: trust_score()
    @callback update_trust_score(node_id(), float()) :: :ok
  end
end
