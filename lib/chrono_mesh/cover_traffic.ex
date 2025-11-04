defmodule ChronoMesh.CoverTraffic do
  @moduledoc """
  Cover traffic generation for anonymity protection.

  Generates dummy pulses that are cryptographically indistinguishable from real
  messages. These dummy pulses prevent attackers from correlating traffic bursts
  with user activity.

  Dummy pulses are:
  - Generated at configurable rates
  - Loop-back messages (node sends to itself)
  - Indistinguishable from real pulses to external observers
  - Mixed with real pulses in the same wave batch

  This prevents:
  - Traffic volume analysis (quiet periods expose non-communicating nodes)
  - Timing correlation attacks (burst patterns reveal message send times)
  - Entry/exit correlation (constant traffic makes it harder to identify endpoints)
  """

  require Logger

  alias ChronoMesh.Pulse

  @doc """
  Generates dummy pulses for a wave if cover traffic is enabled.

  Returns a list of {pulse, recipient_node_id} tuples ready for dispatch.
  If cover traffic is disabled, returns empty list.

  Configuration options:
  - `enabled`: boolean, whether to generate dummy pulses
  - `min_pulses_per_wave`: minimum pulses per wave (includes real + dummy)
  - `constant_rate`: target messages per second (default: disabled)
  - `strategy`: "constant" (fixed rate) | "adaptive" (context-aware)
  """
  @spec generate_for_wave(map(), binary(), non_neg_integer()) :: [{Pulse.t(), binary()}]
  def generate_for_wave(config, local_node_id, batch_size) when is_map(config) and is_binary(local_node_id) do
    case get_in(config, ["cover_traffic", "enabled"]) do
      false ->
        []

      nil ->
        []

      true ->
        min_pulses = get_in(config, ["cover_traffic", "min_pulses_per_wave"]) || 1
        generate_dummies(local_node_id, batch_size, min_pulses)

      _ ->
        []
    end
  end

  @doc """
  Generates a single dummy pulse that is indistinguishable from a real pulse.

  The pulse contains:
  - Random frame_id (16 bytes)
  - Random token_chain with 1-3 encrypted tokens
  - Random payload (32-64 bytes to vary size)
  - Valid auth_tag (required field)
  """
  @spec generate_dummy_pulse() :: Pulse.t()
  def generate_dummy_pulse do
    frame_id = :crypto.strong_rand_bytes(16)
    payload = :crypto.strong_rand_bytes(Enum.random(32..64))
    auth_tag = :crypto.strong_rand_bytes(16)

    # Generate 1-2 tokens to simulate a multi-hop path
    token_count = Enum.random(1..2)
    token_chain = generate_token_chain(token_count)

    %Pulse{
      frame_id: frame_id,
      shard_index: 0,
      shard_count: 1,
      token_chain: token_chain,
      payload: payload,
      auth_tag: auth_tag,
      fec_enabled: false,
      parity_count: 0,
      data_shard_count: 1,
      sequence_number: nil,
      dialogue_id: nil,
      privacy_tier: "low"
    }
  end

  @doc """
  Generates a random token chain for a dummy pulse.

  Each token is encrypted to a node in the path. For dummy pulses,
  we generate random tokens that look like real encrypted data.
  """
  @spec generate_token_chain(non_neg_integer()) :: [binary()]
  def generate_token_chain(count) when count > 0 do
    1..count
    |> Enum.map(fn _ -> :crypto.strong_rand_bytes(80) end)
    |> Enum.to_list()
  end

  defp generate_dummies(local_node_id, batch_size, min_pulses) do
    required_dummies = max(min_pulses - batch_size, 0)

    if required_dummies > 0 do
      Logger.debug(
        "Cover traffic: Generating #{required_dummies} dummy pulses (batch: #{batch_size}, min: #{min_pulses})"
      )

      1..required_dummies
      |> Enum.map(fn _ ->
        {generate_dummy_pulse(), local_node_id}
      end)
      |> Enum.to_list()
    else
      []
    end
  end
end
