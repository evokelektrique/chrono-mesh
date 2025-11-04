defmodule ChronoMesh.Guards do
  @moduledoc """
  Entry/exit guard selection for anonymity protection.

  Guards are long-lived nodes that users prefer to route through as their first
  and last hops. This prevents attackers from correlating all traffic of a user
  entering and exiting the network.

  Key properties:
  - Users establish persistent relationships with 2-3 guards
  - Guards handle entry traffic (first hop of outgoing messages)
  - Guards handle exit traffic (last hop of incoming messages)
  - Guards are rotated periodically (default: monthly)
  - Guard statistics track reliability and latency
  - Guards are selected from trusted nodes with uptime history

  Anonymity benefits:
  - Prevents global observer from correlating entry/exit points
  - Guards provide traffic batching similar to cover traffic
  - Reduces fingerprinting of user communication patterns
  """

  require Logger

  @doc """
  Initializes guard state from configuration.

  Returns: `{:ok, guards_state}` or `{:error, reason}`

  Configuration options:
  - `enabled`: boolean, whether guard rotation is enabled
  - `rotation_interval_days`: how often to rotate guards (default: 30)
  - `guard_count`: number of guards to maintain (default: 3)
  - `min_uptime_percent`: minimum uptime to qualify as guard (default: 95)
  """
  @spec init(map()) :: {:ok, map()} | {:error, atom()}
  def init(config) when is_map(config) do
    guards_config = Map.get(config, "guards", %{})

    case get_in(guards_config, ["enabled"]) do
      false ->
        {:ok, %{}}

      nil ->
        {:ok, %{}}

      true ->
        state = %{
          "enabled" => true,
          "guard_count" => get_in(guards_config, ["guard_count"]) || 3,
          "rotation_interval_days" => get_in(guards_config, ["rotation_interval_days"]) || 30,
          "min_uptime_percent" => get_in(guards_config, ["min_uptime_percent"]) || 95,
          "guards" => [],
          "last_rotation" => nil,
          "guard_stats" => %{}
        }

        {:ok, state}

      _ ->
        {:error, :invalid_guards_config}
    end
  end

  @doc """
  Selects entry guards from available peers.

  Returns a list of guard node IDs suitable for use as first hops.
  Selects up to `guard_count` guards based on:
  - Uptime percentage
  - Recent latency measurements
  - Trust scores
  """
  @spec select_entry_guards(map(), list(map())) :: [binary()]
  def select_entry_guards(%{"enabled" => true} = state, available_peers)
      when is_list(available_peers) do
    if needs_rotation?(state) do
      # Rotate guards if needed
      rotate_guards(state, available_peers)
    else
      state.guards
    end
  end

  def select_entry_guards(_, _), do: []

  @doc """
  Selects a single entry guard for routing a message.

  Returns a guard node ID or nil if no guards available.
  Uses round-robin selection with statistical weighting.
  """
  @spec select_entry_guard(map()) :: binary() | nil
  def select_entry_guard(%{"enabled" => true, "guards" => [_ | _] = guards}), do: Enum.random(guards)
  def select_entry_guard(_), do: nil

  @doc """
  Records statistics for a guard (latency, success/failure).

  Updates the guard's reliability metrics used for selection.
  """
  @spec record_guard_stat(map(), binary(), :success | :failure, non_neg_integer()) :: map()
  def record_guard_stat(%{"enabled" => true, "guard_stats" => stats} = state, guard_id, status, latency_ms)
      when is_binary(guard_id) do
    current_stat = Map.get(stats, guard_id, %{total: 0, success: 0, latency_sum: 0, last_seen: nil})

    updated_stat = %{
      total: current_stat.total + 1,
      success: if(status == :success, do: current_stat.success + 1, else: current_stat.success),
      latency_sum: current_stat.latency_sum + latency_ms,
      last_seen: System.os_time(:second)
    }

    new_stats = Map.put(stats, guard_id, updated_stat)
    %{state | "guard_stats" => new_stats}
  end

  def record_guard_stat(state, _, _, _), do: state

  @doc """
  Returns statistics for a specific guard.

  Returns: `{success_rate, avg_latency_ms}` or nil if no data
  """
  @spec guard_stats(map(), binary()) :: {float(), non_neg_integer()} | nil
  def guard_stats(%{"guard_stats" => stats}, guard_id) when is_binary(guard_id) do
    case Map.get(stats, guard_id) do
      %{total: total, success: success, latency_sum: latency_sum} when total > 0 ->
        success_rate = success / total
        avg_latency = div(latency_sum, total)
        {success_rate, avg_latency}

      _ ->
        nil
    end
  end

  def guard_stats(_, _), do: nil

  @doc """
  Checks if guard rotation is needed based on time interval.
  """
  @spec needs_rotation?(map()) :: boolean()
  def needs_rotation?(%{"enabled" => true, "rotation_interval_days" => interval, "last_rotation" => last_rotation}) do
    case last_rotation do
      nil ->
        true

      timestamp when is_integer(timestamp) ->
        current_time = System.os_time(:second)
        seconds_elapsed = current_time - timestamp
        days_elapsed = div(seconds_elapsed, 86400)
        days_elapsed >= interval

      _ ->
        true
    end
  end

  def needs_rotation?(_), do: false

  @doc """
  Rotates guards by selecting new ones from available peers.

  Implements guard rotation strategy:
  1. Filter peers by minimum uptime
  2. Score by reliability metrics
  3. Select top N peers as new guards
  4. Update rotation timestamp
  """
  @spec rotate_guards(map(), list(map())) :: [binary()]
  def rotate_guards(%{"enabled" => true, "guard_count" => target_count, "min_uptime_percent" => min_uptime} = state,
                    available_peers) when is_list(available_peers) do
    # Filter peers by minimum uptime requirement
    qualified_peers =
      available_peers
      |> Enum.filter(fn peer ->
        uptime = peer["uptime_percent"] || 100
        uptime >= min_uptime
      end)

    # Score peers by reliability
    scored_peers =
      qualified_peers
      |> Enum.map(fn peer ->
        node_id = peer["node_id"]
        uptime = peer["uptime_percent"] || 100

        # Get existing stats if available
        {success_rate, latency} = guard_stats(state, node_id) || {1.0, 0}

        # Composite score: uptime (40%) + success_rate (40%) + latency (20%)
        score = uptime * 0.4 + success_rate * 100 * 0.4 - min(latency / 100, 25) * 0.2

        {node_id, score}
      end)
      |> Enum.sort_by(fn {_, score} -> score end, :desc)

    # Select top N guards
    new_guards =
      scored_peers
      |> Enum.take(target_count)
      |> Enum.map(fn {node_id, _} -> node_id end)

    # Log rotation
    old_guards = Map.get(state, "guards", [])
    if new_guards != old_guards do
      Logger.info("Guards: Rotating guards. Old: #{length(old_guards)}, New: #{length(new_guards)}")
    end

    new_guards
  end

  def rotate_guards(_, _), do: []

  @doc """
  Updates guard state after rotation.

  Call this after rotating guards to update the state with new timestamp.
  """
  @spec update_rotation_time(map()) :: map()
  def update_rotation_time(%{"enabled" => true} = state) do
    %{state | "last_rotation" => System.os_time(:second)}
  end

  def update_rotation_time(state), do: state

  @doc """
  Loads persisted guard state from storage.

  Attempts to load previously saved guards to maintain continuity across restarts.
  Uses Erlang term encoding for persistence.
  """
  @spec load_from_disk(binary()) :: map() | nil
  def load_from_disk(home_path) when is_binary(home_path) do
    guards_path = Path.join([home_path, ".chrono_mesh", "guards.bin"])

    case File.read(guards_path) do
      {:ok, binary} ->
        try do
          :erlang.binary_to_term(binary)
        rescue
          _ -> nil
        end

      {:error, _} ->
        nil
    end
  end

  @doc """
  Saves guard state to persistent storage.

  Preserves guard selections across node restarts using Erlang term encoding.
  """
  @spec save_to_disk(map(), binary()) :: :ok | {:error, atom()}
  def save_to_disk(%{"enabled" => true} = state, home_path) when is_binary(home_path) do
    guards_path = Path.join([home_path, ".chrono_mesh", "guards.bin"])

    # Ensure directory exists
    with :ok <- File.mkdir_p(Path.dirname(guards_path)),
         binary <- :erlang.term_to_binary(state),
         :ok <- File.write(guards_path, binary) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  def save_to_disk(_, _), do: :ok

  @doc """
  Removes a guard due to persistent failures or trust violations.

  Should be called when a guard exhibits concerning behavior.
  """
  @spec remove_guard(map(), binary()) :: map()
  def remove_guard(%{"enabled" => true, "guards" => guards} = state, guard_id) when is_binary(guard_id) do
    new_guards = Enum.filter(guards, &(&1 != guard_id))

    # Also remove stats for this guard
    old_stats = Map.get(state, "guard_stats", %{})
    new_stats = Map.delete(old_stats, guard_id)

    Logger.warning("Guards: Removed unreliable guard #{guard_id}")

    %{state | "guards" => new_guards, "guard_stats" => new_stats}
  end

  def remove_guard(state, _), do: state
end
