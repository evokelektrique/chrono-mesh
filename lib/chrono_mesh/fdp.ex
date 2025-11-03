defmodule ChronoMesh.FDP do
  @moduledoc """
  Fragmented Data Protocol (FDP) for receiver-side frame reassembly.

  Tracks incoming shards by frame_id, detects when all shards are received,
  and reassembles complete frames for delivery. Handles cleanup of incomplete
  frames that time out.

  ## Forward Error Correction (FEC)

  Supports Forward Error Correction (FEC) for recovery from lost shards:
  - When FEC is enabled, frames can be reassembled even if some data shards are missing
  - Recovery uses parity shards to reconstruct missing data shards
  - FEC metadata (fec_enabled, parity_count, data_shard_count) is passed via pulse
  - FEC recovery is automatic when sufficient shards (data + parity) are received

  See `ChronoMesh.FEC` for details on FEC implementation.
  """

  use GenServer

  require Logger

  alias ChronoMesh.Events

  @typedoc "Frame ID (16 bytes binary)"
  @type frame_id :: binary()

  @typedoc "Shard index within a frame"
  @type shard_index :: non_neg_integer()

  @typedoc "Frame tracking state"
  @type frame_state :: %{
          shards: %{shard_index() => binary()},
          shard_count: pos_integer(),
          first_seen: non_neg_integer(),
          last_seen: non_neg_integer(),
          fec_enabled: boolean(),
          parity_count: non_neg_integer(),
          data_shard_count: pos_integer()
        }

  @typedoc "FDP GenServer state"
  @type state :: %{
          frames: %{frame_id() => frame_state()},
          frame_timeout_ms: non_neg_integer(),
          cleanup_interval_ms: non_neg_integer(),
          max_frame_size: non_neg_integer()
        }

  # Public API ----------------------------------------------------------------

  @doc """
  Start the FDP GenServer process.

  Options:
  - `:frame_timeout_ms` - Time to wait for missing shards (default: 5 minutes)
  - `:cleanup_interval_ms` - How often to run cleanup (default: 1 minute)
  - `:max_frame_size` - Maximum frame size in bytes (default: 10MB)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Register an incoming shard. Returns `{:ok, :complete}` if frame is now complete,
  `{:ok, :incomplete}` if more shards are needed, or `{:error, reason}` on failure.

  FEC metadata can be provided for Forward Error Correction support:
  - `fec_enabled`: Whether FEC is enabled for this frame
  - `parity_count`: Number of parity shards
  - `data_shard_count`: Number of data shards (excluding parity)
  """
  @spec register_shard(frame_id(), shard_index(), pos_integer(), binary(), keyword()) ::
          {:ok, :complete | :incomplete} | {:error, term()}
  def register_shard(frame_id, shard_index, shard_count, plaintext, opts \\ [])
      when is_binary(frame_id) and is_integer(shard_index) and is_integer(shard_count) and
             shard_count > 0 and is_binary(plaintext) do
    case GenServer.whereis(__MODULE__) do
      nil ->
        {:error, :fdp_not_running}

      pid ->
        fec_enabled = Keyword.get(opts, :fec_enabled, false)
        parity_count = Keyword.get(opts, :parity_count, 0)
        data_shard_count = Keyword.get(opts, :data_shard_count, shard_count)

        GenServer.call(
          pid,
          {:register_shard, frame_id, shard_index, shard_count, plaintext, fec_enabled,
           parity_count, data_shard_count}
        )
    end
  end

  @doc """
  Check if a frame has all required shards.
  """
  @spec check_complete(frame_id()) :: boolean()
  def check_complete(frame_id) when is_binary(frame_id) do
    case GenServer.whereis(__MODULE__) do
      nil -> false
      pid -> GenServer.call(pid, {:check_complete, frame_id})
    end
  end

  @doc """
  Reassemble a complete frame from all shards. Returns `{:ok, binary()}` or `{:error, reason}`.
  Removes the frame from tracking after successful reassembly.
  """
  @spec reassemble(frame_id()) :: {:ok, binary()} | {:error, term()}
  def reassemble(frame_id) when is_binary(frame_id) do
    case GenServer.whereis(__MODULE__) do
      nil -> {:error, :fdp_not_running}
      pid -> GenServer.call(pid, {:reassemble, frame_id})
    end
  end

  @doc """
  Get list of missing shard indices for a frame.
  """
  @spec get_missing_shards(frame_id()) :: {:ok, [shard_index()]} | {:error, term()}
  def get_missing_shards(frame_id) when is_binary(frame_id) do
    case GenServer.whereis(__MODULE__) do
      nil -> {:error, :fdp_not_running}
      pid -> GenServer.call(pid, {:get_missing_shards, frame_id})
    end
  end

  # GenServer callbacks -------------------------------------------------------

  @impl true
  @spec init(keyword()) :: {:ok, state()}
  def init(opts) do
    frame_timeout_ms = Keyword.get(opts, :frame_timeout_ms, :timer.minutes(5))
    cleanup_interval_ms = Keyword.get(opts, :cleanup_interval_ms, :timer.minutes(1))
    max_frame_size = Keyword.get(opts, :max_frame_size, 10 * 1024 * 1024)

    state = %{
      frames: %{},
      frame_timeout_ms: frame_timeout_ms,
      cleanup_interval_ms: cleanup_interval_ms,
      max_frame_size: max_frame_size
    }

    schedule_cleanup(cleanup_interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_call(
        {:register_shard, frame_id, shard_index, shard_count, plaintext, fec_enabled,
         parity_count, data_shard_count},
        _from,
        state
      ) do
    now = now_ms()

    # Validate shard_index
    if shard_index >= shard_count do
      {:reply, {:error, :invalid_shard_index}, state}
    else
      case Map.get(state.frames, frame_id) do
        nil ->
          # New frame - check size first
          total_size = byte_size(plaintext)

          if total_size > state.max_frame_size do
            {:reply, {:error, :frame_too_large}, state}
          else
            # Default FEC values if not provided (backward compatibility)
            frame_fec_enabled = if fec_enabled != nil, do: fec_enabled, else: false
            frame_parity_count = if parity_count != nil, do: parity_count, else: 0

            frame_data_shard_count =
              if data_shard_count > 0, do: data_shard_count, else: shard_count

            frame_state = %{
              shards: %{shard_index => plaintext},
              shard_count: shard_count,
              first_seen: now,
              last_seen: now,
              fec_enabled: frame_fec_enabled,
              parity_count: frame_parity_count,
              data_shard_count: frame_data_shard_count
            }

            # Check if frame is complete (with FEC support)
            complete? = check_frame_complete(frame_state)

            new_frames = Map.put(state.frames, frame_id, frame_state)
            new_state = %{state | frames: new_frames}

            Events.emit(:shard_received, %{shard_index: shard_index}, %{
              frame_id: frame_id,
              shard_count: shard_count,
              received_count: 1
            })

            if complete? do
              Events.emit(:frame_complete, %{frame_id: frame_id}, %{
                frame_id: frame_id,
                shard_count: shard_count
              })
            end

            result = if complete?, do: :complete, else: :incomplete
            {:reply, {:ok, result}, new_state}
          end

        existing ->
          # Existing frame - check if shard already exists
          if shard_index in Map.keys(existing.shards) do
            # Duplicate shard - update timestamp but don't overwrite
            frame_state = %{existing | last_seen: now}
            new_frames = Map.put(state.frames, frame_id, frame_state)
            new_state = %{state | frames: new_frames}

            {:reply, {:ok, :incomplete}, new_state}
          else
            # New shard - add it
            new_shards = Map.put(existing.shards, shard_index, plaintext)

            # Check frame size
            total_size = calculate_total_size(new_shards)

            if total_size > state.max_frame_size do
              {:reply, {:error, :frame_too_large}, state}
            else
              # Update FEC metadata if provided (first shard sets it)
              updated_fec_enabled =
                if existing.fec_enabled, do: existing.fec_enabled, else: fec_enabled || false

              updated_parity_count =
                if existing.parity_count > 0, do: existing.parity_count, else: parity_count || 0

              updated_data_shard_count =
                if existing.data_shard_count > 0, do: existing.data_shard_count, else: shard_count

              frame_state = %{
                existing
                | shards: new_shards,
                  last_seen: now,
                  fec_enabled: updated_fec_enabled,
                  parity_count: updated_parity_count,
                  data_shard_count: updated_data_shard_count
              }

              # Check if frame is complete (with FEC support)
              complete? = check_frame_complete(frame_state)

              # Update state
              new_frames = Map.put(state.frames, frame_id, frame_state)
              new_state = %{state | frames: new_frames}

              # Emit event
              Events.emit(:shard_received, %{shard_index: shard_index}, %{
                frame_id: frame_id,
                shard_count: frame_state.shard_count,
                received_count: map_size(frame_state.shards)
              })

              if complete? do
                Events.emit(:frame_complete, %{frame_id: frame_id}, %{
                  frame_id: frame_id,
                  shard_count: frame_state.shard_count
                })
              end

              result = if complete?, do: :complete, else: :incomplete
              {:reply, {:ok, result}, new_state}
            end
          end
      end
    end
  end

  @impl true
  def handle_call({:check_complete, frame_id}, _from, state) do
    case Map.get(state.frames, frame_id) do
      nil ->
        {:reply, false, state}

      frame_state ->
        complete? = check_frame_complete(frame_state)
        {:reply, complete?, state}
    end
  end

  @impl true
  def handle_call({:reassemble, frame_id}, _from, state) do
    case Map.get(state.frames, frame_id) do
      nil ->
        {:reply, {:error, :frame_not_found}, state}

      frame_state ->
        # Check if we have enough shards (with FEC support)
        if not check_frame_complete(frame_state) do
          {:reply, {:error, :frame_incomplete}, state}
        else
          # Try FEC recovery if needed
          recovered_shards =
            if frame_state.fec_enabled do
              try_fec_recovery(frame_state)
            else
              frame_state.shards
            end

          # Reassemble only data shards (exclude parity shards)
          data_shard_count = frame_state.data_shard_count

          reassembled =
            0..(data_shard_count - 1)
            |> Enum.map(fn idx ->
              case Map.get(recovered_shards, idx) do
                nil -> raise "Missing data shard #{idx} after FEC recovery"
                shard -> shard
              end
            end)
            |> IO.iodata_to_binary()

          # Remove frame from tracking
          new_frames = Map.delete(state.frames, frame_id)
          new_state = %{state | frames: new_frames}

          {:reply, {:ok, reassembled}, new_state}
        end
    end
  end

  @impl true
  def handle_call({:get_missing_shards, frame_id}, _from, state) do
    case Map.get(state.frames, frame_id) do
      nil ->
        {:reply, {:error, :frame_not_found}, state}

      frame_state ->
        all_indices = MapSet.new(0..(frame_state.shard_count - 1))
        received_indices = MapSet.new(Map.keys(frame_state.shards))

        missing =
          MapSet.difference(all_indices, received_indices) |> MapSet.to_list() |> Enum.sort()

        {:reply, {:ok, missing}, state}
    end
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    now = now_ms()
    expired_before = now - state.frame_timeout_ms

    {expired_frames, active_frames} =
      state.frames
      |> Enum.split_with(fn {_frame_id, frame_state} ->
        frame_state.last_seen < expired_before
      end)

    # Emit timeout events for expired frames
    Enum.each(expired_frames, fn {frame_id, frame_state} ->
      Events.emit(:frame_timeout, %{frame_id: frame_id}, %{
        frame_id: frame_id,
        shard_count: frame_state.shard_count,
        received_count: map_size(frame_state.shards),
        age_ms: now - frame_state.first_seen
      })
    end)

    # Update state with only active frames
    new_frames = Map.new(active_frames)
    new_state = %{state | frames: new_frames}

    # Schedule next cleanup
    schedule_cleanup(state.cleanup_interval_ms)

    {:noreply, new_state}
  end

  # Internal helpers ----------------------------------------------------------

  @spec now_ms() :: non_neg_integer()
  defp now_ms, do: System.system_time(:millisecond)

  @spec schedule_cleanup(non_neg_integer()) :: reference()
  defp schedule_cleanup(interval_ms) do
    Process.send_after(self(), :cleanup_expired, interval_ms)
  end

  @spec calculate_total_size(%{shard_index() => binary()}) :: non_neg_integer()
  defp calculate_total_size(shards) do
    shards
    |> Map.values()
    |> Enum.map(&byte_size/1)
    |> Enum.sum()
  end

  # Check if frame is complete (with FEC support)
  @spec check_frame_complete(frame_state()) :: boolean()
  defp check_frame_complete(frame_state) do
    data_shard_count = frame_state.data_shard_count
    received_shards = frame_state.shards

    # Count received data and parity shards
    received_data_shards =
      received_shards
      |> Enum.filter(fn {idx, _} -> idx < data_shard_count end)
      |> length()

    received_parity_shards =
      received_shards
      |> Enum.filter(fn {idx, _} -> idx >= data_shard_count end)
      |> length()

    if frame_state.fec_enabled do
      # With FEC: need enough data shards OR data + parity >= data_shard_count
      received_data_shards >= data_shard_count or
        received_data_shards + received_parity_shards >= data_shard_count
    else
      # Without FEC: need all shards
      map_size(received_shards) >= frame_state.shard_count
    end
  end

  # Try FEC recovery if needed
  @spec try_fec_recovery(frame_state()) :: %{shard_index() => binary()}
  defp try_fec_recovery(frame_state) do
    data_shard_count = frame_state.data_shard_count
    received_shards = frame_state.shards

    # Find missing data shards
    all_data_indices = MapSet.new(0..(data_shard_count - 1))

    received_data_indices =
      received_shards
      |> Map.keys()
      |> Enum.filter(&(&1 < data_shard_count))
      |> MapSet.new()

    missing_data_indices =
      MapSet.difference(all_data_indices, received_data_indices) |> MapSet.to_list()

    if length(missing_data_indices) == 0 do
      # All data shards received - no recovery needed
      received_shards
    else
      # Try to recover missing shards
      case ChronoMesh.FEC.recover_shards(received_shards, missing_data_indices, data_shard_count) do
        recovered when is_map(recovered) and map_size(recovered) > 0 ->
          # Merge recovered shards with received shards
          Map.merge(received_shards, recovered)

        _ ->
          # Recovery failed - return original shards (will fail reassembly)
          received_shards
      end
    end
  end
end
