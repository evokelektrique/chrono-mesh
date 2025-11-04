defmodule ChronoMesh.ODP do
  @moduledoc """
  Ordered Dialogue Protocol (ODP) for in-order frame delivery and multi-frame streaming.

  Tracks sequence numbers per dialogue session (sender-recipient pair) and ensures
  frames are delivered in order. Buffers out-of-order frames until missing sequences arrive.
  """

  use GenServer
  require Logger

  alias ChronoMesh.Events

  @typedoc "Dialogue ID (16-byte binary identifying a sender-recipient session)"
  @type dialogue_id :: binary()

  @typedoc "Sequence number within a dialogue"
  @type sequence_number :: non_neg_integer()

  @typedoc "Sender or recipient node ID (32-byte binary)"
  @type node_id :: binary()

  @typedoc "Sequence state for a dialogue"
  @type sequence_state :: %{
          expected_seq: sequence_number(),
          buffered: %{sequence_number() => binary()},
          last_delivered: sequence_number(),
          first_seen: non_neg_integer(),
          last_seen: non_neg_integer()
        }

  @typedoc "ODP GenServer state"
  @type state :: %{
          dialogues: %{dialogue_id() => sequence_state()},
          max_buffer_size: non_neg_integer(),
          sequence_timeout_ms: non_neg_integer(),
          max_sequence_gap: non_neg_integer(),
          delivery_callback: (dialogue_id(), sequence_number(), binary() -> :ok)
        }

  # Public API ----------------------------------------------------------------

  @doc """
  Starts the ODP GenServer process.

  Options:
  - `:max_buffer_size` - Maximum frames to buffer per dialogue (default: 100)
  - `:sequence_timeout_ms` - Timeout for waiting for missing sequences (default: 5 minutes)
  - `:max_sequence_gap` - Maximum gap allowed before resetting sequence (default: 1000)
  - `:delivery_callback` - Function to call when frame is ready for delivery (required)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Registers an incoming frame with sequence number.

  Returns `{:ok, :delivered}` if frame was delivered immediately,
  `{:ok, :buffered}` if frame was buffered for later delivery,
  or `{:error, reason}` on failure.
  """
  @spec register_frame(
          dialogue_id(),
          sequence_number(),
          binary(),
          node_id(),
          node_id()
        ) :: {:ok, :delivered | :buffered} | {:error, term()}
  def register_frame(dialogue_id, sequence_number, frame_data, sender_id, recipient_id)
      when is_binary(dialogue_id) and byte_size(dialogue_id) == 16 and
             is_integer(sequence_number) and sequence_number >= 0 and
             is_binary(frame_data) and
             is_binary(sender_id) and byte_size(sender_id) == 32 and
             is_binary(recipient_id) and byte_size(recipient_id) == 32 do
    GenServer.call(__MODULE__, {:register_frame, dialogue_id, sequence_number, frame_data, sender_id, recipient_id}, :infinity)
  end

  @doc """
  Gets currently buffered frames for a dialogue.

  Returns `{:ok, buffered_frames}` where buffered_frames is a map of
  `sequence_number => frame_data`, or `{:error, reason}` on failure.
  """
  @spec get_buffered(dialogue_id()) :: {:ok, %{sequence_number() => binary()}} | {:error, term()}
  def get_buffered(dialogue_id) when is_binary(dialogue_id) and byte_size(dialogue_id) == 16 do
    GenServer.call(__MODULE__, {:get_buffered, dialogue_id}, :infinity)
  end

  @doc """
  Resets the sequence for a dialogue session.

  Clears all buffered frames and resets expected sequence to 0.
  """
  @spec reset_session(dialogue_id()) :: :ok
  def reset_session(dialogue_id) when is_binary(dialogue_id) and byte_size(dialogue_id) == 16 do
    GenServer.call(__MODULE__, {:reset_session, dialogue_id}, :infinity)
  end

  # GenServer callbacks -------------------------------------------------------

  @impl true
  def init(opts) do
    max_buffer_size = Keyword.get(opts, :max_buffer_size, 100)
    sequence_timeout_ms = Keyword.get(opts, :sequence_timeout_ms, :timer.minutes(5))
    max_sequence_gap = Keyword.get(opts, :max_sequence_gap, 1000)

    delivery_callback =
      Keyword.get(opts, :delivery_callback) ||
        raise ArgumentError, "delivery_callback is required"

    # Schedule cleanup
    cleanup_timer = schedule_cleanup(sequence_timeout_ms)

    state = %{
      dialogues: %{},
      max_buffer_size: max_buffer_size,
      sequence_timeout_ms: sequence_timeout_ms,
      max_sequence_gap: max_sequence_gap,
      delivery_callback: delivery_callback,
      cleanup_timer: cleanup_timer
    }

    {:ok, state}
  end

  @impl true
  def handle_call({:register_frame, dialogue_id, sequence_number, frame_data, _sender_id, _recipient_id}, _from, state) do
    now = now_ms()

    dialogue_state =
      case Map.get(state.dialogues, dialogue_id) do
        nil ->
          # New dialogue - start with sequence 0
          %{
            expected_seq: 0,
            buffered: %{},
            last_delivered: -1,
            first_seen: now,
            last_seen: now
          }

        existing ->
          existing
      end

    # Check for sequence gap (possible reset)
    gap = sequence_number - dialogue_state.expected_seq

    if gap > state.max_sequence_gap do
      # Gap too large - reset sequence
      Logger.warning(
        "ODP: Sequence gap #{gap} too large for dialogue #{Base.encode16(dialogue_id)}, resetting"
      )

      Events.emit(:sequence_gap, %{
        dialogue_id: dialogue_id,
        gap: gap,
        expected: dialogue_state.expected_seq,
        received: sequence_number
      })

      reset_state = %{
        expected_seq: sequence_number,
        buffered: %{sequence_number => frame_data},
        last_delivered: sequence_number - 1,
        first_seen: now,
        last_seen: now
      }

      updated_dialogues = Map.put(state.dialogues, dialogue_id, reset_state)
      {:reply, {:ok, :buffered}, %{state | dialogues: updated_dialogues}}
    else
      # Check if this is the expected sequence
      if sequence_number == dialogue_state.expected_seq do
        # Deliver immediately
        deliver_frame(state.delivery_callback, dialogue_id, sequence_number, frame_data)

        # Check if we can deliver buffered frames
        {delivered_count, updated_state} = deliver_ready_sequences(dialogue_id, dialogue_state, state)

        Events.emit(:frame_delivered, %{
          dialogue_id: dialogue_id,
          sequence_number: sequence_number,
          buffered_delivered: delivered_count
        })

        {:reply, {:ok, :delivered}, updated_state}
      else
        # Out of order - buffer it
        if sequence_number < dialogue_state.expected_seq do
          # Duplicate or old frame - ignore
          Logger.debug(
            "ODP: Ignoring out-of-order frame (seq #{sequence_number} < expected #{dialogue_state.expected_seq})"
          )

          {:reply, {:ok, :buffered}, state}
        else
          # Future frame - buffer it
          buffered_count = map_size(dialogue_state.buffered)

          if buffered_count >= state.max_buffer_size do
            {:reply, {:error, :buffer_full}, state}
          else
            updated_buffered = Map.put(dialogue_state.buffered, sequence_number, frame_data)
            updated_state_map = %{
              dialogue_state
              | buffered: updated_buffered,
                last_seen: now
            }

            updated_dialogues = Map.put(state.dialogues, dialogue_id, updated_state_map)

            Events.emit(:frame_buffered, %{
              dialogue_id: dialogue_id,
              sequence_number: sequence_number,
              expected: dialogue_state.expected_seq,
              buffered_count: buffered_count + 1
            })

            {:reply, {:ok, :buffered}, %{state | dialogues: updated_dialogues}}
          end
        end
      end
    end
  end

  @impl true
  def handle_call({:get_buffered, dialogue_id}, _from, state) do
    case Map.get(state.dialogues, dialogue_id) do
      nil ->
        {:reply, {:error, :dialogue_not_found}, state}

      dialogue_state ->
        {:reply, {:ok, dialogue_state.buffered}, state}
    end
  end

  @impl true
  def handle_call({:reset_session, dialogue_id}, _from, state) do
    updated_dialogues = Map.delete(state.dialogues, dialogue_id)

    Events.emit(:session_reset, %{dialogue_id: dialogue_id})

    {:reply, :ok, %{state | dialogues: updated_dialogues}}
  end

  @impl true
  def handle_info(:cleanup_expired, state) do
    now = now_ms()
    timeout = state.sequence_timeout_ms

    {active_dialogues, expired_count} =
      state.dialogues
      |> Enum.reduce({%{}, 0}, fn {dialogue_id, dialogue_state}, {active, expired} ->
        age = now - dialogue_state.last_seen

        if age > timeout do
          Events.emit(:session_expired, %{dialogue_id: dialogue_id, age_ms: age})
          {active, expired + 1}
        else
          {Map.put(active, dialogue_id, dialogue_state), expired}
        end
      end)

    if expired_count > 0 do
      Logger.debug("ODP: Cleaned up #{expired_count} expired dialogue sessions")
    end

    # Reschedule cleanup
    cleanup_timer = schedule_cleanup(state.sequence_timeout_ms)

    {:noreply, %{state | dialogues: active_dialogues, cleanup_timer: cleanup_timer}}
  end

  @impl true
  def terminate(_reason, state) do
    if state.cleanup_timer != nil do
      Process.cancel_timer(state.cleanup_timer)
    end

    :ok
  end

  # Private functions ---------------------------------------------------------

  defp deliver_frame(callback, dialogue_id, sequence_number, frame_data) do
    try do
      callback.(dialogue_id, sequence_number, frame_data)
    rescue
      e ->
        Logger.error("ODP: Delivery callback failed: #{inspect(e)}")
        :ok
    end
  end

  defp deliver_ready_sequences(dialogue_id, dialogue_state, state) do
    # Deliver consecutive buffered frames starting from expected_seq
    {delivered_count, updated_buffered, updated_expected, updated_last} =
      deliver_ready_recursive(
        dialogue_state.expected_seq + 1,
        dialogue_state.buffered,
        0,
        dialogue_state.expected_seq,
        dialogue_id,
        state.delivery_callback
      )

    updated_dialogue_state = %{
      dialogue_state
      | expected_seq: updated_expected,
        buffered: updated_buffered,
        last_delivered: updated_last
    }

    updated_dialogues = Map.put(state.dialogues, dialogue_id, updated_dialogue_state)

    {delivered_count, %{state | dialogues: updated_dialogues}}
  end

  defp deliver_ready_recursive(expected_seq, buffered, delivered_count, last_delivered, dialogue_id, callback) do
    case Map.pop(buffered, expected_seq) do
      {nil, _} ->
        # No more consecutive frames
        {delivered_count, buffered, expected_seq, last_delivered}

      {frame_data, remaining_buffered} ->
        # Deliver this frame and continue
        deliver_frame(callback, dialogue_id, expected_seq, frame_data)

        deliver_ready_recursive(
          expected_seq + 1,
          remaining_buffered,
          delivered_count + 1,
          expected_seq,
          dialogue_id,
          callback
        )
    end
  end

  defp schedule_cleanup(interval_ms) do
    Process.send_after(self(), :cleanup_expired, interval_ms)
  end

  defp now_ms do
    System.system_time(:millisecond)
  end
end
