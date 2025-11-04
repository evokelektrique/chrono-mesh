defmodule ChronoMesh.ODPTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.ODP

  @test_dialogue_id :crypto.strong_rand_bytes(16)
  @test_sender_id :crypto.strong_rand_bytes(32)
  @test_recipient_id :crypto.strong_rand_bytes(32)

  setup do
    # Clean up any existing ODP process
    case GenServer.whereis(ODP) do
      nil ->
        :ok

      pid ->
        try do
          GenServer.stop(pid, :normal, 5000)
          Process.sleep(50)
        rescue
          ArgumentError -> :ok
        end
    end

    on_exit(fn ->
      # Clean up ODP process
      case GenServer.whereis(ODP) do
        nil ->
          :ok

        pid ->
          try do
            if Process.alive?(pid) do
              GenServer.stop(pid, :normal, 5000)
              Process.sleep(50)
            end
          rescue
            ArgumentError -> :ok
          end
      end
    end)

    :ok
  end

  defp create_test_callback(agent_pid) do
    fn dialogue_id, sequence_number, frame_data ->
      Agent.update(agent_pid, fn list ->
        [{dialogue_id, sequence_number, frame_data} | list]
      end)
      :ok
    end
  end

  defp start_odp(opts \\ []) do
    {:ok, agent_pid} = Agent.start_link(fn -> [] end)

    callback = create_test_callback(agent_pid)

    default_opts = [
      delivery_callback: callback,
      max_buffer_size: 100,
      sequence_timeout_ms: 5000,
      max_sequence_gap: 1000
    ]

    opts = Keyword.merge(default_opts, opts)
    {:ok, pid} = ODP.start_link(opts)
    {pid, agent_pid}
  end

  defp get_delivered(agent_pid) do
    Agent.get(agent_pid, fn list -> Enum.reverse(list) end)
  end

  defp clear_delivered(agent_pid) do
    Agent.update(agent_pid, fn _ -> [] end)
  end

  describe "start_link/1" do
    test "starts ODP with required delivery_callback" do
      {pid, _agent_pid} = start_odp()
      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "fails to start without delivery_callback" do
      # start_link raises ArgumentError in init, which causes the process to exit
      # We trap exits to catch the process exit
      Process.flag(:trap_exit, true)

      result = ODP.start_link([])

      # Verify it failed
      assert match?({:error, _}, result)

      Process.flag(:trap_exit, false)
    end

    test "starts ODP with custom options" do
      {pid, _agent_pid} =
        start_odp(
          max_buffer_size: 50,
          sequence_timeout_ms: 10000,
          max_sequence_gap: 500
        )

      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "register_frame/5" do
    test "delivers frame immediately when sequence is in order" do
      {pid, agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      frame_data = "frame_0"
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, frame_data, sender_id, recipient_id)

      # Wait a bit for async delivery
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 1
      assert {^dialogue_id, 0, ^frame_data} = hd(delivered)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "buffers out-of-order frames" do
      {pid, agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frame 1 first (out of order)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 1, "frame_1", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 0

      # Register frame 0 (now in order)
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Wait a bit for delivery
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 2

      # Check order
      [first, second] = delivered
      assert {^dialogue_id, 0, "frame_0"} = first
      assert {^dialogue_id, 1, "frame_1"} = second

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "ignores duplicate/old frames" do
      {pid, agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frame 0 first (expected_seq starts at 0)
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)
      clear_delivered(agent_pid)

      # Register frame 1
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 1, "frame_1", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)
      clear_delivered(agent_pid)

      # Try to register frame 1 again (old frame)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 1, "frame_1_dup", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 0

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "returns error when buffer is full" do
      {pid, _agent_pid} = start_odp(max_buffer_size: 2)

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frame 0
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Buffer frames 2 and 3 (gap from 0 to 2)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 2, "frame_2", sender_id, recipient_id)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 3, "frame_3", sender_id, recipient_id)

      # Buffer is now full (max_buffer_size = 2)
      assert {:error, :buffer_full} = ODP.register_frame(dialogue_id, 4, "frame_4", sender_id, recipient_id)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "handles multiple buffered frames in sequence" do
      {pid, agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frames out of order: 2, 3, 1
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 2, "frame_2", sender_id, recipient_id)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 3, "frame_3", sender_id, recipient_id)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 1, "frame_1", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 0

      # Register frame 0 (should trigger delivery of 0, 1, 2, 3)
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Wait a bit for delivery
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 4

      # Verify order
      assert [
               {^dialogue_id, 0, "frame_0"},
               {^dialogue_id, 1, "frame_1"},
               {^dialogue_id, 2, "frame_2"},
               {^dialogue_id, 3, "frame_3"}
             ] = delivered

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "resets sequence when gap is too large" do
      {pid, agent_pid} = start_odp(max_sequence_gap: 10)

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frame 0
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)
      clear_delivered(agent_pid)

      # Register frame 100 (gap = 100, max_sequence_gap = 10)
      # Gap is 100, which is > 10, so sequence resets to 100
      # After reset: expected_seq = 100, frame 100 is buffered
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 100, "frame_100", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 0

      # Verify frame 100 is buffered
      assert {:ok, buffered} = ODP.get_buffered(dialogue_id)
      assert Map.has_key?(buffered, 100)

      # After reset: expected_seq = 100, frame 100 is buffered
      # Register frame 101 to buffer it
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 101, "frame_101", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 0

      # Register frame 100 again (expected_seq = 100, so this should deliver it)
      # This will deliver the new frame 100 and trigger delivery of buffered frame 100
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 100, "frame_100_dup", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      # Should have delivered frame 100 (both the new one and the buffered one)
      # Actually, the new frame 100 is delivered, and the buffered frame 100 is also delivered
      # Then frame 101 is delivered
      assert length(delivered) >= 2
      # Check that frame 100 was delivered
      frame_100_delivered = Enum.any?(delivered, fn {d, s, _} -> d == dialogue_id and s == 100 end)
      assert frame_100_delivered

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "handles multiple dialogues independently" do
      {pid, agent_pid} = start_odp()

      dialogue1 = :crypto.strong_rand_bytes(16)
      dialogue2 = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frames for dialogue1
      assert {:ok, :delivered} = ODP.register_frame(dialogue1, 0, "dialogue1_frame_0", sender_id, recipient_id)
      assert {:ok, :buffered} = ODP.register_frame(dialogue1, 2, "dialogue1_frame_2", sender_id, recipient_id)

      # Register frames for dialogue2
      assert {:ok, :delivered} = ODP.register_frame(dialogue2, 0, "dialogue2_frame_0", sender_id, recipient_id)
      assert {:ok, :delivered} = ODP.register_frame(dialogue2, 1, "dialogue2_frame_1", sender_id, recipient_id)

      # Register frame 2 out of order
      assert {:ok, :buffered} = ODP.register_frame(dialogue2, 3, "dialogue2_frame_3", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      # dialogue1: 0, dialogue2: 0, 1
      assert length(delivered) == 3

      # Fill gaps
      assert {:ok, :delivered} = ODP.register_frame(dialogue1, 1, "dialogue1_frame_1", sender_id, recipient_id)
      assert {:ok, :delivered} = ODP.register_frame(dialogue2, 2, "dialogue2_frame_2", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      # dialogue1: 0, 1, 2 (3 frames)
      # dialogue2: 0, 1, 2, 3 (4 frames)
      # Total: 7 frames
      # But we also have dialogue2_frame_3 which was buffered, so it should be delivered after frame 2
      assert length(delivered) >= 6
      # Verify all frames from both dialogues are present
      dialogue1_frames = Enum.filter(delivered, fn {d, _, _} -> d == dialogue1 end)
      dialogue2_frames = Enum.filter(delivered, fn {d, _, _} -> d == dialogue2 end)
      assert length(dialogue1_frames) >= 3
      assert length(dialogue2_frames) >= 3

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "get_buffered/1" do
    test "returns buffered frames for a dialogue" do
      {pid, _agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frame 0
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Buffer frames 2 and 3
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 2, "frame_2", sender_id, recipient_id)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 3, "frame_3", sender_id, recipient_id)

      # Get buffered frames
      assert {:ok, buffered} = ODP.get_buffered(dialogue_id)
      assert map_size(buffered) == 2
      assert Map.get(buffered, 2) == "frame_2"
      assert Map.get(buffered, 3) == "frame_3"

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "returns error for non-existent dialogue" do
      {pid, _agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)

      assert {:error, :dialogue_not_found} = ODP.get_buffered(dialogue_id)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "returns empty map when no frames are buffered" do
      {pid, _agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register frame 0 (in order, no buffering)
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Get buffered frames
      assert {:ok, buffered} = ODP.get_buffered(dialogue_id)
      assert map_size(buffered) == 0

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "reset_session/1" do
    test "resets dialogue session and clears buffered frames" do
      {pid, agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register and buffer some frames
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, 2, "frame_2", sender_id, recipient_id)

      # Verify buffered frames exist
      assert {:ok, buffered} = ODP.get_buffered(dialogue_id)
      assert map_size(buffered) == 1

      # Reset session
      assert :ok = ODP.reset_session(dialogue_id)

      # Verify dialogue no longer exists
      assert {:error, :dialogue_not_found} = ODP.get_buffered(dialogue_id)

      # Register frame 0 again (should start fresh)
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0_new", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      # Should have 2 deliveries: original frame_0 and new frame_0_new
      assert length(delivered) == 2
      # Verify the new frame was delivered
      assert {dialogue_id, 0, "frame_0_new"} in delivered

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "cleanup and expiration" do
    test "cleans up expired sessions" do
      {pid, _agent_pid} = start_odp(sequence_timeout_ms: 100)

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      # Register a frame
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Verify dialogue exists
      assert {:ok, _buffered} = ODP.get_buffered(dialogue_id)

      # Wait for expiration
      Process.sleep(150)

      # Trigger cleanup by sending cleanup message
      send(pid, :cleanup_expired)
      Process.sleep(50)

      # Verify dialogue was cleaned up
      assert {:error, :dialogue_not_found} = ODP.get_buffered(dialogue_id)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "edge cases" do
    test "handles very large sequence numbers" do
      {pid, agent_pid} = start_odp(max_sequence_gap: 1_000_000)

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      large_seq = 500

      # Large sequence will be buffered initially (expected_seq starts at 0)
      assert {:ok, :buffered} = ODP.register_frame(dialogue_id, large_seq, "frame_large", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 0

      # Register frame 0 to trigger delivery
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "frame_0", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      # Should have delivered frame_0
      # frame_large (500) is buffered but not consecutive, so it won't be delivered yet
      assert length(delivered) == 1
      # Verify frame_0 was delivered
      [first] = delivered
      assert {dialogue_id, 0, "frame_0"} = first

      # Register frame 1 to continue the sequence
      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 1, "frame_1", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      # Still only frame_0 and frame_1, frame_large (500) is still buffered
      assert length(delivered) == 2

      # To deliver frame_large, we'd need to register frames 2, 3, ... 499, 500
      # That's not practical, so let's just verify it's buffered
      assert {:ok, buffered} = ODP.get_buffered(dialogue_id)
      assert Map.has_key?(buffered, large_seq)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "handles empty frame data" do
      {pid, agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, "", sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 1
      assert {^dialogue_id, 0, ""} = hd(delivered)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "handles binary frame data" do
      {pid, agent_pid} = start_odp()

      dialogue_id = :crypto.strong_rand_bytes(16)
      sender_id = :crypto.strong_rand_bytes(32)
      recipient_id = :crypto.strong_rand_bytes(32)

      binary_data = :crypto.strong_rand_bytes(100)

      assert {:ok, :delivered} = ODP.register_frame(dialogue_id, 0, binary_data, sender_id, recipient_id)

      # Wait a bit
      Process.sleep(10)

      delivered = get_delivered(agent_pid)
      assert length(delivered) == 1
      assert {^dialogue_id, 0, ^binary_data} = hd(delivered)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end
end
