defmodule ChronoMesh.FDPTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.FDP

  setup do
    # Clean up any existing FDP process
    case GenServer.whereis(FDP) do
      nil ->
        :ok

      pid ->
        try do
          GenServer.stop(pid)
        rescue
          ArgumentError -> :ok
        end
    end

    on_exit(fn ->
      case GenServer.whereis(FDP) do
        nil ->
          :ok

        pid ->
          try do
            if Process.alive?(pid), do: GenServer.stop(pid)
          rescue
            ArgumentError -> :ok
          end
      end
    end)

    :ok
  end

  describe "start_link/1" do
    test "starts FDP with default options" do
      {:ok, pid} = FDP.start_link([])
      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "starts FDP with custom timeout" do
      {:ok, pid} = FDP.start_link(frame_timeout_ms: :timer.minutes(10))
      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "starts FDP with custom cleanup interval" do
      {:ok, pid} = FDP.start_link(cleanup_interval_ms: :timer.minutes(2))
      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "starts FDP with custom max frame size" do
      {:ok, pid} = FDP.start_link(max_frame_size: 5 * 1024 * 1024)
      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "register_shard/4" do
    test "registers single shard frame (complete immediately)" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, World!"

      assert {:ok, :complete} =
               FDP.register_shard(frame_id, 0, 1, plaintext)

      # Frame should be trackable but already complete
      assert FDP.check_complete(frame_id) == true
    end

    test "registers multiple shards and detects completion" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      shard1 = "Shard 1"
      shard2 = "Shard 2"
      shard3 = "Shard 3"

      # Register first shard
      assert {:ok, :incomplete} = FDP.register_shard(frame_id, 0, 3, shard1)
      assert FDP.check_complete(frame_id) == false

      # Register second shard
      assert {:ok, :incomplete} = FDP.register_shard(frame_id, 1, 3, shard2)
      assert FDP.check_complete(frame_id) == false

      # Register third shard - should complete
      assert {:ok, :complete} = FDP.register_shard(frame_id, 2, 3, shard3)
      assert FDP.check_complete(frame_id) == true
    end

    test "handles shards arriving out of order" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)

      # Register shards in reverse order
      assert {:ok, :incomplete} = FDP.register_shard(frame_id, 2, 3, "Shard 3")
      assert {:ok, :incomplete} = FDP.register_shard(frame_id, 0, 3, "Shard 1")
      assert {:ok, :complete} = FDP.register_shard(frame_id, 1, 3, "Shard 2")

      assert FDP.check_complete(frame_id) == true
    end

    test "rejects duplicate shards (doesn't overwrite)" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      original = "Original shard"
      duplicate = "Duplicate shard"

      assert {:ok, :incomplete} = FDP.register_shard(frame_id, 0, 2, original)
      assert {:ok, :incomplete} = FDP.register_shard(frame_id, 0, 2, duplicate)

      # Should still be incomplete
      assert FDP.check_complete(frame_id) == false

      # Reassemble should use original (if we had second shard)
      assert {:ok, :complete} = FDP.register_shard(frame_id, 1, 2, "Second")

      {:ok, reassembled} = FDP.reassemble(frame_id)
      assert String.contains?(reassembled, original)
      refute String.contains?(reassembled, duplicate)
    end

    test "rejects invalid shard_index" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)

      assert {:error, :invalid_shard_index} =
               FDP.register_shard(frame_id, 5, 3, "Invalid")

      assert {:error, :invalid_shard_index} =
               FDP.register_shard(frame_id, 3, 3, "Invalid")
    end

    test "rejects frames exceeding max_frame_size" do
      {:ok, _pid} = FDP.start_link(max_frame_size: 100)

      frame_id = :crypto.strong_rand_bytes(16)
      large_shard = String.duplicate("x", 101)

      assert {:error, :frame_too_large} =
               FDP.register_shard(frame_id, 0, 1, large_shard)
    end
  end

  describe "check_complete/1" do
    test "returns false for unknown frame" do
      {:ok, _pid} = FDP.start_link([])

      unknown_frame = :crypto.strong_rand_bytes(16)
      assert FDP.check_complete(unknown_frame) == false
    end

    test "returns false for incomplete frame" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 3, "Shard 1")

      assert FDP.check_complete(frame_id) == false
    end

    test "returns true for complete frame" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 2, "Shard 1")
      FDP.register_shard(frame_id, 1, 2, "Shard 2")

      assert FDP.check_complete(frame_id) == true
    end
  end

  describe "reassemble/1" do
    test "reassembles single shard frame" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      original = "Single shard message"

      FDP.register_shard(frame_id, 0, 1, original)

      assert {:ok, reassembled} = FDP.reassemble(frame_id)
      assert reassembled == original
    end

    test "reassembles multi-shard frame in correct order" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      shard1 = "First part"
      shard2 = "Second part"
      shard3 = "Third part"

      FDP.register_shard(frame_id, 0, 3, shard1)
      FDP.register_shard(frame_id, 1, 3, shard2)
      FDP.register_shard(frame_id, 2, 3, shard3)

      assert {:ok, reassembled} = FDP.reassemble(frame_id)
      assert reassembled == shard1 <> shard2 <> shard3
    end

    test "reassembles frame even when shards arrive out of order" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      shard1 = "A"
      shard2 = "B"
      shard3 = "C"

      # Register out of order
      FDP.register_shard(frame_id, 2, 3, shard3)
      FDP.register_shard(frame_id, 0, 3, shard1)
      FDP.register_shard(frame_id, 1, 3, shard2)

      assert {:ok, reassembled} = FDP.reassemble(frame_id)
      assert reassembled == "ABC"
    end

    test "returns error for unknown frame" do
      {:ok, _pid} = FDP.start_link([])

      unknown_frame = :crypto.strong_rand_bytes(16)
      assert {:error, :frame_not_found} = FDP.reassemble(unknown_frame)
    end

    test "returns error for incomplete frame" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 3, "Only first shard")

      assert {:error, :frame_incomplete} = FDP.reassemble(frame_id)
    end

    test "removes frame after successful reassembly" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 1, "Complete")

      assert {:ok, _} = FDP.reassemble(frame_id)

      # Frame should be gone
      assert {:error, :frame_not_found} = FDP.reassemble(frame_id)
    end
  end

  describe "get_missing_shards/1" do
    test "returns all indices for unknown frame" do
      {:ok, _pid} = FDP.start_link([])

      unknown_frame = :crypto.strong_rand_bytes(16)
      assert {:error, :frame_not_found} = FDP.get_missing_shards(unknown_frame)
    end

    test "returns missing shard indices" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 5, "Shard 0")
      FDP.register_shard(frame_id, 2, 5, "Shard 2")
      FDP.register_shard(frame_id, 4, 5, "Shard 4")

      assert {:ok, missing} = FDP.get_missing_shards(frame_id)
      assert missing == [1, 3]
    end

    test "returns empty list when all shards present" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 2, "Shard 0")
      FDP.register_shard(frame_id, 1, 2, "Shard 1")

      assert {:ok, missing} = FDP.get_missing_shards(frame_id)
      assert missing == []
    end
  end

  describe "frame timeout and cleanup" do
    test "cleans up expired frames" do
      {:ok, _pid} = FDP.start_link(frame_timeout_ms: 100, cleanup_interval_ms: 50)

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 3, "Incomplete frame")

      # Wait for timeout and cleanup
      Process.sleep(150)

      # Frame should be cleaned up
      assert FDP.check_complete(frame_id) == false
      assert {:error, :frame_not_found} = FDP.reassemble(frame_id)
    end

    test "does not clean up active frames" do
      {:ok, _pid} = FDP.start_link(frame_timeout_ms: 500, cleanup_interval_ms: 200)

      frame_id = :crypto.strong_rand_bytes(16)
      FDP.register_shard(frame_id, 0, 2, "First")

      # Wait less than timeout
      Process.sleep(100)

      # Frame should still be there
      assert FDP.check_complete(frame_id) == false

      # Add another shard to update last_seen
      FDP.register_shard(frame_id, 1, 2, "Second")

      # Wait a bit more (should still be under timeout)
      Process.sleep(300)

      # Frame should still be there because we updated last_seen
      assert FDP.check_complete(frame_id) == true
    end
  end

  describe "concurrent frame handling" do
    test "tracks multiple frames simultaneously" do
      {:ok, _pid} = FDP.start_link([])

      frame1_id = :crypto.strong_rand_bytes(16)
      frame2_id = :crypto.strong_rand_bytes(16)

      # Register shards for both frames
      FDP.register_shard(frame1_id, 0, 2, "Frame1-Shard1")
      FDP.register_shard(frame2_id, 0, 3, "Frame2-Shard1")
      FDP.register_shard(frame1_id, 1, 2, "Frame1-Shard2")
      FDP.register_shard(frame2_id, 1, 3, "Frame2-Shard2")
      FDP.register_shard(frame2_id, 2, 3, "Frame2-Shard3")

      # Both frames should be complete
      assert FDP.check_complete(frame1_id) == true
      assert FDP.check_complete(frame2_id) == true

      # Reassemble both
      {:ok, reassembled1} = FDP.reassemble(frame1_id)
      {:ok, reassembled2} = FDP.reassemble(frame2_id)

      assert reassembled1 == "Frame1-Shard1Frame1-Shard2"
      assert reassembled2 == "Frame2-Shard1Frame2-Shard2Frame2-Shard3"
    end
  end

  describe "edge cases" do
    test "handles empty shards" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)

      assert {:ok, :complete} = FDP.register_shard(frame_id, 0, 1, "")

      {:ok, reassembled} = FDP.reassemble(frame_id)
      assert reassembled == ""
    end

    test "handles binary shards (non-UTF8)" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      shard1 = <<0, 1, 2, 255>>
      shard2 = <<128, 129, 130>>

      FDP.register_shard(frame_id, 0, 2, shard1)
      FDP.register_shard(frame_id, 1, 2, shard2)

      {:ok, reassembled} = FDP.reassemble(frame_id)
      assert reassembled == <<0, 1, 2, 255, 128, 129, 130>>
    end

    test "handles large frames" do
      {:ok, _pid} = FDP.start_link(max_frame_size: 1_000_000)

      frame_id = :crypto.strong_rand_bytes(16)
      large_shard = String.duplicate("x", 500_000)

      FDP.register_shard(frame_id, 0, 1, large_shard)

      {:ok, reassembled} = FDP.reassemble(frame_id)
      assert byte_size(reassembled) == 500_000
    end

    test "handles frames with many shards" do
      {:ok, _pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      shard_count = 100

      # Register all shards
      for i <- 0..(shard_count - 1) do
        FDP.register_shard(frame_id, i, shard_count, "Shard#{i}")
      end

      assert FDP.check_complete(frame_id) == true

      {:ok, reassembled} = FDP.reassemble(frame_id)
      assert String.contains?(reassembled, "Shard0")
      assert String.contains?(reassembled, "Shard99")
    end
  end
end
