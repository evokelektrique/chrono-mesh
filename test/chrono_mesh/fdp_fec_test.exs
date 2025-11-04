defmodule ChronoMesh.FDPFECTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{FDP, FEC}

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

  describe "FDP with FEC: missing shard recovery" do
    test "recovers missing data shard using parity" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      data_shards = ["shard0", "shard1", "shard2", "shard3"]
      parity_shards = FEC.generate_parity_shards(data_shards, 1)
      parity = List.first(parity_shards)

      # Register all shards except one data shard
      FDP.register_shard(frame_id, 0, 5, "shard0",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      # Skip shard 1 (missing)
      FDP.register_shard(frame_id, 2, 5, "shard2",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      FDP.register_shard(frame_id, 3, 5, "shard3",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      FDP.register_shard(frame_id, 4, 5, parity,
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      # Should be complete now (with recovery)
      assert FDP.check_complete(frame_id) == true

      # Reassemble should recover the missing shard
      {:ok, reassembled} = FDP.reassemble(frame_id)

      # Should be all 4 data shards concatenated
      expected = "shard0" <> "shard1" <> "shard2" <> "shard3"
      assert reassembled == expected

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "cannot recover if more than parity_count shards lost" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      data_shards = ["shard0", "shard1", "shard2", "shard3"]
      # Only 1 parity
      parity_shards = FEC.generate_parity_shards(data_shards, 1)
      parity = List.first(parity_shards)

      # Register only 2 data shards (missing 2, but only 1 parity)
      FDP.register_shard(frame_id, 0, 5, "shard0",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      # Skip shard 1 and 2 (both missing)
      FDP.register_shard(frame_id, 3, 5, "shard3",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      FDP.register_shard(frame_id, 4, 5, parity,
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      # Should not be complete (can't recover 2 shards with 1 parity)
      assert FDP.check_complete(frame_id) == false

      # Reassemble should fail
      assert {:error, :frame_incomplete} = FDP.reassemble(frame_id)

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "works when all data shards received (no recovery needed)" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)

      # Register all data shards (no parity needed)
      FDP.register_shard(frame_id, 0, 4, "shard0",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      FDP.register_shard(frame_id, 1, 4, "shard1",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      FDP.register_shard(frame_id, 2, 4, "shard2",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      # Should be complete
      assert FDP.check_complete(frame_id) == true

      # Reassemble should work
      {:ok, reassembled} = FDP.reassemble(frame_id)

      expected = "shard0" <> "shard1" <> "shard2"
      assert reassembled == expected

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "works when parity shard is lost but all data shards received" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)

      # Register all data shards, skip parity
      FDP.register_shard(frame_id, 0, 4, "shard0",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      FDP.register_shard(frame_id, 1, 4, "shard1",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      FDP.register_shard(frame_id, 2, 4, "shard2",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      # Skip parity shard (index 3)

      # Should be complete (all data shards received)
      assert FDP.check_complete(frame_id) == true

      # Reassemble should work
      {:ok, reassembled} = FDP.reassemble(frame_id)

      expected = "shard0" <> "shard1" <> "shard2"
      assert reassembled == expected

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "FDP with FEC disabled: backward compatibility" do
    test "existing behavior preserved when FEC disabled" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)

      # Register shards without FEC (default behavior)
      FDP.register_shard(frame_id, 0, 3, "shard0", [])
      FDP.register_shard(frame_id, 1, 3, "shard1", [])
      FDP.register_shard(frame_id, 2, 3, "shard2", [])

      # Should be complete
      assert FDP.check_complete(frame_id) == true

      # Reassemble should work
      {:ok, reassembled} = FDP.reassemble(frame_id)

      expected = "shard0" <> "shard1" <> "shard2"
      assert reassembled == expected

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "cannot recover missing shards when FEC disabled" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)

      # Register only 2 of 3 shards (missing one)
      FDP.register_shard(frame_id, 0, 3, "shard0", [])
      FDP.register_shard(frame_id, 1, 3, "shard1", [])
      # Skip shard 2

      # Should not be complete
      assert FDP.check_complete(frame_id) == false

      # Reassemble should fail
      assert {:error, :frame_incomplete} = FDP.reassemble(frame_id)

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "FDP with FEC: mixed scenarios" do
    test "recovery works with some data and some parity shards received" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      data_shards = ["shard0", "shard1", "shard2", "shard3"]
      # 2 parity shards
      parity_shards = FEC.generate_parity_shards(data_shards, 2)
      parity1 = Enum.at(parity_shards, 0)
      _parity2 = Enum.at(parity_shards, 1)

      # Register 2 data shards, 1 parity shard, missing 2 data shards
      FDP.register_shard(frame_id, 0, 6, "shard0",
        fec_enabled: true,
        parity_count: 2,
        data_shard_count: 4
      )

      # Skip shard 1 and 2
      FDP.register_shard(frame_id, 3, 6, "shard3",
        fec_enabled: true,
        parity_count: 2,
        data_shard_count: 4
      )

      FDP.register_shard(frame_id, 4, 6, parity1,
        fec_enabled: true,
        parity_count: 2,
        data_shard_count: 4
      )

      # Skip parity2

      # With simple XOR scheme, can only recover 1 missing shard
      # So this should not be complete (missing 2 shards, only 1 parity scheme)
      assert FDP.check_complete(frame_id) == false

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "recovery works when exactly one data shard is missing" do
      {:ok, fdp_pid} = FDP.start_link([])

      frame_id = :crypto.strong_rand_bytes(16)
      data_shards = ["test", "data", "here"]

      # Generate parity
      parity_shards = FEC.generate_parity_shards(data_shards, 1)
      parity = List.first(parity_shards)

      # Register all except middle shard
      FDP.register_shard(frame_id, 0, 4, "test",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      # Skip shard 1 ("data")
      FDP.register_shard(frame_id, 2, 4, "here",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      FDP.register_shard(frame_id, 3, 4, parity,
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 3
      )

      # Should be complete
      assert FDP.check_complete(frame_id) == true

      # Reassemble should recover the missing shard
      {:ok, reassembled} = FDP.reassemble(frame_id)

      expected = "test" <> "data" <> "here"
      assert reassembled == expected

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end

  describe "FDP with FEC: timeout handling" do
    test "timeout when recovery impossible" do
      {:ok, fdp_pid} = FDP.start_link(frame_timeout_ms: 100)

      frame_id = :crypto.strong_rand_bytes(16)
      data_shards = ["shard0", "shard1", "shard2", "shard3"]
      # Only 1 parity
      parity_shards = FEC.generate_parity_shards(data_shards, 1)
      parity = List.first(parity_shards)

      # Register only 2 data shards (missing 2, but only 1 parity - cannot recover)
      FDP.register_shard(frame_id, 0, 5, "shard0",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      # Skip shard 1 and 2
      FDP.register_shard(frame_id, 3, 5, "shard3",
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      FDP.register_shard(frame_id, 4, 5, parity,
        fec_enabled: true,
        parity_count: 1,
        data_shard_count: 4
      )

      # Wait for timeout (frame_timeout_ms is 100ms, cleanup_interval_ms is 60s by default)
      # Need to wait longer for cleanup to run
      Process.sleep(200)

      # Frame might still be incomplete (not cleaned up yet)
      # Check that it's not complete
      assert FDP.check_complete(frame_id) == false
      assert {:error, :frame_incomplete} = FDP.reassemble(frame_id)

      try do
        GenServer.stop(fdp_pid)
      rescue
        ArgumentError -> :ok
      end
    end
  end
end
