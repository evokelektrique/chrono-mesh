defmodule ChronoMesh.PDQTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{PDQ, Pulse}

  @test_disk_path "test_data/pdq"

  setup do
    # Clean up test directory
    File.rm_rf(@test_disk_path)

    # Clean up any existing PDQ process
    case GenServer.whereis(PDQ) do
      nil ->
        :ok

      pid ->
        try do
          GenServer.stop(pid, :normal, 5000)
          # Wait a bit to ensure process fully terminates
          Process.sleep(50)
        rescue
          ArgumentError -> :ok
        end
    end

    # Clean up ETS table if it exists
    try do
      case :ets.whereis(:pdq_metadata) do
        :undefined -> :ok
        _tid -> :ets.delete(:pdq_metadata)
      end
    rescue
      ArgumentError -> :ok
    end

    on_exit(fn ->
      # Clean up test directory
      File.rm_rf(@test_disk_path)

      # Clean up PDQ process
      case GenServer.whereis(PDQ) do
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

      # Clean up ETS table
      try do
        case :ets.whereis(:pdq_metadata) do
          :undefined -> :ok
          _tid -> :ets.delete(:pdq_metadata)
        end
      rescue
        ArgumentError -> :ok
      end
    end)

    :ok
  end

  describe "start_link/1" do
    test "starts PDQ with default options" do
      {:ok, pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)
      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "starts PDQ with custom disk path" do
      custom_path = Path.join(@test_disk_path, "custom")
      {:ok, pid} = PDQ.start_link(disk_path: custom_path, encryption_enabled: false)
      assert Process.alive?(pid)
      assert File.exists?(custom_path)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "starts PDQ with encryption enabled" do
      {:ok, pid} =
        PDQ.start_link(
          disk_path: @test_disk_path,
          encryption_enabled: true,
          encryption_key: :crypto.strong_rand_bytes(32)
        )

      assert Process.alive?(pid)

      try do
        GenServer.stop(pid)
      rescue
        ArgumentError -> :ok
      end
    end

    test "creates necessary directories on startup" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)
      assert File.exists?(@test_disk_path)
      assert File.exists?(Path.join(@test_disk_path, "waves"))
      assert File.exists?(Path.join(@test_disk_path, "metadata"))
    end
  end

  describe "write_wave/3" do
    test "writes pulses to disk" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12345
      frame_id = :crypto.strong_rand_bytes(16)
      pulse = create_test_pulse(frame_id)
      next_node_id = :crypto.strong_rand_bytes(32)

      assert :ok = PDQ.write_wave(wave_id, [{pulse, next_node_id}])

      # Verify file was created
      wave_dir = Path.join([@test_disk_path, "waves", "wave_#{wave_id}"])
      assert File.exists?(wave_dir)

      filename = "frame_#{Base.encode16(frame_id, case: :lower)}.pulse"
      filepath = Path.join(wave_dir, filename)
      assert File.exists?(filepath)
    end

    test "writes multiple pulses for a wave" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12346

      pulses =
        for _i <- 1..5 do
          frame_id = :crypto.strong_rand_bytes(16)
          pulse = create_test_pulse(frame_id)
          next_node_id = :crypto.strong_rand_bytes(32)
          {pulse, next_node_id}
        end

      assert :ok = PDQ.write_wave(wave_id, pulses)

      # Verify all files were created
      wave_dir = Path.join([@test_disk_path, "waves", "wave_#{wave_id}"])
      files = File.ls!(wave_dir) |> Enum.filter(&String.ends_with?(&1, ".pulse"))
      assert length(files) == 5
    end

    test "writes empty wave list" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12347
      assert :ok = PDQ.write_wave(wave_id, [])
    end

    test "writes encrypted pulses when encryption enabled" do
      encryption_key = :crypto.strong_rand_bytes(32)

      {:ok, _pid} =
        PDQ.start_link(
          disk_path: @test_disk_path,
          encryption_enabled: true,
          encryption_key: encryption_key
        )

      wave_id = 12348
      frame_id = :crypto.strong_rand_bytes(16)
      pulse = create_test_pulse(frame_id)
      next_node_id = :crypto.strong_rand_bytes(32)

      assert :ok = PDQ.write_wave(wave_id, [{pulse, next_node_id}])

      # Verify file was created (encrypted)
      wave_dir = Path.join([@test_disk_path, "waves", "wave_#{wave_id}"])
      filename = "frame_#{Base.encode16(frame_id, case: :lower)}.pulse"
      filepath = Path.join(wave_dir, filename)
      assert File.exists?(filepath)

      # Verify file is encrypted (not plain Erlang term)
      data = File.read!(filepath)
      # Encrypted data should start with auth_tag (16 bytes)
      assert byte_size(data) >= 16
    end
  end

  describe "load_wave/1" do
    test "loads pulses from disk" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12349
      frame_id = :crypto.strong_rand_bytes(16)
      pulse = create_test_pulse(frame_id)
      next_node_id = :crypto.strong_rand_bytes(32)

      # Write first
      assert :ok = PDQ.write_wave(wave_id, [{pulse, next_node_id}])

      # Load
      assert {:ok, loaded_pulses} = PDQ.load_wave(wave_id)
      assert length(loaded_pulses) == 1

      {loaded_pulse, loaded_next_node_id} = List.first(loaded_pulses)
      assert loaded_pulse.frame_id == pulse.frame_id
      assert loaded_next_node_id == next_node_id
    end

    test "loads multiple pulses from disk" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12350

      pulses =
        for _i <- 1..3 do
          frame_id = :crypto.strong_rand_bytes(16)
          pulse = create_test_pulse(frame_id)
          next_node_id = :crypto.strong_rand_bytes(32)
          {pulse, next_node_id}
        end

      # Write
      assert :ok = PDQ.write_wave(wave_id, pulses)

      # Load
      assert {:ok, loaded_pulses} = PDQ.load_wave(wave_id)
      assert length(loaded_pulses) == 3

      # Verify all pulses are loaded correctly
      loaded_frame_ids = Enum.map(loaded_pulses, fn {p, _} -> p.frame_id end)
      original_frame_ids = Enum.map(pulses, fn {p, _} -> p.frame_id end)
      assert Enum.sort(loaded_frame_ids) == Enum.sort(original_frame_ids)
    end

    test "returns empty list for non-existent wave" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 99999
      assert {:ok, []} = PDQ.load_wave(wave_id)
    end

    test "loads encrypted pulses when encryption enabled" do
      encryption_key = :crypto.strong_rand_bytes(32)

      {:ok, _pid} =
        PDQ.start_link(
          disk_path: @test_disk_path,
          encryption_enabled: true,
          encryption_key: encryption_key
        )

      wave_id = 12351
      frame_id = :crypto.strong_rand_bytes(16)
      pulse = create_test_pulse(frame_id)
      next_node_id = :crypto.strong_rand_bytes(32)

      # Write encrypted
      assert :ok = PDQ.write_wave(wave_id, [{pulse, next_node_id}])

      # Load and decrypt
      assert {:ok, loaded_pulses} = PDQ.load_wave(wave_id)
      assert length(loaded_pulses) == 1

      {loaded_pulse, loaded_next_node_id} = List.first(loaded_pulses)
      assert loaded_pulse.frame_id == pulse.frame_id
      assert loaded_next_node_id == next_node_id
    end
  end

  describe "delete_wave/1" do
    test "deletes wave directory and files" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12352
      frame_id = :crypto.strong_rand_bytes(16)
      pulse = create_test_pulse(frame_id)
      next_node_id = :crypto.strong_rand_bytes(32)

      # Write
      assert :ok = PDQ.write_wave(wave_id, [{pulse, next_node_id}])

      # Verify exists
      wave_dir = Path.join([@test_disk_path, "waves", "wave_#{wave_id}"])
      assert File.exists?(wave_dir)

      # Delete
      assert :ok = PDQ.delete_wave(wave_id)

      # Verify deleted
      refute File.exists?(wave_dir)
    end

    test "deletes non-existent wave without error" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 99998
      assert :ok = PDQ.delete_wave(wave_id)
    end
  end

  describe "recover_all_waves/0" do
    test "recovers all waves from disk" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      # Write multiple waves
      wave_ids = [12353, 12354, 12355]

      for wave_id <- wave_ids do
        frame_id = :crypto.strong_rand_bytes(16)
        pulse = create_test_pulse(frame_id)
        next_node_id = :crypto.strong_rand_bytes(32)
        assert :ok = PDQ.write_wave(wave_id, [{pulse, next_node_id}])
      end

      # Recover
      assert {:ok, waves} = PDQ.recover_all_waves()
      assert map_size(waves) == 3

      # Verify all waves are present
      for wave_id <- wave_ids do
        assert Map.has_key?(waves, wave_id)
        assert length(waves[wave_id]) == 1
      end
    end

    test "returns empty map when no waves exist" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      assert {:ok, waves} = PDQ.recover_all_waves()
      assert waves == %{}
    end
  end

  describe "disk_path/0" do
    test "returns configured disk path" do
      custom_path = Path.join(@test_disk_path, "custom_path")

      {:ok, _pid} = PDQ.start_link(disk_path: custom_path, encryption_enabled: false)

      assert PDQ.disk_path() == custom_path
    end
  end

  describe "error handling" do
    test "handles corrupted pulse files gracefully" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12356
      wave_dir = Path.join([@test_disk_path, "waves", "wave_#{wave_id}"])
      File.mkdir_p!(wave_dir)

      # Create a corrupted file
      corrupted_file = Path.join(wave_dir, "frame_1234567890abcdef.pulse")
      File.write!(corrupted_file, "corrupted data")

      # Should handle gracefully (skip corrupted files)
      result = PDQ.load_wave(wave_id)
      # Should either return empty list or error
      assert match?({:ok, []}, result) or match?({:error, _}, result)
    end

    test "handles invalid frame_id in filename" do
      {:ok, _pid} = PDQ.start_link(disk_path: @test_disk_path, encryption_enabled: false)

      wave_id = 12357
      wave_dir = Path.join([@test_disk_path, "waves", "wave_#{wave_id}"])
      File.mkdir_p!(wave_dir)

      # Create file with invalid frame_id (corrupted filename)
      invalid_file = Path.join(wave_dir, "frame_invalid.pulse")
      # Write invalid data that won't match the filename
      pulse = create_test_pulse(:crypto.strong_rand_bytes(16))
      File.write!(invalid_file, :erlang.term_to_binary({pulse, <<>>}))

      # Should handle gracefully
      result = PDQ.load_wave(wave_id)
      assert match?({:ok, []}, result) or match?({:error, _}, result)
    end

    test "handles decryption failures gracefully" do
      encryption_key = :crypto.strong_rand_bytes(32)

      {:ok, _pid} =
        PDQ.start_link(
          disk_path: @test_disk_path,
          encryption_enabled: true,
          encryption_key: encryption_key
        )

      wave_id = 12358
      wave_dir = Path.join([@test_disk_path, "waves", "wave_#{wave_id}"])
      File.mkdir_p!(wave_dir)

      # Create file with wrong encryption
      wrong_key = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      pulse = create_test_pulse(frame_id)
      next_node_id = :crypto.strong_rand_bytes(32)
      data = :erlang.term_to_binary({pulse, next_node_id})

      # Encrypt with wrong key
      nonce_material = wrong_key <> frame_id <> "pdq"
      key = derive_key(nonce_material, "key", 32)
      nonce = derive_key(nonce_material, "nonce", 12)
      associated_data = frame_id

      {ciphertext, auth_tag} =
        :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, data, associated_data, true)

      encrypted_data = <<auth_tag::binary-size(16), ciphertext::binary>>
      filename = "frame_#{Base.encode16(frame_id, case: :lower)}.pulse"
      filepath = Path.join(wave_dir, filename)
      File.write!(filepath, encrypted_data)

      # Should handle gracefully (skip un-decryptable files)
      result = PDQ.load_wave(wave_id)
      assert match?({:ok, []}, result) or match?({:error, _}, result)
    end
  end

  # Helper functions

  defp create_test_pulse(frame_id) do
    %Pulse{
      frame_id: frame_id,
      shard_index: 0,
      shard_count: 1,
      token_chain: [],
      payload: "test payload",
      auth_tag: :crypto.strong_rand_bytes(16),
      fec_enabled: false,
      parity_count: 0,
      data_shard_count: 0
    }
  end

  defp derive_key(material, salt, size) do
    hashed = :crypto.hash(:sha256, material <> salt)
    binary_part(hashed, 0, size)
  end
end
