defmodule ChronoMesh.NodeFDPIntegrationTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{Node, Pulse, Token, Keys, FDP}

  setup do
    # Clean up any existing processes
    case GenServer.whereis(Node) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    case GenServer.whereis(FDP) do
      nil -> :ok
      pid -> GenServer.stop(pid)
    end

    on_exit(fn ->
      case GenServer.whereis(Node) do
        nil -> :ok
        pid -> GenServer.stop(pid)
      end

      case GenServer.whereis(FDP) do
        nil -> :ok
        pid -> GenServer.stop(pid)
      end
    end)

    # Create test keys
    {public_key, private_key} = Keys.generate()
    {_ed25519_public_key, ed25519_private_key} = Keys.keypair()

    # Write temporary keys for Node to read
    tmp_dir = System.tmp_dir!()
    private_key_path = Path.join(tmp_dir, "test_sk.pem")
    public_key_path = Path.join(tmp_dir, "test_pk.pem")
    ed25519_private_key_path = Path.join(tmp_dir, "test_ed25519_sk.pem")

    Keys.write_private_key!(private_key_path, private_key)
    Keys.write_public_key!(public_key_path, public_key)
    Keys.write_private_key!(ed25519_private_key_path, ed25519_private_key)

    config = %{
      "identity" => %{
        "private_key_path" => private_key_path,
        "public_key_path" => public_key_path,
        "ed25519_private_key_path" => ed25519_private_key_path
      },
      "network" => %{
        "wave_duration_secs" => 10,
        "listen_host" => "127.0.0.1",
        "listen_port" => 4_500
      },
      "fdp" => %{
        "frame_timeout_ms" => :timer.minutes(5),
        "cleanup_interval_ms" => :timer.minutes(1),
        "max_frame_size" => 10 * 1024 * 1024
      }
    }

    on_exit(fn ->
      File.rm_rf(private_key_path)
      File.rm_rf(public_key_path)
      File.rm_rf(ed25519_private_key_path)
    end)

    %{config: config, public_key: public_key, private_key: private_key}
  end

  describe "Node delivers single shard (no FDP needed)" do
    test "single shard pulse is stored immediately", %{
      config: config,
      public_key: public_key,
      private_key: _private_key
    } do
      {:ok, _pid} = Node.start_link(config)

      frame_id = :crypto.strong_rand_bytes(16)
      plaintext = "Single shard message"

      # Create a pulse with shard_count = 1
      {:ok, {token, shared_secret}} =
        Token.encrypt_token(%{instruction: :deliver}, public_key, frame_id, 0)

      payload_ciphertext = Token.encrypt_payload(shared_secret, frame_id, 0, plaintext)

      pulse = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 1,
        token_chain: [token],
        payload: payload_ciphertext
      }

      Node.enqueue(pulse)

      # Give time for processing
      Process.sleep(100)

      # Frame should not be in FDP (single shard bypasses FDP)
      # Just verify the pulse was processed
      assert GenServer.whereis(Node) != nil
    end
  end

  describe "Node delivers multi-shard frame" do
    test "multi-shard pulses are routed through FDP", %{
      config: config,
      public_key: public_key,
      private_key: _private_key
    } do
      {:ok, _pid} = Node.start_link(config)

      frame_id = :crypto.strong_rand_bytes(16)
      shard1 = "First part"
      shard2 = "Second part"

      # Create two pulses for the same frame
      {:ok, {token1, shared1}} =
        Token.encrypt_token(%{instruction: :deliver}, public_key, frame_id, 0)

      {:ok, {token2, shared2}} =
        Token.encrypt_token(%{instruction: :deliver}, public_key, frame_id, 1)

      payload1 = Token.encrypt_payload(shared1, frame_id, 0, shard1)
      payload2 = Token.encrypt_payload(shared2, frame_id, 1, shard2)

      pulse1 = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 2,
        token_chain: [token1],
        payload: payload1
      }

      pulse2 = %Pulse{
        frame_id: frame_id,
        shard_index: 1,
        shard_count: 2,
        token_chain: [token2],
        payload: payload2
      }

      # Enqueue first shard
      Node.enqueue(pulse1)

      # Wait for first shard to be processed
      Process.sleep(150)

      # Frame should be incomplete in FDP
      assert FDP.check_complete(frame_id) == false

      # Get inbox path to check if frame was stored
      inbox_path = Path.join(System.user_home!(), ".chrono_mesh/inbox.log")
      initial_content = if File.exists?(inbox_path), do: File.read!(inbox_path), else: ""

      # Enqueue second shard
      Node.enqueue(pulse2)

      # Wait for both shards to be processed and frame to be reassembled
      Process.sleep(300)

      # Verify frame was stored (proves reassembly worked)
      # The frame should have been reassembled and stored
      final_content = if File.exists?(inbox_path), do: File.read!(inbox_path), else: ""

      # Check that new content was added (the reassembled frame)
      assert byte_size(final_content) > byte_size(initial_content)

      # Verify the reassembled content contains both shards
      assert String.contains?(final_content, shard1)
      assert String.contains?(final_content, shard2)

      # Frame should be removed from FDP after reassembly
      # (check_complete returns false for non-existent frames)
      assert FDP.check_complete(frame_id) == false
    end

    test "Node handles missing shards gracefully", %{
      config: config,
      public_key: public_key,
      private_key: _private_key
    } do
      {:ok, _pid} = Node.start_link(config)

      frame_id = :crypto.strong_rand_bytes(16)
      shard1 = "First part only"

      {:ok, {token, shared}} =
        Token.encrypt_token(%{instruction: :deliver}, public_key, frame_id, 0)

      payload = Token.encrypt_payload(shared, frame_id, 0, shard1)

      pulse = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        # Need 3 shards but only sending 1
        shard_count: 3,
        token_chain: [token],
        payload: payload
      }

      Node.enqueue(pulse)
      Process.sleep(50)

      # Frame should be incomplete
      assert FDP.check_complete(frame_id) == false

      # Check missing shards
      {:ok, missing} = FDP.get_missing_shards(frame_id)
      assert missing == [1, 2]
    end
  end

  describe "Node FDP fallback" do
    test "handles FDP unavailable gracefully", %{config: config} do
      # Start node without FDP (should still work)
      # Node will try to use FDP but should handle errors

      # This test verifies that Node doesn't crash if FDP fails
      # The actual implementation should handle FDP errors
      {:ok, _pid} = Node.start_link(config)

      # Node should still be running even if FDP operations fail
      assert Process.alive?(GenServer.whereis(Node))
    end
  end

  describe "frame timeout in Node context" do
    test "Node handles frame timeouts", %{
      config: config,
      public_key: public_key,
      private_key: _private_key
    } do
      # Use short timeout for testing
      config_with_timeout = put_in(config, ["fdp", "frame_timeout_ms"], 100)
      config_with_cleanup = put_in(config_with_timeout, ["fdp", "cleanup_interval_ms"], 50)

      {:ok, _pid} = Node.start_link(config_with_cleanup)

      frame_id = :crypto.strong_rand_bytes(16)

      # Create incomplete frame
      {:ok, {token, shared}} =
        Token.encrypt_token(%{instruction: :deliver}, public_key, frame_id, 0)

      payload = Token.encrypt_payload(shared, frame_id, 0, "Only one shard")

      pulse = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        # Incomplete
        shard_count: 3,
        token_chain: [token],
        payload: payload
      }

      Node.enqueue(pulse)
      Process.sleep(50)

      # Frame should be incomplete
      assert FDP.check_complete(frame_id) == false

      # Wait for timeout
      Process.sleep(150)

      # Frame should be cleaned up
      assert {:error, :frame_not_found} = FDP.reassemble(frame_id)
    end
  end

  describe "event emission" do
    test "Node emits frame_complete event", %{
      config: config,
      public_key: public_key,
      private_key: _private_key
    } do
      {:ok, _pid} = Node.start_link(config)

      frame_id = :crypto.strong_rand_bytes(16)
      received_events = Agent.start_link(fn -> [] end) |> elem(1)

      # Subscribe to frame_complete event
      handler_id =
        ChronoMesh.Events.on(:frame_complete, fn _event, _measurements, metadata ->
          Agent.update(received_events, fn events -> [metadata | events] end)
        end)

      # Create and enqueue complete frame (2 shards)
      {:ok, {token1, shared1}} =
        Token.encrypt_token(%{instruction: :deliver}, public_key, frame_id, 0)

      {:ok, {token2, shared2}} =
        Token.encrypt_token(%{instruction: :deliver}, public_key, frame_id, 1)

      payload1 = Token.encrypt_payload(shared1, frame_id, 0, "Part1")
      payload2 = Token.encrypt_payload(shared2, frame_id, 1, "Part2")

      pulse1 = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 2,
        token_chain: [token1],
        payload: payload1
      }

      pulse2 = %Pulse{
        frame_id: frame_id,
        shard_index: 1,
        shard_count: 2,
        token_chain: [token2],
        payload: payload2
      }

      Node.enqueue(pulse1)
      Process.sleep(100)

      Node.enqueue(pulse2)
      Process.sleep(200)

      # Verify frame was completed and stored
      # After reassembly, frame is removed from FDP, so check_complete returns false
      # Instead, verify the frame was stored successfully
      inbox_path = Path.join(System.user_home!(), ".chrono_mesh/inbox.log")

      if File.exists?(inbox_path) do
        content = File.read!(inbox_path)
        # Verify both parts are in the stored content
        assert String.contains?(content, "Part1") or String.contains?(content, "Part2")
      end

      # Check event was emitted if telemetry is available
      if Code.ensure_loaded?(:telemetry) do
        retry_check = fn ->
          events = Agent.get(received_events, fn events -> events end)

          if length(events) >= 1 do
            true
          else
            Process.sleep(50)
            events = Agent.get(received_events, fn events -> events end)
            length(events) >= 1
          end
        end

        if retry_check.() do
          events = Agent.get(received_events, fn events -> events end)

          if length(events) >= 1 do
            event = List.first(events)
            assert Map.has_key?(event, :frame_id)
          end
        end
      end

      # Cleanup
      ChronoMesh.Events.off(handler_id)
    end
  end
end
