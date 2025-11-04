defmodule ChronoMesh.PFPTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{Keys, PFP, Node, ControlServer}

  setup do
    # Only clean up in on_exit to avoid interfering with tests
    on_exit(fn ->
      # Clean up after test - use exit to avoid blocking
      cleanup_process = fn name ->
        case GenServer.whereis(name) do
          nil -> :ok
          pid ->
            if Process.alive?(pid) do
              ref = Process.monitor(pid)
              Process.exit(pid, :normal)
              receive do
                {:DOWN, ^ref, :process, ^pid, _reason} -> :ok
              after
                200 ->
                  if Process.alive?(pid) do
                    Process.exit(pid, :kill)
                    receive do
                      {:DOWN, ^ref, :process, ^pid, _reason} -> :ok
                    after
                      100 -> :ok
                    end
                  else
                    :ok
                  end
              end
            else
              :ok
            end
        end
      end

      cleanup_process.(Node)
      cleanup_process.(ControlServer)
      Process.sleep(50)
    end)

    :ok
  end

  describe "detect_failure/4" do
    test "composes a valid failure notice" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :connection_error
      {private_key, _public_key} = Keys.generate()
      {_ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      assert is_map(failure_notice)
      assert failure_notice.frame_id == frame_id
      assert failure_notice.failed_node_id == failed_node_id
      assert failure_notice.failure_type == failure_type
      assert is_integer(failure_notice.timestamp)
      assert is_binary(failure_notice.signature)
      assert byte_size(failure_notice.signature) > 0
    end

    test "generates timestamp in failure notice" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :timeout
      {private_key, _public_key} = Keys.generate()
      {_ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      assert is_integer(failure_notice.timestamp)
      assert failure_notice.timestamp > 0
    end

    test "generates signature in failure notice" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :connection_error
      {private_key, _public_key} = Keys.generate()
      {_ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      assert is_binary(failure_notice.signature)
      assert byte_size(failure_notice.signature) == 64
    end
  end

  describe "verify_failure_notice/2" do
    test "verifies a valid Ed25519 failure notice" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :connection_error
      {private_key, public_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      assert PFP.verify_failure_notice(failure_notice, public_key,
               ed25519_public_key: ed25519_public_key
             ) == true
    end

    test "rejects invalid Ed25519 signature" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :timeout
      {private_key, public_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      # Tamper with signature
      tampered_notice = %{failure_notice | signature: :crypto.strong_rand_bytes(64)}

      assert PFP.verify_failure_notice(tampered_notice, public_key,
               ed25519_public_key: ed25519_public_key
             ) == false
    end
  end

  describe "handle_failure_notice/2" do
    test "accepts a valid Ed25519 failure notice" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :timeout
      {private_key, public_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      assert PFP.handle_failure_notice(failure_notice, public_key,
               ed25519_public_key: ed25519_public_key
             ) == :ok
    end

    test "rejects invalid Ed25519 signature" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :connection_error
      {private_key, public_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      # Tamper with signature
      tampered_notice = %{failure_notice | signature: :crypto.strong_rand_bytes(64)}

      assert PFP.handle_failure_notice(tampered_notice, public_key,
               ed25519_public_key: ed25519_public_key
             ) == {:error, :invalid_signature}
    end
  end

  describe "reroute_path/3" do
    test "generates alternative path avoiding failed node" do
      node1 = :crypto.strong_rand_bytes(32)
      node2 = :crypto.strong_rand_bytes(32)
      node3 = :crypto.strong_rand_bytes(32)
      failed_path = [node1, node2, node3]

      failed_node_id = node2

      available_peers = [
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      ]

      assert {:ok, new_path} = PFP.reroute_path(failed_path, failed_node_id, available_peers)

      # New path replaces everything after the failed node
      # Original path: [node1, node2, node3] (length 3)
      # Valid prefix: [node1] (length 1)
      # Remaining path: [node3] (length 1)
      # New path: [node1] ++ [new_node] = length 2
      assert length(new_path) == 2

      # Failed node should not be in new path
      assert failed_node_id not in new_path

      # Nodes before failure point should be preserved
      assert Enum.at(new_path, 0) == node1
    end

    test "returns error if failed node not in path" do
      failed_path = [
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      ]

      failed_node_id = :crypto.strong_rand_bytes(32)
      available_peers = [:crypto.strong_rand_bytes(32)]

      assert PFP.reroute_path(failed_path, failed_node_id, available_peers) ==
               {:error, :failed_node_not_in_path}
    end

    test "returns error if insufficient peers for rerouting" do
      failed_path = [
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      ]

      failed_node_id = Enum.at(failed_path, 1)

      # Only 1 peer available, but need 2 for remaining path
      available_peers = [:crypto.strong_rand_bytes(32)]

      assert PFP.reroute_path(failed_path, failed_node_id, available_peers) ==
               {:error, :insufficient_peers}
    end

    test "preserves valid prefix of failed path" do
      node1 = :crypto.strong_rand_bytes(32)
      node2 = :crypto.strong_rand_bytes(32)
      node3 = :crypto.strong_rand_bytes(32)
      node4 = :crypto.strong_rand_bytes(32)

      failed_path = [node1, node2, node3, node4]
      failed_node_id = node2

      available_peers = [
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      ]

      assert {:ok, new_path} = PFP.reroute_path(failed_path, failed_node_id, available_peers)

      # First node should be preserved
      assert Enum.at(new_path, 0) == node1

      # Failed node should not be in path
      assert node2 not in new_path
    end

    test "does not reuse nodes from failed path in new path" do
      failed_path = [
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      ]

      failed_node_id = Enum.at(failed_path, 1)

      available_peers = [
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      ]

      assert {:ok, new_path} = PFP.reroute_path(failed_path, failed_node_id, available_peers)

      # New path suffix should not contain any nodes from failed path
      # (except the preserved prefix)
      new_suffix = Enum.drop(new_path, 1)
      failed_path_tail = Enum.drop(failed_path, 1)

      assert Enum.count(new_suffix, &(&1 in failed_path_tail)) == 0
    end
  end

  describe "send_failure_notice/3" do
    test "sends failure notice when node is running" do
      # Create a temporary private key file
      tmp_dir = System.tmp_dir!()
      key_path = Path.join(tmp_dir, "test_private_key_#{System.unique_integer([:positive])}.pem")
      {private_key, _public_key} = Keys.generate()
      Keys.write_private_key!(key_path, private_key)

      {ed25519_private_key_for_node, _ed25519_public_key_for_node} = Keys.keypair()
      ed25519_key_path = Path.join(tmp_dir, "test_ed25519_private_key_#{System.unique_integer([:positive])}.pem")
      Keys.write_private_key!(ed25519_key_path, ed25519_private_key_for_node)

      # Use a unique port to avoid conflicts
      unique_port = 4000 + :rand.uniform(1000)

      # Start a node process
      config = %{
        "network" => %{
          "listen_host" => "127.0.0.1",
          "listen_port" => unique_port,
          "wave_duration_secs" => 10
        },
        "identity" => %{
          "private_key_path" => key_path,
          "ed25519_private_key_path" => ed25519_key_path
        }
      }

      # Retry if port is in use
      case ChronoMesh.Node.start_link(config) do
        {:ok, _node_pid} ->
          :ok

        {:error, {:already_started, existing_pid}} ->
          GenServer.stop(existing_pid, :normal, 5000)
          Process.sleep(100)
          {:ok, _node_pid} = ChronoMesh.Node.start_link(config)

        {:error, {:stop, :eaddrinuse}} ->
          # Port conflict - try another port
          unique_port2 = unique_port + 1
          config2 = put_in(config, ["network", "listen_port"], unique_port2)

          case ChronoMesh.Node.start_link(config2) do
            {:ok, _node_pid} -> :ok
            other -> raise "Failed to start node even with different port: #{inspect(other)}"
          end

        {:error, reason} ->
          raise "Failed to start node: #{inspect(reason)}"
      end

      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :timeout

      {_ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )
      path = [:crypto.strong_rand_bytes(32)]

      assert PFP.send_failure_notice(failure_notice, path, config) == :ok

      # File cleanup only - process cleanup handled by on_exit
      File.rm(key_path)
      File.rm(ed25519_key_path)
    end

    test "returns error when node is not running" do
      # Ensure node is stopped
      case GenServer.whereis(ChronoMesh.Node) do
        nil -> :ok
        pid -> GenServer.stop(pid)
      end

      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :connection_error
      {private_key, _public_key} = Keys.generate()

      {_ed25519_public_key, ed25519_private_key} = Keys.keypair()

      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )
      path = [:crypto.strong_rand_bytes(32)]

      assert PFP.send_failure_notice(failure_notice, path, %{}) == {:error, :node_not_running}
    end
  end

  describe "integration: failure detection and rerouting" do
    test "end-to-end failure detection and path rerouting" do
      frame_id = :crypto.strong_rand_bytes(16)
      failed_node_id = :crypto.strong_rand_bytes(32)
      failure_type = :timeout
      {private_key, public_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()

      # Detect failure (Ed25519)
      failure_notice =
        PFP.detect_failure(
          frame_id,
          failed_node_id,
          failure_type,
          private_key,
          ed25519_private_key: ed25519_private_key
        )

      # Verify failure notice
      assert PFP.verify_failure_notice(failure_notice, public_key,
               ed25519_public_key: ed25519_public_key
             ) == true

      # Handle failure notice
      assert PFP.handle_failure_notice(failure_notice, public_key,
               ed25519_public_key: ed25519_public_key
             ) == :ok

      # Reroute path
      node1 = :crypto.strong_rand_bytes(32)
      node3 = :crypto.strong_rand_bytes(32)
      failed_path = [node1, failed_node_id, node3]

      available_peers = [
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(32)
      ]

      assert {:ok, new_path} = PFP.reroute_path(failed_path, failed_node_id, available_peers)

      # Verify new path doesn't include failed node
      assert failed_node_id not in new_path

      # Verify preserved prefix (first node before failure)
      assert Enum.at(new_path, 0) == node1

      # New path replaces everything after the failed node
      # Original path: [node1, failed_node_id, node3] (length 3)
      # Valid prefix: [node1] (length 1)
      # Remaining path: [node3] (length 1)
      # New path: [node1] ++ [new_node] = length 2
      assert length(new_path) == 2
    end
  end
end
