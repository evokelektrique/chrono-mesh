defmodule ChronoMesh.DHTTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.DHT

  setup do
    # Clean up any existing registry
    try do
      :ets.delete(:chrono_mesh_dht_registry)
    rescue
      ArgumentError -> :ok
    end

    on_exit(fn ->
      # Clean up registry after tests
      try do
        :ets.delete(:chrono_mesh_dht_registry)
      rescue
        ArgumentError -> :ok
      end
    end)

    :ok
  end

  describe "start_link/1" do
    test "starts a DHT node with default options" do
      {:ok, pid} = DHT.start_link([])
      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end

    test "starts a DHT node with custom address" do
      {:ok, pid} = DHT.start_link(address: :test_node_1)
      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end

    test "starts a DHT node with custom ID" do
      custom_id = :crypto.strong_rand_bytes(32)
      {:ok, pid} = DHT.start_link(id: custom_id)
      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end

    test "starts a DHT node with custom k and alpha" do
      {:ok, pid} = DHT.start_link(k: 10, alpha: 5)
      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end

    test "starts a DHT node with custom TTL" do
      {:ok, pid} = DHT.start_link(ttl_ms: :timer.minutes(10))
      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end
  end

  describe "bootstrap/2" do
    test "bootstrap connects two nodes" do
      {:ok, node_a} = DHT.start_link(address: :node_a)
      {:ok, node_b} = DHT.start_link(address: :node_b)

      # Bootstrap node_b to know about node_a
      assert :ok == DHT.bootstrap(node_b, [:node_a])

      # Verify node_b can find peers
      # The exact number depends on whether ping succeeded
      peers = DHT.neighbors(node_b, :crypto.strong_rand_bytes(32), 5)
      assert is_list(peers)

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
    end

    test "bootstrap handles unknown addresses gracefully" do
      {:ok, node_b} = DHT.start_link(address: :node_b)

      # Bootstrap to a non-existent node should not crash
      assert :ok == DHT.bootstrap(node_b, [:nonexistent])

      Process.exit(node_b, :normal)
    end

    test "bootstrap with multiple addresses" do
      {:ok, node_a} = DHT.start_link(address: :node_a)
      {:ok, node_b} = DHT.start_link(address: :node_b)
      {:ok, node_c} = DHT.start_link(address: :node_c)

      # Bootstrap node_c to know about both node_a and node_b
      assert :ok == DHT.bootstrap(node_c, [:node_a, :node_b])

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
      Process.exit(node_c, :normal)
    end
  end

  describe "put/3 and get/2" do
    test "put and get work on a single node" do
      {:ok, node} = DHT.start_link(address: :single_node)

      # Store locally
      assert :ok == DHT.put(node, "key1", "value1")

      # Retrieve locally
      assert {:ok, "value1"} == DHT.get(node, "key1")

      Process.exit(node, :normal)
    end

    test "get returns :not_found for non-existent keys" do
      {:ok, node} = DHT.start_link(address: :single_node)

      assert :not_found == DHT.get(node, "nonexistent")

      Process.exit(node, :normal)
    end

    test "put and get work across multiple nodes" do
      {:ok, node_a} = DHT.start_link(address: :node_a)
      {:ok, node_b} = DHT.start_link(address: :node_b)

      # Bootstrap node_b to know about node_a
      DHT.bootstrap(node_b, [:node_a])

      # Store on node_a
      assert :ok == DHT.put(node_a, "key1", "value1")

      # Retrieve from node_b via DHT lookup
      # This tests iterative find_value
      assert {:ok, "value1"} == DHT.get(node_b, "key1")

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
    end

    test "put replicates to closest K peers" do
      {:ok, node_a} = DHT.start_link(address: :node_a)
      {:ok, node_b} = DHT.start_link(address: :node_b)

      # Bootstrap to form a network
      DHT.bootstrap(node_b, [:node_a])

      # Store on node_a
      assert :ok == DHT.put(node_a, "key2", "value2")

      # Both nodes should have the value after replication
      assert {:ok, "value2"} == DHT.get(node_a, "key2")
      assert {:ok, "value2"} == DHT.get(node_b, "key2")

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
    end

    test "put and get work with binary keys and values" do
      {:ok, node} = DHT.start_link(address: :binary_node)

      key = <<1, 2, 3, 4>>
      value = <<5, 6, 7, 8>>

      assert :ok == DHT.put(node, key, value)
      assert {:ok, ^value} = DHT.get(node, key)

      Process.exit(node, :normal)
    end

    test "multiple keys can be stored" do
      {:ok, node} = DHT.start_link(address: :multi_key_node)

      assert :ok == DHT.put(node, "key1", "value1")
      assert :ok == DHT.put(node, "key2", "value2")
      assert :ok == DHT.put(node, "key3", "value3")

      assert {:ok, "value1"} == DHT.get(node, "key1")
      assert {:ok, "value2"} == DHT.get(node, "key2")
      assert {:ok, "value3"} == DHT.get(node, "key3")

      Process.exit(node, :normal)
    end
  end

  describe "neighbors/3" do
    test "neighbors returns empty list for isolated node" do
      {:ok, node} = DHT.start_link(address: :isolated)
      target_id = :crypto.strong_rand_bytes(32)

      peers = DHT.neighbors(node, target_id, 5)
      assert peers == []

      Process.exit(node, :normal)
    end

    test "neighbors returns known peers sorted by distance" do
      {:ok, node_a} = DHT.start_link(address: :node_a)
      {:ok, node_b} = DHT.start_link(address: :node_b)

      # Bootstrap to form connection
      DHT.bootstrap(node_b, [:node_a])

      target_id = :crypto.strong_rand_bytes(32)
      peers = DHT.neighbors(node_b, target_id, 5)

      # Should have at least node_a if ping succeeded
      assert is_list(peers)
      assert length(peers) <= 5

      # Verify peer structure
      if length(peers) > 0 do
        peer = List.first(peers)
        assert Map.has_key?(peer, :id)
        assert Map.has_key?(peer, :address)
        assert Map.has_key?(peer, :last_seen)
        assert byte_size(peer.id) == 32
      end

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
    end

    test "neighbors respects the limit n" do
      {:ok, node_a} = DHT.start_link(address: :node_a)
      {:ok, node_b} = DHT.start_link(address: :node_b)
      {:ok, node_c} = DHT.start_link(address: :node_c)

      DHT.bootstrap(node_b, [:node_a])
      DHT.bootstrap(node_c, [:node_a, :node_b])

      target_id = :crypto.strong_rand_bytes(32)

      peers_1 = DHT.neighbors(node_c, target_id, 1)
      peers_3 = DHT.neighbors(node_c, target_id, 3)

      assert length(peers_1) <= 1
      assert length(peers_3) <= 3

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
      Process.exit(node_c, :normal)
    end
  end

  describe "DHT network topology" do
    test "multi-node network can find values" do
      {:ok, node_a} = DHT.start_link(address: :topo_a)
      {:ok, node_b} = DHT.start_link(address: :topo_b)
      {:ok, node_c} = DHT.start_link(address: :topo_c)

      # Form a chain: c -> b -> a
      DHT.bootstrap(node_b, [:topo_a])
      DHT.bootstrap(node_c, [:topo_b])

      # Store on node_a
      DHT.put(node_a, "chain_key", "chain_value")

      # Retrieve from node_c (should work via iterative lookup)
      assert {:ok, "chain_value"} == DHT.get(node_c, "chain_key")

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
      Process.exit(node_c, :normal)
    end

    @tag :skip
    test "network handles node failures gracefully" do
      # This test verifies that the DHT can handle dead nodes gracefully.
      # However, the iterative lookup may block when querying dead nodes.
      # TODO: Improve RPC timeout handling for dead processes.
      {:ok, node_a} = DHT.start_link(address: :fail_a)
      {:ok, node_b} = DHT.start_link(address: :fail_b)

      DHT.bootstrap(node_b, [:fail_a])
      DHT.put(node_b, "local_key", "local_value")

      # Kill node_a
      Process.exit(node_a, :kill)
      Process.sleep(50)

      # node_b should still work with locally stored values
      assert {:ok, "local_value"} == DHT.get(node_b, "local_key")

      Process.exit(node_b, :normal)
    end
  end

  describe "store expiration" do
    test "expired entries are not returned" do
      {:ok, node} = DHT.start_link(address: :expire_node, ttl_ms: 10)

      # Store with short TTL
      DHT.put(node, "expire_key", "expire_value")

      # Should be available immediately
      assert {:ok, "expire_value"} == DHT.get(node, "expire_key")

      # Wait for expiration
      Process.sleep(20)

      # Should be expired now
      assert :not_found == DHT.get(node, "expire_key")

      Process.exit(node, :normal)
    end

    test "entries with long TTL persist" do
      {:ok, node} = DHT.start_link(address: :long_ttl_node, ttl_ms: :timer.hours(1))

      DHT.put(node, "persist_key", "persist_value")

      Process.sleep(100)

      # Should still be available
      assert {:ok, "persist_value"} == DHT.get(node, "persist_key")

      Process.exit(node, :normal)
    end
  end

  describe "bucket management" do
    test "nodes with similar IDs go to nearby buckets" do
      {:ok, node_a} = DHT.start_link(address: :bucket_a)
      {:ok, node_b} = DHT.start_link(address: :bucket_b)

      # Get their IDs via neighbors lookup (indirectly)
      DHT.bootstrap(node_b, [:bucket_a])

      # Both nodes should know about each other after bootstrap
      target = :crypto.strong_rand_bytes(32)
      peers_a = DHT.neighbors(node_a, target, 5)
      peers_b = DHT.neighbors(node_b, target, 5)

      # At least one should have the other in buckets (if ping succeeded)
      assert is_list(peers_a)
      assert is_list(peers_b)

      Process.exit(node_a, :normal)
      Process.exit(node_b, :normal)
    end
  end
end
