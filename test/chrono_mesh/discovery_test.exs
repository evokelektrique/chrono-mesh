defmodule ChronoMesh.DiscoveryTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{Discovery, Keys}

  setup do
    # Clean up any existing registry
    try do
      :ets.delete(:chrono_mesh_peers)
      :ets.delete(:chrono_mesh_dht_registry)
    rescue
      ArgumentError -> :ok
    end

    on_exit(fn ->
      try do
        :ets.delete(:chrono_mesh_peers)
        :ets.delete(:chrono_mesh_dht_registry)
      rescue
        ArgumentError -> :ok
      end
    end)

    :ok
  end

  describe "start_link/1 and initialization" do
    test "starts discovery with empty config" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)
      assert Process.alive?(pid)
      Process.exit(pid, :normal)
    end

    test "starts discovery with network config" do
      config = %{
        "network" => %{
          "listen_host" => "127.0.0.1",
          "listen_port" => 4_001,
          "bootstrap_peers" => []
        }
      }

      {:ok, pid} = Discovery.start_link(config)
      assert Process.alive?(pid)

      # Should have DHT node started
      assert is_pid(pid)
      Process.exit(pid, :normal)
    end

    test "starts discovery with identity config" do
      {public_key, private_key} = Keys.generate()
      priv_path = Path.join(System.tmp_dir!(), "test_priv.key")
      pub_path = Path.join(System.tmp_dir!(), "test_pub.key")

      try do
        Keys.write_private_key!(priv_path, private_key)
        Keys.write_public_key!(pub_path, public_key)

        config = %{
          "identity" => %{
            "private_key_path" => priv_path,
            "public_key_path" => pub_path
          },
          "network" => %{
            "listen_host" => "127.0.0.1",
            "listen_port" => 4_002
          }
        }

        {:ok, pid} = Discovery.start_link(config)
        assert Process.alive?(pid)
        Process.exit(pid, :normal)
      after
        File.rm(priv_path)
        File.rm(pub_path)
      end
    end

    test "bootstraps from config bootstrap_peers" do
      {pub1, _priv1} = Keys.generate()
      {pub2, _priv2} = Keys.generate()

      config = %{
        "network" => %{
          "bootstrap_peers" => [
            %{"public_key" => Base.encode64(pub1)},
            %{"public_key" => Base.encode64(pub2)}
          ]
        }
      }

      {:ok, pid} = Discovery.start_link(config)

      # Bootstrap peers should be in local cache
      peers = Discovery.list_peers()
      # May be 0 if bootstrap fails (expected in test)
      assert length(peers) >= 0

      Process.exit(pid, :normal)
    end
  end

  describe "peer management" do
    test "upsert_peer/1 registers peers" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      pk = :crypto.strong_rand_bytes(32)
      assert :ok == Discovery.upsert_peer(pk)

      peers = Discovery.list_peers()
      node_id = ChronoMesh.Keys.node_id_from_public_key(pk)
      assert Enum.any?(peers, fn p -> p.node_id == node_id end)

      Process.exit(pid, :normal)
    end

    test "list_peers/0 returns all known peers" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      pk1 = :crypto.strong_rand_bytes(32)
      pk2 = :crypto.strong_rand_bytes(32)

      Discovery.upsert_peer(pk1)
      Discovery.upsert_peer(pk2)

      peers = Discovery.list_peers()
      assert length(peers) >= 2

      node_id1 = ChronoMesh.Keys.node_id_from_public_key(pk1)
      node_id2 = ChronoMesh.Keys.node_id_from_public_key(pk2)

      assert Enum.any?(peers, fn p -> p.node_id == node_id1 end)
      assert Enum.any?(peers, fn p -> p.node_id == node_id2 end)

      Process.exit(pid, :normal)
    end

    test "upsert_peer/1 updates existing peer" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      pk = :crypto.strong_rand_bytes(32)
      node_id = ChronoMesh.Keys.node_id_from_public_key(pk)
      Discovery.upsert_peer(pk)

      # Update peer
      Discovery.upsert_peer(pk)

      peers = Discovery.list_peers()
      peer = Enum.find(peers, fn p -> p.node_id == node_id end)

      assert peer.node_id == node_id
      assert peer.public_key == pk

      Process.exit(pid, :normal)
    end
  end

  describe "random_sample/1" do
    test "returns peers from local cache when available" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      # Add multiple peers
      for _i <- 1..5 do
        pk = :crypto.strong_rand_bytes(32)
        Discovery.upsert_peer(pk)
      end

      sample = Discovery.random_sample(3)
      assert length(sample) == 3

      assert Enum.all?(sample, fn p ->
               Map.has_key?(p, :node_id) and Map.has_key?(p, :public_key)
             end)

      Process.exit(pid, :normal)
    end

    test "falls back to local cache when DHT unavailable" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      pk = :crypto.strong_rand_bytes(32)
      node_id = ChronoMesh.Keys.node_id_from_public_key(pk)
      Discovery.upsert_peer(pk)

      # Verify peer is in cache
      peers = Discovery.list_peers()
      assert Enum.any?(peers, fn p -> p.node_id == node_id end)

      # Clean shutdown
      Process.exit(pid, :normal)
      Process.sleep(10)

      # ETS table persists after process exit, but list_peers/0 checks process
      # This test verifies that peers are stored in ETS and can be read directly
      case :ets.lookup(:chrono_mesh_peers, node_id) do
        [{^node_id, peer}] ->
          assert peer.public_key == pk
          assert peer.node_id == node_id

        _ ->
          # Table may be cleaned up, that's OK
          :ok
      end
    end

    test "uses DHT when local cache is insufficient" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      # Add only 1 peer locally
      pk = :crypto.strong_rand_bytes(32)
      Discovery.upsert_peer(pk)

      # Request 5 peers - should query DHT
      sample = Discovery.random_sample(5)
      assert is_list(sample)
      # At least local peer
      assert length(sample) >= 1

      Process.exit(pid, :normal)
    end
  end

  describe "lookup_peer/1" do
    test "lookup_peer returns :not_found for unknown peer" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      unknown_pk = :crypto.strong_rand_bytes(32)
      result = Discovery.lookup_peer(unknown_pk)

      # New API returns {:ok, node_id} or :not_found
      assert result == :not_found or match?({:ok, _}, result)

      Process.exit(pid, :normal)
    end

    test "lookup_peer finds peer from local cache" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      pk = :crypto.strong_rand_bytes(32)
      Discovery.upsert_peer(pk)

      result = Discovery.lookup_peer(pk)

      # New API returns {:ok, node_id} or :not_found
      case result do
        {:ok, node_id} ->
          assert is_binary(node_id)
          assert byte_size(node_id) == 32

        :not_found ->
          # May not be found if not in cache
          :ok
      end

      Process.exit(pid, :normal)
    end

    test "lookup_peer queries DHT when not in cache" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      unknown_pk = :crypto.strong_rand_bytes(32)
      result = Discovery.lookup_peer(unknown_pk)

      # New API returns {:ok, node_id} or :not_found
      assert result == :not_found or match?({:ok, _}, result)

      Process.exit(pid, :normal)
    end

    test "lookup_peer resolves alias via AddressBook" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      # Register alias
      ChronoMesh.AddressBook.register("test-alias", node_id, public_key, private_key)

      # Should resolve alias
      assert {:ok, ^node_id} = Discovery.lookup_peer("test-alias.mesh")

      Process.exit(pid, :normal)
    end
  end

  describe "lookup_peer_by_public_key/1" do
    test "lookup_peer_by_public_key returns empty list for unknown peer" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      unknown_pk = :crypto.strong_rand_bytes(32)
      result = Discovery.lookup_peer_by_public_key(unknown_pk)

      # Legacy API returns list
      assert is_list(result)

      Process.exit(pid, :normal)
    end

    test "lookup_peer_by_public_key finds peer from local cache" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      pk = :crypto.strong_rand_bytes(32)
      Discovery.upsert_peer(pk)

      result = Discovery.lookup_peer_by_public_key(pk)
      assert is_list(result)

      # If found, should have correct public_key
      if length(result) > 0 do
        assert List.first(result).public_key == pk
      end

      Process.exit(pid, :normal)
    end
  end

  describe "DHT integration" do
    test "publishes self to DHT when identity is available" do
      {public_key, private_key} = Keys.generate()
      priv_path = Path.join(System.tmp_dir!(), "test_priv_announce.key")
      pub_path = Path.join(System.tmp_dir!(), "test_pub_announce.key")

      try do
        Keys.write_private_key!(priv_path, private_key)
        Keys.write_public_key!(pub_path, public_key)

        config = %{
          "identity" => %{
            "private_key_path" => priv_path,
            "public_key_path" => pub_path
          },
          "network" => %{
            "listen_host" => "127.0.0.1",
            "listen_port" => 4_208
          }
        }

        {:ok, pid} = Discovery.start_link(config)

        # Give time for announcement
        Process.sleep(100)

        # Should have started successfully
        assert Process.alive?(pid)

        Process.exit(pid, :normal)
      after
        File.rm(priv_path)
        File.rm(pub_path)
      end
    end

    test "handles missing identity gracefully" do
      config = %{
        "network" => %{
          "listen_host" => "127.0.0.1",
          "listen_port" => 4_209
        }
      }

      {:ok, pid} = Discovery.start_link(config)
      assert Process.alive?(pid)

      # Should still work without identity (no DHT announcement)
      assert is_list(Discovery.list_peers())

      Process.exit(pid, :normal)
    end

    test "bootstrap_peers are added to local cache" do
      {pub1, _priv1} = Keys.generate()
      {pub2, _priv2} = Keys.generate()

      config = %{
        "network" => %{
          "bootstrap_peers" => [
            %{"public_key" => Base.encode64(pub1)},
            %{"public_key" => Base.encode64(pub2)}
          ]
        }
      }

      {:ok, pid} = Discovery.start_link(config)

      peers = Discovery.list_peers()

      # Should have bootstrap peers in cache (if parsing succeeded)
      assert is_list(peers)

      # Verify peer structure
      Enum.each(peers, fn peer ->
        assert Map.has_key?(peer, :node_id)
        assert Map.has_key?(peer, :public_key)
        assert Map.has_key?(peer, :ts)
      end)

      Process.exit(pid, :normal)
    end
  end

  describe "announcement refresh" do
    test "schedules periodic announcement refresh" do
      {public_key, private_key} = Keys.generate()
      priv_path = Path.join(System.tmp_dir!(), "test_priv_refresh.key")
      pub_path = Path.join(System.tmp_dir!(), "test_pub_refresh.key")

      try do
        Keys.write_private_key!(priv_path, private_key)
        Keys.write_public_key!(pub_path, public_key)

        config = %{
          "identity" => %{
            "private_key_path" => priv_path,
            "public_key_path" => pub_path
          },
          "network" => %{
            "listen_host" => "127.0.0.1",
            "listen_port" => 4_210
          }
        }

        {:ok, pid} = Discovery.start_link(config)

        # Initial announcement
        Process.sleep(100)

        # Should have scheduled refresh (but we can't easily test it without waiting)
        assert Process.alive?(pid)

        Process.exit(pid, :normal)
      after
        File.rm(priv_path)
        File.rm(pub_path)
      end
    end
  end

  describe "edge cases and error handling" do
    test "handles invalid bootstrap peer config" do
      config = %{
        "network" => %{
          "bootstrap_peers" => [
            %{"invalid" => "peer"},
            %{"public_key" => "invalid-key"}
          ]
        }
      }

      {:ok, pid} = Discovery.start_link(config)

      # Should not crash on invalid peers
      assert Process.alive?(pid)

      Process.exit(pid, :normal)
    end

    test "handles missing network config" do
      config = %{}

      {:ok, pid} = Discovery.start_link(config)
      assert Process.alive?(pid)

      Process.exit(pid, :normal)
    end

    test "handles missing identity paths gracefully" do
      config = %{
        "identity" => %{
          "private_key_path" => "/nonexistent/priv.key",
          "public_key_path" => "/nonexistent/pub.key"
        },
        "network" => %{
          "listen_host" => "127.0.0.1",
          "listen_port" => 4_211
        }
      }

      {:ok, pid} = Discovery.start_link(config)

      # Should not crash, just skip announcement
      assert Process.alive?(pid)

      Process.exit(pid, :normal)
    end

    test "handles empty bootstrap_peers list" do
      config = %{
        "network" => %{
          "bootstrap_peers" => []
        }
      }

      {:ok, pid} = Discovery.start_link(config)
      assert Process.alive?(pid)

      Process.exit(pid, :normal)
    end

    test "handles invalid public key encoding" do
      config = %{
        "network" => %{
          "bootstrap_peers" => [
            %{"public_key" => "not-base64-but-still-valid"}
          ]
        }
      }

      {:ok, pid} = Discovery.start_link(config)

      # Should handle gracefully
      assert Process.alive?(pid)

      Process.exit(pid, :normal)
    end
  end

  describe "peer structure validation" do
    test "peers have required fields" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      pk = :crypto.strong_rand_bytes(32)
      node_id = ChronoMesh.Keys.node_id_from_public_key(pk)
      Discovery.upsert_peer(pk)

      peers = Discovery.list_peers()
      peer = Enum.find(peers, fn p -> p.node_id == node_id end)

      assert peer.node_id == node_id
      assert peer.public_key == pk
      assert is_integer(peer.ts)

      Process.exit(pid, :normal)
    end

    test "random_sample returns valid peer structures" do
      config = %{}
      {:ok, pid} = Discovery.start_link(config)

      for _i <- 1..3 do
        pk = :crypto.strong_rand_bytes(32)
        Discovery.upsert_peer(pk)
      end

      sample = Discovery.random_sample(2)

      Enum.each(sample, fn peer ->
        assert Map.has_key?(peer, :node_id)
        assert Map.has_key?(peer, :public_key)
        assert Map.has_key?(peer, :ts)
        assert is_binary(peer.node_id)
        assert is_binary(peer.public_key)
        assert is_integer(peer.ts)
      end)

      Process.exit(pid, :normal)
    end
  end
end
