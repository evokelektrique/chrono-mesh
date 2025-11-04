defmodule ChronoMesh.AddressBookSubscriptionsTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{AddressBook, DHT, Keys}

  setup do
    # Clean up ETS tables before each test
    cleanup_tables()
    {:ok, dht_pid} = DHT.start_link([])
    {:ok, dht_pid: dht_pid}
  end

  defp cleanup_tables do
    tables = [
      :chrono_mesh_address_book,
      :chrono_mesh_subscriptions,
      :chrono_mesh_subscription_rate_limit,
      :chrono_mesh_alias_rate_limit,
      :chrono_mesh_published_aliases
    ]

    Enum.each(tables, fn table ->
      if :ets.whereis(table) != :undefined do
        :ets.delete_all_objects(table)
      end
    end)
  end

  describe "subscribe/3" do
    test "subscribes to a node successfully", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id) == :ok
      assert target_node_id in AddressBook.list_subscriptions(subscriber_node_id)
    end

    test "rejects duplicate subscription", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id) == :ok
      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id) ==
               {:error, :already_subscribed}
    end

    test "rejects invalid node_id size", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      invalid_node_id = <<0::size(16)>>

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, invalid_node_id) ==
               {:error, :invalid_node_id}
    end

    test "rejects subscription to subscription list key", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      # This would be a subscription list key, not a node_id
      fake_node_id = <<"subs:", 0::size(248)>>

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, fake_node_id) ==
               {:error, :invalid_node_id}
    end

    test "enforces subscription limit (max 100)", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      # Create 100 subscriptions
      1..100
      |> Enum.each(fn _i ->
        {target_pub, _target_priv} = Keys.generate()
        target_node_id = Keys.node_id_from_public_key(target_pub)
        assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id) == :ok
      end)

      # 101st subscription should fail
      {target_pub, _target_priv} = Keys.generate()
      target_node_id = Keys.node_id_from_public_key(target_pub)

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id) ==
               {:error, :max_subscriptions_exceeded}
    end
  end

  describe "unsubscribe/2" do
    test "unsubscribes from a node successfully", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)
      assert AddressBook.unsubscribe(subscriber_node_id, target_node_id) == :ok
      assert target_node_id not in AddressBook.list_subscriptions(subscriber_node_id)
    end

    test "returns :not_subscribed when unsubscribing from non-existent subscription", %{
      dht_pid: _dht_pid
    } do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      assert AddressBook.unsubscribe(subscriber_node_id, target_node_id) ==
               {:error, :not_subscribed}
    end

    test "removes subscription list when all subscriptions are removed", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)
      assert AddressBook.get_subscription_list(subscriber_node_id) != nil

      AddressBook.unsubscribe(subscriber_node_id, target_node_id)
      assert AddressBook.get_subscription_list(subscriber_node_id) == nil
    end
  end

  describe "list_subscriptions/1" do
    test "lists all subscribed node_ids", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      {target1_pub, _target1_priv} = Keys.generate()
      {target2_pub, _target2_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target1_node_id = Keys.node_id_from_public_key(target1_pub)
      target2_node_id = Keys.node_id_from_public_key(target2_pub)

      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target1_node_id)
      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target2_node_id)

      subscriptions = AddressBook.list_subscriptions(subscriber_node_id)
      assert length(subscriptions) == 2
      assert target1_node_id in subscriptions
      assert target2_node_id in subscriptions
    end

    test "returns empty list when no subscriptions exist", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      assert AddressBook.list_subscriptions(subscriber_node_id) == []
    end
  end

  describe "publish_subscription_list/5" do
    test "publishes subscription list to DHT", %{dht_pid: dht_pid} do
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      # Create subscription
      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)

      # Announce subscriber to DHT (required for signature verification)
      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )

      Process.sleep(50)

      # Publish subscription list
      assert AddressBook.publish_subscription_list(
               dht_pid,
               subscriber_node_id,
               subscriber_priv,
               ed25519_priv,
               ed25519_pub
             ) == :ok

      # Verify subscription list was published to DHT
      key = "subs:" <> subscriber_node_id

      case DHT.get(dht_pid, key) do
        {:ok, value} ->
          subscription_list = :erlang.binary_to_term(value, [:safe])
          assert subscription_list.subscriber_node_id == subscriber_node_id
          assert target_node_id in subscription_list.subscribed_nodes
          assert byte_size(subscription_list.signature) == 64

        _ ->
          flunk("Subscription list not found in DHT")
      end
    end

    test "publishes subscription list with Ed25519 signature", %{dht_pid: dht_pid} do
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      # Create subscription
      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)

      # Announce subscriber to DHT with Ed25519 keys
      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )

      Process.sleep(50)

      # Publish subscription list with Ed25519
      assert AddressBook.publish_subscription_list(
               dht_pid,
               subscriber_node_id,
               subscriber_priv,
               ed25519_priv,
               ed25519_pub
             ) == :ok

      # Verify Ed25519 signature
      key = "subs:" <> subscriber_node_id

      case DHT.get(dht_pid, key) do
        {:ok, value} ->
          subscription_list = :erlang.binary_to_term(value, [:safe])
          assert subscription_list.ed25519_public_key == ed25519_pub
          assert byte_size(subscription_list.signature) == 64

        _ ->
          flunk("Subscription list not found in DHT")
      end
    end

    test "enforces rate limiting (max 1 per minute)", %{dht_pid: dht_pid} do
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)

      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )

      Process.sleep(50)

      # First publish should succeed
      assert AddressBook.publish_subscription_list(
               dht_pid,
               subscriber_node_id,
               subscriber_priv,
               ed25519_priv,
               ed25519_pub
             ) == :ok

      # Second publish immediately should fail
      assert AddressBook.publish_subscription_list(
               dht_pid,
               subscriber_node_id,
               subscriber_priv,
               ed25519_priv,
               ed25519_pub
             ) == {:error, :rate_limit_exceeded}
    end

    test "returns :no_subscriptions when no subscriptions exist", %{dht_pid: dht_pid} do
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      assert AddressBook.publish_subscription_list(
               dht_pid,
               subscriber_node_id,
               subscriber_priv,
               ed25519_priv,
               ed25519_pub
             ) == {:error, :no_subscriptions}
    end
  end

  describe "verify_subscription_list/2" do
    test "verifies valid subscription list signature", %{dht_pid: dht_pid} do
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)

      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )

      Process.sleep(50)

      :ok =
        AddressBook.publish_subscription_list(
          dht_pid,
          subscriber_node_id,
          subscriber_priv,
          ed25519_priv,
          ed25519_pub
        )

      # Retrieve and verify
      key = "subs:" <> subscriber_node_id

      case DHT.get(dht_pid, key) do
        {:ok, value} ->
          subscription_list = :erlang.binary_to_term(value, [:safe])
          assert AddressBook.verify_subscription_list(dht_pid, subscription_list) == true

        _ ->
          flunk("Subscription list not found in DHT")
      end
    end

    test "rejects forged subscription list (invalid signature size)", %{dht_pid: dht_pid} do
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      {target_pub, _target_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)
      target_node_id = Keys.node_id_from_public_key(target_pub)

      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)

      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )

      Process.sleep(50)

      # Create forged subscription list with invalid signature size
      forged_sub_list = %{
        subscriber_node_id: subscriber_node_id,
        subscribed_nodes: [target_node_id],
        timestamp: :erlang.system_time(:millisecond),
        expires_at: :erlang.system_time(:millisecond) + :timer.hours(1),
        signature: <<0::size(16)>>, # Invalid size (should be 64 for Ed25519)
        ed25519_public_key: ed25519_pub
      }

      # Should reject invalid signature size
      assert AddressBook.verify_subscription_list(dht_pid, forged_sub_list) == false
    end
  end

  describe "publish_alias/6" do
    test "publishes alias to DHT", %{dht_pid: dht_pid} do
      {owner_pub, owner_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      owner_node_id = Keys.node_id_from_public_key(owner_pub)

      # Register alias locally
      AddressBook.register("alice", owner_node_id, owner_pub, owner_priv)

      # Announce owner to DHT
      :ok =
        DHT.announce_node(
          dht_pid,
          owner_pub,
          owner_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )
      Process.sleep(50)

      # Publish alias
      assert AddressBook.publish_alias(
               dht_pid,
               "alice",
               owner_node_id,
               owner_priv,
               ed25519_priv,
               ed25519_pub
             ) == :ok

      # Verify alias was published to DHT
      key = "alias:alice.mesh:" <> owner_node_id

      case DHT.get(dht_pid, key) do
        {:ok, value} ->
          published_alias = :erlang.binary_to_term(value, [:safe])
          assert published_alias.alias == "alice.mesh"
          assert published_alias.node_id == owner_node_id
          assert byte_size(published_alias.signature) == 64

        _ ->
          flunk("Published alias not found in DHT")
      end
    end

    test "publishes alias with Ed25519 signature", %{dht_pid: dht_pid} do
      {owner_pub, owner_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      owner_node_id = Keys.node_id_from_public_key(owner_pub)

      AddressBook.register("alice", owner_node_id, owner_pub, owner_priv)

      :ok =
        DHT.announce_node(
          dht_pid,
          owner_pub,
          owner_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )

      Process.sleep(50)

      assert AddressBook.publish_alias(
               dht_pid,
               "alice",
               owner_node_id,
               owner_priv,
               ed25519_priv,
               ed25519_pub
             ) == :ok

      # Verify Ed25519 signature
      key = "alias:alice.mesh:" <> owner_node_id

      case DHT.get(dht_pid, key) do
        {:ok, value} ->
          published_alias = :erlang.binary_to_term(value, [:safe])
          assert published_alias.ed25519_public_key == ed25519_pub
          assert byte_size(published_alias.signature) == 64

        _ ->
          flunk("Published alias not found in DHT")
      end
    end

    test "enforces rate limiting for alias publishing", %{dht_pid: dht_pid} do
      {owner_pub, owner_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      owner_node_id = Keys.node_id_from_public_key(owner_pub)

      AddressBook.register("alice", owner_node_id, owner_pub, owner_priv)

      :ok =
        DHT.announce_node(
          dht_pid,
          owner_pub,
          owner_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )
      Process.sleep(50)

      # First publish should succeed
      assert AddressBook.publish_alias(
               dht_pid,
               "alice",
               owner_node_id,
               owner_priv,
               ed25519_priv,
               ed25519_pub
             ) == :ok

      # Second publish immediately should fail
      assert AddressBook.publish_alias(
               dht_pid,
               "alice",
               owner_node_id,
               owner_priv,
               ed25519_priv,
               ed25519_pub
             ) == {:error, :rate_limit_exceeded}
    end

    test "returns :alias_not_found when alias doesn't exist locally", %{dht_pid: dht_pid} do
      {owner_pub, owner_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      owner_node_id = Keys.node_id_from_public_key(owner_pub)

      assert AddressBook.publish_alias(
               dht_pid,
               "unknown",
               owner_node_id,
               owner_priv,
               ed25519_priv,
               ed25519_pub
             ) == {:error, :alias_not_found}
    end
  end

  describe "verify_published_alias/2" do
    test "verifies valid published alias signature", %{dht_pid: dht_pid} do
      {owner_pub, owner_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      owner_node_id = Keys.node_id_from_public_key(owner_pub)

      AddressBook.register("alice", owner_node_id, owner_pub, owner_priv)

      :ok =
        DHT.announce_node(
          dht_pid,
          owner_pub,
          owner_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )
      Process.sleep(50)

      :ok =
        AddressBook.publish_alias(
          dht_pid,
          "alice",
          owner_node_id,
          owner_priv,
          ed25519_priv,
          ed25519_pub
        )

      # Retrieve and verify
      key = "alias:alice.mesh:" <> owner_node_id

      case DHT.get(dht_pid, key) do
        {:ok, value} ->
          published_alias = :erlang.binary_to_term(value, [:safe])
          assert AddressBook.verify_published_alias(dht_pid, published_alias) == true

        _ ->
          flunk("Published alias not found in DHT")
      end
    end

    test "rejects forged alias (invalid signature size)", %{dht_pid: dht_pid} do
      {owner_pub, owner_priv} = Keys.generate()
      {ed25519_pub, ed25519_priv} = Keys.keypair()
      owner_node_id = Keys.node_id_from_public_key(owner_pub)

      :ok =
        DHT.announce_node(
          dht_pid,
          owner_pub,
          owner_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: ed25519_priv,
          ed25519_public_key: ed25519_pub
        )
      Process.sleep(50)

      # Create forged alias with invalid signature size
      forged_alias = %{
        alias: "alice.mesh",
        node_id: owner_node_id,
        owner_public_key: owner_pub,
        signature: <<0::size(16)>>, # Invalid size (should be 64 for Ed25519)
        published_at: :erlang.system_time(:millisecond),
        expires_at: :erlang.system_time(:millisecond) + :timer.hours(24),
        ed25519_public_key: ed25519_pub
      }

      # Should reject invalid signature size
      assert AddressBook.verify_published_alias(dht_pid, forged_alias) == false
    end
  end

  describe "resolve_distributed/3" do
    test "resolves alias from DHT for subscribed node", %{dht_pid: dht_pid} do
      # Setup subscriber
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {sub_ed25519_pub, sub_ed25519_priv} = Keys.keypair()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      # Setup target (publisher)
      {target_pub, target_priv} = Keys.generate()
      {target_ed25519_pub, target_ed25519_priv} = Keys.keypair()
      target_node_id = Keys.node_id_from_public_key(target_pub)

      # Subscribe to target
      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)

      # Announce both nodes to DHT
      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: sub_ed25519_priv,
          ed25519_public_key: sub_ed25519_pub
        )
      :ok =
        DHT.announce_node(
          dht_pid,
          target_pub,
          target_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: target_ed25519_priv,
          ed25519_public_key: target_ed25519_pub
        )
      Process.sleep(50)

      # Register and publish alias on target
      AddressBook.register("alice", target_node_id, target_pub, target_priv)
      :ok =
        AddressBook.publish_alias(
          dht_pid,
          "alice",
          target_node_id,
          target_priv,
          target_ed25519_priv,
          target_ed25519_pub
        )

      # Resolve alias from subscriber
      assert AddressBook.resolve_distributed(dht_pid, subscriber_node_id, "alice") ==
               {:ok, target_node_id}
    end

    test "returns :not_found when alias not found in subscribed nodes", %{dht_pid: dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      assert AddressBook.resolve_distributed(dht_pid, subscriber_node_id, "unknown") ==
               :not_found
    end

    test "rejects alias with invalid signature size", %{dht_pid: dht_pid} do
      {subscriber_pub, subscriber_priv} = Keys.generate()
      {sub_ed25519_pub, sub_ed25519_priv} = Keys.keypair()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      {target_pub, target_priv} = Keys.generate()
      {target_ed25519_pub, target_ed25519_priv} = Keys.keypair()
      target_node_id = Keys.node_id_from_public_key(target_pub)

      AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id)

      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: sub_ed25519_priv,
          ed25519_public_key: sub_ed25519_pub
        )
      :ok =
        DHT.announce_node(
          dht_pid,
          target_pub,
          target_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: target_ed25519_priv,
          ed25519_public_key: target_ed25519_pub
        )
      Process.sleep(50)

      # Publish forged alias with invalid signature size directly to DHT (bypassing AddressBook)
      forged_alias = %{
        alias: "alice.mesh",
        node_id: target_node_id,
        owner_public_key: target_pub,
        signature: <<0::size(16)>>, # Invalid size (should be 64 for Ed25519)
        published_at: :erlang.system_time(:millisecond),
        expires_at: :erlang.system_time(:millisecond) + :timer.hours(24),
        ed25519_public_key: target_ed25519_pub
      }

      key = "alias:alice.mesh:" <> target_node_id
      value = :erlang.term_to_binary(forged_alias, [:compressed])
      DHT.put(dht_pid, key, value, :timer.hours(24))

      # Should reject invalid signature size
      assert AddressBook.resolve_distributed(dht_pid, subscriber_node_id, "alice") ==
               :not_found
    end
  end

  describe "resolve/1 with DHT cache" do
    test "resolves alias from local cache of published aliases", %{dht_pid: _dht_pid} do
      # This test verifies that resolve/1 checks the published_aliases cache
      # We'll manually insert a published alias into the cache
      published_alias = %{
        alias: "alice.mesh",
        node_id: :crypto.strong_rand_bytes(32),
        owner_public_key: :crypto.strong_rand_bytes(32),
        signature: :crypto.strong_rand_bytes(64),
        published_at: :erlang.system_time(:millisecond),
        expires_at: :erlang.system_time(:millisecond) + :timer.hours(24),
        ed25519_public_key: :crypto.strong_rand_bytes(32)
      }

      # Manually insert into cache (simulating DHT retrieval)
      if :ets.whereis(:chrono_mesh_published_aliases) == :undefined do
        :ets.new(:chrono_mesh_published_aliases, [:set, :named_table, :public])
      end

      :ets.insert(:chrono_mesh_published_aliases, {"alice.mesh", published_alias})

      # Should resolve from cache
      assert AddressBook.resolve("alice.mesh") == {:ok, published_alias.node_id}
    end

    test "expires cached aliases after TTL", %{dht_pid: _dht_pid} do
      expired_alias = %{
        alias: "alice.mesh",
        node_id: :crypto.strong_rand_bytes(32),
        owner_public_key: :crypto.strong_rand_bytes(32),
        signature: :crypto.strong_rand_bytes(64),
        published_at: :erlang.system_time(:millisecond) - :timer.hours(25),
        expires_at: :erlang.system_time(:millisecond) - :timer.hours(1),
        ed25519_public_key: :crypto.strong_rand_bytes(32)
      }

      if :ets.whereis(:chrono_mesh_published_aliases) == :undefined do
        :ets.new(:chrono_mesh_published_aliases, [:set, :named_table, :public])
      end

      :ets.insert(:chrono_mesh_published_aliases, {"alice.mesh", expired_alias})

      # Should return :not_found and remove expired alias
      assert AddressBook.resolve("alice.mesh") == :not_found
    end
  end

  describe "Security: subscription chaining prevention" do
    test "cannot subscribe to subscription list keys", %{dht_pid: _dht_pid} do
      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      # Attempt to subscribe to a subscription list key (should fail)
      fake_subscription_key = <<"subs:", 0::size(248)>>

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, fake_subscription_key) ==
               {:error, :invalid_node_id}
    end
  end

  describe "Integration: end-to-end subscribe→publish→retrieve" do
    test "complete flow works correctly", %{dht_pid: dht_pid} do
      # Setup subscriber
      {subscriber_pub, subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      # Setup publisher
      {publisher_pub, publisher_priv} = Keys.generate()
      publisher_node_id = Keys.node_id_from_public_key(publisher_pub)

      # Subscribe
      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, publisher_node_id) ==
               :ok

      # Announce both nodes
      {sub_ed25519_pub, sub_ed25519_priv} = Keys.keypair()
      {pub_ed25519_pub, pub_ed25519_priv} = Keys.keypair()

      :ok =
        DHT.announce_node(
          dht_pid,
          subscriber_pub,
          subscriber_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: sub_ed25519_priv,
          ed25519_public_key: sub_ed25519_pub
        )
      :ok =
        DHT.announce_node(
          dht_pid,
          publisher_pub,
          publisher_priv,
          :timer.minutes(5),
          [],
          ed25519_private_key: pub_ed25519_priv,
          ed25519_public_key: pub_ed25519_pub
        )
      Process.sleep(50)

      # Publish subscription list
      assert AddressBook.publish_subscription_list(
               dht_pid,
               subscriber_node_id,
               subscriber_priv,
               sub_ed25519_priv,
               sub_ed25519_pub
             ) == :ok

      # Register and publish alias
      AddressBook.register("alice", publisher_node_id, publisher_pub, publisher_priv)
      assert AddressBook.publish_alias(
               dht_pid,
               "alice",
               publisher_node_id,
               publisher_priv,
               pub_ed25519_priv,
               pub_ed25519_pub
             ) == :ok

      # Resolve alias from subscriber
      assert AddressBook.resolve_distributed(dht_pid, subscriber_node_id, "alice") ==
               {:ok, publisher_node_id}
    end
  end
end
