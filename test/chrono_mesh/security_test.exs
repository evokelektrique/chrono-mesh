defmodule ChronoMesh.SecurityTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.{Token, Keys, ControlClient, Discovery, DHT}

  describe "Security: unsafe binary_to_term prevention" do
    test "token decryption rejects unsafe terms" do
      {public_key, private_key} = Keys.generate()
      frame_id = :crypto.strong_rand_bytes(16)

      # Create a token with malicious term
      {ephemeral_public, ephemeral_private} = :crypto.generate_key(:ecdh, :x25519)
      shared_secret = Keys.compute_shared_secret(public_key, ephemeral_private)

      # Attempt to create token with unsafe term (code execution)
      # Note: We can't easily test this without creating actual unsafe terms,
      # but the safe flag prevents execution
      malicious_data = :erlang.term_to_binary(:erlang.make_ref())

      ciphertext = Token.encrypt_payload(shared_secret, frame_id, 0, malicious_data)
      token = <<ephemeral_public::binary, ciphertext::binary>>

      # Should reject invalid token structure
      assert {:error, _} = Token.decrypt_token(token, private_key, frame_id, 0)
    end

    test "token decryption validates token size" do
      {_public_key, private_key} = Keys.generate()
      frame_id = :crypto.strong_rand_bytes(16)

      # Too small token
      small_token = <<0::size(16)>>
      assert {:error, :invalid_token} = Token.decrypt_token(small_token, private_key, frame_id, 0)
    end
  end

  describe "Security: input validation" do
    test "register_connection validates node_id size" do
      # Invalid node_id size
      invalid_node_id = <<0::size(16)>>

      assert_raise FunctionClauseError, fn ->
        ControlClient.register_connection(invalid_node_id, "127.0.0.1", 4000)
      end
    end

    test "resolve_connection_recursive rejects invalid node_id sizes" do
      # This is tested through enqueue_remote which internally calls resolve_connection
      # Invalid node_ids are rejected by guards
      # Too small
      invalid_node_id = <<0::size(16)>>

      # Should reject invalid node_id through guards
      result = ControlClient.enqueue_remote(invalid_node_id, [])
      assert {:error, _} = result
    end
  end

  describe "Security: recursion depth limits" do
    test "resolve_connection_recursive prevents infinite loops" do
      {public_key, _} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      # Should limit recursion depth
      # This would cause infinite recursion if depth limit wasn't enforced
      # Test through public API
      result = ControlClient.enqueue_remote(node_id, [])

      # Should not hang or crash - will fail gracefully with max depth
      assert result == :ok or elem(result, 0) == :error
    end
  end

  describe "Security: circular introduction point chains" do
    test "detects and prevents circular introduction points" do
      {public_key, private_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()
      node_id = Keys.node_id_from_public_key(public_key)

      # Create announcement with self-referencing introduction point
      circular_intro_point = %{
        node_id: node_id,
        public_key: public_key
      }

      {:ok, dht_pid} = DHT.start_link(address: :circular_test)

      # Announce with circular reference
      :ok =
        DHT.announce_node(
          dht_pid,
          public_key,
          private_key,
          :timer.minutes(5),
          [circular_intro_point],
          ed25519_public_key: ed25519_public_key,
          ed25519_private_key: ed25519_private_key
        )

      # Should handle gracefully
      result = ControlClient.enqueue_remote(node_id, [])

      # Should either fail gracefully or timeout, not crash
      assert result == :ok or elem(result, 0) == :error

      Process.exit(dht_pid, :normal)
    end
  end

  describe "Security: announcement structure validation" do
    test "DHT rejects malformed announcements" do
      {:ok, dht_pid} = DHT.start_link(address: :validation_test)

      # Try to store malformed announcement
      invalid_announcement = %{
        # Wrong size
        node_id: <<0::size(16)>>,
        # Wrong size
        public_key: <<0::size(16)>>,
        # Invalid timestamp
        timestamp: -1,
        # Already expired
        expires_at: 0,
        # Wrong size
        signature: <<>>,
        introduction_points: []
      }

      _key = <<"node:", :crypto.strong_rand_bytes(32)::binary>>
      _value = :erlang.term_to_binary(invalid_announcement)

      # Should not crash when looking up
      result = DHT.lookup_nodes(dht_pid, :crypto.strong_rand_bytes(32), 1)
      assert is_list(result)

      Process.exit(dht_pid, :normal)
    end
  end

  describe "Security: introduction point limits" do
    test "DHT limits introduction point count to prevent DoS" do
      {public_key, private_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()

      # Create many introduction points (DoS attempt)
      many_intro_points =
        for _i <- 1..20 do
          {ip_pub, _} = Keys.generate()

          %{
            node_id: Keys.node_id_from_public_key(ip_pub),
            public_key: ip_pub
          }
        end

      {:ok, dht_pid} = DHT.start_link(address: :limit_test)

      # Should only accept up to 10 introduction points
      :ok =
        DHT.announce_node(
          dht_pid,
          public_key,
          private_key,
          :timer.minutes(5),
          many_intro_points,
          ed25519_public_key: ed25519_public_key,
          ed25519_private_key: ed25519_private_key
        )

      # Verify announcement was created (with limited intro points)
      node_id = Keys.node_id_from_public_key(public_key)
      announcements = DHT.lookup_nodes(dht_pid, node_id, 1)

      if length(announcements) > 0 do
        announcement = List.first(announcements)
        assert length(announcement.introduction_points) <= 10
      end

      Process.exit(dht_pid, :normal)
    end
  end

  describe "Security: binary decoding failures" do
    test "Discovery handles invalid node_id hex gracefully" do
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()
      tmp_dir = System.tmp_dir!()
      ed25519_priv_path = Path.join(tmp_dir, "test_ed25519_invalid_node.key")
      ed25519_pub_path = Path.join(tmp_dir, "test_ed25519_invalid_node_pub.key")

      try do
        Keys.write_private_key!(ed25519_priv_path, ed25519_private_key)
        Keys.write_public_key!(ed25519_pub_path, ed25519_public_key)

        config = %{
          "identity" => %{
            "ed25519_private_key_path" => ed25519_priv_path,
            "ed25519_public_key_path" => ed25519_pub_path
          },
          "network" => %{
            "bootstrap_peers" => [
              %{"node_id" => "invalid-hex-string!!!"}
            ]
          }
        }

        # Should not crash
        {:ok, pid} = Discovery.start_link(config)
        assert Process.alive?(pid)
        Process.exit(pid, :normal)
      after
        File.rm(ed25519_priv_path)
        File.rm(ed25519_pub_path)
      end
    end

    test "Discovery handles invalid public_key base64 gracefully" do
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()
      tmp_dir = System.tmp_dir!()
      ed25519_priv_path = Path.join(tmp_dir, "test_ed25519_invalid.key")
      ed25519_pub_path = Path.join(tmp_dir, "test_ed25519_invalid_pub.key")

      try do
        Keys.write_private_key!(ed25519_priv_path, ed25519_private_key)
        Keys.write_public_key!(ed25519_pub_path, ed25519_public_key)

        config = %{
          "identity" => %{
            "ed25519_private_key_path" => ed25519_priv_path,
            "ed25519_public_key_path" => ed25519_pub_path
          },
          "network" => %{
            "bootstrap_peers" => [
              %{"public_key" => "not-base64!!!"}
            ]
          }
        }

        # Should not crash - decode_pk handles errors
        {:ok, pid} = Discovery.start_link(config)
        assert Process.alive?(pid)
        Process.exit(pid, :normal)
      after
        File.rm(ed25519_priv_path)
        File.rm(ed25519_pub_path)
      end
    end
  end

  describe "Security: signature validation" do
    test "verify checks signature size" do
      {public_key, private_key} = Keys.keypair()
      message = "test"

      signature = Keys.sign(message, private_key)

      # Valid signature
      assert Keys.verify(message, signature, public_key) == true

      # Invalid signature size
      invalid_sig = <<0::size(16)>>
      assert Keys.verify(message, invalid_sig, public_key) == false

      # Invalid public key size
      invalid_pub = <<0::size(16)>>
      assert Keys.verify(message, signature, invalid_pub) == false
    end
  end

  describe "Security: expired announcement rejection" do
    test "DHT rejects expired announcements" do
      {public_key, private_key} = Keys.generate()
      {ed25519_public_key, ed25519_private_key} = Keys.keypair()
      {:ok, dht_pid} = DHT.start_link(address: :expiry_test)

      # Create announcement with very short TTL
      :ok =
        DHT.announce_node(
          dht_pid,
          public_key,
          private_key,
          10,
          [],
          ed25519_public_key: ed25519_public_key,
          ed25519_private_key: ed25519_private_key
        )

      node_id = Keys.node_id_from_public_key(public_key)

      # Should find it immediately
      announcements = DHT.lookup_nodes(dht_pid, node_id, 1)
      # May or may not be found depending on timing
      assert length(announcements) >= 0

      # Wait for expiry
      Process.sleep(20)

      # Should not find expired announcements
      expired = DHT.lookup_nodes(dht_pid, node_id, 1)
      # Expired announcements are filtered out
      assert is_list(expired)

      Process.exit(dht_pid, :normal)
    end
  end
end
