defmodule ChronoMesh.KeysTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.Keys

  describe "generate/0" do
    test "generates valid X25519 keypair" do
      {public_key, private_key} = Keys.generate()

      assert is_binary(public_key)
      assert is_binary(private_key)
      assert byte_size(public_key) == 32
      assert byte_size(private_key) == 32
    end

    test "generates unique keypairs" do
      {pub1, priv1} = Keys.generate()
      {pub2, priv2} = Keys.generate()

      assert pub1 != pub2
      assert priv1 != priv2
    end
  end

  describe "key persistence" do
    setup do
      tmp_dir = Path.join(System.tmp_dir!(), "keys_test_#{System.unique_integer([:positive])}")
      File.mkdir_p!(tmp_dir)

      on_exit(fn ->
        File.rm_rf(tmp_dir)
      end)

      %{tmp_dir: tmp_dir}
    end

    test "write_private_key!/2 and read_private_key!/1 round-trip", %{tmp_dir: tmp_dir} do
      {_public_key, private_key} = Keys.generate()
      path = Path.join(tmp_dir, "private.key")

      assert :ok == Keys.write_private_key!(path, private_key)
      assert File.exists?(path)

      read_key = Keys.read_private_key!(path)
      assert read_key == private_key
    end

    test "write_public_key!/2 and read_public_key!/1 round-trip", %{tmp_dir: tmp_dir} do
      {public_key, _private_key} = Keys.generate()
      path = Path.join(tmp_dir, "public.key")

      assert :ok == Keys.write_public_key!(path, public_key)
      assert File.exists?(path)

      read_key = Keys.read_public_key!(path)
      assert read_key == public_key
    end

    test "read_private_key!/1 raises on missing file", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "nonexistent.key")

      assert_raise File.Error, fn ->
        Keys.read_private_key!(path)
      end
    end

    test "read_public_key!/1 raises on missing file", %{tmp_dir: tmp_dir} do
      path = Path.join(tmp_dir, "nonexistent.key")

      assert_raise File.Error, fn ->
        Keys.read_public_key!(path)
      end
    end
  end

  describe "compute_shared_secret/2" do
    test "computes same shared secret for both parties" do
      {alice_pub, alice_priv} = Keys.generate()
      {bob_pub, bob_priv} = Keys.generate()

      alice_secret = Keys.compute_shared_secret(bob_pub, alice_priv)
      bob_secret = Keys.compute_shared_secret(alice_pub, bob_priv)

      assert alice_secret == bob_secret
      assert byte_size(alice_secret) == 32
    end

    test "different keypairs produce different secrets" do
      {_alice_pub, alice_priv} = Keys.generate()
      {bob_pub, _bob_priv} = Keys.generate()
      {charlie_pub, _charlie_priv} = Keys.generate()

      ab_secret = Keys.compute_shared_secret(bob_pub, alice_priv)
      ac_secret = Keys.compute_shared_secret(charlie_pub, alice_priv)

      assert ab_secret != ac_secret
    end
  end

  describe "sign/2 and verify/4" do
    test "sign/2 produces consistent signatures" do
      {_public_key, private_key} = Keys.generate()
      message = "test message"

      signature1 = Keys.sign(message, private_key)
      signature2 = Keys.sign(message, private_key)

      assert signature1 == signature2
      assert byte_size(signature1) == 32
    end

    test "verify/4 verifies valid signatures" do
      {public_key, private_key} = Keys.generate()
      message = "test message"

      signature = Keys.sign(message, private_key)
      assert Keys.verify(message, signature, public_key, private_key) == true
    end

    test "verify/4 rejects invalid signatures" do
      {public_key, private_key} = Keys.generate()
      {_other_pub, other_priv} = Keys.generate()
      message = "test message"

      signature = Keys.sign(message, other_priv)

      # Signature from different key should not verify
      assert Keys.verify(message, signature, public_key, private_key) == false
    end

    test "verify/4 rejects tampered messages" do
      {public_key, private_key} = Keys.generate()
      message = "test message"
      tampered = "tampered message"

      signature = Keys.sign(message, private_key)

      # Signature for original message should not verify tampered message
      assert Keys.verify(tampered, signature, public_key, private_key) == false
    end

    test "verify_public/3 performs structure check" do
      {public_key, private_key} = Keys.generate()
      message = "test message"

      signature = Keys.sign(message, private_key)

      # verify_public checks structure only (basic validation)
      assert Keys.verify_public(message, signature, public_key) == true
    end

    test "verify_public/3 rejects invalid structure" do
      {public_key, _private_key} = Keys.generate()

      # Invalid signature size
      invalid_sig = <<0::size(16)>>

      assert Keys.verify_public("message", invalid_sig, public_key) == false
    end
  end

  describe "node_id_from_public_key/1" do
    test "derives node ID from public key" do
      {public_key, _private_key} = Keys.generate()

      node_id = Keys.node_id_from_public_key(public_key)

      assert is_binary(node_id)
      assert byte_size(node_id) == 32
    end

    test "same public key produces same node ID" do
      {public_key, _private_key} = Keys.generate()

      node_id1 = Keys.node_id_from_public_key(public_key)
      node_id2 = Keys.node_id_from_public_key(public_key)

      assert node_id1 == node_id2
    end

    test "different public keys produce different node IDs" do
      {pub1, _priv1} = Keys.generate()
      {pub2, _priv2} = Keys.generate()

      id1 = Keys.node_id_from_public_key(pub1)
      id2 = Keys.node_id_from_public_key(pub2)

      assert id1 != id2
    end

    test "node ID is SHA256 hash of public key" do
      {public_key, _private_key} = Keys.generate()

      node_id = Keys.node_id_from_public_key(public_key)

      # Node ID is SHA256 hash of public key (not the public key itself)
      assert is_binary(node_id)
      assert byte_size(node_id) == 32
      expected_node_id = :crypto.hash(:sha256, public_key)
      assert node_id == expected_node_id
    end
  end

  describe "edge cases" do
    test "handles empty message" do
      {public_key, private_key} = Keys.generate()
      message = ""

      signature = Keys.sign(message, private_key)
      assert Keys.verify(message, signature, public_key, private_key) == true
    end

    test "handles large messages" do
      {public_key, private_key} = Keys.generate()
      message = String.duplicate("a", 10_000)

      signature = Keys.sign(message, private_key)
      assert Keys.verify(message, signature, public_key, private_key) == true
    end

    test "handles binary messages" do
      {public_key, private_key} = Keys.generate()
      message = <<0, 1, 2, 3, 255, 254, 253>>

      signature = Keys.sign(message, private_key)
      assert Keys.verify(message, signature, public_key, private_key) == true
    end
  end
end
