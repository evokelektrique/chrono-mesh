defmodule ChronoMesh.AEADTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.Token

  describe "encrypt_aead/4 and decrypt_aead/5" do
    test "encrypts and decrypts plaintext successfully" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      assert is_binary(ciphertext)
      assert is_binary(auth_tag)
      assert byte_size(auth_tag) == 16

      assert {:ok, decrypted} =
               Token.decrypt_aead(shared_secret, frame_id, shard_index, ciphertext, auth_tag)

      assert decrypted == plaintext
    end

    test "generates same ciphertext for same inputs (deterministic encryption)" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      {ciphertext1, auth_tag1} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)
      {ciphertext2, auth_tag2} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      # Ciphertext should be the same (deterministic encryption from derived nonce)
      assert ciphertext1 == ciphertext2
      assert auth_tag1 == auth_tag2

      # Both should decrypt correctly
      assert {:ok, decrypted1} =
               Token.decrypt_aead(shared_secret, frame_id, shard_index, ciphertext1, auth_tag1)

      assert {:ok, decrypted2} =
               Token.decrypt_aead(shared_secret, frame_id, shard_index, ciphertext2, auth_tag2)

      assert decrypted1 == plaintext
      assert decrypted2 == plaintext
    end

    test "generates different ciphertext for different shard_index" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      plaintext = "Hello, ChronoMesh!"

      {ciphertext1, auth_tag1} = Token.encrypt_aead(shared_secret, frame_id, 0, plaintext)
      {ciphertext2, auth_tag2} = Token.encrypt_aead(shared_secret, frame_id, 1, plaintext)

      # Ciphertext should be different due to different shard_index (different nonce)
      assert ciphertext1 != ciphertext2
      assert auth_tag1 != auth_tag2

      # Both should decrypt correctly
      assert {:ok, decrypted1} =
               Token.decrypt_aead(shared_secret, frame_id, 0, ciphertext1, auth_tag1)

      assert {:ok, decrypted2} =
               Token.decrypt_aead(shared_secret, frame_id, 1, ciphertext2, auth_tag2)

      assert decrypted1 == plaintext
      assert decrypted2 == plaintext
    end

    test "rejects tampered ciphertext" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      # Tamper with ciphertext
      tampered_ciphertext = <<0>> <> binary_part(ciphertext, 1, byte_size(ciphertext) - 1)

      assert Token.decrypt_aead(
               shared_secret,
               frame_id,
               shard_index,
               tampered_ciphertext,
               auth_tag
             ) == {:error, :invalid_auth_tag}
    end

    test "rejects tampered auth_tag" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      # Tamper with auth_tag
      tampered_auth_tag = <<0>> <> binary_part(auth_tag, 1, byte_size(auth_tag) - 1)

      assert Token.decrypt_aead(
               shared_secret,
               frame_id,
               shard_index,
               ciphertext,
               tampered_auth_tag
             ) == {:error, :invalid_auth_tag}
    end

    test "rejects wrong shared_secret" do
      shared_secret = :crypto.strong_rand_bytes(32)
      wrong_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      assert Token.decrypt_aead(
               wrong_secret,
               frame_id,
               shard_index,
               ciphertext,
               auth_tag
             ) == {:error, :invalid_auth_tag}
    end

    test "rejects wrong frame_id" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      wrong_frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      assert Token.decrypt_aead(
               shared_secret,
               wrong_frame_id,
               shard_index,
               ciphertext,
               auth_tag
             ) == {:error, :invalid_auth_tag}
    end

    test "rejects wrong shard_index" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      wrong_shard_index = 1
      plaintext = "Hello, ChronoMesh!"

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      assert Token.decrypt_aead(
               shared_secret,
               frame_id,
               wrong_shard_index,
               ciphertext,
               auth_tag
             ) == {:error, :invalid_auth_tag}
    end

    test "handles empty plaintext" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = ""

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      assert {:ok, decrypted} =
               Token.decrypt_aead(shared_secret, frame_id, shard_index, ciphertext, auth_tag)

      assert decrypted == plaintext
    end

    test "handles large plaintext" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = String.duplicate("A", 10_000)

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      assert {:ok, decrypted} =
               Token.decrypt_aead(shared_secret, frame_id, shard_index, ciphertext, auth_tag)

      assert decrypted == plaintext
    end

    test "handles binary data" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = :crypto.strong_rand_bytes(1024)

      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      assert {:ok, decrypted} =
               Token.decrypt_aead(shared_secret, frame_id, shard_index, ciphertext, auth_tag)

      assert decrypted == plaintext
    end

    test "auth_tag is always 16 bytes (Poly1305)" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)

      for shard_index <- 0..10 do
        plaintext = "Test #{shard_index}"
        {_ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

        assert byte_size(auth_tag) == 16
      end
    end
  end

  describe "encrypt_payload/decrypt_payload API (concatenated format)" do
    test "encrypt_payload and decrypt_payload use AEAD (concatenated format)" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      ciphertext = Token.encrypt_payload(shared_secret, frame_id, shard_index, plaintext)

      assert {:ok, decrypted} =
               Token.decrypt_payload(shared_secret, frame_id, shard_index, ciphertext)

      assert decrypted == plaintext
    end

    test "encrypt_payload returns concatenated format (ciphertext + auth_tag)" do
      shared_secret = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      shard_index = 0
      plaintext = "Hello, ChronoMesh!"

      # encrypt_payload returns ciphertext + auth_tag concatenated
      concatenated = Token.encrypt_payload(shared_secret, frame_id, shard_index, plaintext)

      # encrypt_aead returns {ciphertext, auth_tag} tuple
      {ciphertext, auth_tag} = Token.encrypt_aead(shared_secret, frame_id, shard_index, plaintext)

      # Concatenated format should equal ciphertext + auth_tag
      expected_concatenated = ciphertext <> auth_tag
      assert concatenated == expected_concatenated

      # Both should decrypt correctly
      assert {:ok, decrypted_concatenated} =
               Token.decrypt_payload(shared_secret, frame_id, shard_index, concatenated)

      assert {:ok, decrypted_aead} =
               Token.decrypt_aead(shared_secret, frame_id, shard_index, ciphertext, auth_tag)

      assert decrypted_concatenated == plaintext
      assert decrypted_aead == plaintext
    end
  end
end
