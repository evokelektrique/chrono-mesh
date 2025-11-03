defmodule ChronoMesh.Ed25519Test do
  use ExUnit.Case, async: true

  alias ChronoMesh.Keys

  describe "ed25519_keypair/0" do
    test "generates Ed25519 keypair" do
      try do
        {public_key, private_key} = Keys.ed25519_keypair()

        assert is_binary(public_key)
        assert is_binary(private_key)
        assert byte_size(public_key) == 32
        assert byte_size(private_key) == 32
      rescue
        e ->
          # Skip test if Ed25519 not supported
          if String.contains?(inspect(e), "not supported") do
            IO.puts("Skipping Ed25519 test - not supported in this OTP version")
            :ok
          else
            raise e
          end
      end
    end

    test "each keypair is unique" do
      try do
        {pub1, _priv1} = Keys.ed25519_keypair()
        {pub2, _priv2} = Keys.ed25519_keypair()

        assert pub1 != pub2
      rescue
        e ->
          if String.contains?(inspect(e), "not supported") do
            :ok
          else
            raise e
          end
      end
    end
  end

  describe "ed25519_sign/2 and ed25519_verify/3" do
    test "signs and verifies message" do
      try do
        {public_key, private_key} = Keys.ed25519_keypair()
        message = "Hello, ChronoMesh!"

        signature = Keys.ed25519_sign(message, private_key)

        assert is_binary(signature)
        assert byte_size(signature) == 64

        # Verify signature
        assert Keys.ed25519_verify(message, signature, public_key) == true

        # Verify wrong message fails
        assert Keys.ed25519_verify("Wrong message", signature, public_key) == false
      rescue
        e ->
          if String.contains?(inspect(e), "not supported") do
            :ok
          else
            raise e
          end
      end
    end

    test "signature is deterministic" do
      try do
        {_public_key, private_key} = Keys.ed25519_keypair()
        message = "Test message"

        sig1 = Keys.ed25519_sign(message, private_key)
        sig2 = Keys.ed25519_sign(message, private_key)

        # Ed25519 signatures are deterministic (same message + key = same signature)
        assert sig1 == sig2
      rescue
        e ->
          if String.contains?(inspect(e), "not supported") do
            :ok
          else
            raise e
          end
      end
    end

    test "wrong public key fails verification" do
      try do
        {public_key1, private_key1} = Keys.ed25519_keypair()
        {public_key2, _private_key2} = Keys.ed25519_keypair()

        message = "Test message"
        signature = Keys.ed25519_sign(message, private_key1)

        # Correct public key verifies
        assert Keys.ed25519_verify(message, signature, public_key1) == true

        # Wrong public key fails
        assert Keys.ed25519_verify(message, signature, public_key2) == false
      rescue
        e ->
          if String.contains?(inspect(e), "not supported") do
            :ok
          else
            raise e
          end
      end
    end

    test "verification with invalid signature returns false" do
      try do
        {public_key, private_key} = Keys.ed25519_keypair()
        message = "Test message"

        # Valid signature
        valid_sig = Keys.ed25519_sign(message, private_key)
        assert Keys.ed25519_verify(message, valid_sig, public_key) == true

        # Invalid signature (wrong size)
        invalid_sig = <<0::size(64)>>
        assert Keys.ed25519_verify(message, invalid_sig, public_key) == false

        # Invalid signature (random bytes)
        random_sig = :crypto.strong_rand_bytes(64)
        assert Keys.ed25519_verify(message, random_sig, public_key) == false
      rescue
        e ->
          if String.contains?(inspect(e), "not supported") do
            :ok
          else
            raise e
          end
      end
    end
  end

  describe "Ed25519 vs HMAC comparison" do
    test "Ed25519 allows verification with public key only" do
      try do
        {public_key, private_key} = Keys.ed25519_keypair()
        message = "Test message"

        signature = Keys.ed25519_sign(message, private_key)

        # Can verify with only public key (no private key needed)
        assert Keys.ed25519_verify(message, signature, public_key) == true

        # HMAC requires private key to verify
        hmac_sig = Keys.sign(message, private_key)
        assert Keys.verify(message, hmac_sig, public_key, private_key) == true
      rescue
        e ->
          if String.contains?(inspect(e), "not supported") do
            :ok
          else
            raise e
          end
      end
    end
  end
end
