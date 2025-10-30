defmodule ChronoMesh.TokenTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.{Keys, Token}

  test "encrypt_token/4 and decrypt_token/4 round-trip instructions" do
    {peer_public, peer_private} = Keys.generate()
    frame_id = :crypto.strong_rand_bytes(16)
    instruction = %{instruction: :forward, host: "relay", port: 4_001}

    {:ok, {token, shared_secret}} =
      Token.encrypt_token(instruction, peer_public, frame_id, 0)

    assert byte_size(token) > 32

    {:ok, {decoded_instruction, decoded_secret}} =
      Token.decrypt_token(token, peer_private, frame_id, 0)

    assert decoded_instruction == instruction
    assert decoded_secret == shared_secret
  end

  test "encrypt_payload/4 and decrypt_payload/4 round-trip" do
    {peer_public, peer_private} = Keys.generate()
    frame_id = :crypto.strong_rand_bytes(16)

    {:ok, {token, shared_secret}} =
      Token.encrypt_token(%{instruction: :deliver}, peer_public, frame_id, 1)

    assert is_binary(token)

    plaintext = "hello cadence"

    ciphertext = Token.encrypt_payload(shared_secret, frame_id, 1, plaintext)
    assert {:ok, ^plaintext} = Token.decrypt_payload(shared_secret, frame_id, 1, ciphertext)

    # Receiver-side shared secret should match after decryption
    {:ok, {_instruction, receiver_secret}} =
      Token.decrypt_token(token, peer_private, frame_id, 1)

    assert Token.decrypt_payload(receiver_secret, frame_id, 1, ciphertext) == {:ok, plaintext}
  end
end
