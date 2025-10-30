defmodule ChronoMesh.Token do
  @moduledoc """
  Helpers for encrypting and decrypting per-hop routing tokens and payload chunks.
  """

  alias ChronoMesh.Keys

  @doc """
  Produces an opaque routing token for the next hop and returns it alongside the
  shared secret derived from ECDH.
  """
  @spec encrypt_token(map(), binary(), binary(), integer()) ::
          {:ok, {binary(), binary()}} | {:error, term()}
  def encrypt_token(instruction_map, peer_public_key, frame_id, shard_index) do
    {ephemeral_public, ephemeral_private} = :crypto.generate_key(:ecdh, :x25519)
    shared_secret = Keys.compute_shared_secret(peer_public_key, ephemeral_private)

    ciphertext =
      cipher(
        :encrypt,
        shared_secret,
        frame_id,
        shard_index,
        :erlang.term_to_binary(instruction_map)
      )

    token = <<ephemeral_public::binary, ciphertext::binary>>
    {:ok, {token, shared_secret}}
  end

  @doc """
  Decrypts an incoming routing token using the node's long-term private key.
  """
  @spec decrypt_token(binary(), binary(), binary(), integer()) ::
          {:ok, {map(), binary()}} | {:error, term()}
  def decrypt_token(token, private_key, frame_id, shard_index) do
    with <<ephemeral_public::binary-size(32), ciphertext::binary>> <- token,
         shared_secret <- Keys.compute_shared_secret(ephemeral_public, private_key),
         data <- cipher(:decrypt, shared_secret, frame_id, shard_index, ciphertext),
         instruction <- :erlang.binary_to_term(data) do
      {:ok, {instruction, shared_secret}}
    else
      _ -> {:error, :invalid_token}
    end
  end

  @doc """
  Encrypts a shard payload using the shared secret derived during token exchange.
  """
  @spec encrypt_payload(binary(), binary(), integer(), binary()) :: binary()
  def encrypt_payload(shared_secret, frame_id, shard_index, plaintext) do
    cipher(:encrypt, shared_secret, frame_id, shard_index, plaintext, "payload")
  end

  @doc """
  Decrypts a shard payload using the shared secret derived during token exchange.
  """
  @spec decrypt_payload(binary(), binary(), integer(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def decrypt_payload(shared_secret, frame_id, shard_index, ciphertext) do
    {:ok, cipher(:decrypt, shared_secret, frame_id, shard_index, ciphertext, "payload")}
  end

  @doc false
  @spec cipher(:encrypt | :decrypt, binary(), binary(), integer(), binary(), binary()) :: binary()
  defp cipher(mode, shared_secret, frame_id, shard_index, data, tag \\ "token")

  defp cipher(mode, shared_secret, frame_id, shard_index, data, tag) when is_binary(data) do
    key_material = shared_secret <> frame_id <> <<shard_index::32>> <> tag
    key = derive_key(key_material, "key", 32)
    nonce = derive_key(key_material, "nonce", 16)

    case mode do
      :encrypt -> :crypto.crypto_one_time(:chacha20, key, nonce, data, true)
      :decrypt -> :crypto.crypto_one_time(:chacha20, key, nonce, data, true)
    end
  end

  @doc false
  @spec derive_key(binary(), binary(), pos_integer()) :: binary()
  defp derive_key(material, salt, size) do
    hashed = :crypto.hash(:sha256, material <> salt)
    binary_part(hashed, 0, size)
  end
end
