defmodule ChronoMesh.Token do
  @moduledoc """
  Helpers for encrypting and decrypting per-hop routing tokens and payload chunks.

  Supports both standard ChaCha20 encryption and Authenticated Encryption with Associated Data (AEAD)
  using ChaCha20-Poly1305 for authenticated payloads with integrity verification.
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
    if byte_size(token) < 32 do
      {:error, :invalid_token}
    else
      with <<ephemeral_public::binary-size(32), ciphertext::binary>> <- token,
           true <- byte_size(ephemeral_public) == 32,
           shared_secret <- Keys.compute_shared_secret(ephemeral_public, private_key),
           data <- cipher(:decrypt, shared_secret, frame_id, shard_index, ciphertext),
           {:ok, instruction} <- safe_binary_to_term(data) do
        {:ok, {instruction, shared_secret}}
      else
        _ -> {:error, :invalid_token}
      end
    end
  end

  @spec safe_binary_to_term(binary()) :: {:ok, term()} | {:error, :unsafe_term}
  defp safe_binary_to_term(data) do
    try do
      term = :erlang.binary_to_term(data, [:safe])
      {:ok, term}
    rescue
      ArgumentError ->
        {:error, :unsafe_term}
    catch
      :error, :badarg ->
        {:error, :unsafe_term}
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

  @doc """
  Encrypts a shard payload using ChaCha20-Poly1305 AEAD.

  Returns `{ciphertext, auth_tag}` where `auth_tag` is a 16-byte Poly1305 MAC tag.
  The `auth_tag` must be verified on decryption to ensure message integrity.
  """
  @spec encrypt_aead(binary(), binary(), integer(), binary()) :: {binary(), binary()}
  def encrypt_aead(shared_secret, frame_id, shard_index, plaintext) do
    key_material = shared_secret <> frame_id <> <<shard_index::32>> <> "payload"
    key = derive_key(key_material, "key", 32)
    nonce = derive_key(key_material, "nonce", 12)

    # ChaCha20-Poly1305 encryption with AEAD
    # Associated data is the frame_id and shard_index for authentication
    associated_data = frame_id <> <<shard_index::32>>

    {ciphertext, auth_tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, plaintext, associated_data, true)

    {ciphertext, auth_tag}
  end

  @doc """
  Decrypts and verifies a shard payload using ChaCha20-Poly1305 AEAD.

  Verifies the `auth_tag` to ensure message integrity. Returns `{:ok, plaintext}` if
  verification succeeds, or `{:error, :invalid_auth_tag}` if verification fails.
  """
  @spec decrypt_aead(binary(), binary(), integer(), binary(), binary()) ::
          {:ok, binary()} | {:error, :invalid_auth_tag}
  def decrypt_aead(shared_secret, frame_id, shard_index, ciphertext, auth_tag) do
    key_material = shared_secret <> frame_id <> <<shard_index::32>> <> "payload"
    key = derive_key(key_material, "key", 32)
    nonce = derive_key(key_material, "nonce", 12)

    # ChaCha20-Poly1305 decryption with AEAD verification
    # Associated data is the frame_id and shard_index for authentication
    associated_data = frame_id <> <<shard_index::32>>

    case :crypto.crypto_one_time_aead(
           :chacha20_poly1305,
           key,
           nonce,
           ciphertext,
           associated_data,
           auth_tag,
           false
         ) do
      plaintext when is_binary(plaintext) ->
        {:ok, plaintext}

      :error ->
        {:error, :invalid_auth_tag}
    end
  end

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

  @spec derive_key(binary(), binary(), pos_integer()) :: binary()
  defp derive_key(material, salt, size) do
    hashed = :crypto.hash(:sha256, material <> salt)
    binary_part(hashed, 0, size)
  end
end
