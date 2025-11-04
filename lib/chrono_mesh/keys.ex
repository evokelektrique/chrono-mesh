defmodule ChronoMesh.Keys do
  @moduledoc """
  Keypair generation and persistence utilities.
  """

  @doc """
  Generates a new X25519 keypair for ECDH.
  """
  @spec generate() :: {binary(), binary()}
  def generate do
    :crypto.generate_key(:ecdh, :x25519)
  end

  @doc """
  Writes the private key to disk (PEM-like format).
  """
  @spec write_private_key!(Path.t(), binary()) :: :ok
  def write_private_key!(path, private_key) do
    body = Base.encode64(private_key)

    pem = """
    -----BEGIN CHRONO_MESH PRIVATE KEY-----
    #{body}
    -----END CHRONO_MESH PRIVATE KEY-----
    """

    File.write!(path, pem)
  end

  @doc """
  Writes the public key to disk.
  """
  @spec write_public_key!(Path.t(), binary()) :: :ok
  def write_public_key!(path, public_key) do
    body = Base.encode64(public_key)

    pem = """
    -----BEGIN CHRONO_MESH PUBLIC KEY-----
    #{body}
    -----END CHRONO_MESH PUBLIC KEY-----
    """

    File.write!(path, pem)
  end

  @doc """
  Reads a public key from disk.
  """
  @spec read_public_key!(Path.t()) :: binary()
  def read_public_key!(path) do
    path
    |> File.read!()
    |> extract_pem_body()
  end

  @doc """
  Reads a private key from disk.
  """
  @spec read_private_key!(Path.t()) :: binary()
  def read_private_key!(path) do
    path
    |> File.read!()
    |> extract_pem_body()
  end

  @doc """
  Computes the shared secret using the local private key and the peer's public key.
  """
  @spec compute_shared_secret(binary(), binary()) :: binary()
  def compute_shared_secret(peer_public_key, private_key) do
    :crypto.compute_key(:ecdh, peer_public_key, private_key, :x25519)
  end

  @doc """
  Generates a new Ed25519 keypair for digital signatures.

  Returns `{public_key, private_key}` where both are 32-byte binaries.
  """
  @spec keypair() :: {binary(), binary()}
  def keypair do
    try do
      :crypto.generate_key(:eddsa, :ed25519)
    rescue
      ArgumentError ->
        raise "Ed25519 not supported in this OTP version. Requires OTP 22+"
    catch
      :error, :function_clause ->
        raise "Ed25519 not supported in this OTP version. Requires OTP 22+"
    end
  end

  @doc """
  Signs a message using Ed25519 with the private key.

  Returns a 64-byte signature that can be verified with only the public key.
  """
  @spec sign(binary(), binary()) :: binary()
  def sign(message, private_key) do
    try do
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    rescue
      ArgumentError ->
        raise "Ed25519 signing failed. Invalid key or message."
    catch
      :error, reason ->
        raise "Ed25519 signing failed: #{inspect(reason)}"
    end
  end

  @doc """
  Verifies an Ed25519 signature using only the public key.

  Returns `true` if the signature is valid, `false` otherwise.
  """
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(message, signature, public_key) do
    try do
      :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
    rescue
      ArgumentError ->
        false
    catch
      :error, _ ->
        false
    end
  end

  @doc """
  Derives a node ID from a public key.

  Uses SHA256 hash of the public key to create a stable 32-byte node_id.
  """
  @spec node_id_from_public_key(binary()) :: binary()
  def node_id_from_public_key(public_key) do
    :crypto.hash(:sha256, public_key)
  end

  @spec extract_pem_body(binary()) :: binary()
  defp extract_pem_body(pem) do
    pem
    |> String.split("\n")
    |> Enum.reject(&String.starts_with?(&1, "-----"))
    |> Enum.join("")
    |> Base.decode64!()
  end
end
