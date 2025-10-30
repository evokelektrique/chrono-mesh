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

  @doc false
  @spec extract_pem_body(binary()) :: binary()
  defp extract_pem_body(pem) do
    pem
    |> String.split("\n")
    |> Enum.reject(&String.starts_with?(&1, "-----"))
    |> Enum.join("")
    |> Base.decode64!()
  end
end
