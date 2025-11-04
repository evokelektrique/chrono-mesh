defmodule ChronoMesh.JoinChallenge do
  @moduledoc """
  Join Challenge module for authenticating new peer introductions.

  Generates and verifies cryptographic challenges for new nodes joining the network.
  Prevents unauthorized nodes from joining without proper authentication.
  """

  require Logger

  alias ChronoMesh.Keys

  @typedoc "Node ID (32-byte binary)"
  @type node_id :: binary()

  @typedoc "Challenge nonce (16-byte binary)"
  @type nonce :: binary()

  @typedoc "Challenge timestamp (milliseconds)"
  @type timestamp :: non_neg_integer()

  @typedoc "Challenge structure"
  @type challenge :: %{
          nonce: nonce(),
          timestamp: timestamp(),
          signature: binary()
        }

  @typedoc "Challenge response"
  @type response :: %{
          challenge_nonce: nonce(),
          proof: binary(),
          signature: binary()
        }

  @doc """
  Generates a challenge for a joining node.

  Creates a challenge with a nonce, timestamp, and signature from the local node.
  The challenge must be responded to within the timeout period.

  Returns `{:ok, challenge}` or `{:error, reason}`.
  """
  @spec generate_challenge(node_id(), binary()) :: {:ok, challenge()} | {:error, term()}
  def generate_challenge(node_id, ed25519_private_key)
      when is_binary(node_id) and byte_size(node_id) == 32 and
             is_binary(ed25519_private_key) and byte_size(ed25519_private_key) == 32 do
    nonce = :crypto.strong_rand_bytes(16)
    timestamp = System.system_time(:millisecond)

    # Create challenge message: node_id || nonce || timestamp
    message = node_id <> nonce <> <<timestamp::64>>
    signature = Keys.sign(message, ed25519_private_key)

    challenge = %{
      nonce: nonce,
      timestamp: timestamp,
      signature: signature
    }

    {:ok, challenge}
  end

  def generate_challenge(_node_id, _ed25519_private_key) do
    {:error, :invalid_arguments}
  end

  @doc """
  Creates a response to a challenge.

  The responding node signs the challenge nonce with their private key as proof.
  Returns `{:ok, response}` or `{:error, reason}`.
  """
  @spec create_response(challenge(), binary()) :: {:ok, response()} | {:error, term()}
  def create_response(challenge, ed25519_private_key)
      when is_map(challenge) and
             is_binary(ed25519_private_key) and byte_size(ed25519_private_key) == 32 do
    # Create proof: sign challenge nonce
    proof = Keys.sign(challenge.nonce, ed25519_private_key)

    # Sign the response: challenge_nonce || proof
    response_message = challenge.nonce <> proof
    signature = Keys.sign(response_message, ed25519_private_key)

    response = %{
      challenge_nonce: challenge.nonce,
      proof: proof,
      signature: signature
    }

    {:ok, response}
  end

  def create_response(_challenge, _ed25519_private_key) do
    {:error, :invalid_arguments}
  end

  @doc """
  Verifies a challenge response.

  Checks that:
  1. The challenge nonce matches
  2. The response signature is valid (using responder's public key)
  3. The challenge hasn't expired (within timeout window)

  Returns `:ok` if valid, `{:error, reason}` otherwise.
  """
  @spec verify_response(
          challenge(),
          response(),
          node_id(),
          binary(),
          non_neg_integer()
        ) :: :ok | {:error, term()}
  def verify_response(challenge, response, responder_node_id, responder_public_key, timeout_ms)
      when is_map(challenge) and is_map(response) and
             is_binary(responder_node_id) and byte_size(responder_node_id) == 32 and
             is_binary(responder_public_key) and byte_size(responder_public_key) == 32 and
             is_integer(timeout_ms) and timeout_ms > 0 do
    # Check challenge nonce matches
    if challenge.nonce != response.challenge_nonce do
      {:error, :nonce_mismatch}
    else
      # Check challenge hasn't expired
      now = System.system_time(:millisecond)
      age = now - challenge.timestamp

      if age > timeout_ms do
        {:error, :challenge_expired}
      else
        # Verify response signature
        response_message = response.challenge_nonce <> response.proof

        if Keys.verify(response_message, response.signature, responder_public_key) do
          :ok
        else
          {:error, :invalid_signature}
        end
      end
    end
  end

  def verify_response(_challenge, _response, _responder_node_id, _responder_public_key, _timeout_ms) do
    {:error, :invalid_arguments}
  end

  @doc """
  Verifies the original challenge signature.

  Checks that the challenge was signed by the challenger (local node).
  """
  @spec verify_challenge_signature(challenge(), node_id(), binary()) :: boolean()
  def verify_challenge_signature(challenge, challenger_node_id, challenger_public_key)
      when is_map(challenge) and
             is_binary(challenger_node_id) and byte_size(challenger_node_id) == 32 and
             is_binary(challenger_public_key) and byte_size(challenger_public_key) == 32 do
    # Reconstruct challenge message
    message = challenger_node_id <> challenge.nonce <> <<challenge.timestamp::64>>

    # Verify signature
    Keys.verify(message, challenge.signature, challenger_public_key)
  end

  def verify_challenge_signature(_challenge, _challenger_node_id, _challenger_public_key) do
    false
  end
end
