defmodule ChronoMesh.JoinChallengeTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{JoinChallenge, Keys, Config}

  # Helper to generate test keys
  defp generate_test_keys do
    # Generate proper Ed25519 keypair using Keys module
    # Returns {public_key, private_key} but we need {private_key, public_key}
    {public_key, private_key} = Keys.keypair()
    {private_key, public_key}
  end

  describe "JoinChallenge.generate_challenge/2" do
    test "generates valid challenge with correct structure" do
      node_id = :crypto.strong_rand_bytes(32)
      {private_key, _public_key} = generate_test_keys()

      assert {:ok, challenge} = JoinChallenge.generate_challenge(node_id, private_key)

      assert Map.has_key?(challenge, :nonce)
      assert Map.has_key?(challenge, :timestamp)
      assert Map.has_key?(challenge, :signature)

      assert byte_size(challenge.nonce) == 16
      assert is_integer(challenge.timestamp)
      assert is_binary(challenge.signature)
    end

    test "generates different nonces for same node_id" do
      node_id = :crypto.strong_rand_bytes(32)
      {private_key, _public_key} = generate_test_keys()

      {:ok, challenge1} = JoinChallenge.generate_challenge(node_id, private_key)
      Process.sleep(1) # Ensure different timestamp
      {:ok, challenge2} = JoinChallenge.generate_challenge(node_id, private_key)

      assert challenge1.nonce != challenge2.nonce
      assert challenge1.timestamp != challenge2.timestamp
    end

    test "returns error for invalid node_id size" do
      invalid_node_id = :crypto.strong_rand_bytes(16) # Wrong size
      {private_key, _public_key} = generate_test_keys()

      assert {:error, :invalid_arguments} = JoinChallenge.generate_challenge(invalid_node_id, private_key)
    end

    test "returns error for invalid private_key size" do
      node_id = :crypto.strong_rand_bytes(32)
      invalid_private_key = :crypto.strong_rand_bytes(16) # Wrong size

      assert {:error, :invalid_arguments} = JoinChallenge.generate_challenge(node_id, invalid_private_key)
    end
  end

  describe "JoinChallenge.create_response/2" do
    test "creates valid response to challenge" do
      node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, _} = generate_test_keys()

      {:ok, challenge} = JoinChallenge.generate_challenge(node_id, challenger_private_key)
      assert {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      assert Map.has_key?(response, :challenge_nonce)
      assert Map.has_key?(response, :proof)
      assert Map.has_key?(response, :signature)

      assert response.challenge_nonce == challenge.nonce
      assert is_binary(response.proof)
      assert is_binary(response.signature)
    end

    test "response includes correct challenge_nonce" do
      node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, _} = generate_test_keys()

      {:ok, challenge} = JoinChallenge.generate_challenge(node_id, challenger_private_key)
      {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      assert response.challenge_nonce == challenge.nonce
    end

    test "returns error for invalid challenge structure" do
      {responder_private_key, _} = generate_test_keys()
      invalid_challenge = %{invalid: "challenge"}

      # create_response will try to access challenge.nonce which will raise KeyError
      assert_raise KeyError, fn ->
        JoinChallenge.create_response(invalid_challenge, responder_private_key)
      end
    end

    test "returns error for invalid private_key size" do
      node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      invalid_private_key = :crypto.strong_rand_bytes(16) # Wrong size

      {:ok, challenge} = JoinChallenge.generate_challenge(node_id, challenger_private_key)
      assert {:error, :invalid_arguments} = JoinChallenge.create_response(challenge, invalid_private_key)
    end
  end

  describe "JoinChallenge.verify_response/5" do
    test "verifies valid response successfully" do
      responder_node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _challenger_public_key} = generate_test_keys()
      {responder_private_key, responder_public_key} = generate_test_keys()

      # Generate challenge for responder_node_id
      {:ok, challenge} = JoinChallenge.generate_challenge(responder_node_id, challenger_private_key)
      # Responder creates response
      {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      timeout_ms = 30_000
      # Verify response: challenge, response, responder_node_id, responder_public_key, timeout
      assert :ok = JoinChallenge.verify_response(challenge, response, responder_node_id, responder_public_key, timeout_ms)
    end

    test "rejects response with nonce mismatch" do
      node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, responder_public_key} = generate_test_keys()

      {:ok, challenge} = JoinChallenge.generate_challenge(node_id, challenger_private_key)
      {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      # Modify response nonce
      invalid_response = %{response | challenge_nonce: :crypto.strong_rand_bytes(16)}

      timeout_ms = 30_000
      assert {:error, :nonce_mismatch} = JoinChallenge.verify_response(challenge, invalid_response, node_id, responder_public_key, timeout_ms)
    end

    test "rejects expired challenge" do
      node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, responder_public_key} = generate_test_keys()

      # Create challenge with old timestamp
      old_timestamp = System.system_time(:millisecond) - 60_000
      nonce = :crypto.strong_rand_bytes(16)
      message = node_id <> nonce <> <<old_timestamp::64>>
      signature = Keys.sign(message, challenger_private_key)

      challenge = %{
        nonce: nonce,
        timestamp: old_timestamp,
        signature: signature
      }

      {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      timeout_ms = 30_000 # 30 seconds
      assert {:error, :challenge_expired} = JoinChallenge.verify_response(challenge, response, node_id, responder_public_key, timeout_ms)
    end

    test "accepts challenge within timeout window" do
      responder_node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, responder_public_key} = generate_test_keys()

      # Create challenge with recent timestamp (5 seconds ago)
      recent_timestamp = System.system_time(:millisecond) - 5_000
      nonce = :crypto.strong_rand_bytes(16)
      # Challenge message: responder_node_id || nonce || timestamp
      message = responder_node_id <> nonce <> <<recent_timestamp::64>>
      signature = Keys.sign(message, challenger_private_key)

      challenge = %{
        nonce: nonce,
        timestamp: recent_timestamp,
        signature: signature
      }

      {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      timeout_ms = 30_000 # 30 seconds
      assert :ok = JoinChallenge.verify_response(challenge, response, responder_node_id, responder_public_key, timeout_ms)
    end

    test "rejects response with invalid signature" do
      node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, responder_public_key} = generate_test_keys()
      {wrong_public_key, _} = generate_test_keys()

      {:ok, challenge} = JoinChallenge.generate_challenge(node_id, challenger_private_key)
      {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      timeout_ms = 30_000
      # Use wrong public key for verification
      assert {:error, :invalid_signature} = JoinChallenge.verify_response(challenge, response, node_id, wrong_public_key, timeout_ms)
    end

    test "returns error for invalid arguments" do
      node_id = :crypto.strong_rand_bytes(32)
      invalid_node_id = :crypto.strong_rand_bytes(16)
      {_, public_key} = generate_test_keys()

      challenge = %{nonce: :crypto.strong_rand_bytes(16), timestamp: System.system_time(:millisecond), signature: <<>>}
      response = %{challenge_nonce: challenge.nonce, proof: <<>>, signature: <<>>}

      assert {:error, :invalid_arguments} = JoinChallenge.verify_response(challenge, response, invalid_node_id, public_key, 30_000)
    end
  end

  describe "JoinChallenge.verify_challenge_signature/3" do
    test "verifies valid challenge signature" do
      challenger_node_id = :crypto.strong_rand_bytes(32)
      {private_key, public_key} = generate_test_keys()

      {:ok, challenge} = JoinChallenge.generate_challenge(challenger_node_id, private_key)

      # verify_challenge_signature uses challenger_node_id and challenger_public_key
      assert JoinChallenge.verify_challenge_signature(challenge, challenger_node_id, public_key) == true
    end

    test "rejects challenge with invalid signature" do
      challenger_node_id = :crypto.strong_rand_bytes(32)
      {private_key, _public_key} = generate_test_keys()
      {_, wrong_public_key} = generate_test_keys()

      {:ok, challenge} = JoinChallenge.generate_challenge(challenger_node_id, private_key)

      assert JoinChallenge.verify_challenge_signature(challenge, challenger_node_id, wrong_public_key) == false
    end

    test "rejects challenge with wrong node_id" do
      challenger_node_id = :crypto.strong_rand_bytes(32)
      wrong_node_id = :crypto.strong_rand_bytes(32)
      {private_key, public_key} = generate_test_keys()

      {:ok, challenge} = JoinChallenge.generate_challenge(challenger_node_id, private_key)

      assert JoinChallenge.verify_challenge_signature(challenge, wrong_node_id, public_key) == false
    end

    test "returns false for invalid arguments" do
      challenge = %{nonce: :crypto.strong_rand_bytes(16), timestamp: System.system_time(:millisecond), signature: <<>>}
      invalid_node_id = :crypto.strong_rand_bytes(16)
      {_, public_key} = generate_test_keys()

      assert JoinChallenge.verify_challenge_signature(challenge, invalid_node_id, public_key) == false
    end
  end

  describe "Config join challenge integration" do
    test "join_challenge_enabled? returns false by default" do
      config = %{}
      assert Config.join_challenge_enabled?(config) == false
    end

    test "join_challenge_enabled? returns true when enabled" do
      config = %{"join_challenge" => %{"enabled" => true}}
      assert Config.join_challenge_enabled?(config) == true
    end

    test "join_challenge_timeout_ms returns default value" do
      config = %{}
      assert Config.join_challenge_timeout_ms(config) == 30_000
    end

    test "join_challenge_timeout_ms returns custom value from config" do
      config = %{"join_challenge" => %{"timeout_ms" => 60_000}}
      assert Config.join_challenge_timeout_ms(config) == 60_000
    end

    test "join_challenge_difficulty returns default value" do
      config = %{}
      assert Config.join_challenge_difficulty(config) == 1
    end

    test "join_challenge_difficulty returns custom value from config" do
      config = %{"join_challenge" => %{"difficulty" => 5}}
      assert Config.join_challenge_difficulty(config) == 5
    end
  end

  describe "Join challenge full flow" do
    test "complete challenge-response flow with valid keys" do
      challenger_node_id = :crypto.strong_rand_bytes(32)
      responder_node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, challenger_public_key} = generate_test_keys()
      {responder_private_key, responder_public_key} = generate_test_keys()

      # Step 1: Challenger generates challenge for responder
      # The challenge message is: responder_node_id || nonce || timestamp, signed by challenger
      assert {:ok, challenge} = JoinChallenge.generate_challenge(responder_node_id, challenger_private_key)

      # Step 2: Verify challenge signature
      # verify_challenge_signature reconstructs the message using the node_id parameter
      # Since the challenge was created with responder_node_id, we verify with responder_node_id
      # and challenger_public_key (the one who signed it)
      assert JoinChallenge.verify_challenge_signature(challenge, responder_node_id, challenger_public_key) == true

      # Step 3: Responder creates response
      assert {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      # Step 4: Challenger verifies response
      timeout_ms = 30_000
      assert :ok = JoinChallenge.verify_response(challenge, response, responder_node_id, responder_public_key, timeout_ms)
    end

    test "challenge-response flow fails with wrong responder" do
      challenger_node_id = :crypto.strong_rand_bytes(32)
      responder_node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, _responder_public_key} = generate_test_keys()
      {_, wrong_public_key} = generate_test_keys()

      # Step 1: Challenger generates challenge
      {:ok, challenge} = JoinChallenge.generate_challenge(responder_node_id, challenger_private_key)

      # Step 2: Responder creates response
      {:ok, response} = JoinChallenge.create_response(challenge, responder_private_key)

      # Step 3: Challenger verifies with wrong public key (should fail)
      timeout_ms = 30_000
      assert {:error, :invalid_signature} = JoinChallenge.verify_response(challenge, response, responder_node_id, wrong_public_key, timeout_ms)
    end
  end

  describe "Join challenge edge cases" do
    test "handles nil arguments gracefully" do
      {private_key, _} = generate_test_keys()

      assert {:error, :invalid_arguments} = JoinChallenge.generate_challenge(nil, private_key)
      assert {:error, :invalid_arguments} = JoinChallenge.generate_challenge(:crypto.strong_rand_bytes(32), nil)
    end

    test "handles empty binary arguments" do
      empty_binary = <<>>
      {private_key, _} = generate_test_keys()

      assert {:error, :invalid_arguments} = JoinChallenge.generate_challenge(empty_binary, private_key)
      assert {:error, :invalid_arguments} = JoinChallenge.generate_challenge(:crypto.strong_rand_bytes(32), empty_binary)
    end

    test "challenge timestamp is monotonic" do
      node_id = :crypto.strong_rand_bytes(32)
      {private_key, _} = generate_test_keys()

      {:ok, challenge1} = JoinChallenge.generate_challenge(node_id, private_key)
      Process.sleep(10)
      {:ok, challenge2} = JoinChallenge.generate_challenge(node_id, private_key)

      assert challenge2.timestamp >= challenge1.timestamp
    end

    test "response proof is unique per challenge" do
      node_id = :crypto.strong_rand_bytes(32)
      {challenger_private_key, _} = generate_test_keys()
      {responder_private_key, _} = generate_test_keys()

      {:ok, challenge1} = JoinChallenge.generate_challenge(node_id, challenger_private_key)
      {:ok, challenge2} = JoinChallenge.generate_challenge(node_id, challenger_private_key)

      {:ok, response1} = JoinChallenge.create_response(challenge1, responder_private_key)
      {:ok, response2} = JoinChallenge.create_response(challenge2, responder_private_key)

      # Different challenges should produce different proofs
      assert response1.proof != response2.proof
      assert response1.signature != response2.signature
    end
  end
end
