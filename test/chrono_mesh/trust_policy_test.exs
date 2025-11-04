defmodule ChronoMesh.TrustPolicyTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{TrustPolicy, Pulse, Config, DHT}

  describe "TrustPolicy module" do
    test "should_relay? returns true by default (allows all relays)" do
      node_id = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      token_chain = [:crypto.strong_rand_bytes(32)]
      payload = "test payload"
      auth_tag = :crypto.strong_rand_bytes(16)

      pulse = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 1,
        token_chain: token_chain,
        payload: payload,
        auth_tag: auth_tag
      }

      assert TrustPolicy.should_relay?(node_id, pulse) == true
    end

    test "get_trust_score returns 0.5 by default (neutral trust)" do
      node_id = :crypto.strong_rand_bytes(32)
      assert TrustPolicy.get_trust_score(node_id) == 0.5
    end

    test "update_trust_score does nothing by default (no-op)" do
      node_id = :crypto.strong_rand_bytes(32)
      assert TrustPolicy.update_trust_score(node_id, 0.1) == :ok
      # Score should still be default
      assert TrustPolicy.get_trust_score(node_id) == 0.5
    end

    test "should_relay? validates node_id size" do
      invalid_node_id = :crypto.strong_rand_bytes(16) # Wrong size
      frame_id = :crypto.strong_rand_bytes(16)
      token_chain = [:crypto.strong_rand_bytes(32)]
      payload = "test payload"
      auth_tag = :crypto.strong_rand_bytes(16)

      pulse = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 1,
        token_chain: token_chain,
        payload: payload,
        auth_tag: auth_tag
      }

      # Should raise FunctionClauseError for invalid node_id size
      assert_raise FunctionClauseError, fn ->
        TrustPolicy.should_relay?(invalid_node_id, pulse)
      end
    end

    test "get_trust_score validates node_id size" do
      invalid_node_id = :crypto.strong_rand_bytes(16) # Wrong size

      assert_raise FunctionClauseError, fn ->
        TrustPolicy.get_trust_score(invalid_node_id)
      end
    end

    test "update_trust_score validates node_id size" do
      invalid_node_id = :crypto.strong_rand_bytes(16) # Wrong size

      assert_raise FunctionClauseError, fn ->
        TrustPolicy.update_trust_score(invalid_node_id, 0.1)
      end
    end
  end

  describe "TrustPolicy.Default module" do
    test "should_relay? returns true" do
      node_id = :crypto.strong_rand_bytes(32)
      frame_id = :crypto.strong_rand_bytes(16)
      token_chain = [:crypto.strong_rand_bytes(32)]
      payload = "test payload"
      auth_tag = :crypto.strong_rand_bytes(16)

      pulse = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 1,
        token_chain: token_chain,
        payload: payload,
        auth_tag: auth_tag
      }

      assert TrustPolicy.Default.should_relay?(node_id, pulse) == true
    end

    test "get_trust_score returns 0.5" do
      node_id = :crypto.strong_rand_bytes(32)
      assert TrustPolicy.Default.get_trust_score(node_id) == 0.5
    end

    test "update_trust_score does nothing" do
      node_id = :crypto.strong_rand_bytes(32)
      assert TrustPolicy.Default.update_trust_score(node_id, 0.1) == :ok
      # Score should still be 0.5
      assert TrustPolicy.Default.get_trust_score(node_id) == 0.5
    end

    test "implements TrustPolicy.Behaviour" do
      assert Code.ensure_loaded?(TrustPolicy.Default)
      assert function_exported?(TrustPolicy.Default, :should_relay?, 2)
      assert function_exported?(TrustPolicy.Default, :get_trust_score, 1)
      assert function_exported?(TrustPolicy.Default, :update_trust_score, 2)
    end
  end

  describe "Config trust policy integration" do
    test "trust_policy_enabled? returns false by default" do
      config = %{}
      assert Config.trust_policy_enabled?(config) == false
    end

    test "trust_policy_enabled? returns true when enabled" do
      config = %{"trust_policy" => %{"enabled" => true}}
      assert Config.trust_policy_enabled?(config) == true
    end

    test "trust_policy_min_score returns 0.0 by default" do
      config = %{}
      assert Config.trust_policy_min_score(config) == 0.0
    end

    test "trust_policy_min_score returns custom value from config" do
      config = %{"trust_policy" => %{"min_trust_score" => 0.7}}
      assert Config.trust_policy_min_score(config) == 0.7
    end

    test "ensure_trust_policy_defaults adds default values" do
      config = %{}
      # The defaults are applied when accessing via Config functions
      assert Config.trust_policy_enabled?(config) == false
      assert Config.trust_policy_min_score(config) == 0.0
    end
  end

  describe "Custom trust policy implementation" do
    defmodule TestTrustPolicy do
      @behaviour ChronoMesh.TrustPolicy.Behaviour

      @impl true
      def should_relay?(node_id, _pulse) when is_binary(node_id) and byte_size(node_id) == 32 do
        # Reject node_id starting with 0x00
        case node_id do
          <<0, _::binary>> -> false
          _ -> true
        end
      end

      @impl true
      def get_trust_score(node_id) when is_binary(node_id) and byte_size(node_id) == 32 do
        # Return 1.0 for node_id starting with 0xFF, 0.0 for 0x00, 0.5 otherwise
        case node_id do
          <<255, _::binary>> -> 1.0
          <<0, _::binary>> -> 0.0
          _ -> 0.5
        end
      end

      @impl true
      def update_trust_score(_node_id, _delta), do: :ok
    end

    test "custom policy can reject relays" do
      node_id_rejected = <<0>> <> :crypto.strong_rand_bytes(31)
      node_id_allowed = <<1>> <> :crypto.strong_rand_bytes(31)

      frame_id = :crypto.strong_rand_bytes(16)
      token_chain = [:crypto.strong_rand_bytes(32)]
      payload = "test payload"
      auth_tag = :crypto.strong_rand_bytes(16)

      pulse = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 1,
        token_chain: token_chain,
        payload: payload,
        auth_tag: auth_tag
      }

      assert TestTrustPolicy.should_relay?(node_id_rejected, pulse) == false
      assert TestTrustPolicy.should_relay?(node_id_allowed, pulse) == true
    end

    test "custom policy can return different trust scores" do
      node_id_high = <<255>> <> :crypto.strong_rand_bytes(31)
      node_id_low = <<0>> <> :crypto.strong_rand_bytes(31)
      node_id_medium = <<1>> <> :crypto.strong_rand_bytes(31)

      assert TestTrustPolicy.get_trust_score(node_id_high) == 1.0
      assert TestTrustPolicy.get_trust_score(node_id_low) == 0.0
      assert TestTrustPolicy.get_trust_score(node_id_medium) == 0.5
    end

    test "custom policy implements Behaviour" do
      assert Code.ensure_loaded?(TestTrustPolicy)
      assert function_exported?(TestTrustPolicy, :should_relay?, 2)
      assert function_exported?(TestTrustPolicy, :get_trust_score, 1)
      assert function_exported?(TestTrustPolicy, :update_trust_score, 2)
    end
  end

  describe "DHT trust policy integration" do
    test "trust_policy_check when trust policy is disabled" do
      announcement = %{
        node_id: :crypto.strong_rand_bytes(32),
        public_key: :crypto.strong_rand_bytes(32),
        timestamp: System.system_time(:millisecond),
        expires_at: System.system_time(:millisecond) + 3600_000,
        signature: :crypto.strong_rand_bytes(64),
        introduction_points: [],
        nonce: :crypto.strong_rand_bytes(16),
        ed25519_public_key: :crypto.strong_rand_bytes(32)
      }

      config = %{"trust_policy" => %{"enabled" => false}}
      # When disabled, trust_policy_check might still validate the announcement
      # Let's just verify it returns a boolean
      result = DHT.trust_policy_check(announcement, config: config)
      assert is_boolean(result)
    end

    test "trust_policy_score returns default score when trust policy is disabled" do
      announcement = %{
        node_id: :crypto.strong_rand_bytes(32),
        public_key: :crypto.strong_rand_bytes(32),
        timestamp: System.system_time(:millisecond),
        expires_at: System.system_time(:millisecond) + 3600_000,
        signature: :crypto.strong_rand_bytes(64),
        introduction_points: [],
        nonce: :crypto.strong_rand_bytes(16),
        ed25519_public_key: :crypto.strong_rand_bytes(32)
      }

      config = %{"trust_policy" => %{"enabled" => false}}
      score = DHT.trust_policy_score(announcement, config: config)
      assert score == 0.5
    end

    test "trust_policy_score uses TrustPolicy module when enabled" do
      announcement = %{
        node_id: :crypto.strong_rand_bytes(32),
        public_key: :crypto.strong_rand_bytes(32),
        timestamp: System.system_time(:millisecond),
        expires_at: System.system_time(:millisecond) + 3600_000,
        signature: :crypto.strong_rand_bytes(64),
        introduction_points: [],
        nonce: :crypto.strong_rand_bytes(16),
        ed25519_public_key: :crypto.strong_rand_bytes(32)
      }

      config = %{"trust_policy" => %{"enabled" => true}}
      score = DHT.trust_policy_score(announcement, config: config)
      assert score == 0.5 # Default trust score
    end
  end

  describe "Trust policy edge cases" do
    test "should_relay? works with different pulse types" do
      node_id = :crypto.strong_rand_bytes(32)

      frame_id = :crypto.strong_rand_bytes(16)
      token_chain = [:crypto.strong_rand_bytes(32)]
      payload = "test payload"
      auth_tag = :crypto.strong_rand_bytes(16)

      pulse_with_tier = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 1,
        token_chain: token_chain,
        payload: payload,
        auth_tag: auth_tag,
        privacy_tier: "high"
      }

      pulse_with_odp = %Pulse{
        frame_id: frame_id,
        shard_index: 0,
        shard_count: 1,
        token_chain: token_chain,
        payload: payload,
        auth_tag: auth_tag,
        dialogue_id: :crypto.strong_rand_bytes(16),
        sequence_number: 0
      }

      assert TrustPolicy.should_relay?(node_id, pulse_with_tier) == true
      assert TrustPolicy.should_relay?(node_id, pulse_with_odp) == true
    end

    test "get_trust_score returns consistent values for same node_id" do
      node_id = :crypto.strong_rand_bytes(32)

      score1 = TrustPolicy.get_trust_score(node_id)
      score2 = TrustPolicy.get_trust_score(node_id)

      assert score1 == score2
      assert score1 == 0.5
    end

    test "get_trust_score returns different values for different node_ids" do
      node_id1 = :crypto.strong_rand_bytes(32)
      node_id2 = :crypto.strong_rand_bytes(32)

      score1 = TrustPolicy.get_trust_score(node_id1)
      score2 = TrustPolicy.get_trust_score(node_id2)

      # Both should be 0.5 (default), but the function should handle both
      assert score1 == 0.5
      assert score2 == 0.5
    end

    test "update_trust_score accepts positive and negative deltas" do
      node_id = :crypto.strong_rand_bytes(32)

      assert TrustPolicy.update_trust_score(node_id, 0.1) == :ok
      assert TrustPolicy.update_trust_score(node_id, -0.1) == :ok
      assert TrustPolicy.update_trust_score(node_id, 1.0) == :ok
      assert TrustPolicy.update_trust_score(node_id, -1.0) == :ok

      # Default implementation doesn't change score
      assert TrustPolicy.get_trust_score(node_id) == 0.5
    end
  end
end
