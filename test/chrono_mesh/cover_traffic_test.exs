defmodule ChronoMesh.CoverTrafficTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.CoverTraffic

  describe "generate_dummy_pulse/0" do
    test "generates a valid pulse structure" do
      pulse = CoverTraffic.generate_dummy_pulse()

      assert pulse.frame_id != nil
      assert is_binary(pulse.frame_id)
      assert byte_size(pulse.frame_id) == 16

      assert pulse.payload != nil
      assert is_binary(pulse.payload)
      assert byte_size(pulse.payload) >= 32 and byte_size(pulse.payload) <= 64

      assert pulse.auth_tag != nil
      assert is_binary(pulse.auth_tag)
      assert byte_size(pulse.auth_tag) == 16
    end

    test "generates random frame_ids (not duplicates)" do
      pulse1 = CoverTraffic.generate_dummy_pulse()
      pulse2 = CoverTraffic.generate_dummy_pulse()

      # Very unlikely to get duplicate 16-byte random values
      assert pulse1.frame_id != pulse2.frame_id
    end

    test "generates randomized payloads" do
      pulse1 = CoverTraffic.generate_dummy_pulse()
      pulse2 = CoverTraffic.generate_dummy_pulse()

      assert pulse1.payload != pulse2.payload
    end

    test "includes token chain with 1-2 tokens" do
      pulse = CoverTraffic.generate_dummy_pulse()

      assert is_list(pulse.token_chain)
      assert length(pulse.token_chain) in [1, 2]
    end

    test "sets correct pulse metadata" do
      pulse = CoverTraffic.generate_dummy_pulse()

      assert pulse.shard_index == 0
      assert pulse.shard_count == 1
      assert pulse.fec_enabled == false
      assert pulse.parity_count == 0
      assert pulse.data_shard_count == 1
      assert pulse.sequence_number == nil
      assert pulse.dialogue_id == nil
      assert pulse.privacy_tier == "low"
    end
  end

  describe "generate_token_chain/1" do
    test "generates correct number of tokens" do
      for count <- [1, 2, 3, 5, 10] do
        tokens = CoverTraffic.generate_token_chain(count)

        assert is_list(tokens)
        assert length(tokens) == count
      end
    end

    test "generates random tokens as binary" do
      tokens = CoverTraffic.generate_token_chain(3)

      Enum.each(tokens, fn token ->
        assert is_binary(token)
        assert byte_size(token) == 80
      end)
    end

    test "generates unique tokens within same chain" do
      tokens = CoverTraffic.generate_token_chain(5)

      # Check for uniqueness
      unique_tokens = Enum.uniq(tokens)
      assert length(unique_tokens) == length(tokens)
    end

    test "generates different chains with different tokens" do
      chain1 = CoverTraffic.generate_token_chain(2)
      chain2 = CoverTraffic.generate_token_chain(2)

      assert chain1 != chain2
    end

  end

  describe "generate_for_wave/3 - configuration handling" do
    test "returns empty list when cover_traffic disabled" do
      config = %{"cover_traffic" => %{"enabled" => false}}
      local_node_id = "test_node"

      result = CoverTraffic.generate_for_wave(config, local_node_id, 5)

      assert result == []
    end

    test "returns empty list when cover_traffic is nil" do
      config = %{}
      local_node_id = "test_node"

      result = CoverTraffic.generate_for_wave(config, local_node_id, 5)

      assert result == []
    end

    test "returns empty list for invalid enabled value" do
      config = %{"cover_traffic" => %{"enabled" => "maybe"}}
      local_node_id = "test_node"

      result = CoverTraffic.generate_for_wave(config, local_node_id, 5)

      assert result == []
    end

    test "generates dummies when enabled is true" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 5
        }
      }

      local_node_id = "test_node"
      batch_size = 2

      result = CoverTraffic.generate_for_wave(config, local_node_id, batch_size)

      assert is_list(result)
      assert length(result) == 3
    end
  end

  describe "generate_for_wave/3 - batching logic" do
    test "generates zero dummies when batch meets minimum" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 3
        }
      }

      local_node_id = "test_node"
      batch_size = 5

      result = CoverTraffic.generate_for_wave(config, local_node_id, batch_size)

      # batch_size (5) >= min_pulses_per_wave (3)
      assert result == []
    end

    test "generates dummies up to minimum threshold" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 10
        }
      }

      local_node_id = "test_node"
      batch_size = 3

      result = CoverTraffic.generate_for_wave(config, local_node_id, batch_size)

      # Should generate 10 - 3 = 7 dummies
      assert length(result) == 7
    end

    test "uses default min_pulses_per_wave when not configured" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true
        }
      }

      local_node_id = "test_node"
      batch_size = 0

      result = CoverTraffic.generate_for_wave(config, local_node_id, batch_size)

      # Default is 1, so should generate 1 dummy for batch_size 0
      assert length(result) == 1
    end

    test "returns tuples with node_id" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 3
        }
      }

      local_node_id = "my_node"
      batch_size = 0

      result = CoverTraffic.generate_for_wave(config, local_node_id, batch_size)

      assert length(result) == 3

      Enum.each(result, fn {pulse, node_id} ->
        assert is_map(pulse)
        assert node_id == "my_node"
      end)
    end
  end

  describe "generate_for_wave/3 - pulse structure" do
    test "generates pulses with proper Pulse struct" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 2
        }
      }

      local_node_id = "test_node"
      batch_size = 0

      result = CoverTraffic.generate_for_wave(config, local_node_id, batch_size)

      assert length(result) == 2

      {pulse1, _} = List.first(result)
      {pulse2, _} = List.last(result)

      # Different pulses should have different frame_ids
      assert pulse1.frame_id != pulse2.frame_id

      # Both should be valid pulses
      assert pulse1.shard_index == 0
      assert pulse2.shard_index == 0
    end

    test "generates indistinguishable pulses" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 5
        }
      }

      local_node_id = "test_node"
      batch_size = 0

      result = CoverTraffic.generate_for_wave(config, local_node_id, batch_size)

      # All pulses should have similar structure
      Enum.each(result, fn {pulse, _} ->
        # Verify required fields for processing
        assert pulse.frame_id != nil
        assert pulse.token_chain != nil
        assert pulse.payload != nil
        assert pulse.auth_tag != nil

        # Verify sizes are reasonable
        assert byte_size(pulse.payload) >= 32
        assert byte_size(pulse.auth_tag) == 16
      end)
    end
  end

  describe "generate_for_wave/3 - edge cases" do
    test "handles zero batch size" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 1
        }
      }

      result = CoverTraffic.generate_for_wave(config, "node", 0)

      assert length(result) == 1
    end

    test "handles large batch sizes" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 5
        }
      }

      result = CoverTraffic.generate_for_wave(config, "node", 1000)

      # Should generate nothing since batch > minimum
      assert result == []
    end

    test "handles large minimum values" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 100
        }
      }

      result = CoverTraffic.generate_for_wave(config, "node", 10)

      # Should generate 100 - 10 = 90 dummies
      assert length(result) == 90
    end

    test "accepts binary node_id" do
      config = %{
        "cover_traffic" => %{
          "enabled" => true,
          "min_pulses_per_wave" => 1
        }
      }

      result = CoverTraffic.generate_for_wave(config, <<"node_id">>, 0)

      assert length(result) == 1
    end
  end

  describe "anonymity properties" do
    test "dummy pulses are cryptographically random" do
      # Generate many pulses and verify randomness
      pulses = for _ <- 1..50, do: CoverTraffic.generate_dummy_pulse()

      frame_ids = Enum.map(pulses, & &1.frame_id)
      unique_frame_ids = Enum.uniq(frame_ids)

      # All frame IDs should be unique (extremely unlikely to collide)
      assert length(unique_frame_ids) == 50
    end

    test "payload sizes vary to avoid pattern analysis" do
      pulses = for _ <- 1..20, do: CoverTraffic.generate_dummy_pulse()

      payload_sizes = Enum.map(pulses, fn p -> byte_size(p.payload) end)

      # Should have some variation in sizes
      unique_sizes = Enum.uniq(payload_sizes)
      assert length(unique_sizes) > 1
    end

    test "token chains vary to simulate different path lengths" do
      pulses = for _ <- 1..20, do: CoverTraffic.generate_dummy_pulse()

      token_counts = Enum.map(pulses, fn p -> length(p.token_chain) end)

      # Should have mix of 1 and 2 token chains
      has_one_token = Enum.any?(token_counts, &(&1 == 1))
      has_two_tokens = Enum.any?(token_counts, &(&1 == 2))

      assert has_one_token
      assert has_two_tokens
    end
  end
end
