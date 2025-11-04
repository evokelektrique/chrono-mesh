defmodule ChronoMesh.PaddingTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.Padding

  describe "pad_payload/2 - configuration handling" do
    test "returns original payload when padding disabled" do
      config = %{"padding" => %{"enabled" => false}}
      payload = "test message"

      {:ok, padded} = Padding.pad_payload(payload, config)

      assert padded == payload
    end

    test "returns original payload when padding not configured" do
      config = %{}
      payload = "test message"

      {:ok, padded} = Padding.pad_payload(payload, config)

      assert padded == payload
    end

    test "returns error for invalid padding config" do
      config = %{"padding" => %{"enabled" => "maybe"}}
      payload = "test message"

      result = Padding.pad_payload(payload, config)

      assert result == {:error, :invalid_padding_config}
    end

    test "pads payload when enabled" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "random_range",
          "min_size" => 256,
          "max_size" => 512
        }
      }

      payload = "short"

      {:ok, padded} = Padding.pad_payload(payload, config)

      # Padded size should include 4-byte header + payload + padding
      # Should be between 256 and 512
      assert byte_size(padded) >= 256
      assert byte_size(padded) <= 512
    end
  end

  describe "pad_payload/2 - padding strategies" do
    test "none strategy returns payload with header" do
      config = %{"padding" => %{"enabled" => true, "strategy" => "none"}}
      payload = "test"

      {:ok, padded} = Padding.pad_payload(payload, config)

      # Should have 4-byte header + payload, no extra padding
      assert byte_size(padded) == 4 + byte_size(payload)
    end

    test "fixed strategy pads to fixed size" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "fixed",
          "fixed_size" => 256
        }
      }

      payload = "short"

      {:ok, padded} = Padding.pad_payload(payload, config)

      # Should be padded to at least fixed_size
      assert byte_size(padded) >= 256
    end

    test "random_range strategy pads within range" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "random_range",
          "min_size" => 300,
          "max_size" => 400
        }
      }

      payload = "test"

      # Test multiple times to catch randomness
      for _ <- 1..10 do
        {:ok, padded} = Padding.pad_payload(payload, config)
        assert byte_size(padded) >= 300
        assert byte_size(padded) <= 400
      end
    end

    test "exponential strategy pads to power of 2" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "exponential"
        }
      }

      payload = "test payload"

      {:ok, padded} = Padding.pad_payload(payload, config)

      # Size should be power of 2
      size = byte_size(padded)
      log_size = :math.log2(size)
      assert Float.floor(log_size) == Float.ceil(log_size)
    end
  end

  describe "unpad_payload/1" do
    test "correctly removes padding" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "random_range",
          "min_size" => 256,
          "max_size" => 512
        }
      }

      original_payload = "This is a test message!"

      {:ok, padded} = Padding.pad_payload(original_payload, config)
      {:ok, unpadded} = Padding.unpad_payload(padded)

      assert unpadded == original_payload
    end

    test "returns error for invalid padding format" do
      # Too short
      result = Padding.unpad_payload(<<1, 2, 3>>)
      assert result == {:error, :padding_too_small}

      # Invalid length header
      result = Padding.unpad_payload(<<999::32, "data"::binary>>)
      assert result == {:error, :invalid_padding_format}
    end

    test "handles round-trip with various payload sizes" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "random_range",
          "min_size" => 256,
          "max_size" => 1024
        }
      }

      payloads = [
        "",
        "a",
        "short",
        "This is a medium length message",
        String.duplicate("x", 200)
      ]

      for original <- payloads do
        {:ok, padded} = Padding.pad_payload(original, config)
        {:ok, unpadded} = Padding.unpad_payload(padded)
        assert unpadded == original
      end
    end
  end

  describe "calculate_target_size/3" do
    test "none strategy returns original size" do
      payload = "test"
      config = %{}

      size = Padding.calculate_target_size(payload, "none", config)

      assert size == byte_size(payload) + 4  # +4 for length header
    end

    test "fixed strategy returns fixed size" do
      payload = "test"
      config = %{"padding" => %{"fixed_size" => 512}}

      size = Padding.calculate_target_size(payload, "fixed", config)

      assert size >= 512
    end

    test "random_range returns size within range" do
      payload = "test"
      config = %{"padding" => %{"min_size" => 300, "max_size" => 400}}

      for _ <- 1..20 do
        size = Padding.calculate_target_size(payload, "random_range", config)
        assert size >= 300
        assert size <= 400
      end
    end

    test "exponential returns power of 2" do
      payload = "test"
      config = %{}

      size = Padding.calculate_target_size(payload, "exponential", config)

      log_size = :math.log2(size)
      assert Float.floor(log_size) == Float.ceil(log_size)
    end

    test "handles min_size larger than payload" do
      payload = "test"
      config = %{"padding" => %{"min_size" => 100, "max_size" => 200}}

      size = Padding.calculate_target_size(payload, "random_range", config)

      # min_size should be used (adjusted to be at least original_size)
      assert size >= 100
      assert size <= 200
    end
  end

  describe "calculate_exponential_size/1" do
    test "rounds up to next power of 2" do
      assert Padding.calculate_exponential_size(1) == 1
      assert Padding.calculate_exponential_size(2) == 2
      assert Padding.calculate_exponential_size(3) == 4
      assert Padding.calculate_exponential_size(4) == 4
      assert Padding.calculate_exponential_size(5) == 8
      assert Padding.calculate_exponential_size(100) == 128
      assert Padding.calculate_exponential_size(256) == 256
      assert Padding.calculate_exponential_size(257) == 512
    end

    test "handles zero" do
      assert Padding.calculate_exponential_size(0) == 1
    end
  end

  describe "get_padding_config/1" do
    test "returns config with defaults" do
      config = %{}

      result = Padding.get_padding_config(config)

      assert result["enabled"] == true
      assert result["strategy"] == "random_range"
      assert result["fixed_size"] == 1024
      assert result["min_size"] == 256
      assert result["max_size"] == 1024
    end

    test "merges provided config with defaults" do
      config = %{"padding" => %{"enabled" => false, "strategy" => "fixed"}}

      result = Padding.get_padding_config(config)

      assert result["enabled"] == false
      assert result["strategy"] == "fixed"
      assert result["fixed_size"] == 1024  # default
    end
  end

  describe "estimate_overhead/3" do
    test "calculates overhead percentage" do
      config = %{"padding" => %{"min_size" => 256, "max_size" => 256}}
      payload = "test"

      # With fixed target of 256
      overhead = Padding.estimate_overhead(payload, "fixed", config)

      # Overhead should be positive
      assert overhead > 0
      assert is_float(overhead)
    end

    test "none strategy has zero overhead" do
      config = %{}
      payload = "test"

      overhead = Padding.estimate_overhead(payload, "none", config)

      assert overhead == 0.0
    end

    test "larger payloads have smaller overhead percentage" do
      config = %{"padding" => %{"min_size" => 512, "max_size" => 512}}

      small_overhead = Padding.estimate_overhead("x", "fixed", config)
      large_overhead = Padding.estimate_overhead(String.duplicate("x", 100), "fixed", config)

      # Larger payload should have smaller percentage overhead
      assert large_overhead < small_overhead
    end
  end

  describe "anonymity properties" do
    test "padding obscures message sizes" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "random_range",
          "min_size" => 256,
          "max_size" => 512
        }
      }

      sizes = [1, 10, 50, 100, 200]

      padded_sizes =
        sizes
        |> Enum.map(fn size ->
          payload = String.duplicate("x", size)
          {:ok, padded} = Padding.pad_payload(payload, config)
          byte_size(padded)
        end)

      # All padded sizes should be in the same range
      assert Enum.min(padded_sizes) >= 256
      assert Enum.max(padded_sizes) <= 512

      # Original size differences should be lost
      unique_padded = padded_sizes |> Enum.uniq() |> length()
      assert unique_padded > 1  # Some variation due to randomness
      assert unique_padded <= 5  # But less variation than original sizes
    end

    test "padding uses cryptographic randomness" do
      config = %{
        "padding" => %{
          "enabled" => true,
          "strategy" => "random_range",
          "min_size" => 512,
          "max_size" => 512
        }
      }

      payload = "test"

      {:ok, padded1} = Padding.pad_payload(payload, config)
      {:ok, padded2} = Padding.pad_payload(payload, config)

      # Padding should be different each time (cryptographic randomness)
      assert padded1 != padded2

      # But unpadded result should be same
      {:ok, unpadded1} = Padding.unpad_payload(padded1)
      {:ok, unpadded2} = Padding.unpad_payload(padded2)

      assert unpadded1 == unpadded2
    end
  end
end
