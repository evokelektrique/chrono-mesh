defmodule ChronoMesh.FECTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.FEC

  describe "generate_parity_shards/2" do
    test "generates parity shards from data shards" do
      data_shards = ["abc", "def", "ghi"]

      parity_shards = FEC.generate_parity_shards(data_shards, 1)

      assert length(parity_shards) == 1
      assert is_binary(List.first(parity_shards))
      assert byte_size(List.first(parity_shards)) == 3
    end

    test "generates multiple parity shards" do
      data_shards = ["abc", "def"]

      parity_shards = FEC.generate_parity_shards(data_shards, 2)

      assert length(parity_shards) == 2
      assert Enum.all?(parity_shards, &byte_size(&1) == 3)
    end

    test "parity shard is XOR of all data shards" do
      data_shards = [<<1, 2, 3>>, <<4, 5, 6>>, <<7, 8, 9>>]

      parity_shards = FEC.generate_parity_shards(data_shards, 1)

      # XOR of all data shards: 1 XOR 4 XOR 7 = 2, 2 XOR 5 XOR 8 = 15, 3 XOR 6 XOR 9 = 12
      expected_parity = :crypto.exor(:crypto.exor(<<1, 2, 3>>, <<4, 5, 6>>), <<7, 8, 9>>)

      assert List.first(parity_shards) == expected_parity
    end

    test "all parity shards are identical (simple XOR scheme)" do
      data_shards = ["test", "data"]

      parity_shards = FEC.generate_parity_shards(data_shards, 3)

      assert length(parity_shards) == 3
      assert Enum.all?(parity_shards, &(&1 == List.first(parity_shards)))
    end

    test "raises error if data shards have different sizes" do
      data_shards = ["abc", "defg"]

      assert_raise ArgumentError, fn ->
        FEC.generate_parity_shards(data_shards, 1)
      end
    end

    test "handles empty data shards list" do
      assert_raise FunctionClauseError, fn ->
        FEC.generate_parity_shards([], 1)
      end
    end

    test "handles single data shard" do
      data_shards = ["single"]

      parity_shards = FEC.generate_parity_shards(data_shards, 1)

      assert length(parity_shards) == 1
      # Parity of single shard is the shard itself
      assert List.first(parity_shards) == "single"
    end
  end

  describe "recover_shards/3" do
    test "recovers single missing data shard" do
      data_shards = [<<1, 2, 3>>, <<4, 5, 6>>, <<7, 8, 9>>]
      parity_shards = FEC.generate_parity_shards(data_shards, 1)
      parity = List.first(parity_shards)

      # Simulate loss of shard at index 1
      received_shards = %{
        0 => <<1, 2, 3>>,
        2 => <<7, 8, 9>>,
        3 => parity
      }

      missing_indices = [1]
      data_shard_count = 3

      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)

      assert recovered == %{1 => <<4, 5, 6>>}
    end

    test "recovers shard when all data shards except one are received" do
      data_shards = ["abc", "def", "ghi", "jkl"]
      parity_shards = FEC.generate_parity_shards(data_shards, 1)
      parity = List.first(parity_shards)

      # Only missing shard at index 2
      received_shards = %{
        0 => "abc",
        1 => "def",
        3 => "jkl",
        4 => parity
      }

      missing_indices = [2]
      data_shard_count = 4

      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)

      assert recovered == %{2 => "ghi"}
    end

    test "returns empty map if no shards need recovery" do
      received_shards = %{
        0 => "abc",
        1 => "def",
        2 => "ghi"
      }

      missing_indices = []
      data_shard_count = 3

      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)

      assert recovered == %{}
    end

    test "returns empty map if missing shard already in received" do
      received_shards = %{
        0 => "abc",
        1 => "def",
        2 => "ghi"
      }

      missing_indices = [1] # Already present
      data_shard_count = 3

      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)

      assert recovered == %{}
    end

    test "cannot recover if more shards missing than parity available" do
      data_shards = ["abc", "def", "ghi", "jkl"]
      parity_shards = FEC.generate_parity_shards(data_shards, 1) # Only 1 parity
      parity = List.first(parity_shards)

      # Missing 2 shards, only 1 parity
      received_shards = %{
        0 => "abc",
        3 => "jkl",
        4 => parity
      }

      missing_indices = [1, 2]
      data_shard_count = 4

      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)

      # Cannot recover 2 shards with only 1 parity
      assert recovered == %{}
    end

    test "can recover with multiple parity shards" do
      data_shards = ["abc", "def", "ghi", "jkl"]
      parity_shards = FEC.generate_parity_shards(data_shards, 2) # 2 parity shards
      parity1 = Enum.at(parity_shards, 0)
      parity2 = Enum.at(parity_shards, 1)

      # Missing 1 shard, have 2 parity (but simple XOR scheme only allows 1 recovery)
      received_shards = %{
        0 => "abc",
        2 => "ghi",
        3 => "jkl",
        4 => parity1,
        5 => parity2
      }

      missing_indices = [1]
      data_shard_count = 4

      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)

      # Can recover with single parity
      assert recovered == %{1 => "def"}
    end

    test "raises error if trying to recover parity shard" do
      received_shards = %{
        0 => "abc",
        1 => "def"
      }

      missing_indices = [4] # Parity shard index
      data_shard_count = 3

      assert_raise ArgumentError, fn ->
        FEC.recover_shards(received_shards, missing_indices, data_shard_count)
      end
    end

    test "handles edge case: single data shard" do
      data_shards = ["single"]
      parity_shards = FEC.generate_parity_shards(data_shards, 1)
      parity = List.first(parity_shards)

      # Missing the only data shard
      received_shards = %{1 => parity}

      missing_indices = [0]
      data_shard_count = 1

      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)

      assert recovered == %{0 => "single"}
    end
  end

  describe "calculate_fec_shard_count/3" do
    test "calculates shard counts with default ratio" do
      {data_count, parity_count, total_count} = FEC.calculate_fec_shard_count(4, 0.25, 1)

      assert data_count == 4
      assert parity_count == 1 # 4 * 0.25 = 1
      assert total_count == 5
    end

    test "calculates shard counts with custom ratio" do
      {data_count, parity_count, total_count} = FEC.calculate_fec_shard_count(8, 0.5, 1)

      assert data_count == 8
      assert parity_count == 4 # 8 * 0.5 = 4
      assert total_count == 12
    end

    test "respects minimum parity shards" do
      {data_count, parity_count, total_count} = FEC.calculate_fec_shard_count(2, 0.1, 1)

      assert data_count == 2
      assert parity_count == 1 # min(2 * 0.1 = 0.2, 1) = 1
      assert total_count == 3
    end

    test "handles large data shard counts" do
      {data_count, parity_count, total_count} = FEC.calculate_fec_shard_count(100, 0.25, 1)

      assert data_count == 100
      assert parity_count == 25 # 100 * 0.25 = 25
      assert total_count == 125
    end

    test "handles single data shard" do
      {data_count, parity_count, total_count} = FEC.calculate_fec_shard_count(1, 0.25, 1)

      assert data_count == 1
      assert parity_count == 1 # min(1 * 0.25 = 0.25, 1) = 1
      assert total_count == 2
    end
  end
end
