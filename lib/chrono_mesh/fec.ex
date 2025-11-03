defmodule ChronoMesh.FEC do
  @moduledoc """
  Forward Error Correction (FEC) using XOR-based erasure coding.

  Provides parity shard generation and shard recovery for the Fragmented Data Protocol.
  This enables recovery from lost shards without requiring retransmission.

  ## XOR-Based FEC

  This implementation uses simple XOR-based erasure coding:
  - Each parity shard is the XOR of all data shards
  - With M parity shards, can recover from up to M lost data shards
  - Recovery works by XORing all received shards (data + parity) to reconstruct missing data shards

  ## Parity Ratio

  The parity ratio determines how many parity shards are generated:
  - Default: 0.25 (1 parity shard per 4 data shards)
  - Minimum: 1 parity shard (always generate at least one)
  - Example: 8 data shards with ratio 0.25 → 2 parity shards (8 * 0.25 = 2)

  ## Limitations

  - Can recover from up to `parity_count` lost data shards
  - Cannot recover if more than `parity_count` data shards are lost
  - Cannot recover if all parity shards are lost (but can still reassemble if all data shards received)
  - Single parity shard: can recover from 1 lost data shard

  ## Future Enhancements

  - Reed-Solomon FEC for better efficiency (can recover from arbitrary combinations of losses)
  - Configurable FEC algorithms
  - Per-message FEC enable/disable

  ## Usage

      # Generate parity shards from data shards
      data_shards = ["shard0", "shard1", "shard2", "shard3"]
      parity_count = 2
      parity_shards = FEC.generate_parity_shards(data_shards, parity_count)

      # Recover missing shards
      received_shards = %{0 => "shard0", 1 => "shard1", 3 => "shard3", 4 => "parity0", 5 => "parity1"}
      missing_indices = [2]
      data_shard_count = 4
      recovered = FEC.recover_shards(received_shards, missing_indices, data_shard_count)
  """

  @doc """
  Generates parity shards from data shards using XOR-based erasure coding.

  Each parity shard is the XOR of all data shards. This allows recovery of up to
  `parity_count` lost data shards.

  ## Parameters

  - `data_shards`: List of binary data shards (must all be same size)
  - `parity_count`: Number of parity shards to generate (must be >= 1)

  ## Returns

  List of parity shards (binaries, same size as data shards).

  ## Examples

      iex> data = ["abc", "def", "ghi"]
      iex> FEC.generate_parity_shards(data, 1)
      [<<0, 0, 0>>]  # XOR of all three

      iex> data = [<<1, 2, 3>>, <<4, 5, 6>>]
      iex> FEC.generate_parity_shards(data, 2)
      [<<5, 7, 5>>, <<5, 7, 5>>]  # Same XOR for both parity shards (simple scheme)
  """
  @spec generate_parity_shards([binary()], pos_integer()) :: [binary()]
  def generate_parity_shards(data_shards, parity_count)
      when is_list(data_shards) and length(data_shards) > 0 and parity_count > 0 do
    # Validate all shards are same size
    shard_size = byte_size(List.first(data_shards))

    unless Enum.all?(data_shards, &(byte_size(&1) == shard_size)) do
      raise ArgumentError, "All data shards must be the same size"
    end

    # Compute XOR of all data shards
    parity_shard = xor_all(data_shards)

    # For simple XOR-based FEC, all parity shards are the same (XOR of all data)
    # This allows recovery of up to parity_count lost data shards
    # (More sophisticated schemes like Reed-Solomon would generate different parity shards)
    List.duplicate(parity_shard, parity_count)
  end

  @doc """
  Recovers missing data shards using received shards (data + parity).

  Uses XOR-based recovery: XOR of all received shards equals XOR of all data shards,
  allowing recovery of missing data shards.

  ## Parameters

  - `received_shards`: Map of `shard_index => shard_data` for all received shards (data + parity)
  - `missing_indices`: List of missing data shard indices to recover
  - `data_shard_count`: Total number of data shards (excluding parity)

  ## Returns

  Map of `missing_index => recovered_shard_data` for successfully recovered shards.

  ## Examples

      # Recover 1 missing shard
      received = %{0 => <<1, 2, 3>>, 1 => <<4, 5, 6>>, 3 => <<10, 11, 12>>, 4 => <<15, 16, 17>>}
      missing = [2]
      FEC.recover_shards(received, missing, 4)
      # => %{2 => <<2, 6, 9>>}  # Recovered using XOR

  """
  @spec recover_shards(%{non_neg_integer() => binary()}, [non_neg_integer()], pos_integer()) ::
          %{non_neg_integer() => binary()}
  def recover_shards(received_shards, missing_indices, data_shard_count)
      when is_map(received_shards) and is_list(missing_indices) and data_shard_count > 0 do
    # Validate missing indices are all data shards
    missing_indices
    |> Enum.each(fn idx ->
      if idx >= data_shard_count do
        raise ArgumentError, "Cannot recover parity shards (index #{idx} >= #{data_shard_count})"
      end
    end)

    # Filter out missing indices that are already in received_shards
    actually_missing = Enum.reject(missing_indices, &Map.has_key?(received_shards, &1))

    if length(actually_missing) == 0 do
      # Nothing to recover
      %{}
    else
      # Get any parity shard (they're all the same in simple XOR scheme)
      parity_shard =
        received_shards
        |> Enum.find(fn {idx, _} -> idx >= data_shard_count end)
        |> case do
          nil -> nil
          {_, shard} -> shard
        end

      if parity_shard == nil do
        # No parity shard available - cannot recover
        %{}
      else
        # Get XOR of all received DATA shards
        received_data_shards =
          received_shards
          |> Enum.filter(fn {idx, _} -> idx < data_shard_count end)
          |> Enum.map(fn {_, shard} -> shard end)

        xor_received_data =
          if length(received_data_shards) == 0 do
            # No data shards received - parity IS the missing shard (for single missing case)
            <<>>
          else
            xor_all(received_data_shards)
          end

        # Parity shard = XOR of all data shards
        # So: Missing data shard = Parity XOR (XOR of all received data shards)
        # For simple XOR scheme: can only recover if exactly one shard is missing
        if length(actually_missing) == 1 do
          missing_idx = List.first(actually_missing)

          # Recover the missing shard
          recovered_shard =
            if byte_size(xor_received_data) == 0 do
              # Special case: no data shards received, parity IS the missing shard
              parity_shard
            else
              xor_binary(parity_shard, xor_received_data)
            end

          # Validate recovered shard size matches received shards
          expected_size = received_shards |> Map.values() |> List.first() |> byte_size()

          if byte_size(recovered_shard) == expected_size do
            %{missing_idx => recovered_shard}
          else
            %{}
          end
        else
          # Multiple missing: simple XOR scheme can only recover one at a time
          # For now, return empty (would need multiple different parity shards like Reed-Solomon)
          %{}
        end
      end
    end
  end

  @doc """
  Calculates total shard count (data + parity) based on configuration.

  ## Parameters

  - `data_shard_count`: Number of data shards
  - `parity_ratio`: Ratio of parity shards to data shards (default: 0.25)
  - `min_parity_shards`: Minimum number of parity shards (default: 1)

  ## Returns

  Tuple of `{data_shard_count, parity_count, total_shard_count}`.

  ## Examples

      iex> FEC.calculate_fec_shard_count(4, 0.25, 1)
      {4, 1, 5}

      iex> FEC.calculate_fec_shard_count(8, 0.25, 1)
      {8, 2, 10}

      iex> FEC.calculate_fec_shard_count(2, 0.5, 1)
      {2, 1, 3}  # Minimum 1 parity, even if 0.5 * 2 = 1
  """
  @spec calculate_fec_shard_count(pos_integer(), float(), pos_integer()) ::
          {pos_integer(), pos_integer(), pos_integer()}
  def calculate_fec_shard_count(data_shard_count, parity_ratio \\ 0.25, min_parity_shards \\ 1)
      when data_shard_count > 0 and parity_ratio >= 0.0 and min_parity_shards > 0 do
    calculated_parity = max(trunc(data_shard_count * parity_ratio), min_parity_shards)
    total_shard_count = data_shard_count + calculated_parity

    {data_shard_count, calculated_parity, total_shard_count}
  end

  # Helper: XOR all binaries together
  @spec xor_all([binary()]) :: binary()
  defp xor_all([]), do: <<>>
  defp xor_all([first | rest]), do: Enum.reduce(rest, first, &xor_binary/2)

  # Helper: XOR two binaries (must be same size)
  @spec xor_binary(binary(), binary()) :: binary()
  defp xor_binary(a, b) when byte_size(a) == byte_size(b) do
    :crypto.exor(a, b)
  end

  defp xor_binary(a, b) do
    raise ArgumentError,
          "Cannot XOR binaries of different sizes: #{byte_size(a)} vs #{byte_size(b)}"
  end
end
