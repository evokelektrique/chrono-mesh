defmodule ChronoMesh.Padding do
  @moduledoc """
  Traffic padding and payload size obfuscation.

  Padding prevents attackers from learning message sizes through packet analysis.
  Different message sizes correlate to different types of messages or communication
  patterns. By normalizing all messages to standard sizes, padding makes traffic
  analysis significantly harder.

  Padding strategies:
  - None: No padding (analyze existing functionality)
  - Fixed size: All messages padded to same size
  - Random range: Sizes randomized within specified range
  - Exponential: Sizes rounded to powers of 2

  Anonymity benefits:
  - Prevents message size inference attacks
  - Blocks traffic-based content classification
  - Makes bulk transfers indistinguishable from regular messages
  - Constant overhead independent of message content

  Performance considerations:
  - Fixed size: Minimal overhead when payload < fixed size
  - Random range: Prevents size patterns while limiting overhead
  - Exponential: Good balance for variable-length messages
  """

  require Logger

  @default_padding_strategy "random_range"
  @default_min_size 256
  @default_max_size 1024

  @doc """
  Pads a payload to obscure its size.

  Configuration options:
  - `enabled`: boolean, whether padding is enabled (default: true)
  - `strategy`: "none" | "fixed" | "random_range" | "exponential" (default: random_range)
  - `fixed_size`: Target size for "fixed" strategy (bytes)
  - `min_size`: Minimum padded size for "random_range" (default: 256)
  - `max_size`: Maximum padded size for "random_range" (default: 1024)

  Returns: `{:ok, padded_payload}` or `{:error, reason}`
  """
  @spec pad_payload(binary(), map()) :: {:ok, binary()} | {:error, atom()}
  def pad_payload(payload, config) when is_binary(payload) and is_map(config) do
    case get_in(config, ["padding", "enabled"]) do
      false ->
        {:ok, payload}

      nil ->
        {:ok, payload}

      true ->
        strategy = get_in(config, ["padding", "strategy"]) || @default_padding_strategy
        do_pad(payload, strategy, config)

      _ ->
        {:error, :invalid_padding_config}
    end
  end

  def pad_payload(payload, _), do: {:ok, payload}

  @doc """
  Removes padding from a padded payload.

  Expects payload format: [original_length (4 bytes BE)] + [original_payload] + [padding]

  Returns: `{:ok, original_payload}` or `{:error, reason}`
  """
  @spec unpad_payload(binary()) :: {:ok, binary()} | {:error, atom()}
  def unpad_payload(padded) when is_binary(padded) and byte_size(padded) >= 4 do
    case padded do
      <<original_length::32, rest::binary>> ->
        if original_length <= byte_size(rest) do
          <<original_payload::binary-size(original_length), _padding::binary>> = rest
          {:ok, original_payload}
        else
          {:error, :invalid_padding_format}
        end

      _ ->
        {:error, :invalid_padding_format}
    end
  end

  def unpad_payload(_), do: {:error, :padding_too_small}

  @doc """
  Calculates target size for padding strategy.

  For "none" strategy, returns original size.
  For other strategies, returns size to pad to.
  """
  @spec calculate_target_size(binary(), atom() | binary(), map()) :: non_neg_integer()
  def calculate_target_size(payload, strategy, config) when is_binary(payload) do
    original_size = byte_size(payload) + 4  # +4 for length header

    case strategy do
      "none" ->
        original_size

      "fixed" ->
        fixed_size = get_in(config, ["padding", "fixed_size"]) || 1024
        max(original_size, fixed_size)

      "random_range" ->
        min_size = get_in(config, ["padding", "min_size"]) || @default_min_size
        max_size = get_in(config, ["padding", "max_size"]) || @default_max_size

        # Ensure range is valid
        min_size = max(min_size, original_size)

        if min_size <= max_size do
          Enum.random(min_size..max_size)
        else
          min_size
        end

      "exponential" ->
        calculate_exponential_size(original_size)

      _ ->
        original_size
    end
  end

  @doc """
  Rounds size up to nearest power of 2.

  Exponential padding makes message sizes harder to distinguish while limiting overhead.
  """
  @spec calculate_exponential_size(non_neg_integer()) :: non_neg_integer()
  def calculate_exponential_size(size) when size > 0 do
    # Find the smallest power of 2 >= size
    size
    |> :math.log2()
    |> Float.ceil()
    |> trunc()
    |> then(&(2 ** &1))
  end

  def calculate_exponential_size(0), do: 1

  @doc """
  Gets padding configuration with defaults.
  """
  @spec get_padding_config(map()) :: map()
  def get_padding_config(config) when is_map(config) do
    padding_config = Map.get(config, "padding", %{})

    %{
      "enabled" => Map.get(padding_config, "enabled", true),
      "strategy" => Map.get(padding_config, "strategy", @default_padding_strategy),
      "fixed_size" => Map.get(padding_config, "fixed_size", 1024),
      "min_size" => Map.get(padding_config, "min_size", @default_min_size),
      "max_size" => Map.get(padding_config, "max_size", @default_max_size)
    }
  end

  @doc """
  Estimates overhead from padding strategy.

  Returns average overhead as percentage of original payload.
  """
  @spec estimate_overhead(binary(), atom() | binary(), map()) :: float()
  def estimate_overhead(payload, strategy, config) when is_binary(payload) do
    original_size = byte_size(payload) + 4
    target_size = calculate_target_size(payload, strategy, config)

    if target_size > 0 do
      ((target_size - original_size) / original_size) * 100
    else
      0.0
    end
  end

  # Private helper functions

  @spec do_pad(binary(), binary() | atom(), map()) :: {:ok, binary()} | {:error, atom()}
  defp do_pad(payload, strategy, config) do
    target_size = calculate_target_size(payload, strategy, config)
    original_length = byte_size(payload)
    header = <<original_length::32>>
    content = header <> payload

    padding_size = target_size - byte_size(content)

    if padding_size < 0 do
      Logger.warning("Padding: Target size #{target_size} smaller than payload #{byte_size(content)}")
      {:ok, content}
    else
      padding = :crypto.strong_rand_bytes(padding_size)
      {:ok, content <> padding}
    end
  end
end
