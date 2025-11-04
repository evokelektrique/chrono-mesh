defmodule ChronoMesh.Config do
  @moduledoc """
  Handles reading and writing the user's configuration file.

  The configuration is stored as YAML at `~/.chrono_mesh/config.yaml`.
  On first run the file is created alongside a freshly generated keypair.
  """

  require Logger

  @default_network %{
    "wave_duration_secs" => 10,
    "default_path_length" => 3,
    "pulse_size_bytes" => 1024,
    "listen_port" => 4_000,
    "listen_host" => "127.0.0.1"
  }

  @default_address_book %{
    "subscriptions" => %{
      "enabled" => true,
      "max_count" => 100,
      "refresh_interval_ms" => :timer.minutes(30),
      "ttl_ms" => :timer.hours(1),
      "rate_limit_ms" => :timer.minutes(1)
    },
    "aliases" => %{
      "publish_ttl_ms" => :timer.hours(24),
      "publish_rate_limit_ms" => :timer.minutes(1)
    }
  }

  @default_pdq %{
    "enabled" => false,
    "memory_capacity_mb" => 1024,
    "memory_swap_threshold" => 0.8,
    "far_future_threshold_waves" => 10,
    "disk_path" => "data/pdq",
    "encryption_enabled" => true,
    "max_disk_size_mb" => 10240,
    "cleanup_interval_ms" => 300_000
  }

  @default_cover_traffic %{
    "enabled" => true,
    "min_pulses_per_wave" => 2,
    "strategy" => "constant"
  }

  @doc """
  Returns `{config_map, created?}`.
  """
  @spec ensure(keyword()) :: {map(), boolean()}
  def ensure(opts \\ []) do
    with {:ok, yaml} <- File.read(config_file()),
         {:ok, data} <- decode_yaml(yaml) do
      # Patch bootstrap_peers if they're in the raw YAML but not parsed
      data_with_bootstrap = load_bootstrap_peers_from_yaml(yaml, data)
      {normalise(data_with_bootstrap), false}
    else
      {:error, :enoent} ->
        path = config_file()
        Logger.info("configuration not found; creating fresh identity at #{path}")
        config = bootstrap(opts)
        :ok = write!(config)
        {config, true}

      {:error, reason} ->
        raise "Failed to load config: #{inspect(reason)}"
    end
  end

  # Parse bootstrap_peers and peers from raw YAML content
  @spec load_bootstrap_peers_from_yaml(String.t(), map()) :: map()
  defp load_bootstrap_peers_from_yaml(yaml_content, config) do
    config
    |> load_peers_from_yaml(yaml_content)
    |> load_bootstrap_peers_from_yaml_helper(yaml_content)
  end

  @spec load_bootstrap_peers_from_yaml_helper(map(), String.t()) :: map()
  defp load_bootstrap_peers_from_yaml_helper(config, yaml_content) do
    case parse_bootstrap_peers_from_yaml(yaml_content) do
      [] ->
        config

      bootstrap_peers when is_list(bootstrap_peers) ->
        network = Map.get(config, "network", %{})
        updated_network = Map.put(network, "bootstrap_peers", bootstrap_peers)
        Map.put(config, "network", updated_network)
    end
  end

  @spec load_peers_from_yaml(map(), String.t()) :: map()
  defp load_peers_from_yaml(config, yaml_content) do
    case parse_peers_from_yaml(yaml_content) do
      [] ->
        config

      peers when is_list(peers) ->
        Map.put(config, "peers", peers)
    end
  end

  # Extract bootstrap_peers list from raw YAML using string parsing
  @spec parse_bootstrap_peers_from_yaml(String.t()) :: [map()]
  defp parse_bootstrap_peers_from_yaml(yaml_content) do
    lines = String.split(yaml_content, "\n")

    lines
    |> Enum.reduce({[], false, nil}, fn line, {acc, in_bootstrap, current_peer} ->
      trimmed = String.trim(line)

      cond do
        trimmed == "bootstrap_peers:" ->
          # Start of bootstrap_peers section
          {acc, true, nil}

        in_bootstrap && String.starts_with?(trimmed, "- ") ->
          # New bootstrap peer item
          kv_str = String.trim_leading(trimmed, "- ") |> String.trim()

          case parse_kv_safe(kv_str) do
            {key, value} ->
              new_peer = %{key => value}
              {[new_peer | acc], in_bootstrap, new_peer}

            nil ->
              {acc, in_bootstrap, nil}
          end

        in_bootstrap && current_peer != nil && String.starts_with?(line, "    ") && !String.starts_with?(trimmed, "-") ->
          # Continuation of current peer (4-space indented)
          case parse_kv_safe(trimmed) do
            {key, value} ->
              updated_peer = Map.put(current_peer, key, value)
              updated_acc = [updated_peer | tl(acc)]
              {updated_acc, in_bootstrap, updated_peer}

            nil ->
              {acc, in_bootstrap, current_peer}
          end

        in_bootstrap && trimmed != "" && !String.starts_with?(line, "  ") ->
          # End of bootstrap_peers section (dedented line)
          {acc, false, nil}

        true ->
          {acc, in_bootstrap, current_peer}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  # Safe version of parse_kv that doesn't raise
  @spec parse_kv_safe(String.t()) :: {String.t(), String.t()} | nil
  defp parse_kv_safe(line) do
    case String.split(line, ":", parts: 2) do
      [key, value] ->
        {String.trim(key), String.trim(value) |> strip_quotes()}

      _ ->
        nil
    end
  end

  # Parse peers list from raw YAML
  @spec parse_peers_from_yaml(String.t()) :: [map()]
  defp parse_peers_from_yaml(yaml_content) do
    lines = String.split(yaml_content, "\n")

    lines
    |> Enum.reduce({[], false, nil}, fn line, {acc, in_peers, current_peer} ->
      trimmed = String.trim(line)

      cond do
        trimmed == "peers:" ->
          # Start of peers section
          {acc, true, nil}

        in_peers && String.starts_with?(trimmed, "- ") ->
          # New peer item
          kv_str = String.trim_leading(trimmed, "- ") |> String.trim()

          case parse_kv_safe(kv_str) do
            {key, value} ->
              new_peer = %{key => value}
              {[new_peer | acc], in_peers, new_peer}

            nil ->
              {acc, in_peers, nil}
          end

        in_peers && current_peer != nil && String.starts_with?(line, "  ") && !String.starts_with?(trimmed, "-") ->
          # Continuation of current peer (2-space indented)
          case parse_kv_safe(trimmed) do
            {key, value} ->
              updated_peer = Map.put(current_peer, key, value)
              updated_acc = [updated_peer | tl(acc)]
              {updated_acc, in_peers, updated_peer}

            nil ->
              {acc, in_peers, current_peer}
          end

        in_peers && trimmed != "" && !String.starts_with?(line, "  ") ->
          # End of peers section (dedented line)
          {acc, false, nil}

        true ->
          {acc, in_peers, current_peer}
      end
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  @doc """
  Writes the configuration map back to disk.
  """
  @spec write!(map()) :: :ok
  def write!(config) when is_map(config) do
    ensure_dirs!()
    yaml = encode_yaml(config)
    File.write!(config_file(), yaml <> "\n")
  end

  @doc """
  Returns the path to the config file.
  """
  @spec config_path() :: Path.t()
  def config_path, do: config_file()

  @doc """
  Returns the current configuration map without attempting to create it.
  """
  @spec read!() :: map()
  def read! do
    {config, _} = ensure()
    config
  end

  defp bootstrap(opts) do
    ensure_dirs!()
    {public_key, private_key} = ChronoMesh.Keys.generate()
    {ed25519_public_key, ed25519_private_key} = ChronoMesh.Keys.keypair()
    identity_filename = derive_identity_name(opts[:name])

    private_key_path =
      Path.join(keys_dir(), "#{identity_filename}_sk.pem")

    public_key_path =
      Path.join(keys_dir(), "#{identity_filename}_pk.pem")

    ed25519_private_key_path =
      Path.join(keys_dir(), "#{identity_filename}_ed25519_sk.pem")

    ed25519_public_key_path =
      Path.join(keys_dir(), "#{identity_filename}_ed25519_pk.pem")

    ChronoMesh.Keys.write_private_key!(private_key_path, private_key)
    ChronoMesh.Keys.write_public_key!(public_key_path, public_key)
    ChronoMesh.Keys.write_private_key!(ed25519_private_key_path, ed25519_private_key)
    ChronoMesh.Keys.write_public_key!(ed25519_public_key_path, ed25519_public_key)

    network_defaults =
      @default_network
      |> Map.put("listen_port", default_listen_port())
      |> Map.put("listen_host", default_listen_host())

    address_book_defaults = ensure_address_book_defaults(%{})

    %{
      "identity" => %{
        "display_name" => identity_filename,
        "private_key_path" => private_key_path,
        "public_key_path" => public_key_path,
        "ed25519_private_key_path" => ed25519_private_key_path,
        "ed25519_public_key_path" => ed25519_public_key_path
      },
      "network" => network_defaults,
      "address_book" => address_book_defaults,
      "peers" => []
    }
  end

  defp ensure_dirs! do
    :ok = File.mkdir_p(keys_dir())
  end

  defp derive_identity_name(nil), do: random_identity_name()
  defp derive_identity_name(name), do: sanitise_name(name)

  defp random_identity_name do
    "peer_" <> Base.encode16(:crypto.strong_rand_bytes(5), case: :lower)
  end

  defp sanitise_name(name) do
    name
    |> String.trim()
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9_-]/, "_")
    |> case do
      "" -> random_identity_name()
      other -> other
    end
  end

  defp normalise(%{"peers" => peers} = config) when is_list(peers) do
    config
    |> ensure_network_defaults()
    |> ensure_address_book_defaults()
    |> ensure_pdq_defaults()
    |> ensure_cover_traffic_defaults()
  end

  defp normalise(config) when is_map(config) do
    config
    |> Map.put_new("peers", [])
    |> ensure_network_defaults()
    |> ensure_address_book_defaults()
    |> ensure_pdq_defaults()
    |> ensure_cover_traffic_defaults()
  end

  defp ensure_network_defaults(config) do
    network =
      config
      |> Map.get("network", %{})
      |> Map.put_new("wave_duration_secs", @default_network["wave_duration_secs"])
      |> Map.put_new("default_path_length", @default_network["default_path_length"])
      |> Map.put_new("pulse_size_bytes", @default_network["pulse_size_bytes"])
      |> Map.put_new("listen_port", default_listen_port())
      |> Map.put_new("listen_host", default_listen_host())

    Map.put(config, "network", network)
  end

  defp ensure_address_book_defaults(config) do
    address_book =
      config
      |> Map.get("address_book", %{})
      |> Map.put_new("subscriptions", %{})
      |> Map.put_new("aliases", %{})
      |> then(fn ab ->
        subscriptions =
          ab
          |> Map.get("subscriptions", %{})
          |> Map.put_new("enabled", @default_address_book["subscriptions"]["enabled"])
          |> Map.put_new("max_count", @default_address_book["subscriptions"]["max_count"])
          |> Map.put_new(
            "refresh_interval_ms",
            @default_address_book["subscriptions"]["refresh_interval_ms"]
          )
          |> Map.put_new("ttl_ms", @default_address_book["subscriptions"]["ttl_ms"])
          |> Map.put_new(
            "rate_limit_ms",
            @default_address_book["subscriptions"]["rate_limit_ms"]
          )

        aliases =
          ab
          |> Map.get("aliases", %{})
          |> Map.put_new("publish_ttl_ms", @default_address_book["aliases"]["publish_ttl_ms"])
          |> Map.put_new(
            "publish_rate_limit_ms",
            @default_address_book["aliases"]["publish_rate_limit_ms"]
          )

        %{ab | "subscriptions" => subscriptions, "aliases" => aliases}
      end)

    Map.put(config, "address_book", address_book)
  end

  defp ensure_pdq_defaults(config) do
    pdq =
      config
      |> Map.get("pdq", %{})
      |> Map.put_new("enabled", @default_pdq["enabled"])
      |> Map.put_new("memory_capacity_mb", @default_pdq["memory_capacity_mb"])
      |> Map.put_new("memory_swap_threshold", @default_pdq["memory_swap_threshold"])
      |> Map.put_new("far_future_threshold_waves", @default_pdq["far_future_threshold_waves"])
      |> Map.put_new("disk_path", @default_pdq["disk_path"])
      |> Map.put_new("encryption_enabled", @default_pdq["encryption_enabled"])
      |> Map.put_new("max_disk_size_mb", @default_pdq["max_disk_size_mb"])
      |> Map.put_new("cleanup_interval_ms", @default_pdq["cleanup_interval_ms"])

    Map.put(config, "pdq", pdq)
  end

  defp ensure_cover_traffic_defaults(config) do
    cover_traffic =
      config
      |> Map.get("cover_traffic", %{})
      |> Map.put_new("enabled", @default_cover_traffic["enabled"])
      |> Map.put_new("min_pulses_per_wave", @default_cover_traffic["min_pulses_per_wave"])
      |> Map.put_new("strategy", @default_cover_traffic["strategy"])

    Map.put(config, "cover_traffic", cover_traffic)
  end

  defp encode_yaml(%{} = config) do
    [
      encode_section("identity", config["identity"]),
      encode_section("network", config["network"]),
      encode_section("address_book", config["address_book"]),
      encode_section("pdq", config["pdq"]),
      encode_peers(config["peers"] || [])
    ]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp encode_section(_name, nil), do: ""

  defp encode_section(name, map) when is_map(map) do
    # Special handling for address_book nested sections
    if name == "address_book" do
      encode_address_book_section(map)
    # Special handling for network section with bootstrap_peers
    else if name == "network" do
      encode_network_section(map)
    else
      [
        "#{name}:",
        Enum.map(map, fn {k, v} -> "  #{k}: #{yaml_value(v)}" end)
      ]
      |> List.flatten()
      |> Enum.join("\n")
    end
    end
  end

  defp encode_network_section(map) do
    lines = [
      "network:",
      map
      |> Enum.reject(fn {k, _v} -> k == "bootstrap_peers" end)
      |> Enum.map(fn {k, v} -> "  #{k}: #{yaml_value(v)}" end)
    ]
    |> List.flatten()

    lines =
      if Map.has_key?(map, "bootstrap_peers") && is_list(map["bootstrap_peers"]) do
        bootstrap_lines = [
          "  bootstrap_peers:"
          | Enum.map(map["bootstrap_peers"], fn peer ->
            [
              "  - public_key: #{yaml_value(Map.get(peer, "public_key", ""))}"
              | if Map.has_key?(peer, "connection_hint") do
                ["    connection_hint: #{yaml_value(Map.get(peer, "connection_hint", ""))}"]
              else
                []
              end
            ]
          end)
          |> List.flatten()
        ]

        lines ++ bootstrap_lines
      else
        lines
      end

    lines |> Enum.reject(&(&1 == "")) |> Enum.join("\n")
  end

  defp encode_address_book_section(map) do
    [
      "address_book:",
      if Map.has_key?(map, "subscriptions") do
        [
          "  subscriptions:",
          encode_nested_section(map["subscriptions"], "    ")
        ]
      else
        []
      end,
      if Map.has_key?(map, "aliases") do
        [
          "  aliases:",
          encode_nested_section(map["aliases"], "    ")
        ]
      else
        []
      end
    ]
    |> List.flatten()
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp encode_nested_section(map, indent) when is_map(map) do
    Enum.map(map, fn {k, v} -> "#{indent}#{k}: #{yaml_value(v)}" end)
  end

  defp encode_nested_section(_, _), do: []

  defp encode_peers([]), do: "peers: []"

  defp encode_peers(peers) do
    header = "peers:"

    body =
      Enum.map(peers, fn peer ->
        lines =
          [
            "  - name: #{yaml_value(peer["name"])}",
            if(peer["node_id"], do: "    node_id: #{yaml_value(peer["node_id"])}", else: nil),
            if(peer["public_key"],
              do: "    public_key: #{yaml_value(peer["public_key"])}",
              else: nil
            ),
            if(peer["note"], do: "    note: #{yaml_value(peer["note"])}", else: nil)
          ]
          |> Enum.reject(&is_nil/1)
          |> Enum.join("\n")

        lines
      end)
      |> Enum.join("\n")

    Enum.join([header, body], "\n")
  end

  defp yaml_value(value) when is_binary(value) do
    if String.contains?(value, ~w(: # - { } [ ])) do
      inspected = inspect(value)
      inspected
    else
      value
    end
  end

  defp yaml_value(value), do: "#{value}"

  defp decode_yaml(content) do
    lines = String.split(content, "\n", trim: false)

    try do
      {result, _, _, _} = parse_lines(lines, %{}, nil, nil, [])
      {:ok, result}
    rescue
      e ->
        {:error, e}
    end
  end

  defp parse_lines([], acc, _section, _peer, peers) do
    acc =
      case peers do
        [] -> acc
        _ -> Map.put(acc, "peers", Enum.reverse(peers))
      end

    {acc, nil, nil, []}
  end

  defp parse_lines([line | rest], acc, section, current_peer, peers) do
    trimmed = String.trim(line)

    cond do
      trimmed == "" ->
        parse_lines(rest, acc, section, current_peer, peers)

      String.ends_with?(trimmed, ":") && !String.starts_with?(trimmed, "-") ->
        new_section = String.trim_trailing(trimmed, ":")

        {acc, peers} =
          if new_section == "peers" do
            {Map.put_new(acc, "peers", []), []}
          else
            # Check if this is a nested section (e.g., "subscriptions:" under "address_book")
            if section == "address_book" and new_section in ["subscriptions", "aliases"] do
              # Nested section under address_book
              current_value = Map.get(acc, section, %{})
              updated_value = Map.put_new(current_value, new_section, %{})
              {Map.put(acc, section, updated_value), peers}
            else
              {Map.put_new(acc, new_section, %{}), peers}
            end
          end

        parse_lines(rest, acc, new_section, nil, peers)

      section in ["identity", "network", "pdq"] && String.starts_with?(line, "  ") ->
        {key, value} = parse_kv(trimmed)
        updated = Map.update!(acc, section, &Map.put(&1, key, value))
        parse_lines(rest, updated, section, current_peer, peers)

      section in ["subscriptions", "aliases"] && String.starts_with?(line, "    ") ->
        # Nested section under address_book (4 spaces for nested keys)
        {key, value} = parse_kv(trimmed)
        address_book = Map.get(acc, "address_book", %{})
        nested_value = Map.get(address_book, section, %{})
        updated_nested = Map.put(nested_value, key, value)
        updated_address_book = Map.put(address_book, section, updated_nested)
        updated = Map.put(acc, "address_book", updated_address_book)
        parse_lines(rest, updated, section, current_peer, peers)

      section == "address_book" && String.starts_with?(line, "  ") ->
        # Top-level address_book keys (subscriptions, aliases)
        {key, value} = parse_kv(trimmed)
        updated = Map.update!(acc, section, &Map.put(&1, key, value))
        parse_lines(rest, updated, section, current_peer, peers)

      section == "peers" && String.starts_with?(trimmed, "- ") ->
        {key, value} = parse_kv(String.trim_leading(trimmed, "- ") |> String.trim())
        peer = Map.put(%{}, key, value)
        parse_lines(rest, acc, section, peer, [peer | peers])

      section == "peers" && current_peer != nil && String.starts_with?(line, "  ") && !String.starts_with?(trimmed, "-") ->
        # Handle both 2-space and 4-space indentation for peer properties
        {key, value} = parse_kv(trimmed)
        updated_peer = Map.put(current_peer, key, value)
        updated_peers = [updated_peer | tl(peers)]
        parse_lines(rest, acc, section, updated_peer, updated_peers)

      trimmed == "peers: []" ->
        parse_lines(rest, Map.put(acc, "peers", []), section, current_peer, peers)

      true ->
        parse_lines(rest, acc, section, current_peer, peers)
    end
  end

  defp parse_kv(line) do
    [key, value] =
      line
      |> String.split(":", parts: 2)
      |> Enum.map(&String.trim/1)

    {key, strip_quotes(value)}
  end

  defp strip_quotes(value) do
    cond do
      String.starts_with?(value, "\"") && String.ends_with?(value, "\"") ->
        value |> String.trim("\"")

      String.starts_with?(value, "'") && String.ends_with?(value, "'") ->
        value |> String.trim("'")

      true ->
        value
    end
  end

  defp base_dir do
    System.get_env("CHRONO_MESH_HOME") || System.user_home!()
  end

  defp config_dir do
    Path.join(base_dir(), ".chrono_mesh")
  end

  defp config_file do
    Path.join(config_dir(), "config.yaml")
  end

  defp keys_dir do
    Path.join(config_dir(), "keys")
  end

  defp default_listen_port do
    case System.get_env("CHRONO_MESH_LISTEN_PORT") do
      nil ->
        @default_network["listen_port"]

      value ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> @default_network["listen_port"]
        end
    end
  end

  defp default_listen_host do
    System.get_env("CHRONO_MESH_LISTEN_HOST") || @default_network["listen_host"]
  end

  # PDQ configuration helpers

  @doc """
  Returns whether PDQ is enabled in the configuration.
  """
  @spec pdq_enabled?(map()) :: boolean()
  def pdq_enabled?(config) do
    case get_in(config, ["pdq", "enabled"]) do
      value when is_boolean(value) -> value
      value when value in ["true", "1", 1] -> true
      _ -> @default_pdq["enabled"]
    end
  end

  @doc """
  Returns the PDQ memory capacity in bytes.
  """
  @spec pdq_memory_capacity_bytes(map()) :: non_neg_integer()
  def pdq_memory_capacity_bytes(config) do
    case get_in(config, ["pdq", "memory_capacity_mb"]) do
      value when is_integer(value) and value > 0 ->
        value * 1024 * 1024

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int * 1024 * 1024
          _ -> @default_pdq["memory_capacity_mb"] * 1024 * 1024
        end

      _ ->
        @default_pdq["memory_capacity_mb"] * 1024 * 1024
    end
  end

  @doc """
  Returns the PDQ memory swap threshold (0.0 to 1.0).
  """
  @spec pdq_memory_swap_threshold(map()) :: float()
  def pdq_memory_swap_threshold(config) do
    case get_in(config, ["pdq", "memory_swap_threshold"]) do
      value when is_float(value) and value >= 0.0 and value <= 1.0 ->
        value

      value when is_integer(value) and value >= 0 and value <= 100 ->
        value / 100.0

      value when is_binary(value) ->
        case Float.parse(value) do
          {float, _} when float >= 0.0 and float <= 1.0 -> float
          {int, _} when int >= 0 and int <= 100 -> int / 100.0
          _ -> @default_pdq["memory_swap_threshold"]
        end

      _ ->
        @default_pdq["memory_swap_threshold"]
    end
  end

  @doc """
  Returns the PDQ far-future threshold in waves.
  """
  @spec pdq_far_future_threshold_waves(map()) :: non_neg_integer()
  def pdq_far_future_threshold_waves(config) do
    case get_in(config, ["pdq", "far_future_threshold_waves"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> @default_pdq["far_future_threshold_waves"]
        end

      _ ->
        @default_pdq["far_future_threshold_waves"]
    end
  end

  @doc """
  Returns the PDQ disk path.
  """
  @spec pdq_disk_path(map()) :: String.t()
  def pdq_disk_path(config) do
    case get_in(config, ["pdq", "disk_path"]) do
      value when is_binary(value) and value != "" -> value
      _ -> @default_pdq["disk_path"]
    end
  end

  @doc """
  Returns whether PDQ encryption is enabled.
  """
  @spec pdq_encryption_enabled?(map()) :: boolean()
  def pdq_encryption_enabled?(config) do
    case get_in(config, ["pdq", "encryption_enabled"]) do
      value when is_boolean(value) -> value
      value when value in ["true", "1", 1] -> true
      _ -> @default_pdq["encryption_enabled"]
    end
  end

  @doc """
  Returns the PDQ cleanup interval in milliseconds.
  """
  @spec pdq_cleanup_interval_ms(map()) :: non_neg_integer()
  def pdq_cleanup_interval_ms(config) do
    case get_in(config, ["pdq", "cleanup_interval_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> @default_pdq["cleanup_interval_ms"]
        end

      _ ->
        @default_pdq["cleanup_interval_ms"]
    end
  end

  @doc """
  Returns whether Ordered Dialogue Protocol (ODP) is enabled.
  """
  @spec odp_enabled?(map()) :: boolean()
  def odp_enabled?(config) do
    case get_in(config, ["odp", "enabled"]) do
      value when is_boolean(value) -> value
      value when value in ["true", "1", 1] -> true
      _ -> false
    end
  end

  @doc """
  Returns whether join challenge is enabled in the configuration.
  """
  @spec join_challenge_enabled?(map()) :: boolean()
  def join_challenge_enabled?(config) do
    case get_in(config, ["join_challenge", "enabled"]) do
      value when is_boolean(value) -> value
      value when value in ["true", "1", 1] -> true
      _ -> false
    end
  end

  @doc """
  Returns whether trust policy is enabled in the configuration.
  """
  @spec trust_policy_enabled?(map()) :: boolean()
  def trust_policy_enabled?(config) do
    case get_in(config, ["trust_policy", "enabled"]) do
      value when is_boolean(value) -> value
      value when value in ["true", "1", 1] -> true
      _ -> false
    end
  end

  @doc """
  Returns whether privacy tiers are enabled in the configuration.
  """
  @spec privacy_tiers_enabled?(map()) :: boolean()
  def privacy_tiers_enabled?(config) do
    case get_in(config, ["privacy_tiers", "enabled"]) do
      value when is_boolean(value) -> value
      value when value in ["true", "1", 1] -> true
      _ -> false
    end
  end

  @doc """
  Returns the multiplier for a given privacy tier.
  Default multipliers: low=1, medium=2, high=5
  Returns 1 for unknown tiers.
  """
  @spec privacy_tier_multiplier(map(), String.t()) :: non_neg_integer()
  def privacy_tier_multiplier(config, tier) when is_binary(tier) do
    # If privacy_tiers config exists, only use values from the tiers map
    case get_in(config, ["privacy_tiers", "tiers"]) do
      nil ->
        # No privacy_tiers config, use standard defaults
        case tier do
          "low" -> 1
          "medium" -> 2
          "high" -> 5
          _ -> 1
        end

      tiers_map when is_map(tiers_map) ->
        # privacy_tiers config exists, only use configured values
        case Map.get(tiers_map, tier) do
          value when is_integer(value) and value > 0 -> value
          _ -> 1
        end

      _ ->
        1
    end
  end

  @doc """
  Returns the minimum trust score from configuration.
  Default value: 0.0
  """
  @spec trust_policy_min_score(map()) :: float()
  def trust_policy_min_score(config) do
    case get_in(config, ["trust_policy", "min_trust_score"]) do
      value when is_float(value) -> value
      value when is_integer(value) -> value / 1.0
      value when is_binary(value) ->
        case Float.parse(value) do
          {float, _} -> float
          _ -> 0.0
        end

      _ ->
        0.0
    end
  end

  @doc """
  Returns the join challenge timeout in milliseconds.
  Default value: 30000 (30 seconds)
  """
  @spec join_challenge_timeout_ms(map()) :: non_neg_integer()
  def join_challenge_timeout_ms(config) do
    case get_in(config, ["join_challenge", "timeout_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> 30_000
        end

      _ ->
        30_000
    end
  end

  @doc """
  Returns the join challenge difficulty level.
  Default value: 1
  """
  @spec join_challenge_difficulty(map()) :: non_neg_integer()
  def join_challenge_difficulty(config) do
    case get_in(config, ["join_challenge", "difficulty"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> 1
        end

      _ ->
        1
    end
  end
end
