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

  @doc """
  Returns `{config_map, created?}`.
  """
  @spec ensure(keyword()) :: {map(), boolean()}
  def ensure(opts \\ []) do
    with {:ok, yaml} <- File.read(config_file()),
         {:ok, data} <- decode_yaml(yaml) do
      {normalise(data), false}
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
    identity_filename = derive_identity_name(opts[:name])

    private_key_path =
      Path.join(keys_dir(), "#{identity_filename}_sk.pem")

    public_key_path =
      Path.join(keys_dir(), "#{identity_filename}_pk.pem")

    ChronoMesh.Keys.write_private_key!(private_key_path, private_key)
    ChronoMesh.Keys.write_public_key!(public_key_path, public_key)

    network_defaults =
      @default_network
      |> Map.put("listen_port", default_listen_port())
      |> Map.put("listen_host", default_listen_host())

    %{
      "identity" => %{
        "display_name" => identity_filename,
        "private_key_path" => private_key_path,
        "public_key_path" => public_key_path
      },
      "network" => network_defaults,
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
  end

  defp normalise(config) when is_map(config) do
    config
    |> Map.put_new("peers", [])
    |> ensure_network_defaults()
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

  defp encode_yaml(%{} = config) do
    [
      encode_section("identity", config["identity"]),
      encode_section("network", config["network"]),
      encode_peers(config["peers"] || [])
    ]
    |> Enum.reject(&(&1 == ""))
    |> Enum.join("\n")
  end

  defp encode_section(_name, nil), do: ""

  defp encode_section(name, map) when is_map(map) do
    [
      "#{name}:",
      Enum.map(map, fn {k, v} -> "  #{k}: #{yaml_value(v)}" end)
    ]
    |> List.flatten()
    |> Enum.join("\n")
  end

  defp encode_peers([]), do: "peers: []"

  defp encode_peers(peers) do
    header = "peers:"

    body =
      Enum.map(peers, fn peer ->
        [
          "  - name: #{yaml_value(peer["name"])}",
          "    address: #{yaml_value(peer["address"])}",
          "    public_key: #{yaml_value(peer["public_key"])}",
          if(peer["note"], do: "    note: #{yaml_value(peer["note"])}", else: nil)
        ]
        |> Enum.reject(&is_nil/1)
        |> Enum.join("\n")
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
            {Map.put_new(acc, new_section, %{}), peers}
          end

        parse_lines(rest, acc, new_section, nil, peers)

      section in ["identity", "network"] && String.starts_with?(line, "  ") ->
        {key, value} = parse_kv(trimmed)
        updated = Map.update!(acc, section, &Map.put(&1, key, value))
        parse_lines(rest, updated, section, current_peer, peers)

      section == "peers" && String.starts_with?(trimmed, "- ") ->
        {key, value} = parse_kv(String.trim_leading(trimmed, "- ") |> String.trim())
        peer = Map.put(%{}, key, value)
        parse_lines(rest, acc, section, peer, [peer | peers])

      section == "peers" && current_peer != nil && String.starts_with?(line, "    ") ->
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
end
