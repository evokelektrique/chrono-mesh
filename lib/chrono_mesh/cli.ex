defmodule ChronoMesh.CLI do
  @moduledoc """
  Entry point for the `chrono_mesh` command-line tool.
  """

  alias ChronoMesh.{Config, Runtime}

  @usage """
  chrono_mesh <command> [options]

  Commands:
    init                         Initialise configuration and keypair
    identity show                Display identity information
    peers list                   Show known peers
    peers add --name N --public-key PATH [--node-id HEX] [--note TEXT]
    start [--mode MODE]          Start local services (MODE: client | server | combined)
    help                         Show this message
  """

  @modes ~w(client server combined)

  @doc """
  Main entry point (for escript).
  """
  @spec main([String.t()]) :: :ok | no_return()
  def main(argv \\ System.argv()) do
    case argv do
      [] ->
        IO.puts(@usage)

      ["help"] ->
        IO.puts(@usage)

      ["init" | rest] ->
        handle_init(rest)

      ["identity", "show"] ->
        with_config(&print_identity/1)

      ["peers", "list"] ->
        with_config(&print_peers/1)

      ["peers", "add" | rest] ->
        with_config(fn config -> handle_peers_add(config, rest) end)

      ["send" | rest] ->
        with_config(fn config -> handle_send(config, rest) end)

      ["start" | rest] ->
        with_config(fn config -> handle_start(config, rest) end)

      _ ->
        IO.puts("Unknown command. Try `chrono_mesh help`.")
        System.halt(1)
    end
  end

  defp handle_init(argv) do
    {opts, _rest, invalid} =
      OptionParser.parse(argv, strict: [name: :string])

    if invalid != [] do
      IO.puts("Invalid options: #{inspect(invalid)}")
      System.halt(1)
    end

    name = opts[:name]

    {_config, created?} = Config.ensure(name: name)

    if created? do
      IO.puts("Configuration created at #{Config.config_path()}")
    else
      IO.puts("Configuration already exists at #{Config.config_path()}")
    end
  end

  defp print_identity(config) do
    identity = config["identity"] || %{}

    IO.puts("""
    Display name : #{identity["display_name"]}
    Private key  : #{identity["private_key_path"]}
    Public key   : #{identity["public_key_path"]}
    """)
  end

  defp print_peers(config) do
    peers = config["peers"] || []

    if peers == [] do
      IO.puts("No peers configured. Use `chrono_mesh peers add ...`.")
    else
      Enum.each(peers, fn peer ->
        node_id_str =
          case peer["node_id"] do
            nil ->
              if peer["public_key"] do
                # Derive from public_key
                try do
                  pubkey = ChronoMesh.Keys.read_public_key!(peer["public_key"])
                  node_id = ChronoMesh.Keys.node_id_from_public_key(pubkey)
                  Base.encode16(node_id, case: :lower)
                rescue
                  _ -> "N/A (requires public_key)"
                end
              else
                "N/A"
              end

            node_id_hex ->
              node_id_hex
          end

        IO.puts("""
        - #{peer["name"]}
            node_id: #{node_id_str}
            public_key: #{peer["public_key"] || "N/A"}
            note: #{peer["note"] || "-"}
        """)
      end)
    end
  end

  defp handle_peers_add(config, argv) do
    {opts, _argv, invalid} =
      OptionParser.parse(argv,
        strict: [name: :string, public_key: :string, node_id: :string, note: :string]
      )

    if invalid != [] do
      IO.puts("Invalid options: #{inspect(invalid)}")
      System.halt(1)
    end

    with {:ok, name} <- fetch_required(opts, :name),
         {:ok, public_key} <- fetch_required(opts, :public_key) do
      peer =
        %{
          "name" => name,
          "public_key" => public_key,
          "note" => opts[:note]
        }
        |> then(fn p ->
          if opts[:node_id] do
            Map.put(p, "node_id", opts[:node_id])
          else
            p
          end
        end)

      updated_config =
        config
        |> Map.update("peers", [], fn peers -> peers ++ [peer] end)

      Config.write!(updated_config)
      IO.puts("Added peer #{name}.")
    else
      {:error, message} ->
        IO.puts(message)
        System.halt(1)
    end
  end

  defp handle_start(config, argv) do
    {opts, _rest, invalid} = OptionParser.parse(argv, strict: [mode: :string])

    if invalid != [] do
      IO.puts("Invalid options: #{inspect(invalid)}")
      System.halt(1)
    end

    mode =
      opts
      |> Keyword.get(:mode, "combined")
      |> String.downcase()

    unless mode in @modes do
      IO.puts("Unknown mode #{mode}. Valid modes: #{Enum.join(@modes, ", ")}")
      System.halt(1)
    end

    IO.puts("Starting chrono_mesh in #{mode} mode…")
    {:ok, _pid} = Runtime.start(mode: String.to_atom(mode), config: config)
    :timer.sleep(:infinity)
  end

  defp handle_send(config, argv) do
    {opts, _rest, invalid} =
      OptionParser.parse(argv,
        strict: [to: :string, message: :string, path_length: :integer]
      )

    if invalid != [] do
      IO.puts("Invalid options: #{inspect(invalid)}")
      System.halt(1)
    end

    with {:ok, recipient} <- fetch_required(opts, :to),
         {:ok, message} <- fetch_required(opts, :message) do
      path_length = determine_path_length(opts[:path_length], config)

      case ChronoMesh.ClientActions.send_message(config, recipient, message,
             path_length: path_length
           ) do
        :ok ->
          IO.puts("Message queued for delivery.")

        {:error, reason} ->
          IO.puts("Failed to queue message: #{reason}")
          System.halt(1)
      end
    else
      {:error, message} ->
        IO.puts(message)
        System.halt(1)
    end
  end

  defp with_config(fun) do
    {config, _} = Config.ensure()
    fun.(config)
  end

  defp fetch_required(opts, key) do
    case opts[key] do
      nil -> {:error, "Missing required option --#{key}"}
      value -> {:ok, value}
    end
  end

  defp determine_path_length(nil, config) do
    config
    |> get_in(["network", "default_path_length"])
    |> parse_int(3)
  end

  defp determine_path_length(value, _config) do
    parse_int(value, 3)
  end

  defp parse_int(value, _default) when is_integer(value), do: value

  defp parse_int(value, default) when is_binary(value) do
    case Integer.parse(value) do
      {int, _rest} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default
end
