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
    peers add --name N --address HOST:PORT --public-key PATH [--note TEXT]
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
        IO.puts("""
        - #{peer["name"]}
            address: #{peer["address"]}
            public_key: #{peer["public_key"]}
            note: #{peer["note"] || "-"}
        """)
      end)
    end
  end

  defp handle_peers_add(config, argv) do
    {opts, _argv, invalid} =
      OptionParser.parse(argv,
        strict: [name: :string, address: :string, public_key: :string, note: :string]
      )

    if invalid != [] do
      IO.puts("Invalid options: #{inspect(invalid)}")
      System.halt(1)
    end

    with {:ok, name} <- fetch_required(opts, :name),
         {:ok, address} <- fetch_required(opts, :address),
         {:ok, public_key} <- fetch_required(opts, :public_key) do
      updated_config =
        config
        |> Map.update("peers", [], fn peers ->
          peers ++
            [
              %{
                "name" => name,
                "address" => address,
                "public_key" => public_key,
                "note" => opts[:note]
              }
            ]
        end)

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
