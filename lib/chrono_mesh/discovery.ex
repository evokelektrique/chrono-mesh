defmodule ChronoMesh.Discovery do
  @moduledoc """
  Lightweight discovery service (DHT skeleton).

  - Maintains an ETS table of known peers: %{public_key => %{host, port, ts}}.
  - On start, publishes self (if identity present) and ingests bootstrap peers.
  - Provides random sampling for path building.

  This is a placeholder for a future Kademlia implementation.
  """

  use GenServer
  require Logger

  @table :chrono_mesh_peers

  @type peer :: %{
          host: String.t(),
          port: non_neg_integer(),
          public_key: binary(),
          ts: non_neg_integer()
        }

  @doc """
  Starts the ETS-backed peer discovery process.
  """
  @spec start_link(map()) :: GenServer.on_start()
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @impl true
  @doc """
  Initializes the discovery process by creating the ETS table, bootstrapping from config,
  and publishing the self-node entry.
  """
  @spec init(map()) :: {:ok, %{config: map()}}
  def init(config) do
    ensure_table()
    bootstrap_from_config(config)
    publish_self(config)
    {:ok, %{config: config}}
  end

  @doc """
  Returns all known peers collected in the in-memory registry.
  """
  @spec list_peers() :: [peer()]
  def list_peers do
    case :ets.tab2list(@table) do
      [] -> []
      entries -> Enum.map(entries, fn {_pk, peer} -> peer end)
    end
  end

  @doc """
  Provides a shuffled subset of peers useful for path construction.
  """
  @spec random_sample(non_neg_integer()) :: [peer()]
  def random_sample(n) when n > 0 do
    list_peers() |> Enum.shuffle() |> Enum.take(n)
  end

  @doc """
  Inserts or updates a peer in the discovery table.
  """
  @spec upsert_peer(binary(), String.t(), non_neg_integer()) :: :ok
  def upsert_peer(pubkey, host, port)
      when is_binary(pubkey) and is_binary(host) and is_integer(port) do
    ts = System.os_time(:second)
    :ets.insert(@table, {pubkey, %{public_key: pubkey, host: host, port: port, ts: ts}})
    :ok
  end

  @doc false
  @spec ensure_table() :: :chrono_mesh_peers
  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined -> :ets.new(@table, [:set, :public, :named_table])
      _ -> @table
    end
  end

  @doc false
  @spec publish_self(map()) :: :ok
  defp publish_self(%{"identity" => %{"public_key_path" => pk_path}, "network" => net}) do
    try do
      pubkey = ChronoMesh.Keys.read_public_key!(pk_path)
      host = Map.get(net, "listen_host", "127.0.0.1")
      port = Map.get(net, "listen_port", 4_000)
      upsert_peer(pubkey, host, port)
      Logger.info("Discovery: published self #{host}:#{port}")
    rescue
      _ -> :ok
    end
  end

  defp publish_self(_), do: :ok

  @doc false
  @spec bootstrap_from_config(map()) :: :ok
  defp bootstrap_from_config(%{"network" => net}) do
    peers = Map.get(net, "bootstrap_peers", [])

    Enum.each(peers, fn peer ->
      case peer do
        %{"address" => addr, "public_key" => pk} ->
          with {host, port} <- parse_addr(addr),
               {:ok, pubkey} <- decode_pk(pk) do
            upsert_peer(pubkey, host, port)
          else
            _ -> Logger.warning("Discovery: invalid bootstrap peer #{inspect(peer)}")
          end

        _ ->
          Logger.warning("Discovery: invalid bootstrap peer #{inspect(peer)}")
      end
    end)
  end

  defp bootstrap_from_config(_), do: :ok

  @doc false
  @spec parse_addr(String.t()) :: {String.t(), pos_integer()}
  defp parse_addr(addr) when is_binary(addr) do
    case String.split(addr, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, _} when port > 0 -> {host, port}
          _ -> raise ArgumentError
        end

      _ ->
        raise ArgumentError
    end
  end

  @doc false
  @spec decode_pk(String.t()) :: {:ok, binary()}
  defp decode_pk(pk) when is_binary(pk) do
    pk = String.trim(pk)

    case Base.decode64(pk) do
      {:ok, bin} -> {:ok, bin}
      :error -> {:ok, pk}
    end
  end
end
