defmodule ChronoMesh.DiscoveryTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.Discovery

  setup do
    {:ok, pid} = start_supervised({Discovery, %{}})
    :ets.delete_all_objects(:chrono_mesh_peers)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :normal)

      try do
        :ets.delete(:chrono_mesh_peers)
      rescue
        ArgumentError -> :ok
      end
    end)

    :ok
  end

  test "upsert_peer/3 registers peers and random_sample/1 returns them" do
    pk = :crypto.strong_rand_bytes(32)
    assert :ok == Discovery.upsert_peer(pk, "127.0.0.1", 4_200)

    peers = Discovery.list_peers()
    assert [%{public_key: ^pk, host: "127.0.0.1", port: 4_200}] = peers

    assert Discovery.random_sample(1) == peers
  end
end
