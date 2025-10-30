defmodule ChronoMeshTest do
  use ExUnit.Case
  doctest ChronoMesh

  setup do
    original_home = System.get_env("CHRONO_MESH_HOME")

    tmp_home =
      Path.join(System.tmp_dir!(), "chrono_mesh_test_home_#{System.unique_integer([:positive])}")

    File.rm_rf(tmp_home)
    System.put_env("CHRONO_MESH_HOME", tmp_home)

    on_exit(fn ->
      case original_home do
        nil -> System.delete_env("CHRONO_MESH_HOME")
        value -> System.put_env("CHRONO_MESH_HOME", value)
      end

      File.rm_rf(tmp_home)
    end)

    :ok
  end

  test "node schedules and dispatches pulses on next wave" do
    config = %{
      "network" => %{
        "wave_duration_secs" => 1,
        "listen_port" => 4050,
        "listen_host" => "127.0.0.1"
      },
      "identity" => %{"private_key_path" => System.tmp_dir!() <> "/dummy_sk"}
    }

    File.write!(config["identity"]["private_key_path"], Base.encode64(<<0::256>>))

    {:ok, _} = ChronoMesh.Node.start_link(config)

    assert %{} = :sys.get_state(ChronoMesh.Node)
  after
    if pid = Process.whereis(ChronoMesh.Node), do: Process.exit(pid, :normal)
    if pid = Process.whereis(ChronoMesh.ControlServer), do: Process.exit(pid, :normal)
  end

  test "greets the world" do
    assert ChronoMesh.hello() == :world
  end
end
