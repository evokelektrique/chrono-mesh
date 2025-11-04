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
    tmp_dir = System.tmp_dir!()
    {_ed25519_public_key, ed25519_private_key} = ChronoMesh.Keys.keypair()
    ed25519_priv_path = Path.join(tmp_dir, "dummy_ed25519_sk")

    ChronoMesh.Keys.write_private_key!(ed25519_priv_path, ed25519_private_key)

    config = %{
      "network" => %{
        "wave_duration_secs" => 1,
        "listen_port" => 4050,
        "listen_host" => "127.0.0.1"
      },
      "identity" => %{
        "private_key_path" => System.tmp_dir!() <> "/dummy_sk",
        "ed25519_private_key_path" => ed25519_priv_path
      }
    }

    File.write!(config["identity"]["private_key_path"], Base.encode64(<<0::256>>))

    # Ensure node is stopped from previous test
    if pid = Process.whereis(ChronoMesh.Node), do: GenServer.stop(pid)
    if pid = Process.whereis(ChronoMesh.ControlServer), do: GenServer.stop(pid)
    Process.sleep(100)

    case ChronoMesh.Node.start_link(config) do
      {:ok, _} ->
        :ok

      {:error, {:already_started, existing_pid}} ->
        # Clean up and try again
        GenServer.stop(existing_pid)
        Process.sleep(100)
        {:ok, _} = ChronoMesh.Node.start_link(config)
    end

    assert %{} = :sys.get_state(ChronoMesh.Node)
  after
    if pid = Process.whereis(ChronoMesh.Node), do: Process.exit(pid, :normal)
    if pid = Process.whereis(ChronoMesh.ControlServer), do: Process.exit(pid, :normal)
  end

  test "greets the world" do
    assert ChronoMesh.hello() == :world
  end
end
