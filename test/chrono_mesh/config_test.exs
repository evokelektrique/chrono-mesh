defmodule ChronoMesh.ConfigTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.Config

  setup do
    tmp_home =
      Path.join(System.tmp_dir!(), "chrono_mesh_config_home_#{System.unique_integer([:positive])}")

    File.rm_rf(tmp_home)

    original_home = System.get_env("CHRONO_MESH_HOME")
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

  test "ensure/1 creates and persists configuration with defaults" do
    {config, created?} = Config.ensure(name: "Test Peer")
    assert created?
    assert config["identity"]["display_name"] == "test_peer"

    assert File.exists?(Config.config_path())

    assert File.exists?(config["identity"]["private_key_path"])
    assert File.exists?(config["identity"]["public_key_path"])

    assert config["network"]["default_path_length"] == 3
    assert config["network"]["pulse_size_bytes"] == 1024

    {persisted, created_again?} = Config.ensure()
    refute created_again?
    assert persisted["identity"]["display_name"] == config["identity"]["display_name"]
  end
end
