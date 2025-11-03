defmodule ChronoMesh.ClientActionsTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{ClientActions, Keys}

  setup do
    # Setup test keys for peers
    {pub1, _priv1} = Keys.generate()
    {pub2, _priv2} = Keys.generate()
    {pub3, _priv3} = Keys.generate()

    pub1_path = Path.join(System.tmp_dir!(), "test_pub1.key")
    pub2_path = Path.join(System.tmp_dir!(), "test_pub2.key")
    pub3_path = Path.join(System.tmp_dir!(), "test_pub3.key")

    Keys.write_public_key!(pub1_path, pub1)
    Keys.write_public_key!(pub2_path, pub2)
    Keys.write_public_key!(pub3_path, pub3)

    config = %{
      "peers" => [
        %{
          "name" => "alice",
          "public_key" => pub1_path
        },
        %{
          "name" => "bob",
          "public_key" => pub2_path
        },
        %{
          "name" => "charlie",
          "public_key" => pub3_path
        }
      ],
      "network" => %{
        "pulse_size_bytes" => 1024,
        "default_path_length" => 2
      }
    }

    on_exit(fn ->
      File.rm(pub1_path)
      File.rm(pub2_path)
      File.rm(pub3_path)
    end)

    %{config: config}
  end

  describe "send_message/4" do
    test "returns error for unknown recipient", %{config: config} do
      result = ClientActions.send_message(config, "unknown", "Hello!", [])

      assert {:error, msg} = result
      assert String.contains?(msg, "Unknown peer")
    end

    test "handles empty peers list" do
      empty_config = %{"peers" => []}

      result = ClientActions.send_message(empty_config, "alice", "Hello!", [])

      assert {:error, _msg} = result
    end

    test "returns error when not enough peers for path", %{config: config} do
      # Single peer, path_length of 2 should fail
      single_peer_config = %{
        "peers" => [List.first(config["peers"])],
        "network" => %{"pulse_size_bytes" => 1024}
      }

      result = ClientActions.send_message(single_peer_config, "alice", "Hello!", path_length: 2)

      assert {:error, _msg} = result
    end
  end
end
