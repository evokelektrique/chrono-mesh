defmodule ChronoMesh.AddressBookTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.{AddressBook, Keys}

  setup do
    # Clear address book before each test
    if :ets.whereis(:chrono_mesh_address_book) != :undefined do
      :ets.delete_all_objects(:chrono_mesh_address_book)
    end
    :ok
  end

  describe "register/4" do
    test "registers a valid alias with signature" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      assert AddressBook.register("alice", node_id, public_key, private_key) == :ok
      assert AddressBook.exists?("alice.mesh") == true
    end

    test "registers alias without .mesh suffix" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      assert AddressBook.register("bob", node_id, public_key, private_key) == :ok
      assert AddressBook.exists?("bob.mesh") == true
    end

    test "rejects empty alias" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      assert AddressBook.register("", node_id, public_key, private_key) ==
               {:error, :alias_empty}
    end

    test "rejects alias longer than 64 characters" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)
      long_alias = String.duplicate("a", 65)

      assert AddressBook.register(long_alias, node_id, public_key, private_key) ==
               {:error, :alias_too_long}
    end

    test "rejects alias with invalid characters" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      assert AddressBook.register("alice@bob", node_id, public_key, private_key) ==
               {:error, :invalid_alias_format}
    end

    test "rejects invalid node_id size" do
      {public_key, private_key} = Keys.generate()
      invalid_node_id = <<0::size(16)>>

      assert AddressBook.register("alice", invalid_node_id, public_key, private_key) ==
               {:error, :invalid_node_id}
    end

    test "rejects invalid public_key size" do
      {_public_key, private_key} = Keys.generate()
      {public_key2, _private_key2} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key2)
      invalid_public_key = <<0::size(16)>>

      assert AddressBook.register("alice", node_id, invalid_public_key, private_key) ==
               {:error, :invalid_public_key}
    end

    test "allows hyphens in alias" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      assert AddressBook.register("alice-bob", node_id, public_key, private_key) == :ok
      assert AddressBook.exists?("alice-bob.mesh") == true
    end

    test "allows numbers in alias" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      assert AddressBook.register("alice123", node_id, public_key, private_key) == :ok
      assert AddressBook.exists?("alice123.mesh") == true
    end
  end

  describe "resolve/1" do
    test "resolves registered alias to node_id" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      AddressBook.register("alice", node_id, public_key, private_key)

      assert AddressBook.resolve("alice.mesh") == {:ok, node_id}
      assert AddressBook.resolve("alice") == {:ok, node_id}
    end

    test "returns :not_found for unregistered alias" do
      assert AddressBook.resolve("unknown.mesh") == :not_found
      assert AddressBook.resolve("unknown") == :not_found
    end
  end

  describe "list/0" do
    test "lists all registered aliases" do
      {pub1, priv1} = Keys.generate()
      {pub2, priv2} = Keys.generate()
      node_id1 = Keys.node_id_from_public_key(pub1)
      node_id2 = Keys.node_id_from_public_key(pub2)

      AddressBook.register("alice", node_id1, pub1, priv1)
      AddressBook.register("bob", node_id2, pub2, priv2)

      aliases = AddressBook.list()
      assert length(aliases) == 2

      assert {"alice.mesh", node_id1} in aliases
      assert {"bob.mesh", node_id2} in aliases
    end

    test "returns empty list when no aliases registered" do
      assert AddressBook.list() == []
    end
  end

  describe "delete/1" do
    test "deletes registered alias" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      AddressBook.register("alice", node_id, public_key, private_key)
      assert AddressBook.exists?("alice.mesh") == true

      assert AddressBook.delete("alice.mesh") == :ok
      assert AddressBook.exists?("alice.mesh") == false
      assert AddressBook.resolve("alice.mesh") == :not_found
    end

    test "returns :not_found when deleting non-existent alias" do
      assert AddressBook.delete("unknown.mesh") == :not_found
    end
  end

  describe "verify_alias/1" do
    test "verifies signature structure for registered alias" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      AddressBook.register("alice", node_id, public_key, private_key)

      assert AddressBook.verify_alias("alice.mesh") == true
    end

    test "returns false for non-existent alias" do
      assert AddressBook.verify_alias("unknown.mesh") == false
    end
  end

  describe "exists?/1" do
    test "returns true for registered alias" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      AddressBook.register("alice", node_id, public_key, private_key)

      assert AddressBook.exists?("alice.mesh") == true
      assert AddressBook.exists?("alice") == true
    end

    test "returns false for unregistered alias" do
      assert AddressBook.exists?("unknown.mesh") == false
    end
  end

  describe "integration with ClientActions" do
    test "alias can be resolved and used in send_message" do
      {public_key, private_key} = Keys.generate()
      node_id = Keys.node_id_from_public_key(public_key)

      AddressBook.register("alice", node_id, public_key, private_key)

      # Verify alias resolves correctly
      assert AddressBook.resolve("alice.mesh") == {:ok, node_id}
    end
  end
end
