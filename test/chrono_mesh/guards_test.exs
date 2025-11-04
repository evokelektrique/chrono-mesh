defmodule ChronoMesh.GuardsTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.Guards

  setup do
    tmp_home = Path.join(System.tmp_dir!(), "chrono_mesh_guards_#{System.unique_integer([:positive])}")
    File.rm_rf(tmp_home)

    on_exit(fn -> File.rm_rf(tmp_home) end)

    {:ok, tmp_home: tmp_home}
  end

  describe "init/1 - configuration initialization" do
    test "initializes with guards enabled" do
      config = %{
        "guards" => %{
          "enabled" => true,
          "guard_count" => 2,
          "rotation_interval_days" => 14
        }
      }

      {:ok, state} = Guards.init(config)

      assert state["enabled"] == true
      assert state["guard_count"] == 2
      assert state["rotation_interval_days"] == 14
      assert state["guards"] == []
    end

    test "returns empty state when guards disabled" do
      config = %{"guards" => %{"enabled" => false}}

      {:ok, state} = Guards.init(config)

      assert state == %{}
    end

    test "returns empty state when guards not configured" do
      config = %{}

      {:ok, state} = Guards.init(config)

      assert state == %{}
    end

    test "uses default values when not specified" do
      config = %{"guards" => %{"enabled" => true}}

      {:ok, state} = Guards.init(config)

      assert state["guard_count"] == 3
      assert state["rotation_interval_days"] == 30
      assert state["min_uptime_percent"] == 95
    end
  end

  describe "select_entry_guard/1" do
    test "returns nil when guards disabled" do
      state = %{}

      result = Guards.select_entry_guard(state)

      assert result == nil
    end

    test "returns nil when no guards available" do
      state = %{"enabled" => true, "guards" => []}

      result = Guards.select_entry_guard(state)

      assert result == nil
    end

    test "selects from available guards" do
      state = %{"enabled" => true, "guards" => ["guard1", "guard2", "guard3"]}

      result = Guards.select_entry_guard(state)

      assert result in ["guard1", "guard2", "guard3"]
    end
  end

  describe "select_entry_guards/2" do
    test "returns empty list when disabled" do
      state = %{"enabled" => false}
      peers = [%{"node_id" => "peer1", "uptime_percent" => 99}]

      result = Guards.select_entry_guards(state, peers)

      assert result == []
    end

    test "returns empty list for invalid state" do
      result = Guards.select_entry_guards(%{}, [])

      assert result == []
    end
  end

  describe "record_guard_stat/4" do
    test "records success statistics" do
      state = %{"enabled" => true, "guard_stats" => %{}}

      updated = Guards.record_guard_stat(state, "guard1", :success, 50)

      assert updated["guard_stats"]["guard1"].total == 1
      assert updated["guard_stats"]["guard1"].success == 1
      assert updated["guard_stats"]["guard1"].latency_sum == 50
    end

    test "records failure statistics" do
      state = %{"enabled" => true, "guard_stats" => %{}}

      updated = Guards.record_guard_stat(state, "guard1", :failure, 1000)

      assert updated["guard_stats"]["guard1"].total == 1
      assert updated["guard_stats"]["guard1"].success == 0
      assert updated["guard_stats"]["guard1"].latency_sum == 1000
    end

    test "accumulates multiple records" do
      state = %{"enabled" => true, "guard_stats" => %{}}

      updated1 = Guards.record_guard_stat(state, "guard1", :success, 50)
      updated2 = Guards.record_guard_stat(updated1, "guard1", :success, 100)
      updated3 = Guards.record_guard_stat(updated2, "guard1", :failure, 75)

      stats = updated3["guard_stats"]["guard1"]

      assert stats.total == 3
      assert stats.success == 2
      assert stats.latency_sum == 225
    end

    test "ignores stats when guards disabled" do
      state = %{"enabled" => false}

      updated = Guards.record_guard_stat(state, "guard1", :success, 50)

      assert updated == state
    end
  end

  describe "guard_stats/2" do
    test "returns nil when no stats exist" do
      state = %{"guard_stats" => %{}}

      result = Guards.guard_stats(state, "unknown_guard")

      assert result == nil
    end

    test "calculates success rate and latency" do
      state = %{
        "guard_stats" => %{
          "guard1" => %{total: 10, success: 8, latency_sum: 500}
        }
      }

      {success_rate, avg_latency} = Guards.guard_stats(state, "guard1")

      assert success_rate == 0.8
      assert avg_latency == 50
    end

    test "handles perfect success rate" do
      state = %{
        "guard_stats" => %{
          "guard1" => %{total: 5, success: 5, latency_sum: 100}
        }
      }

      {success_rate, avg_latency} = Guards.guard_stats(state, "guard1")

      assert success_rate == 1.0
      assert avg_latency == 20
    end

    test "handles zero success rate" do
      state = %{
        "guard_stats" => %{
          "guard1" => %{total: 5, success: 0, latency_sum: 500}
        }
      }

      {success_rate, avg_latency} = Guards.guard_stats(state, "guard1")

      assert success_rate == 0.0
      assert avg_latency == 100
    end
  end

  describe "needs_rotation?/1" do
    test "returns true when no rotation time set" do
      state = %{"enabled" => true, "rotation_interval_days" => 30, "last_rotation" => nil}

      assert Guards.needs_rotation?(state) == true
    end

    test "returns false when rotation not yet due" do
      now = System.os_time(:second)
      yesterday = now - 86400  # 1 day ago

      state = %{
        "enabled" => true,
        "rotation_interval_days" => 30,
        "last_rotation" => yesterday
      }

      assert Guards.needs_rotation?(state) == false
    end

    test "returns true when rotation is due" do
      now = System.os_time(:second)
      thirty_days_ago = now - 30 * 86400

      state = %{
        "enabled" => true,
        "rotation_interval_days" => 30,
        "last_rotation" => thirty_days_ago
      }

      assert Guards.needs_rotation?(state) == true
    end

    test "returns false when guards disabled" do
      assert Guards.needs_rotation?(%{}) == false
    end
  end

  describe "rotate_guards/2" do
    test "selects qualified guards by uptime" do
      state = %{
        "enabled" => true,
        "guard_count" => 2,
        "min_uptime_percent" => 95,
        "guards" => []
      }

      peers = [
        %{"node_id" => "high_uptime", "uptime_percent" => 99},
        %{"node_id" => "low_uptime", "uptime_percent" => 90},
        %{"node_id" => "medium_uptime", "uptime_percent" => 96}
      ]

      guards = Guards.rotate_guards(state, peers)

      assert length(guards) <= 2
      # high_uptime and medium_uptime should be selected
      assert "low_uptime" not in guards
    end

    test "limits guard selection to guard_count" do
      state = %{
        "enabled" => true,
        "guard_count" => 2,
        "min_uptime_percent" => 90,
        "guards" => []
      }

      peers = [
        %{"node_id" => "guard1", "uptime_percent" => 99},
        %{"node_id" => "guard2", "uptime_percent" => 98},
        %{"node_id" => "guard3", "uptime_percent" => 97},
        %{"node_id" => "guard4", "uptime_percent" => 96}
      ]

      guards = Guards.rotate_guards(state, peers)

      assert length(guards) <= 2
    end

    test "handles empty peers list" do
      state = %{
        "enabled" => true,
        "guard_count" => 2,
        "min_uptime_percent" => 95,
        "guards" => ["old_guard"]
      }

      guards = Guards.rotate_guards(state, [])

      assert guards == []
    end

    test "returns empty list when disabled" do
      result = Guards.rotate_guards(%{}, [])

      assert result == []
    end
  end

  describe "update_rotation_time/1" do
    test "updates last_rotation timestamp" do
      state = %{"enabled" => true, "last_rotation" => nil}

      updated = Guards.update_rotation_time(state)

      assert updated["last_rotation"] != nil
      assert is_integer(updated["last_rotation"])
    end

    test "ignores state when guards disabled" do
      state = %{"enabled" => false}

      updated = Guards.update_rotation_time(state)

      assert updated == state
    end
  end

  describe "save_to_disk/2 and load_from_disk/1" do
    test "saves and loads guard state", %{tmp_home: tmp_home} do
      state = %{
        "enabled" => true,
        "guards" => ["guard1", "guard2"],
        "guard_count" => 2,
        "rotation_interval_days" => 30,
        "last_rotation" => System.os_time(:second)
      }

      assert Guards.save_to_disk(state, tmp_home) == :ok

      loaded = Guards.load_from_disk(tmp_home)

      assert loaded != nil
      assert loaded["guards"] == ["guard1", "guard2"]
      assert loaded["guard_count"] == 2
    end

    test "returns nil when file doesn't exist", %{tmp_home: tmp_home} do
      loaded = Guards.load_from_disk(tmp_home)

      assert loaded == nil
    end

    test "handles corrupted file gracefully", %{tmp_home: tmp_home} do
      guards_path = Path.join([tmp_home, ".chrono_mesh", "guards.bin"])
      File.mkdir_p!(Path.dirname(guards_path))
      File.write!(guards_path, "corrupted data")

      loaded = Guards.load_from_disk(tmp_home)

      assert loaded == nil
    end

    test "ignores save when guards disabled", %{tmp_home: tmp_home} do
      state = %{"enabled" => false}

      assert Guards.save_to_disk(state, tmp_home) == :ok

      # File should not be created
      guards_path = Path.join([tmp_home, ".chrono_mesh", "guards.bin"])
      assert !File.exists?(guards_path)
    end
  end

  describe "remove_guard/2" do
    test "removes guard from list" do
      state = %{
        "enabled" => true,
        "guards" => ["guard1", "guard2", "guard3"],
        "guard_stats" => %{"guard1" => %{}, "guard2" => %{}}
      }

      updated = Guards.remove_guard(state, "guard2")

      assert updated["guards"] == ["guard1", "guard3"]
      assert !Map.has_key?(updated["guard_stats"], "guard2")
      assert Map.has_key?(updated["guard_stats"], "guard1")
    end

    test "ignores when guard not found" do
      state = %{
        "enabled" => true,
        "guards" => ["guard1"],
        "guard_stats" => %{}
      }

      updated = Guards.remove_guard(state, "nonexistent")

      assert updated["guards"] == ["guard1"]
    end

    test "ignores when guards disabled" do
      state = %{"enabled" => false}

      updated = Guards.remove_guard(state, "guard1")

      assert updated == state
    end
  end
end
