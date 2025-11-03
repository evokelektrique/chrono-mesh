defmodule ChronoMesh.AddressBookConfigTest do
  use ExUnit.Case, async: false

  alias ChronoMesh.AddressBook

  describe "configuration helpers" do
    test "max_subscriptions/1 returns default when config is nil" do
      assert AddressBook.max_subscriptions(nil) == 100
    end

    test "max_subscriptions/1 returns default when config is empty" do
      assert AddressBook.max_subscriptions(%{}) == 100
    end

    test "max_subscriptions/1 returns configured value" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "max_count" => 50
          }
        }
      }

      assert AddressBook.max_subscriptions(config) == 50
    end

    test "subscription_ttl_ms/1 returns default when config is nil" do
      assert AddressBook.subscription_ttl_ms(nil) == :timer.hours(1)
    end

    test "subscription_ttl_ms/1 returns configured value" do
      ttl_ms = :timer.hours(2)

      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "ttl_ms" => ttl_ms
          }
        }
      }

      assert AddressBook.subscription_ttl_ms(config) == ttl_ms
    end

    test "subscription_ttl_ms/1 parses string values" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "ttl_ms" => "7200000"
          }
        }
      }

      assert AddressBook.subscription_ttl_ms(config) == 7_200_000
    end

    test "subscription_ttl_ms/1 returns default for invalid string values" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "ttl_ms" => "invalid"
          }
        }
      }

      assert AddressBook.subscription_ttl_ms(config) == :timer.hours(1)
    end

    test "subscription_rate_limit_ms/1 returns default when config is nil" do
      assert AddressBook.subscription_rate_limit_ms(nil) == :timer.minutes(1)
    end

    test "subscription_rate_limit_ms/1 returns configured value" do
      rate_limit_ms = :timer.minutes(2)

      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "rate_limit_ms" => rate_limit_ms
          }
        }
      }

      assert AddressBook.subscription_rate_limit_ms(config) == rate_limit_ms
    end

    test "subscription_rate_limit_ms/1 parses string values" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "rate_limit_ms" => "120000"
          }
        }
      }

      assert AddressBook.subscription_rate_limit_ms(config) == 120_000
    end

    test "alias_publish_ttl_ms/1 returns default when config is nil" do
      assert AddressBook.alias_publish_ttl_ms(nil) == :timer.hours(24)
    end

    test "alias_publish_ttl_ms/1 returns configured value" do
      ttl_ms = :timer.hours(48)

      config = %{
        "address_book" => %{
          "aliases" => %{
            "publish_ttl_ms" => ttl_ms
          }
        }
      }

      assert AddressBook.alias_publish_ttl_ms(config) == ttl_ms
    end

    test "alias_publish_rate_limit_ms/1 returns default when config is nil" do
      assert AddressBook.alias_publish_rate_limit_ms(nil) == :timer.minutes(1)
    end

    test "alias_publish_rate_limit_ms/1 returns configured value" do
      rate_limit_ms = :timer.minutes(5)

      config = %{
        "address_book" => %{
          "aliases" => %{
            "publish_rate_limit_ms" => rate_limit_ms
          }
        }
      }

      assert AddressBook.alias_publish_rate_limit_ms(config) == rate_limit_ms
    end

    test "subscriptions_enabled?/1 returns default when config is nil" do
      assert AddressBook.subscriptions_enabled?(nil) == true
    end

    test "subscriptions_enabled?/1 returns configured boolean value" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "enabled" => false
          }
        }
      }

      assert AddressBook.subscriptions_enabled?(config) == false
    end

    test "subscriptions_enabled?/1 parses string 'true'" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "enabled" => "true"
          }
        }
      }

      assert AddressBook.subscriptions_enabled?(config) == true
    end

    test "subscriptions_enabled?/1 parses string '1'" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "enabled" => "1"
          }
        }
      }

      assert AddressBook.subscriptions_enabled?(config) == true
    end

    test "subscriptions_enabled?/1 parses string 'yes'" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "enabled" => "yes"
          }
        }
      }

      assert AddressBook.subscriptions_enabled?(config) == true
    end

    test "subscriptions_enabled?/1 returns false for unrecognized string values" do
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "enabled" => "false"
          }
        }
      }

      assert AddressBook.subscriptions_enabled?(config) == false
    end

    test "subscription_refresh_interval_ms/1 returns default when config is nil" do
      assert AddressBook.subscription_refresh_interval_ms(nil) == :timer.minutes(30)
    end

    test "subscription_refresh_interval_ms/1 returns configured value" do
      refresh_interval_ms = :timer.minutes(60)

      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "refresh_interval_ms" => refresh_interval_ms
          }
        }
      }

      assert AddressBook.subscription_refresh_interval_ms(config) == refresh_interval_ms
    end
  end

  describe "subscribe/4 with configuration" do
    setup do
      # Clean up ETS tables before each test
      cleanup_tables()
      :ok
    end

    defp cleanup_tables do
      tables = [:chrono_mesh_subscriptions]

      Enum.each(tables, fn table ->
        if :ets.whereis(table) != :undefined do
          :ets.delete_all_objects(table)
        end
      end)
    end

    test "respects configured max_subscriptions limit" do
      alias ChronoMesh.Keys

      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      # Configure max_count to 5
      config = %{
        "address_book" => %{
          "subscriptions" => %{
            "max_count" => 5
          }
        }
      }

      # Create 5 target nodes
      target_nodes =
        for _ <- 1..5 do
          {target_pub, _target_priv} = Keys.generate()
          Keys.node_id_from_public_key(target_pub)
        end

      # Subscribe to all 5 nodes (should succeed)
      Enum.each(target_nodes, fn target_node_id ->
        assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id, config) ==
                 :ok
      end)

      # Try to subscribe to a 6th node (should fail)
      {target_pub, _target_priv} = Keys.generate()
      target_node_id = Keys.node_id_from_public_key(target_pub)

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id, config) ==
               {:error, :max_subscriptions_exceeded}
    end

    test "uses default max_subscriptions when config is nil" do
      alias ChronoMesh.Keys

      {subscriber_pub, _subscriber_priv} = Keys.generate()
      subscriber_node_id = Keys.node_id_from_public_key(subscriber_pub)

      # Create 100 target nodes (default max)
      target_nodes =
        for _ <- 1..100 do
          {target_pub, _target_priv} = Keys.generate()
          Keys.node_id_from_public_key(target_pub)
        end

      # Subscribe to all 100 nodes (should succeed)
      Enum.each(target_nodes, fn target_node_id ->
        assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id, nil) ==
                 :ok
      end)

      # Try to subscribe to a 101st node (should fail)
      {target_pub, _target_priv} = Keys.generate()
      target_node_id = Keys.node_id_from_public_key(target_pub)

      assert AddressBook.subscribe(subscriber_node_id, subscriber_pub, target_node_id, nil) ==
               {:error, :max_subscriptions_exceeded}
    end
  end
end
