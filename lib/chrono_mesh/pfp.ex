defmodule ChronoMesh.PFP do
  @moduledoc """
  Path Failure Protocol (PFP) for detecting and handling path failures.

  Detects when a path breaks (no response from next hop), composes failure notices,
  and provides path rerouting logic for reliable message delivery.
  """

  @typedoc "Frame ID (16 bytes binary)"
  @type frame_id :: binary()

  @typedoc "Node ID where failure occurred"
  @type node_id :: binary()

  @typedoc "Type of failure"
  @type failure_type :: :timeout | :connection_error | :invalid_response

  @typedoc "Failure Notice Packet"
  @type failure_notice :: %{
          frame_id: frame_id(),
          failed_node_id: node_id(),
          failure_type: failure_type(),
          timestamp: non_neg_integer(),
          signature: binary()
        }

  @typedoc "Active path tracking"
  @type active_path :: %{
          frame_id: frame_id(),
          path: [node_id()],
          current_hop: non_neg_integer(),
          created_at: non_neg_integer(),
          last_activity: non_neg_integer()
        }

  @doc """
  Detects a path failure and composes a failure notice.

  Returns a failure notice packet that can be sent upstream to notify
  the sender about the path failure.
  """
  @spec detect_failure(frame_id(), node_id(), failure_type(), binary()) ::
          failure_notice()
  def detect_failure(frame_id, failed_node_id, failure_type, private_key)
      when is_binary(frame_id) and byte_size(frame_id) == 16 and
             is_binary(failed_node_id) and byte_size(failed_node_id) == 32 and
             is_atom(failure_type) and is_binary(private_key) do
    timestamp = System.system_time(:millisecond)

    # Compose failure notice
    failure_notice = %{
      frame_id: frame_id,
      failed_node_id: failed_node_id,
      failure_type: failure_type,
      timestamp: timestamp,
      signature: <<>>
    }

    # Sign the failure notice
    message = encode_failure_notice_message(failure_notice)
    signature = ChronoMesh.Keys.sign(message, private_key)

    %{failure_notice | signature: signature}
  end

  @doc """
  Sends a failure notice upstream to notify the sender about a path failure.

  The failure notice is sent back through the path to the original sender.
  """
  @spec send_failure_notice(failure_notice(), [node_id()], map()) :: :ok | {:error, term()}
  def send_failure_notice(failure_notice, path, _config) when is_list(path) do
    # Determine the upstream node (previous hop in path)
    # For now, we'll send to the local node's control client
    # In a full implementation, this would route back through the path

    case GenServer.whereis(ChronoMesh.Node) do
      nil ->
        {:error, :node_not_running}

      _pid ->
        # Emit event for failure notice
        ChronoMesh.Events.emit(:path_failure, %{
          frame_id: failure_notice.frame_id,
          failed_node_id: failure_notice.failed_node_id,
          failure_type: failure_notice.failure_type
        })

        :ok
    end
  end

  @doc """
  Handles a received failure notice.

  Verifies the failure notice signature and processes it.
  Returns `:ok` if valid, `{:error, reason}` if invalid.
  """
  @spec handle_failure_notice(failure_notice(), binary()) :: :ok | {:error, term()}
  def handle_failure_notice(failure_notice, public_key)
      when is_map(failure_notice) and is_binary(public_key) do
    # Verify signature
    message = encode_failure_notice_message(failure_notice)

    if ChronoMesh.Keys.verify_public(message, failure_notice.signature, public_key) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  @doc """
  Generates an alternative path for a failed route.

  Takes the failed path and generates a new path avoiding the failed node.
  """
  @spec reroute_path([node_id()], node_id(), [node_id()]) :: {:ok, [node_id()]} | {:error, term()}
  def reroute_path(failed_path, failed_node_id, available_peers) when is_list(failed_path) do
    # Remove failed node and nodes before it from available peers
    failed_index = Enum.find_index(failed_path, &(&1 == failed_node_id))

    if failed_index == nil do
      {:error, :failed_node_not_in_path}
    else
      # Get nodes before the failure point (these are still valid)
      valid_prefix = Enum.take(failed_path, failed_index)

      # Get nodes after the failure point (these need to be rerouted)
      remaining_path = Enum.drop(failed_path, failed_index + 1)

      # Get available peers excluding failed nodes and already-used nodes
      used_nodes = MapSet.new(failed_path)
      available = Enum.reject(available_peers, &MapSet.member?(used_nodes, &1))

      if length(available) < length(remaining_path) do
        {:error, :insufficient_peers}
      else
        # Build new path: keep valid prefix, add new nodes for remaining hops
        new_suffix =
          available
          |> Enum.shuffle()
          |> Enum.take(length(remaining_path))

        new_path = valid_prefix ++ new_suffix
        {:ok, new_path}
      end
    end
  end

  @doc """
  Verifies a failure notice signature using the sender's public key.

  Returns `true` if valid, `false` otherwise.
  """
  @spec verify_failure_notice(failure_notice(), binary()) :: boolean()
  def verify_failure_notice(failure_notice, public_key)
      when is_map(failure_notice) and is_binary(public_key) do
    message = encode_failure_notice_message(failure_notice)
    ChronoMesh.Keys.verify_public(message, failure_notice.signature, public_key)
  end

  # Private helpers -----------------------------------------------------------

  @spec encode_failure_notice_message(failure_notice()) :: binary()
  defp encode_failure_notice_message(failure_notice) do
    failure_type_binary =
      case failure_notice.failure_type do
        :timeout -> <<0>>
        :connection_error -> <<1>>
        :invalid_response -> <<2>>
        _ -> <<255>>
      end

    failure_notice.frame_id <>
      failure_notice.failed_node_id <>
      failure_type_binary <>
      <<failure_notice.timestamp::64>>
  end
end
