defmodule ChronoMesh.Node do
  @moduledoc """
  Minimal node implementation that performs Time-Wave Relay (TWR) batching.

  Maintains an in-memory map of pulses indexed by their target wave.
  On each wave tick it shuffles the batch and forwards pulses to the next hop.
  """

  @dialyzer {:nowarn_function, handle_cast: 2}
  @dialyzer {:nowarn_function, process_token: 2}
  @dialyzer {:nowarn_function, deliver_pulse: 3}
  @dialyzer {:nowarn_function, store_payload: 2}
  @dialyzer {:nowarn_function, inbox_path: 0}

  use GenServer
  require Logger

  alias ChronoMesh.Pulse, as: Pulse
  alias ChronoMesh.Token, as: Token
  alias ChronoMesh.Keys, as: Keys
  alias ChronoMesh.FDP, as: FDP
  alias ChronoMesh.PDQ, as: PDQ
  alias ChronoMesh.ODP, as: ODP
  alias ChronoMesh.Config, as: Config

  @type state :: %{
          wave_duration: pos_integer(),
          pulses: %{optional(non_neg_integer()) => [{Pulse.t(), binary()}]},
          config: map(),
          listen_host: String.t(),
          listen_port: non_neg_integer(),
          local_address: String.t(),
          private_key: binary(),
          ed25519_private_key: binary(),
          local_node_id: binary(),
          fdp_pid: pid() | nil,
          pdq_pid: pid() | nil,
          odp_pid: pid() | nil,
          active_paths: %{optional(binary()) => [binary()]}
        }

  # Public API ----------------------------------------------------------------

  @doc """
  Starts the node process responsible for forwarding pulses.
  """
  @spec start_link(map()) :: GenServer.on_start()
  def start_link(config) do
    GenServer.start_link(__MODULE__, config, name: __MODULE__)
  end

  @doc """
  Enqueues a pulse for processing by the running node.
  """
  @spec enqueue(Pulse.t()) :: :ok
  def enqueue(%Pulse{} = pulse) do
    case GenServer.whereis(__MODULE__) do
      nil ->
        Logger.warning("Node process not running; cannot enqueue pulse.")
        :ok

      pid ->
        GenServer.cast(pid, {:enqueue, pulse})
    end
  end

  # GenServer callbacks -------------------------------------------------------

  @impl true
  @doc """
  Prepares the node state, spawns supporting infrastructure and kicks off wave scheduling.
  """
  @spec init(map()) :: {:ok, state()} | {:stop, term()}
  def init(config) do
    wave_duration = parse_wave_duration(config)
    listen_port = parse_listen_port(config)
    listen_host = parse_listen_host(config)
    local_address = "#{listen_host}:#{listen_port}"

    # Start control server, handle already_started case
    control_server_result =
      case ChronoMesh.ControlServer.start_link(port: listen_port, config: config) do
        {:ok, _control_pid} -> :ok
        {:error, {:already_started, _pid}} -> :ok
        {:error, reason} -> {:stop, reason}
      end

    if match?({:stop, _}, control_server_result) do
      control_server_result
    else
      # Start FDP process for frame reassembly
      fdp_opts = [
        frame_timeout_ms: parse_fdp_timeout(config),
        cleanup_interval_ms: parse_fdp_cleanup_interval(config),
        max_frame_size: parse_fdp_max_size(config)
      ]

      {:ok, fdp_pid} = FDP.start_link(fdp_opts)

      # Start PDQ process if enabled
      pdq_pid =
        if Config.pdq_enabled?(config) do
          pdq_opts = [
            disk_path: Config.pdq_disk_path(config),
            encryption_enabled: Config.pdq_encryption_enabled?(config),
            encryption_key:
              get_in(config, ["identity", "ed25519_private_key_path"])
              |> Keys.read_private_key!(),
            cleanup_interval_ms: Config.pdq_cleanup_interval_ms(config)
          ]

          case PDQ.start_link(pdq_opts) do
            {:ok, pid} ->
              # Recover pending waves from disk on startup
              case PDQ.recover_all_waves() do
                {:ok, recovered_waves} when is_map(recovered_waves) ->
                  wave_count = map_size(recovered_waves)
                  Logger.info("PDQ: Recovered #{wave_count} waves from disk")

                # Waves will be loaded on-demand during wave_tick

                {:ok, _} ->
                  Logger.info("PDQ: No waves to recover from disk")

                {:error, reason} ->
                  Logger.warning("PDQ: Failed to recover waves: #{inspect(reason)}")
              end

              pid

            {:error, reason} ->
              Logger.error("Failed to start PDQ: #{inspect(reason)}")
              nil
          end
        else
          nil
        end

      # Start ODP process if enabled
      odp_pid =
        if Config.odp_enabled?(config) do
          # Create delivery callback that stores payload
          delivery_callback = fn dialogue_id, sequence_number, frame_data ->
            # Store the delivered frame (in-order)
            store_payload_for_odp(frame_data, dialogue_id, sequence_number)
          end

          odp_opts = [
            max_buffer_size: Config.odp_max_buffer_size(config),
            sequence_timeout_ms: Config.odp_sequence_timeout_ms(config),
            max_sequence_gap: Config.odp_max_sequence_gap(config),
            delivery_callback: delivery_callback
          ]

          case ODP.start_link(odp_opts) do
            {:ok, pid} ->
              Logger.debug("ODP: Started with buffer size #{Config.odp_max_buffer_size(config)}")
              pid

            {:error, reason} ->
              Logger.error("Failed to start ODP: #{inspect(reason)}")
              nil
          end
        else
          nil
        end

      Logger.info("Node started with wave duration #{wave_duration}s")
      schedule_wave(wave_duration)

      private_key =
        config
        |> get_in(["identity", "private_key_path"])
        |> Keys.read_private_key!()

      # Load Ed25519 keys (required for signatures)
      ed25519_private_key_path = get_in(config, ["identity", "ed25519_private_key_path"])

      unless ed25519_private_key_path != nil and is_binary(ed25519_private_key_path) do
        raise ArgumentError,
              "ed25519_private_key_path must be configured in config[\"identity\"][\"ed25519_private_key_path\"]"
      end

      ed25519_private_key = Keys.read_private_key!(ed25519_private_key_path)

      unless is_binary(ed25519_private_key) and byte_size(ed25519_private_key) == 32 do
        raise ArgumentError, "ed25519_private_key must be a 32-byte binary"
      end

      # Derive Ed25519 public key and node_id for ODP
      ed25519_public_key =
        case get_in(config, ["identity", "ed25519_public_key_path"]) do
          nil ->
            # Fallback: derive from X25519 public key if available
            case get_in(config, ["identity", "public_key_path"]) do
              nil ->
                # Last resort: derive node_id from Ed25519 private key hash
                # (this is a temporary workaround until config includes public key)
                :crypto.hash(:sha256, ed25519_private_key <> "ed25519_pubkey")

              x25519_public_key_path ->
                Keys.read_public_key!(x25519_public_key_path)
            end

          ed25519_public_key_path ->
            Keys.read_public_key!(ed25519_public_key_path)
        end

      local_node_id = Keys.node_id_from_public_key(ed25519_public_key)

      {:ok,
       %{
         wave_duration: wave_duration,
         pulses: %{},
         config: config,
         listen_port: listen_port,
         listen_host: listen_host,
         local_address: local_address,
         private_key: private_key,
         ed25519_private_key: ed25519_private_key,
         local_node_id: local_node_id,
         fdp_pid: fdp_pid,
         pdq_pid: pdq_pid,
         odp_pid: odp_pid,
         active_paths: %{}
       }}
    end
  end

  @impl true
  @doc false
  @spec handle_cast({:enqueue, Pulse.t()}, state()) :: {:noreply, state()}
  def handle_cast({:enqueue, %Pulse{} = pulse}, state) do
    case process_token(pulse, state) do
      {:ok, {:deliver, shared_secret, remaining_pulse}} ->
        updated_state = deliver_pulse(remaining_pulse, shared_secret, state)
        {:noreply, updated_state}

      {:ok, {:forward, node_id, updated_pulse}} ->
        # Check trust policy before relaying
        trust_enabled = Config.trust_policy_enabled?(state.config)

        should_relay =
          if trust_enabled do
            module_name =
              get_in(state.config, ["trust_policy", "module"]) || "ChronoMesh.TrustPolicy.Default"

            module =
              try do
                String.to_existing_atom("Elixir." <> module_name)
              rescue
                ArgumentError ->
                  case Code.string_to_quoted(module_name) do
                    {:ok, {:__aliases__, _, parts}} ->
                      Module.concat([Elixir | parts])

                    _ ->
                      nil
                  end
              end

            if module != nil and Code.ensure_loaded?(module) and
                 function_exported?(module, :should_relay?, 2) do
              module.should_relay?(node_id, updated_pulse)
            else
              # Fallback to default trust policy
              ChronoMesh.TrustPolicy.should_relay?(node_id, updated_pulse)
            end
          else
            # Trust policy disabled, allow relay
            true
          end

        if not should_relay do
          Logger.debug("Trust policy: Rejecting relay to node_id #{Base.encode16(node_id)}")

          ChronoMesh.Events.emit(:pulse_rejected, %{reason: :trust_policy}, %{
            pulse: updated_pulse
          })

          {:noreply, state}
        else
          # Calculate target wave based on privacy tier if present
          base_wave = current_wave(state.wave_duration)

          wave_multiplier =
            if updated_pulse.privacy_tier != nil do
              Config.privacy_tier_multiplier(state.config, updated_pulse.privacy_tier)
            else
              1
            end

          next_wave = base_wave + wave_multiplier
          entry = {updated_pulse, node_id}

          Logger.debug(
            "Node: Scheduling pulse for wave #{next_wave} (current: #{base_wave}, multiplier: #{wave_multiplier}, frame_id: #{Base.encode16(updated_pulse.frame_id)})"
          )

          # Check if we should swap to disk (PDQ)
          updated_state =
            if state.pdq_pid != nil do
              # Check if wave is far-future or memory threshold exceeded
              current_wave_id = current_wave(state.wave_duration)
              far_future_threshold = Config.pdq_far_future_threshold_waves(state.config)
              is_far_future = next_wave > current_wave_id + far_future_threshold

              should_swap =
                is_far_future or
                  memory_usage_exceeds_threshold?(state.pulses, state.config)

              if should_swap do
                # Check if wave already exists in memory (need to merge)
                existing_pulses = Map.get(state.pulses, next_wave, [])
                all_pulses = [entry | existing_pulses]

                # Swap entire wave to disk
                case PDQ.write_wave(next_wave, all_pulses, []) do
                  :ok ->
                    Logger.debug(
                      "PDQ: Swapped wave #{next_wave} to disk (#{length(all_pulses)} pulses, #{if is_far_future, do: "far-future", else: "memory-threshold"})"
                    )

                    # Remove from memory pool since it's on disk
                    updated_map = Map.delete(state.pulses, next_wave)
                    %{state | pulses: updated_map}

                  {:error, reason} ->
                    Logger.warning(
                      "PDQ: Failed to swap wave #{next_wave} to disk: #{inspect(reason)}, keeping in memory"
                    )

                    # Fallback to memory if disk write fails
                    updated_map = Map.update(state.pulses, next_wave, [entry], &[entry | &1])
                    %{state | pulses: updated_map}
                end
              else
                # Keep in memory
                updated_map = Map.update(state.pulses, next_wave, [entry], &[entry | &1])
                %{state | pulses: updated_map}
              end
            else
              # PDQ disabled, keep in memory
              updated_map = Map.update(state.pulses, next_wave, [entry], &[entry | &1])
              %{state | pulses: updated_map}
            end

          # Track active path for failure detection
          frame_id = updated_pulse.frame_id
          current_path = Map.get(updated_state.active_paths, frame_id, [])

          updated_paths =
            if node_id not in current_path do
              Map.put(updated_state.active_paths, frame_id, current_path ++ [node_id])
            else
              updated_state.active_paths
            end

          ChronoMesh.Events.emit(:pulse_enqueued, %{count: 1}, %{pulse: updated_pulse})
          {:noreply, %{updated_state | active_paths: updated_paths}}
        end

      {:error, reason} ->
        Logger.error(
          "Dropping pulse #{if is_binary(pulse.frame_id), do: Base.encode16(pulse.frame_id), else: "unknown"} due to #{inspect(reason)}"
        )
        {:noreply, state}
    end
  end

  @impl true
  @doc false
  @spec handle_info(term(), state()) :: {:noreply, state()} | {:stop, term(), state()}
  def handle_info(:wave_tick, state) do
    wave = current_wave(state.wave_duration)
    {batch, pulses} = Map.pop(state.pulses, wave, [])

    # Load pulses from disk if PDQ is enabled
    disk_batch =
      if state.pdq_pid != nil do
        case PDQ.load_wave(wave) do
          {:ok, disk_pulses} when is_list(disk_pulses) and length(disk_pulses) > 0 ->
            Logger.debug("PDQ: Loaded #{length(disk_pulses)} pulses from disk for wave #{wave}")
            # Delete wave from disk after loading
            PDQ.delete_wave(wave)
            disk_pulses

          {:ok, []} ->
            []

          {:error, reason} ->
            Logger.warning("PDQ: Failed to load wave #{wave} from disk: #{inspect(reason)}")
            []
        end
      else
        []
      end

    # Merge memory and disk batches
    combined_batch = batch ++ disk_batch

    if combined_batch != [] do
      Logger.debug(
        "Dispatching #{length(combined_batch)} pulses for wave #{wave} (#{length(batch)} from memory, #{length(disk_batch)} from disk)"
      )

      combined_batch
      |> Enum.shuffle()
      |> Enum.each(fn {pulse, node_id} -> forward_pulse(pulse, node_id, state) end)
    else
      Logger.debug("No pulses scheduled for wave #{wave}")
    end

    schedule_wave(state.wave_duration)
    {:noreply, %{state | pulses: pulses}}
  end

  @impl true
  @doc false
  def handle_info({:retry_forward, %Pulse{} = pulse, node_id, attempt}, state) do
    max_attempts = 3

    case ChronoMesh.ControlClient.enqueue_remote(node_id, [pulse]) do
      :ok ->
        # Remove from active paths on success
        updated_paths = Map.delete(state.active_paths, pulse.frame_id)
        {:noreply, %{state | active_paths: updated_paths}}

      {:error, reason} when attempt < max_attempts ->
        Logger.warning(
          "Retry #{attempt}/#{max_attempts} forwarding to node_id #{Base.encode16(node_id)} failed: #{inspect(reason)}"
        )

        Process.send_after(self(), {:retry_forward, pulse, node_id, attempt + 1}, 200)
        {:noreply, state}

      {:error, reason} ->
        Logger.error(
          "Giving up forwarding to node_id #{Base.encode16(node_id)}: #{inspect(reason)}"
        )

        # Detect path failure after max retries
        path = Map.get(state.active_paths, pulse.frame_id, [])

        failure_notice =
          ChronoMesh.PFP.detect_failure(
            pulse.frame_id,
            node_id,
            :timeout,
            state.private_key,
            ed25519_private_key: state.ed25519_private_key
          )

        # Send failure notice upstream
        ChronoMesh.PFP.send_failure_notice(failure_notice, path, state.config)

        # Remove from active paths
        updated_paths = Map.delete(state.active_paths, pulse.frame_id)
        {:noreply, %{state | active_paths: updated_paths}}
    end
  end

  @doc false
  @impl true
  def handle_info(message, state) do
    Logger.debug("Unhandled message #{inspect(message)}")
    {:noreply, state}
  end

  # Internal helpers ----------------------------------------------------------

  @spec forward_pulse(Pulse.t(), binary(), state()) :: :ok
  defp forward_pulse(%Pulse{} = pulse, node_id, state) do
    Logger.debug(
      "Forwarding pulse (#{byte_size(pulse.payload)} bytes) to node_id #{Base.encode16(node_id)}"
    )

    ChronoMesh.Events.emit(:pulse_forwarded, %{}, %{pulse: pulse})

    case ChronoMesh.ControlClient.enqueue_remote(node_id, [pulse]) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error("Failed to forward pulse to node_id #{Base.encode16(node_id)} -> #{reason}")

        # Detect path failure
        path = Map.get(state.active_paths, pulse.frame_id, [])

        failure_notice =
          ChronoMesh.PFP.detect_failure(
            pulse.frame_id,
            node_id,
            :connection_error,
            state.private_key,
            ed25519_private_key: state.ed25519_private_key
          )

        # Send failure notice upstream
        ChronoMesh.PFP.send_failure_notice(failure_notice, path, state.config)

        # Retry forwarding
        Process.send_after(self(), {:retry_forward, pulse, node_id, 1}, 100)
    end
  end

  @spec schedule_wave(pos_integer()) :: reference()
  defp schedule_wave(wave_duration) do
    now = System.os_time(:second)
    next_wave = current_wave(wave_duration) + 1

    millis_until =
      max(next_wave * wave_duration - now, 0) * 1000

    Process.send_after(self(), :wave_tick, millis_until)
  end

  @spec current_wave(pos_integer()) :: non_neg_integer()
  defp current_wave(wave_duration) do
    System.os_time(:second) |> div(wave_duration)
  end

  @spec parse_wave_duration(map()) :: pos_integer()
  defp parse_wave_duration(config) do
    case get_in(config, ["network", "wave_duration_secs"]) do
      value when is_integer(value) ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _rest} -> int
          :error -> 10
        end

      _ ->
        10
    end
  end

  @spec parse_listen_port(map()) :: pos_integer()
  defp parse_listen_port(config) do
    case get_in(config, ["network", "listen_port"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> 4_000
        end

      _ ->
        4_000
    end
  end

  @spec parse_listen_host(map()) :: String.t()
  defp parse_listen_host(config) do
    case get_in(config, ["network", "listen_host"]) do
      value when is_binary(value) and value != "" -> value
      _ -> "127.0.0.1"
    end
  end

  defp process_token(%Pulse{token_chain: []}, _state), do: {:error, :no_token}

  @spec process_token(Pulse.t(), map()) ::
          {:ok, {:forward, binary(), Pulse.t()}}
          | {:ok, {:deliver, binary(), Pulse.t()}}
          | {:error, term()}
  defp process_token(%Pulse{token_chain: [token | rest]} = pulse, state) do
    case Token.decrypt_token(token, state.private_key, pulse.frame_id, pulse.shard_index) do
      {:ok, {%{instruction: :forward, node_id: node_id}, _shared}} ->
        {:ok, {:forward, node_id, %{pulse | token_chain: rest}}}

      {:ok, {%{instruction: :deliver}, shared}} ->
        {:ok, {:deliver, shared, %{pulse | token_chain: rest}}}

      {:ok, {data, _shared}} ->
        {:error, {:unknown_instruction, data}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec deliver_pulse(Pulse.t(), binary(), state()) :: state()
  defp deliver_pulse(%Pulse{} = pulse, shared_secret, state) do
    # Always use ChaCha20-Poly1305 AEAD decryption
    # Verify auth_tag size (must be 16 bytes for Poly1305)
    decrypt_result =
      if byte_size(pulse.auth_tag) == 16 do
        Token.decrypt_aead(
          shared_secret,
          pulse.frame_id,
          pulse.shard_index,
          pulse.payload,
          pulse.auth_tag
        )
      else
        {:error, :invalid_auth_tag}
      end

    case decrypt_result do
      {:ok, plaintext} ->
        # Check if this is an ODP frame (has dialogue_id and sequence_number)
        is_odp_frame = pulse.dialogue_id != nil and pulse.sequence_number != nil

        # Route through FDP for frame reassembly if multi-shard
        # Remove from active paths on successful delivery
        updated_paths = Map.delete(state.active_paths, pulse.frame_id)

        if pulse.shard_count == 1 do
          # Single shard
          if is_odp_frame and state.odp_pid != nil do
            # Route to ODP for ordered delivery
            # Extract sender_id from token chain (first token's node_id)
            sender_id =
              case pulse.token_chain do
                # Fallback if no tokens
                [] -> <<0::256>>
                _ -> extract_sender_id_from_path(state.active_paths, pulse.frame_id)
              end

            # Get local node_id (recipient)
            recipient_id = state.local_node_id

            case ODP.register_frame(
                   pulse.dialogue_id,
                   pulse.sequence_number,
                   plaintext,
                   sender_id,
                   recipient_id
                 ) do
              {:ok, :delivered} ->
                Logger.debug("ODP: Frame delivered immediately (seq #{pulse.sequence_number})")

                ChronoMesh.Events.emit(:pulse_delivered, %{bytes: byte_size(plaintext)}, %{
                  pulse: pulse
                })

              {:ok, :buffered} ->
                Logger.debug("ODP: Frame buffered (seq #{pulse.sequence_number})")

              {:error, reason} ->
                Logger.warning("ODP: Failed to register frame: #{inspect(reason)}")
            end

            %{state | active_paths: updated_paths}
          else
            # Single shard - store immediately, no reassembly needed
            store_payload(state, plaintext)

            ChronoMesh.Events.emit(:pulse_delivered, %{bytes: byte_size(plaintext)}, %{
              pulse: pulse
            })

            %{state | active_paths: updated_paths}
          end
        else
          # Multi-shard - route through FDP
          # Pass FEC metadata if available
          fec_opts = [
            fec_enabled: pulse.fec_enabled || false,
            parity_count: pulse.parity_count || 0,
            data_shard_count: pulse.data_shard_count || pulse.shard_count
          ]

          case FDP.register_shard(
                 pulse.frame_id,
                 pulse.shard_index,
                 pulse.shard_count,
                 plaintext,
                 fec_opts
               ) do
            {:ok, :complete} ->
              # Frame is complete - reassemble
              case FDP.reassemble(pulse.frame_id) do
                {:ok, reassembled} ->
                  if is_odp_frame and state.odp_pid != nil do
                    # Route to ODP for ordered delivery
                    sender_id = extract_sender_id_from_path(state.active_paths, pulse.frame_id)
                    recipient_id = state.local_node_id

                    case ODP.register_frame(
                           pulse.dialogue_id,
                           pulse.sequence_number,
                           reassembled,
                           sender_id,
                           recipient_id
                         ) do
                      {:ok, :delivered} ->
                        Logger.debug(
                          "ODP: Reassembled frame delivered (seq #{pulse.sequence_number})"
                        )

                        ChronoMesh.Events.emit(
                          :pulse_delivered,
                          %{
                            bytes: byte_size(reassembled),
                            frame_id: pulse.frame_id,
                            shard_count: pulse.shard_count
                          },
                          %{pulse: pulse}
                        )

                      {:ok, :buffered} ->
                        Logger.debug(
                          "ODP: Reassembled frame buffered (seq #{pulse.sequence_number})"
                        )

                      {:error, reason} ->
                        Logger.warning(
                          "ODP: Failed to register reassembled frame: #{inspect(reason)}"
                        )
                    end

                    %{state | active_paths: updated_paths}
                  else
                    # Store directly (not ODP frame)
                    store_payload(state, reassembled)

                    ChronoMesh.Events.emit(
                      :pulse_delivered,
                      %{
                        bytes: byte_size(reassembled),
                        frame_id: pulse.frame_id,
                        shard_count: pulse.shard_count
                      },
                      %{pulse: pulse}
                    )

                    # Return updated state with cleaned paths
                    %{state | active_paths: updated_paths}
                  end

                {:error, reason} ->
                  Logger.error(
                    "Failed to reassemble frame #{Base.encode16(pulse.frame_id)}: #{inspect(reason)}"
                  )

                  %{state | active_paths: updated_paths}
              end

            {:ok, :incomplete} ->
              # Frame incomplete - waiting for more shards
              Logger.debug(
                "Received shard #{pulse.shard_index + 1}/#{pulse.shard_count} of frame #{Base.encode16(pulse.frame_id)}"
              )

              %{state | active_paths: updated_paths}

            {:error, reason} ->
              Logger.error(
                "FDP error for shard #{pulse.shard_index} of frame #{Base.encode16(pulse.frame_id)}: #{inspect(reason)}"
              )

              %{state | active_paths: updated_paths}
          end
        end

      {:error, :invalid_auth_tag} ->
        Logger.error(
          "Invalid auth_tag for shard #{pulse.shard_index} of frame #{Base.encode16(pulse.frame_id)}"
        )

        state

      {:error, reason} ->
        Logger.error(
          "Failed to decrypt shard #{pulse.shard_index} of frame #{Base.encode16(pulse.frame_id)}: #{inspect(reason)}"
        )

        state
    end
  end

  @spec store_payload(state(), binary()) :: :ok
  defp store_payload(_state, payload) do
    path = inbox_path()
    :ok = File.mkdir_p(Path.dirname(path))
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
    message = payload |> IO.iodata_to_binary() |> String.trim_trailing()
    line = "#{timestamp} :: #{message}"
    File.write(path, line <> "\n", [:append])
    Logger.info("Stored incoming pulse (#{byte_size(payload)} bytes) -> #{path}")
  end

  @spec inbox_path() :: Path.t()
  defp inbox_path do
    base_dir = System.get_env("CHRONO_MESH_HOME") || System.user_home!()
    Path.join(base_dir, ".chrono_mesh/inbox.log")
  end

  @spec parse_fdp_timeout(map()) :: non_neg_integer()
  defp parse_fdp_timeout(config) do
    case get_in(config, ["fdp", "frame_timeout_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.minutes(5)
        end

      _ ->
        :timer.minutes(5)
    end
  end

  @spec parse_fdp_cleanup_interval(map()) :: non_neg_integer()
  defp parse_fdp_cleanup_interval(config) do
    case get_in(config, ["fdp", "cleanup_interval_ms"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> :timer.minutes(1)
        end

      _ ->
        :timer.minutes(1)
    end
  end

  @spec parse_fdp_max_size(map()) :: non_neg_integer()
  defp parse_fdp_max_size(config) do
    case get_in(config, ["fdp", "max_frame_size"]) do
      value when is_integer(value) and value > 0 ->
        value

      value when is_binary(value) ->
        case Integer.parse(value) do
          {int, _} when int > 0 -> int
          _ -> 10 * 1024 * 1024
        end

      _ ->
        10 * 1024 * 1024
    end
  end

  # PDQ memory management helpers

  @spec memory_usage_exceeds_threshold?(map(), map()) :: boolean()
  defp memory_usage_exceeds_threshold?(pulses_map, config) do
    memory_capacity = Config.pdq_memory_capacity_bytes(config)
    swap_threshold = Config.pdq_memory_swap_threshold(config)
    threshold_bytes = trunc(memory_capacity * swap_threshold)

    current_usage = calculate_memory_usage(pulses_map)
    exceeds = current_usage >= threshold_bytes

    if exceeds do
      Logger.debug(
        "PDQ: Memory usage #{current_usage} bytes exceeds threshold #{threshold_bytes} bytes"
      )
    end

    exceeds
  end

  @spec calculate_memory_usage(map()) :: non_neg_integer()
  defp calculate_memory_usage(pulses_map) do
    # Calculate approximate memory usage by serializing pulses
    pulses_map
    |> Map.values()
    |> List.flatten()
    |> Enum.reduce(0, fn {pulse, _node_id}, acc ->
      # Approximate size: pulse struct + payload + token_chain
      # Overhead for struct and metadata
      pulse_size =
        byte_size(pulse.payload) +
          Enum.reduce(pulse.token_chain, 0, fn token, sum -> sum + byte_size(token) end) +
          byte_size(pulse.frame_id) +
          byte_size(pulse.auth_tag) +
          100

      acc + pulse_size
    end)
  end

  # ODP helpers

  defp store_payload_for_odp(frame_data, dialogue_id, sequence_number) do
    # Store the in-order frame (called by ODP when ready)
    path = inbox_path()
    :ok = File.mkdir_p(Path.dirname(path))
    timestamp = DateTime.utc_now() |> DateTime.to_iso8601()
    message = frame_data |> IO.iodata_to_binary() |> String.trim_trailing()
    dialogue_hex = Base.encode16(dialogue_id)
    line = "#{timestamp} [ODP seq:#{sequence_number} dialogue:#{dialogue_hex}] :: #{message}"
    File.write(path, line <> "\n", [:append])

    Logger.info(
      "Stored ODP frame (seq #{sequence_number}, #{byte_size(frame_data)} bytes) -> #{path}"
    )
  end

  defp extract_sender_id_from_path(active_paths, frame_id) do
    # Extract sender (first node in path) from active_paths
    case Map.get(active_paths, frame_id) do
      [sender_id | _] -> sender_id
      # Fallback
      _ -> <<0::256>>
    end
  end
end
