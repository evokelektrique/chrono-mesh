defmodule ChronoMesh.PDQ do
  @moduledoc """
  Pending Delivery Queue (PDQ) for persistent disk storage of pulses.

  Provides two-tier storage (memory/disk) for reliable message delivery.
  Pulses are encrypted before writing to disk and can survive node restarts.
  """

  use GenServer
  require Logger

  alias ChronoMesh.Pulse

  @typedoc "Wave ID (non-negative integer)"
  @type wave_id :: non_neg_integer()

  @typedoc "Frame ID (16-byte binary)"
  @type frame_id :: binary()

  @typedoc "PDQ state"
  @type state :: %{
          disk_path: String.t(),
          encryption_enabled: boolean(),
          encryption_key: binary() | nil,
          metadata_table: atom(),
          cleanup_timer: reference() | nil
        }

  # Public API ----------------------------------------------------------------

  @doc """
  Starts the PDQ GenServer process.

  Options:
  - `:disk_path` - Directory for PDQ storage (default: "data/pdq")
  - `:encryption_enabled` - Enable encryption (default: true)
  - `:encryption_key` - Encryption key for disk storage (optional, derived if not provided)
  - `:cleanup_interval_ms` - Cleanup interval in milliseconds (default: 5 minutes)
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Writes pulses for a wave to disk storage.

  Returns `:ok` on success, or `{:error, reason}` on failure.
  """
  @spec write_wave(wave_id(), [{Pulse.t(), binary()}], keyword()) :: :ok | {:error, term()}
  def write_wave(wave_id, pulses, opts \\ []) do
    GenServer.call(__MODULE__, {:write_wave, wave_id, pulses, opts}, :infinity)
  end

  @doc """
  Loads pulses for a wave from disk storage.

  Returns `{:ok, pulses}` where pulses is a list of `{Pulse.t(), next_node_id}` tuples,
  or `{:error, reason}` on failure.
  """
  @spec load_wave(wave_id()) :: {:ok, [{Pulse.t(), binary()}]} | {:error, term()}
  def load_wave(wave_id) do
    GenServer.call(__MODULE__, {:load_wave, wave_id}, :infinity)
  end

  @doc """
  Deletes pulses for a wave from disk storage.

  Returns `:ok` on success, or `{:error, reason}` on failure.
  """
  @spec delete_wave(wave_id()) :: :ok | {:error, term()}
  def delete_wave(wave_id) do
    GenServer.call(__MODULE__, {:delete_wave, wave_id}, :infinity)
  end

  @doc """
  Recovers all pending waves from disk storage.

  Returns `{:ok, waves}` where waves is a map of `wave_id => [{Pulse.t(), binary()}]`,
  or `{:error, reason}` on failure.
  """
  @spec recover_all_waves() :: {:ok, %{wave_id() => [{Pulse.t(), binary()}]}} | {:error, term()}
  def recover_all_waves do
    GenServer.call(__MODULE__, :recover_all_waves, :infinity)
  end

  @doc """
  Gets the disk path for PDQ storage.
  """
  @spec disk_path() :: String.t()
  def disk_path do
    GenServer.call(__MODULE__, :disk_path, :infinity)
  end

  # GenServer callbacks -------------------------------------------------------

  @impl true
  def init(opts) do
    disk_path = Keyword.get(opts, :disk_path, "data/pdq")
    encryption_enabled = Keyword.get(opts, :encryption_enabled, true)
    cleanup_interval_ms = Keyword.get(opts, :cleanup_interval_ms, 300_000)

    # Create disk directory
    File.mkdir_p!(disk_path)
    File.mkdir_p!(Path.join(disk_path, "waves"))
    File.mkdir_p!(Path.join(disk_path, "metadata"))

    # Derive encryption key from node identity if not provided
    encryption_key =
      if encryption_enabled do
        case Keyword.get(opts, :encryption_key) do
          nil -> derive_encryption_key(opts)
          key when is_binary(key) -> key
        end
      else
        nil
      end

    # Create ETS table for metadata
    # Delete existing table if it exists (from previous run)
    metadata_table = :pdq_metadata

    try do
      case :ets.whereis(metadata_table) do
        :undefined -> :ok
        _tid -> :ets.delete(metadata_table)
      end
    rescue
      ArgumentError -> :ok
    end

    :ets.new(metadata_table, [:set, :named_table, :public, read_concurrency: true])

    # Schedule cleanup
    cleanup_timer = schedule_cleanup(cleanup_interval_ms)

    state = %{
      disk_path: disk_path,
      encryption_enabled: encryption_enabled,
      encryption_key: encryption_key,
      metadata_table: metadata_table,
      cleanup_timer: cleanup_timer
    }

    Logger.info("PDQ started with disk_path: #{disk_path}, encryption: #{encryption_enabled}")
    {:ok, state}
  end

  @impl true
  def handle_call({:write_wave, wave_id, pulses, _opts}, _from, state) do
    result = do_write_wave(wave_id, pulses, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:load_wave, wave_id}, _from, state) do
    result = do_load_wave(wave_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call({:delete_wave, wave_id}, _from, state) do
    result = do_delete_wave(wave_id, state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:recover_all_waves, _from, state) do
    result = do_recover_all_waves(state)
    {:reply, result, state}
  end

  @impl true
  def handle_call(:disk_path, _from, state) do
    {:reply, state.disk_path, state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    do_cleanup(state)
    # Default 5 minutes
    cleanup_timer = schedule_cleanup(300_000)
    {:noreply, %{state | cleanup_timer: cleanup_timer}}
  end

  @impl true
  def terminate(_reason, state) do
    # Cancel cleanup timer if it exists
    if state.cleanup_timer != nil do
      Process.cancel_timer(state.cleanup_timer)
    end

    # Delete ETS table if it exists
    if state.metadata_table != nil do
      try do
        :ets.delete(state.metadata_table)
      rescue
        ArgumentError -> :ok
      end
    end

    :ok
  end

  # Private functions ---------------------------------------------------------

  defp do_write_wave(wave_id, pulses, state) when is_list(pulses) and length(pulses) > 0 do
    wave_dir = wave_directory(wave_id, state.disk_path)

    try do
      File.mkdir_p!(wave_dir)

      # Write each pulse to a separate file
      Enum.each(pulses, fn {pulse, next_node_id} ->
        frame_id = pulse.frame_id
        filename = pulse_filename(frame_id)
        filepath = Path.join(wave_dir, filename)

        # Serialize pulse and next_node_id
        data = :erlang.term_to_binary({pulse, next_node_id})

        # Encrypt if enabled
        encrypted_data =
          cond do
            state.encryption_enabled and state.encryption_key != nil ->
              encrypt_pulse_data(data, frame_id, state.encryption_key)

            state.encryption_enabled and state.encryption_key == nil ->
              Logger.error(
                "PDQ: Encryption enabled but no encryption key provided, writing unencrypted"
              )

              data

            true ->
              data
          end

        # Write to file
        File.write!(filepath, encrypted_data)

        # Update metadata
        :ets.insert(state.metadata_table, {frame_id, wave_id, System.system_time(:millisecond)})
      end)

      Logger.debug("PDQ: Wrote #{length(pulses)} pulses for wave #{wave_id}")
      :ok
    rescue
      e ->
        Logger.error("PDQ: Failed to write wave #{wave_id}: #{inspect(e)}")
        {:error, {:write_failed, wave_id, Exception.message(e)}}
    end
  end

  defp do_write_wave(_wave_id, [], _state) do
    :ok
  end

  defp do_load_wave(wave_id, state) do
    wave_dir = wave_directory(wave_id, state.disk_path)

    try do
      if File.exists?(wave_dir) do
        pulses =
          wave_dir
          |> File.ls!()
          |> Enum.filter(&String.ends_with?(&1, ".pulse"))
          |> Enum.map(fn filename ->
            filepath = Path.join(wave_dir, filename)
            load_pulse_file(filepath, state)
          end)
          |> Enum.filter(&match?({:ok, _}, &1))
          |> Enum.map(fn {:ok, pulse_data} -> pulse_data end)

        Logger.debug("PDQ: Loaded #{length(pulses)} pulses for wave #{wave_id}")
        {:ok, pulses}
      else
        {:ok, []}
      end
    rescue
      e ->
        Logger.error("PDQ: Failed to load wave #{wave_id}: #{inspect(e)}")
        {:error, {:load_failed, wave_id, Exception.message(e)}}
    end
  end

  defp do_delete_wave(wave_id, state) do
    wave_dir = wave_directory(wave_id, state.disk_path)

    try do
      if File.exists?(wave_dir) do
        # Delete all pulse files
        File.ls!(wave_dir)
        |> Enum.filter(&String.ends_with?(&1, ".pulse"))
        |> Enum.each(fn filename ->
          filepath = Path.join(wave_dir, filename)
          File.rm(filepath)
        end)

        # Remove wave directory
        File.rmdir(wave_dir)

        # Clean up metadata
        :ets.match_delete(state.metadata_table, {:_, wave_id, :_})

        Logger.debug("PDQ: Deleted wave #{wave_id}")
        :ok
      else
        :ok
      end
    rescue
      e ->
        Logger.error("PDQ: Failed to delete wave #{wave_id}: #{inspect(e)}")
        {:error, {:delete_failed, wave_id, Exception.message(e)}}
    end
  end

  defp do_recover_all_waves(state) do
    waves_dir = Path.join(state.disk_path, "waves")

    try do
      if File.exists?(waves_dir) do
        waves =
          File.ls!(waves_dir)
          |> Enum.filter(&String.starts_with?(&1, "wave_"))
          |> Enum.map(fn dirname ->
            # Extract wave_id from directory name "wave_12345"
            wave_id =
              dirname
              |> String.replace("wave_", "")
              |> String.to_integer()

            case do_load_wave(wave_id, state) do
              {:ok, pulses} -> {wave_id, pulses}
              {:error, _} -> {wave_id, []}
            end
          end)
          |> Enum.into(%{})

        Logger.info("PDQ: Recovered #{map_size(waves)} waves from disk")
        {:ok, waves}
      else
        {:ok, %{}}
      end
    rescue
      e ->
        Logger.error("PDQ: Failed to recover waves: #{inspect(e)}")
        {:error, {:recover_failed, Exception.message(e)}}
    end
  end

  defp load_pulse_file(filepath, state) do
    try do
      data = File.read!(filepath)

      # Extract frame_id from filename (format: frame_<hex>.pulse)
      frame_id =
        try do
          filepath
          |> Path.basename()
          |> String.replace("frame_", "")
          |> String.replace(".pulse", "")
          |> Base.decode16!(case: :lower)
        rescue
          ArgumentError ->
            # Invalid hex encoding in filename - likely corrupted file
            Logger.warning("PDQ: Failed to load pulse file #{filepath}: invalid frame_id in filename")
            throw({:error, :invalid_filename})
        end

      # Decrypt if enabled
      decrypted_data =
        cond do
          state.encryption_enabled and state.encryption_key != nil ->
            case decrypt_pulse_data_with_frame_id(data, frame_id, state.encryption_key) do
              {:ok, decrypted} -> {:ok, decrypted}
              {:error, reason} -> {:error, reason}
            end

          state.encryption_enabled and state.encryption_key == nil ->
            # Encryption enabled but no key - try to read as plaintext (backward compatibility)
            Logger.warning("PDQ: Encryption enabled but no key, attempting to read as plaintext")
            {:ok, data}

          true ->
            {:ok, data}
        end

      case decrypted_data do
        {:ok, plaintext} ->
          # Deserialize
          case :erlang.binary_to_term(plaintext, [:safe]) do
            {pulse, next_node_id} when is_struct(pulse, Pulse) ->
              {:ok, {pulse, next_node_id}}

            _ ->
              {:error, :invalid_format}
          end

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      e ->
        Logger.warning("PDQ: Failed to load pulse file #{filepath}: #{inspect(e)}")
        {:error, Exception.message(e)}
    catch
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp encrypt_pulse_data(data, frame_id, encryption_key) do
    # Use frame_id as nonce material for uniqueness
    nonce_material = encryption_key <> frame_id <> "pdq"
    key = derive_key(nonce_material, "key", 32)
    nonce = derive_key(nonce_material, "nonce", 12)

    # Associated data: frame_id for authentication
    associated_data = frame_id

    {ciphertext, auth_tag} =
      :crypto.crypto_one_time_aead(:chacha20_poly1305, key, nonce, data, associated_data, true)

    # Prepend auth_tag for verification on decryption
    <<auth_tag::binary-size(16), ciphertext::binary>>
  end

  defp decrypt_pulse_data_with_frame_id(data, frame_id, encryption_key) do
    # Check if data has minimum size (16 bytes for auth_tag)
    if byte_size(data) < 16 do
      {:error, :invalid_format}
    else
      try do
        <<auth_tag::binary-size(16), ciphertext::binary>> = data

        nonce_material = encryption_key <> frame_id <> "pdq"
        key = derive_key(nonce_material, "key", 32)
        nonce = derive_key(nonce_material, "nonce", 12)
        associated_data = frame_id

        case :crypto.crypto_one_time_aead(
               :chacha20_poly1305,
               key,
               nonce,
               ciphertext,
               associated_data,
               auth_tag,
               false
             ) do
          plaintext when is_binary(plaintext) ->
            {:ok, plaintext}

          :error ->
            {:error, :decryption_failed}
        end
      rescue
        MatchError ->
          {:error, :invalid_format}
      end
    end
  end

  defp derive_key(material, salt, size) do
    hashed = :crypto.hash(:sha256, material <> salt)
    binary_part(hashed, 0, size)
  end

  defp derive_encryption_key(opts) do
    # Try to get node identity from config
    case Keyword.get(opts, :node_private_key) do
      nil ->
        # Fallback: generate a random key (not ideal for persistence across restarts)
        :crypto.strong_rand_bytes(32)

      private_key when is_binary(private_key) ->
        # Derive key from node identity
        :crypto.hash(:sha256, private_key <> "pdq_encryption_key")
    end
  end

  defp wave_directory(wave_id, disk_path) do
    Path.join([disk_path, "waves", "wave_#{wave_id}"])
  end

  defp pulse_filename(frame_id) do
    "frame_#{Base.encode16(frame_id, case: :lower)}.pulse"
  end

  defp do_cleanup(state) do
    # Clean up old metadata entries
    # This is a placeholder - can be extended to clean up old waves
    now = System.system_time(:millisecond)
    # 1 hour
    cutoff = now - 3_600_000

    :ets.select_delete(state.metadata_table, [
      {{:_, :_, :"$1"}, [{:<, :"$1", cutoff}], [true]}
    ])

    Logger.debug("PDQ: Cleaned up old metadata entries")
  end

  defp schedule_cleanup(interval_ms) do
    Process.send_after(self(), :cleanup, interval_ms)
  end
end
