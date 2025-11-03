defmodule ChronoMesh.Events do
  @moduledoc """
  Lightweight event hooks for applications embedding the Cadence runtime.

  Internally we rely on `:telemetry`.  Consumers can register callbacks for the
  predefined events exposed here via `on/2` and remove them using `off/1`.

  ## Example

      handler_id =
        ChronoMesh.Events.on(:pulse_forwarded, fn _event, _measurements, metadata ->
          IO.inspect(metadata, label: "forwarded pulse")
        end)

      # ... later
      ChronoMesh.Events.off(handler_id)
  """

  @type event_name ::
          :pulse_enqueued
          | :pulse_forwarded
          | :pulse_delivered
          | :control_received
          | :shard_received
          | :frame_complete
          | :frame_timeout

  @type handler_id :: {:chrono_mesh, event_name(), reference()} | {:noop, event_name()}

  require Logger

  @events %{
    pulse_enqueued: [:chrono_mesh, :pulse, :enqueued],
    pulse_forwarded: [:chrono_mesh, :pulse, :forwarded],
    pulse_delivered: [:chrono_mesh, :pulse, :delivered],
    control_received: [:chrono_mesh, :control, :received],
    shard_received: [:chrono_mesh, :fdp, :shard_received],
    frame_complete: [:chrono_mesh, :fdp, :frame_complete],
    frame_timeout: [:chrono_mesh, :fdp, :frame_timeout]
  }

  @doc """
  Returns the atom keys supported by this module.
  """
  @spec events() :: [event_name()]
  def events, do: Map.keys(@events)

  @doc """
  Registers a handler function for the given event.

  The function will receive three arguments:

    * `event` - the telemetry event name (list)
    * `measurements` - map of numeric measurements
    * `metadata` - additional context
  """
  @spec on(event_name(), (list(), map(), map() -> any())) :: handler_id()
  def on(event, callback) when is_function(callback, 3) do
    event_name = Map.fetch!(@events, event)

    if telemetry_loaded?() do
      handler_id = {:chrono_mesh, event, make_ref()}
      apply(:telemetry, :attach, [handler_id, event_name, &__MODULE__.dispatch/4, callback])
      handler_id
    else
      Logger.debug("telemetry not available; handler will operate in no-op mode")
      {:noop, event}
    end
  end

  @doc """
  Detaches a previously registered handler.
  """
  @spec off(handler_id()) :: :ok | {:error, :not_found}
  def off(handler_id)

  def off({:noop, _event}), do: :ok

  def off(handler_id) do
    if telemetry_loaded?() do
      apply(:telemetry, :detach, [handler_id])
    else
      :ok
    end
  end

  @doc false
  def dispatch(event, measurements, metadata, callback) do
    callback.(event, measurements, metadata)
  end

  @doc false
  @spec emit(event_name(), map(), map()) :: :ok
  def emit(event, measurements \\ %{}, metadata \\ %{}) do
    if telemetry_loaded?() do
      event_name = Map.fetch!(@events, event)
      apply(:telemetry, :execute, [event_name, measurements, metadata])
    end
  end

  defp telemetry_loaded? do
    Code.ensure_loaded?(:telemetry)
  end
end
