defmodule ChronoMesh.EventsTest do
  use ExUnit.Case, async: true

  alias ChronoMesh.Events

  test "events/0 exposes known event names" do
    assert :pulse_enqueued in Events.events()
  end

  test "on/2 behaves as no-op when telemetry is unavailable" do
    handler_id = Events.on(:pulse_enqueued, fn _event, _measurements, _metadata -> :ok end)
    assert match?({:noop, :pulse_enqueued}, handler_id)
    assert :ok = Events.off(handler_id)
  end
end
