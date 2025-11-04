#!/usr/bin/env elixir

# Helper script to register a connection endpoint
# Usage: elixir register_connection.exs <node_id_hex> <host> <port>

[node_id_hex, host, port_str] = System.argv()

node_id = Base.decode16!(node_id_hex, case: :lower)
port = String.to_integer(port_str)

# Ensure ControlClient registry exists
ChronoMesh.ControlClient.register_connection(node_id, host, port)

IO.puts("Registered connection: #{node_id_hex} -> #{host}:#{port}")
