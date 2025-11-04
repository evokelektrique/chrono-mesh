# ChronoMesh

A secure, privacy-preserving anonymous messaging network built on Time-Wave Relay (TWR) protocol with onion routing and synchronized batch forwarding.

ChronoMesh is an Elixir/Erlang implementation of a mixed network that achieves strong anonymity through temporal synchronization and multi-hop encrypted message routing.

## What is ChronoMesh?

ChronoMesh is a decentralized peer-to-peer network designed for secure, anonymous communication. It combines several cryptographic and networking techniques to provide:

- Sender/Receiver Anonymity: Multi-hop onion routing obscures communication relationships
- Strong Encryption: ChaCha20-Poly1305 AEAD for payload confidentiality
- Unlinkability: Time-Wave Relay prevents traffic analysis through batch synchronization
- Forward Secrecy: Ephemeral X25519 keys per message for per-hop encryption
- Node Authentication: Ed25519 signatures for peer identity verification

## Key Concepts & Terminology

### Time-Wave Relay (TWR)

A synchronization protocol where all nodes forward messages at fixed time intervals called waves. Instead of forwarding immediately, nodes batch messages and dispatch them together at wave boundaries, preventing attackers from correlating message send/receive times.

**Wave Duration**: Configurable interval (e.g., 2 seconds) at which all nodes synchronously dispatch pending messages.

### Onion Routing

Multi-hop message paths where each intermediate node decrypts one layer of encryption (one "token") to learn the next hop. The full path is unknown to any individual node.

**Path Example**: `Sender → Node A → Node B → Recipient`
- Sender encrypts tokens for each hop
- Node A decrypts → sees only "forward to Node B"
- Node B decrypts → sees only "forward to Recipient"
- Recipient decrypts → reads message payload

### Token Chain

A series of encrypted routing instructions, one per hop in the path. Each token is encrypted with the X25519 public key of its corresponding node. Only that node can decrypt and follow its routing instruction.

### Pulse

The fundamental unit of message transmission in ChronoMesh. A pulse contains:
- Encrypted token chain (routing information)
- Encrypted payload (actual message)
- Frame ID (unique identifier)
- Shard information (for chunking large messages)

### Control Server

A local TCP server running on each node that receives messages from clients and enqueues them as pulses for wave dispatch.

### Address Book

A distributed registry system where nodes publish their presence and connection endpoints, allowing other nodes to discover and route to them.

### Distributed Hash Table (DHT)

Used for peer discovery and address book storage. Nodes register their public keys and connection information with bootstrap peers.

## Use Cases

### 1. Secure Messaging

Send messages between nodes without exposing sender/receiver relationships to network observers.

### 2. Privacy-Preserving Applications

Build applications that require anonymity, such as:
- Whistleblowing platforms
- Activist networks
- Sensitive research collaboration
- Confidential business communication

### 3. Network Resilience

The decentralized architecture survives node failures and provides network resilience.

### 4. Research & Development

Experiment with anonymous communication protocols and study anonymity properties.

## Features

- End-to-end encrypted messaging
- Multi-hop onion routing
- Time-synchronized wave dispatch
- Ephemeral key exchange (X25519)
- Message authentication (Ed25519)
- Configurable path lengths
- Support for multiple nodes in a network
- Peer discovery via DHT
- Combined mode (node + client shell in one process)

## Requirements

- **Erlang/OTP 24+** (for Elixir runtime)
- **Elixir 1.14+** (programming language)
- **Python 3.7+** (for demo cluster scripts)
- **OpenSSL** (for cryptographic operations)
- **git** (for version control)

### System Requirements

- Linux, macOS, or WSL2 on Windows
- Minimum 256MB RAM per node
- 2+ CPU cores recommended

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/evokelektrique/chrono_mesh.git
cd chrono_mesh
```

### 2. Install Elixir

**On macOS with Homebrew:**
```bash
brew install elixir
```

**On Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install elixir erlang
```

**On Windows/WSL2:**
Follow [Elixir installation guide](https://elixir-lang.org/install.html)

### 3. Install Dependencies

```bash
mix deps.get
```

## Building & Compilation

### Build the Escript (Standalone Executable)

```bash
mix escript.build
```

This creates a standalone executable at `./chrono_mesh` that can be run without Elixir installed.

### Verify Build

```bash
./chrono_mesh --help
```

Expected output:
```
ChronoMesh v0.1.0

USAGE
    chrono_mesh <command> [options]

COMMANDS
    init     Initialize a new ChronoMesh node
    run      Start a ChronoMesh node
    send     Send a message to another node
    help     Show this help message
```

### Development Build (with Mix)

Run without building the escript:
```bash
mix run -- send --to node2 --message "Hello" --path-length 1
```

### Run Tests

```bash
mix test
```

## CLI Usage

### 1. Initialize a Node

Before running a node, initialize it with keys and configuration:

```bash
chrono_mesh init \
  --name my_node \
  --home ~/.chrono_mesh
```

Creates:
- Ed25519 key pair for signing
- X25519 key pair for encryption
- Default configuration file

### 2. Start a Node

```bash
chrono_mesh run \
  --config-file ~/.chrono_mesh/config.yaml \
  --mode combined
```

**Modes:**
- `combined`: Node + interactive client shell (default)
- `server`: Node only (for headless operation)

### 3. Send a Message

```bash
./chrono_mesh send \
  --to recipient_node_name \
  --message "Your message here" \
  --path-length 2
```

**Parameters:**
- `--to`: Name of recipient node (must be in peers list)
- `--message`: Message content
- `--path-length`: Number of hops (1-10 recommended)

**Example:**
```bash
./chrono_mesh send \
  --to alice \
  --message "Meeting at noon?" \
  --path-length 3
```

### 4. View Received Messages

Messages are stored in `~/.chrono_mesh/inbox.log`:

```bash
cat ~/.chrono_mesh/inbox.log
```

Each message shows:
```
2025-11-04T14:33:40.720835Z :: Hello from node1!
```

Format: `[ISO8601 Timestamp] :: [Decrypted Message]`

## Demo Cluster

For testing and demonstration, use the included Python demo script:

### Start a 2-Node Cluster

```bash
python3 scripts/demo_cluster.py -n 2 -w 2 -c
```

**Options:**
- `-n NUM`: Number of nodes (default: 2)
- `-w SECONDS`: Wave duration (default: 2)
- `-c`: Combined mode (node + client)
- `-i`: Interactive mode (keeps cluster running)
- `-p PORT`: Starting port (default: random)

### What the Demo Does

1. **Generates keys** - Ed25519 and X25519 key pairs for each node
2. **Creates configs** - YAML configuration files with bootstrap peers
3. **Starts nodes** - Launches nodes on random ports
4. **Sends test message** - node1 → node2 via network
5. **Verifies delivery** - Checks inbox.log for message

### Expected Output

```
All nodes are running
Message queued for delivery
Message delivered to node2!

Inbox contents:
2025-11-04T14:37:06.362780Z :: Hello from node1!
```

### Custom Configuration

Edit the demo script or manually create `config.yaml`:

```yaml
identity:
  display_name: mynode
  public_key_path: /path/to/public.key
  private_key_path: /path/to/private.key

network:
  listen_host: 127.0.0.1
  listen_port: 5000
  wave_duration_secs: 2
  default_path_length: 2

peers:
  - name: other_node
    public_key: /path/to/other_node.pub
```

## Architecture Overview

### Message Flow

1. **User sends message** → CLI `send` command
2. **Path building** → Selects Sender → Intermediates → Recipient
3. **Token encryption** → Creates onion layers with X25519
4. **Payload encryption** → ChaCha20-Poly1305 AEAD
5. **Local queueing** → Sends pulse to local Control Server
6. **Wave scheduling** → Node schedules pulse for next wave
7. **Wave dispatch** → At wave boundary, pulse forwarded to first hop
8. **Hop forwarding** → Each intermediate decrypts token, forwards to next hop
9. **Delivery** → Recipient receives, decrypts, stores in inbox.log

### Core Modules

- **ChronoMesh.Node** - Main event processor, wave scheduling, pulse dispatch
- **ChronoMesh.ControlServer** - TCP server accepting local messages
- **ChronoMesh.ClientActions** - Message encryption, path building, token creation
- **ChronoMesh.Config** - Configuration loading and management
- **ChronoMesh.Discovery** - Peer discovery, DHT operations
- **ChronoMesh.AddressBook** - Peer registration and endpoint management
- **ChronoMesh.Pulse** - Message structure and serialization

## Security Considerations

### Encryption Algorithms

- **X25519**: Elliptic-curve Diffie-Hellman for per-hop encryption
- **ChaCha20-Poly1305**: AEAD cipher for message payloads
- **Ed25519**: Digital signatures for node authentication

### Anonymity Properties

- **Sender Anonymity**: Intermediate nodes cannot identify sender
- **Receiver Anonymity**: Intermediate nodes cannot identify recipient
- **Unlinkability**: Messages from same sender cannot be linked over time (due to wave batching)
- **Forward Secrecy**: Compromising old keys doesn't reveal past messages

### Limitations

- **Local Observer**: Node operator can see messages sent/received from that node
- **Global Observer**: Powerful network observer can potentially correlate timing patterns
- **Small Network**: Limited nodes reduce anonymity set; use larger networks for stronger anonymity

## Configuration

Full configuration example:

```yaml
identity:
  display_name: node1
  ed25519_private_key_path: ~/.chrono_mesh/keys/ed25519_sk.pem
  ed25519_public_key_path: ~/.chrono_mesh/keys/ed25519_pk.pem
  private_key_path: ~/.chrono_mesh/keys/x25519_sk.pem
  public_key_path: ~/.chrono_mesh/keys/x25519_pk.pem

network:
  listen_host: 127.0.0.1
  listen_port: 5000
  pulse_size_bytes: 1024
  wave_duration_secs: 2
  default_path_length: 2
  bootstrap_peers:
    - public_key: /path/to/bootstrap_node.pub
      connection_hint: 127.0.0.1:5001

peers:
  - name: node2
    public_key: /path/to/node2.pub

address_book:
  subscriptions:
    enabled: true
    max_count: 100
    rate_limit_ms: 60000

pdq:
  enabled: false
  disk_path: data/pdq
  encryption_enabled: true
```

## Troubleshooting

### Port Already in Use

```
Error: eaddrinuse
```

**Solution:** Use a different port or let the system assign one:
```bash
python3 scripts/demo_cluster.py -n 2 -p 0  # -p 0 = auto-assign
```

### Messages Not Delivering

**Checklist:**
1. Verify both nodes are running: `ps aux | grep chrono_mesh`
2. Check peers are configured: `cat ~/.chrono_mesh/config.yaml | grep peers`
3. Look for errors in logs: `grep error /tmp/node1.log`
4. Ensure wave duration is not too short: minimum 1 second recommended

### Connection Refused

```
Failed to queue message: Unable to reach node 127.0.0.1:5000
```

**Solution:** Increase wait time for node startup:
```bash
sleep 10  # Wait for nodes to initialize
./chrono_mesh send --to node2 --message "test" --path-length 1
```

## Development

### Running Tests

```bash
mix test
```

### Running Specific Test

```bash
mix test test/chrono_mesh/config_test.exs
```

### Code Coverage

```bash
mix coveralls
```

### Building Documentation

```bash
mix docs
```

View in `doc/index.html`

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature/your-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

### Papers & Concepts

- **Onion Routing**: [Tor Project](https://www.torproject.org/)
- **Mix Networks**: Chaum, D. "Untraceable electronic mail, return addresses, and digital pseudonyms"
- **Dining Cryptographers**: Chaum, D. "The Dining Cryptographers Problem: Unconditional Sender and Recipient Untraceability"

### Cryptography

- [X25519 Elliptic Curve Diffie-Hellman](https://cr.yp.to/ecdh.html)
- [ChaCha20 and Poly1305](https://tools.ietf.org/html/rfc7539)
- [Ed25519 Signatures](https://tools.ietf.org/html/rfc8032)

## Support

For issues and questions:

- GitHub Issues: [chrono_mesh/issues](https://github.com/evokelektrique/chrono_mesh/issues)
- Discussions: [chrono_mesh/discussions](https://github.com/evokelektrique/chrono_mesh/discussions)

## Acknowledgments

Built with Elixir/Erlang, leveraging the BEAM VM for robust concurrent processing.
