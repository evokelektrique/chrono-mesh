#!/usr/bin/env python3
"""
ChronoMesh Cluster Demo Script

This script demonstrates a multi-node ChronoMesh network by:
1. Setting up multiple nodes with keys and configuration
2. Configuring bootstrap peers for connection endpoint registration
3. Configuring peer relationships between all nodes
4. Starting nodes as separate processes
5. Sending test messages between nodes
6. Displaying message delivery results

Usage: ./scripts/demo_cluster.py [OPTIONS]

Options:
  -n, --nodes N      Number of nodes to create (default: 3)
  -p, --port PORT    Starting port number (default: 0 = random)
  -w, --wave-duration N  Wave duration in seconds (default: 2)
  -i, --interactive  Run in interactive mode (keep nodes running)
  -c, --clean        Clean up before starting (remove existing demo data)
  -h, --help         Show this help message
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
import signal
import socket
import yaml
from pathlib import Path
from typing import List, Dict, Tuple, Optional


# Colors for output
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color


def print_error(msg: str):
    print(f"{Colors.RED}{msg}{Colors.NC}", file=sys.stderr)


def print_success(msg: str):
    print(f"{Colors.GREEN}[✓]{Colors.NC} {msg}")


def print_warn(msg: str):
    print(f"{Colors.YELLOW}[!]{Colors.NC} {msg}")


def print_info(msg: str):
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def print_section(msg: str):
    print(f"\n{Colors.CYAN}{'━' * 40}{Colors.NC}")
    print(f"{Colors.CYAN}{msg}{Colors.NC}")
    print(f"{Colors.CYAN}{'━' * 40}{Colors.NC}\n")


def find_free_port() -> int:
    """Find a free port by binding to port 0 and letting the OS assign one."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


class DemoCluster:
    def __init__(self, num_nodes: int, start_port: int, wave_duration: int, 
                 interactive: bool, clean: bool):
        self.root = Path(__file__).parent.parent
        self.build_dir = self.root / "tmp" / "demo_cluster"
        self.escript = self.root / "chrono_mesh"
        self.num_nodes = num_nodes
        self.start_port = start_port
        self.wave_duration = wave_duration
        self.interactive = interactive
        self.clean = clean
        
        # Node information
        self.nodes: List[str] = []
        self.ports: List[int] = []
        self.pids: List[int] = []
        self.pubkeys: List[str] = []
        self.node_ids: List[str] = []
        
        # Setup signal handlers for cleanup
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle cleanup on interrupt"""
        self.cleanup()
        sys.exit(0)
    
    def run_escript(self, node_dir: Path, command: List[str], 
                   env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
        """Run the chrono_mesh escript with given command"""
        env_dict = os.environ.copy()
        env_dict["CHRONO_MESH_HOME"] = str(node_dir)
        env_dict["HOME"] = str(node_dir)
        if env:
            env_dict.update(env)
        
        result = subprocess.run(
            [str(self.escript)] + command,
            cwd=str(node_dir),
            env=env_dict,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    
    def build_escript(self) -> bool:
        """Build the chrono_mesh escript"""
        print_section("Step 1/6: Building escript")
        
        if not self.escript.exists():
            print_info("Building escript...")
            result = subprocess.run(
                ["mix", "escript.build"],
                cwd=str(self.root),
                capture_output=True
            )
            if result.returncode != 0:
                print_error("Failed to build escript")
                return False
        else:
            print_success("Escript is up to date")
        
        return True
    
    def prepare_directories(self) -> bool:
        """Prepare node directories"""
        print_section("Step 2/6: Preparing node directories")

        if self.clean and self.build_dir.exists():
            print_info("Cleaning existing demo data...")
            shutil.rmtree(self.build_dir)

        self.build_dir.mkdir(parents=True, exist_ok=True)

        # Initialize node arrays with random ports if start_port is 0
        if self.start_port == 0:
            print_info("Generating random ports for nodes...")

        for i in range(1, self.num_nodes + 1):
            node_name = f"node{i}"
            # Generate a random free port if start_port is 0, otherwise use sequential ports
            port = find_free_port() if self.start_port == 0 else self.start_port + i - 1
            self.nodes.append(node_name)
            self.ports.append(port)
            self.pids.append(0)
            self.pubkeys.append("")
            self.node_ids.append("")

        if self.start_port == 0:
            print_success(f"Generated random ports: {self.ports}")
        else:
            print_success(f"Prepared directories for {self.num_nodes} nodes")
        return True
    
    def initialize_nodes(self) -> bool:
        """Initialize all nodes"""
        print_section("Step 3/6: Initializing nodes")
        
        for i, node in enumerate(self.nodes, 1):
            print_info(f"Initializing {node} (port {self.ports[i-1]})...")
            node_dir = self.build_dir / node
            
            # Create node directory
            node_dir.mkdir(parents=True, exist_ok=True)
            
            # Initialize node
            env = {"CHRONO_MESH_LISTEN_PORT": str(self.ports[i-1])}
            returncode, stdout, stderr = self.run_escript(
                node_dir,
                ["init", "--name", node],
                env
            )
            
            if returncode != 0:
                print_error(f"Failed to initialize {node}")
                print_error(stderr)
                return False
            
            # Update config file with port, wave duration, and default_path_length
            config_file = node_dir / ".chrono_mesh" / "config.yaml"
            if not config_file.exists():
                print_error(f"Config file not found: {config_file}")
                return False
            
            self._update_config_file(config_file, self.ports[i-1])
            
            # Extract public key path
            returncode, stdout, stderr = self.run_escript(
                node_dir,
                ["identity", "show"]
            )
            
            if returncode != 0:
                print_error(f"Failed to get identity for {node}")
                return False
            
            # Parse public key path from output
            pubkey_path = None
            for line in stdout.split('\n'):
                if 'Public key' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        pubkey_path = parts[1].strip()
                        break
            
            if not pubkey_path:
                # Fallback: try to read from config
                with open(config_file) as f:
                    config = yaml.safe_load(f)
                    if config and "identity" in config:
                        pubkey_path = config["identity"].get("public_key_path")
            
            if not pubkey_path:
                print_error(f"Failed to extract public key path for {node}")
                return False
            
            # Convert to absolute path if relative
            if not os.path.isabs(pubkey_path):
                pubkey_path = str(node_dir / pubkey_path)
            
            if not os.path.exists(pubkey_path):
                print_error(f"Public key file does not exist: {pubkey_path}")
                return False
            
            self.pubkeys[i-1] = pubkey_path
            
            # Extract node_id if available
            for line in stdout.split('\n'):
                if 'node_id' in line.lower():
                    parts = line.split(':')
                    if len(parts) > 1:
                        self.node_ids[i-1] = parts[1].strip()
                        break
            
            print_success(f"Initialized {node}")
        
        print_success("All nodes initialized")
        
        # Configure bootstrap peers
        self._configure_bootstrap_peers()
        
        return True
    
    def _update_config_file(self, config_file: Path, port: int):
        """Update config file with port, wave duration, and default_path_length"""
        with open(config_file) as f:
            config = yaml.safe_load(f) or {}
        
        if "network" not in config:
            config["network"] = {}
        
        # Preserve existing bootstrap_peers if they exist
        existing_bootstrap_peers = config["network"].get("bootstrap_peers")
        
        config["network"]["listen_port"] = port
        config["network"]["wave_duration_secs"] = self.wave_duration
        config["network"]["default_path_length"] = 2
        
        # Restore bootstrap_peers if they existed
        if existing_bootstrap_peers:
            config["network"]["bootstrap_peers"] = existing_bootstrap_peers
        
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    def _configure_bootstrap_peers(self):
        """Configure bootstrap peers in each node's config"""
        print_info("Configuring bootstrap peers for connection endpoint registration...")
        
        for i, node in enumerate(self.nodes, 1):
            node_dir = self.build_dir / node
            config_file = node_dir / ".chrono_mesh" / "config.yaml"
            
            if not config_file.exists():
                print_warn(f"Config file not found for {node}: {config_file}")
                continue
            
            with open(config_file) as f:
                config = yaml.safe_load(f) or {}
            
            if "network" not in config:
                config["network"] = {}
            
            # Build bootstrap peers list (all other nodes)
            bootstrap_peers = []
            for j in range(1, self.num_nodes + 1):
                if j != i:
                    peer_pubkey = self.pubkeys[j-1]
                    peer_port = self.ports[j-1]
                    if peer_pubkey:  # Only add if we have a valid pubkey
                        bootstrap_peers.append({
                            "public_key": peer_pubkey,
                            "connection_hint": f"127.0.0.1:{peer_port}"
                        })
            
            config["network"]["bootstrap_peers"] = bootstrap_peers
            
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            
            # Verify it was written
            with open(config_file) as f:
                verify_config = yaml.safe_load(f)
                if verify_config.get("network", {}).get("bootstrap_peers"):
                    print_info(f"Configured {len(bootstrap_peers)} bootstrap peers for {node}")
                else:
                    print_warn(f"Failed to write bootstrap peers for {node}")
        
        print_success("Bootstrap peers configured")
    
    def configure_peers(self) -> bool:
        """Configure peer relationships"""
        print_section("Step 4/6: Configuring peer relationships")
        
        for i, node in enumerate(self.nodes, 1):
            print_info(f"Configuring peers for {node}...")
            node_dir = self.build_dir / node
            added_count = 0
            
            for j in range(1, self.num_nodes + 1):
                if j != i:
                    peer_name = self.nodes[j-1]
                    peer_pubkey = self.pubkeys[j-1]
                    
                    returncode, stdout, stderr = self.run_escript(
                        node_dir,
                        ["peers", "add", "--name", peer_name, "--public-key", peer_pubkey]
                    )
                    
                    if returncode == 0:
                        added_count += 1
                    else:
                        print_warn(f"Failed to add peer {peer_name} to {node}: {stderr}")
            
            expected_count = self.num_nodes - 1
            if added_count < expected_count:
                print_warn(f"Only added {added_count}/{expected_count} peers for {node}")
            
            print_success(f"Configured peers for {node} ({added_count}/{expected_count})")
        
        print_success("Peer configuration complete")
        return True
    
    def start_nodes(self) -> bool:
        """Start all nodes"""
        print_section("Step 5/6: Starting nodes")
        
        for i, node in enumerate(self.nodes, 1):
            print_info(f"Starting {node} on port {self.ports[i-1]}...")
            node_dir = self.build_dir / node
            log_file = self.build_dir / f"{node}.log"
            
            env = {"CHRONO_MESH_LISTEN_PORT": str(self.ports[i-1])}
            
            # Start node in background
            process = subprocess.Popen(
                [str(self.escript), "start", "--mode", "combined"],
                cwd=str(node_dir),
                env={**os.environ, "CHRONO_MESH_HOME": str(node_dir), 
                     "HOME": str(node_dir), **env},
                stdout=open(log_file, 'w'),
                stderr=subprocess.STDOUT
            )
            
            self.pids[i-1] = process.pid
            
            # Wait a moment for node to start
            time.sleep(0.5)
            
            # Check if process is still running
            if process.poll() is not None:
                print_error(f"Node {node} failed to start. Check {log_file}")
                with open(log_file) as f:
                    print(f.read()[-2000:])  # Last 2000 chars
                return False
            
            print_success(f"Started {node} (PID: {process.pid})")
        
        # Wait for nodes to initialize
        print_info("Waiting for nodes to initialize...")
        time.sleep(3)
        
        # Verify connection endpoints
        self._verify_connection_endpoints()
        
        # Verify nodes are running
        all_running = True
        for i, pid in enumerate(self.pids, 1):
            if pid == 0:
                continue
            try:
                os.kill(pid, 0)  # Check if process exists
            except OSError:
                print_error(f"Node {self.nodes[i-1]} (PID: {pid}) is not running")
                all_running = False
        
        if not all_running:
            print_error("Some nodes failed to start")
            return False
        
        print_success("All nodes are running")
        return True
    
    def _verify_connection_endpoints(self):
        """Verify that connection endpoints are registered"""
        print_info("Verifying connection endpoint registration...")
        
        registered_count = 0
        for i, node in enumerate(self.nodes, 1):
            log_file = self.build_dir / f"{node}.log"
            if log_file.exists():
                with open(log_file) as f:
                    content = f.read()
                    if "bootstrap" in content.lower() or "connection" in content.lower():
                        registered_count += 1
        
        if registered_count == self.num_nodes:
            print_success("Connection endpoints registered for all nodes via bootstrap peers")
        else:
            print_warn(f"Some nodes may not have registered connection endpoints "
                      f"({registered_count}/{self.num_nodes} verified)")
            print_info("Bootstrap peers should auto-register on startup via Discovery")
    
    def send_test_messages(self) -> bool:
        """Send test messages between nodes"""
        print_section("Step 6/6: Sending test messages")
        
        # Verify peer configuration
        print_info("Verifying peer configuration...")
        sender = self.nodes[0]
        sender_dir = self.build_dir / sender
        
        returncode, stdout, stderr = self.run_escript(
            sender_dir,
            ["peers", "list"]
        )
        
        if returncode != 0:
            print_error(f"Failed to list peers: {stderr}")
            return False
        
        # Count peers
        peer_count = stdout.count("- ") if "- " in stdout else 0
        if peer_count == 0:
            print_error("No peers configured")
            return False
        
        print_success(f"{sender} has {peer_count} peers configured")
        
        # Send message from first node to last node
        recipient = self.nodes[-1]
        message = f"Hello from {sender}!"
        
        print_info(f"Sending message from {sender} to {recipient}...")
        
        returncode, stdout, stderr = self.run_escript(
            sender_dir,
            ["send", "--to", recipient, "--message", message, "--path-length", "2"]
        )
        
        if returncode != 0:
            print_error(f"Failed to send message: {stderr}")
            return False
        
        print_success("Message queued for delivery")
        
        # Wait for message delivery
        wait_time = (self.wave_duration * 4) + 2
        print_info(f"Waiting {wait_time}s for message delivery...")
        time.sleep(wait_time)
        
        # Check inbox
        recipient_dir = self.build_dir / recipient
        inbox_file = recipient_dir / ".chrono_mesh" / "inbox.log"
        
        if inbox_file.exists():
            with open(inbox_file) as f:
                content = f.read()
                if message in content:
                    print_success(f"Message delivered to {recipient}!")
                    print(f"\n{Colors.CYAN}Inbox contents:{Colors.NC}")
                    print(content[-500:])  # Last 500 chars
                    return True
                else:
                    print_warn(f"Message not yet delivered to {recipient}")
                    if content:
                        print(f"\n{Colors.CYAN}Inbox contents:{Colors.NC}")
                        print(content[-500:])
        else:
            print_warn(f"Inbox file not found: {inbox_file}")
        
        return False
    
    def cleanup(self):
        """Clean up all node processes"""
        print(f"\n{Colors.YELLOW}[*] Shutting down demo nodes...{Colors.NC}")
        
        for pid in self.pids:
            if pid > 0:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass
        
        # Wait a bit for graceful shutdown
        time.sleep(1)
        
        # Force kill any remaining processes
        for pid in self.pids:
            if pid > 0:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        
        print(f"{Colors.GREEN}[*] Cleanup complete{Colors.NC}")
    
    def run(self) -> bool:
        """Run the complete demo"""
        print(f"""
{Colors.CYAN}
╔══════════════════════════════════════════════════════╗
║        ChronoMesh Cluster Demo                       ║
║        Multi-Node Network Demonstration             ║
╚══════════════════════════════════════════════════════╝
{Colors.NC}
{Colors.CYAN}Configuration:{Colors.NC}
  Nodes: {self.num_nodes}
  Starting Port: {"Random (auto-assign)" if self.start_port == 0 else self.start_port}
  Wave Duration: {self.wave_duration}s
  Interactive: {self.interactive}
""")
        
        try:
            if not self.build_escript():
                return False
            
            if not self.prepare_directories():
                return False
            
            if not self.initialize_nodes():
                return False
            
            if not self.configure_peers():
                return False
            
            # Re-add bootstrap peers (configure_peers may have overwritten them)
            self._configure_bootstrap_peers()
            
            if not self.start_nodes():
                return False
            
            if not self.send_test_messages():
                print_warn("Message delivery verification failed")
            
            if self.interactive:
                print(f"\n{Colors.YELLOW}Nodes are running. Press Ctrl+C to stop.{Colors.NC}")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
            
            return True
        
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        finally:
            if not self.interactive:
                self.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="ChronoMesh Cluster Demo Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "-n", "--nodes",
        type=int,
        default=3,
        help="Number of nodes to create (default: 3)"
    )
    
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=0,
        help="Starting port number (default: 0 = auto-assign random ports)"
    )
    
    parser.add_argument(
        "-w", "--wave-duration",
        type=int,
        default=2,
        help="Wave duration in seconds (default: 2)"
    )
    
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run in interactive mode (keep nodes running)"
    )
    
    parser.add_argument(
        "-c", "--clean",
        action="store_true",
        help="Clean up before starting (remove existing demo data)"
    )
    
    args = parser.parse_args()
    
    # Validate inputs
    if args.nodes < 2:
        print_error("Number of nodes must be at least 2")
        sys.exit(1)

    if args.port != 0 and args.port < 1024:
        print_error("Starting port must be 0 (auto-assign) or >= 1024")
        sys.exit(1)
    
    demo = DemoCluster(
        num_nodes=args.nodes,
        start_port=args.port,
        wave_duration=args.wave_duration,
        interactive=args.interactive,
        clean=args.clean
    )
    
    success = demo.run()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

