# WirePolicy Compiler (WPC)

![Build Status](https://img.shields.io/github/actions/workflow/status/fahmitech/wpc/go.yml?branch=main)
![Go Report Card](https://goreportcard.com/badge/github.com/fahmitech/wpc)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

**WPC** is a declarative infrastructure-as-code tool for network security. It allows you to define firewall policies in YAML, compile them into native kernel instructions (`nftables` for Linux, WFP for Windows), and enforce them with a background daemon.

It solves two specific problems:
1.  **Complexity:** Abstraction over raw `nftables` syntax and Windows API.
2.  **Drift:** Continuous monitoring to revert unauthorized manual changes.

---

## Usage

### 1. Define Policy
Create a `policy.yaml` file. The syntax is designed to be readable and version-controllable.

```yaml
version: v1
inbound:
  default: drop
  rules:
    - name: "ssh-management"
      port: 22
      proto: tcp
      source: ["10.0.0.0/8", "192.168.1.50"]
      
    - name: "web-traffic"
      port: [80, 443]
      proto: tcp

outbound:
  default: accept
```

### 2. Apply
Run the compiler. WPC validates the syntax, snapshots the current state, and applies the new rules atomically.

```bash
$ wpc apply -f policy.yaml

[INFO] Validating syntax... OK
[INFO] Snapshotting rollback state (id: 8f2a1c)... OK
[INFO] Compiling to nftables bytecode... OK
[INFO] Loading ruleset... DONE
```

### 3. Continuous Enforcement (Drift Detection)
The `wpc-agent` runs as a systemd service. It hashes the active kernel ruleset and compares it to the applied policy.

If a user manually alters the firewall (e.g., `iptables -F`), WPC detects the anomaly and restores the defined policy immediately.

```bash
# Logs from journalctl
[WARN] Drift detected: active ruleset hash mismatch.
[INFO] Reverting to last known good configuration (policy.yaml).
[INFO] State restored.
```

---

## Installation

**Linux (Binary)**
```bash
curl -sfL https://github.com/fahmitech/wpc/releases/latest/download/install.sh | sudo bash
```

**Go Install**
```bash
go install github.com/fahmitech/wpc/cmd/wpc@latest
```

---

## Technical Details

### Architecture
WPC operates as a split-stack:
*   **Compiler:** Parses YAML and generates platform-specific instructions. It does not require root privileges to run dry-runs.
*   **Agent:** Runs with privileges (root/SYSTEM). It handles the netlink sockets (Linux) or WFP API calls (Windows).

### Safety Mechanisms
*   **Atomic Loading:** Rules are loaded in a single transaction. The firewall is never in a half-configured state.
*   **Automatic Rollback:** During interactive sessions (SSH), WPC requires a confirmation signal after applying rules. If the signal is not received within 60 seconds (e.g., you locked yourself out), the previous ruleset is automatically restored.

### Supported Backends
*   **Linux:** `nftables` (Kernel 3.13+)
*   **Windows:** Windows Filtering Platform (Server 2016+)

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1.  Fork the repository
2.  Create your feature branch (`git checkout -b feature/optimization`)
3.  Commit your changes
4.  Push to the branch
5.  Open a Pull Request

## License

Apache 2.0