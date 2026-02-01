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
version: v2
global:
  interface: wg0
  ipv6_mode: allow
  egress_policy: allow
  allow_tunneling: true

rules:
  - name: "allow-ssh"
    action: accept
    proto: tcp
    port: "22"
    src: ["10.0.0.0/8"]
```

#### Fleet Example (Profiles for App vs DB Servers)

Keep one policy file in Git and apply a profile per server role.

```yaml
version: v2
global:
  interface: wg0
  ipv6_mode: allow
  egress_policy: allow
  allow_tunneling: true

definitions:
  admins: ["10.0.0.0/8"]
  app_net: ["10.10.0.0/24"]
  db_net: ["10.20.0.0/24"]

profiles:
  app:
    rules:
      - name: "ssh-from-admins"
        action: accept
        proto: tcp
        port: "22"
        src: ["admins"]
      - name: "https-public"
        action: accept
        proto: tcp
        port: "443"
        src: ["any"]

  db:
    rules:
      - name: "ssh-from-admins"
        action: accept
        proto: tcp
        port: "22"
        src: ["admins"]
      - name: "db-from-apps"
        action: accept
        proto: tcp
        port: "5432"
        src: ["app_net"]
```

#### Advanced Policy Example (Egress Lockdown, Bogons, GeoIP)

```yaml
version: v2
global:
  interface: wg0
  ipv6_mode: allow
  egress_policy: block
  dns_servers: ["1.1.1.1", "2606:4700:4700::1111"]
  allow_tunneling: false
  protect_interface_only: true
  bogon_interfaces: ["eth0"]

  geo_block_interfaces: ["eth0"]
  geo_block_mode: allow
  geo_block_feeds:
    - name: fr
      url: https://www.ipdeny.com/ipblocks/data/countries/fr.zone
      ip_version: 4
      refresh_sec: 86400
    - name: fr6
      url: https://www.ipdeny.com/ipv6/ipaddresses/blocks/fr.zone
      ip_version: 6
      refresh_sec: 86400

definitions:
  admins: ["10.0.0.0/8", "192.168.1.50/32"]
  app: ["10.100.0.10/32"]
  db: ["10.100.0.20/32"]

rules:
  - name: "ssh-management"
    action: accept
    proto: tcp
    port: "22"
    src: ["admins"]
    dst: ["app"]

  - name: "block-admin-to-prod-db"
    action: drop
    proto: tcp
    port: "5432"
    src: ["admins"]
    dst: ["db"]
```

#### Policy Reference (Allowed Values)

**Top-level**
- `version`: string (examples use `v2`)
- `global`: object (see below)
- `definitions`: map of `name -> list[string]`
- `rules`: list of rules
- `profiles` (optional): map of `profileName -> { rules: [...] }`

**`global`**
- `interface`: string matching `^[a-zA-Z0-9_\\-\\.]+$` (example: `wg0`)
- `ipv6_mode`: `allow` | `block`
- `egress_policy`: `allow` | `block`
- `dns_servers`: list of IPv4/IPv6 addresses (strings)
- `allow_tunneling`: `true` | `false`
- `sentinel_interval`: integer (seconds)
- `protect_interface_only`: `true` | `false`
- `bogon_interfaces`: list of interface names (same safe string format as `interface`)
- `windows_log_blocked`: `true` | `false`
- `windows_log_allowed`: `true` | `false`
- `windows_log_file`: string (path)
- `windows_log_max_kb`: integer (>0 recommended)
- `geo_block_interfaces`: list of interface names
- `geo_block_mode`: `deny` | `allow`
- `geo_block_feeds`: list of feeds:
  - `name`: string matching `^[a-zA-Z0-9_\\-\\.]+$`
  - `url`: `https://...` (HTTPS required)
  - `ip_version`: `4` | `6`
  - `sha256` (optional): 64 hex chars
  - `refresh_sec` (optional): integer `>= 0`

**`definitions` values**
- Each entry can be:
  - CIDR (e.g. `10.0.0.0/8`, `2001:db8::/32`)
  - IP (e.g. `10.0.0.1`, `2606:4700:4700::1111`)
  - `any`

**Rule fields (`rules[]` and `profiles.*.rules[]`)**
- `name` (optional): string matching `^[a-zA-Z0-9_\\-\\.]+$`
- `comment` (optional): string
- `action`: `accept` | `drop`
- `proto`: `any` | `tcp` | `udp` | `icmp` | `icmpv6`
- `port`: `any` | `"1"`..`"65535"` | `"start-end"`
  - `port` cannot be set when `proto` is `any`, `icmp`, or `icmpv6`
- `src`: list of entries (each is `any`, a definition name, an IP, or a CIDR)
- `dst`: list of entries (each is `any`, a definition name, an IP, or a CIDR)

### 2. Validate

```bash
wpc check policy.yaml
wpc check policy.yaml --profile app
```

### 3. Apply (Linux nftables)
WPC validates the policy, snapshots the active nftables ruleset for rollback, loads the new ruleset atomically, and arms a rollback timer.

```bash
$ sudo wpc apply -f policy.yaml --os linux --confirm-timeout 60
$ sudo wpc apply -f policy.yaml --os linux --confirm-timeout 60 --profile app

[INFO] Validating syntax... OK
[INFO] Snapshotting rollback state... OK
[INFO] Loading ruleset... DONE
[WARN] Rollback timer armed (60s). Confirm with: sudo wpc confirm --id <SESSION_ID>
```

### 4. Confirm (Disarm Rollback)

```bash
sudo wpc confirm --id <SESSION_ID>
```

### 5. Continuous Enforcement (Drift Detection)
The Sentinel daemon hashes the active kernel ruleset and compares it to the last applied state.

It also refreshes GeoIP feeds on a schedule (if configured) and updates nftables sets without rebuilding the full ruleset.

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
*   **Sentinel:** Runs with privileges (root). It detects drift and can re-apply the last known-good ruleset.

### Safety Mechanisms
*   **Atomic Loading:** Rules are loaded in a single transaction. The firewall is never in a half-configured state.
*   **Automatic Rollback:** `wpc apply` arms a timer and requires `wpc confirm` within the timeout. If not confirmed, the previous ruleset is restored.
*   **Rate-Limited Logging:** Linux emits rate-limited drop logs; Windows configures firewall profile logging.

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