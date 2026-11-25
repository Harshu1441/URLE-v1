# ULRE — Installation Guide

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| **Control Plane Host** | Go `1.23+` and Node.js `20+` |
| **Managed Linux Hosts** | Linux kernel **4.18+** with unified `cgroup v2` at `/sys/fs/cgroup`, `systemd 239+` |
| **PSI (optional)** | Kernel `4.20+` with `CONFIG_PSI=y` — enables PSI-based OOM conditions; `memory %` and `memory.events` conditions work without it |
| **Docker enforcement** | Docker Engine `20.10+` socket at `/var/run/docker.sock` |

> **Recommended:** Kernel 5.10+ for full feature coverage (PSI, all cgroup v2 controllers, `memory.oom.group`). Kernel 4.18 is the tested minimum and runs all core features except PSI.

---

## 1. Build & Start the Control Plane + Web Console

```bash
# Build the Web Console
cd frontend
npm install
npm run build

# Configure required runtime environment variables before starting
export ULRE_ADMIN_PASSWORD="<strong-admin-password>"
export ULRE_JWT_SECRET="<strong-random-32-plus-char-secret>"
export ULRE_AGENT_TOKEN="<initial-agent-registration-token>"

# Start the Control Plane (serves the Web Console from --static-dir)
cd ../control-plane
go run ./cmd/control-plane \
  --addr :8080 \
  --static-dir ../frontend/dist \
  --log-config log.conf \
  --data-dir /var/lib/ulre-cp
```

### Log rotation (`log.conf`)

The control plane writes structured rotating logs. Customize `control-plane/log.conf`:

```ini
log_base_dir = /var/log/ulre
max_size_mb  = 500        # rotate after 500 MB (configurable)
max_files    = 10         # keep up to 10 archived files
level        = INFO       # DEBUG | INFO | WARN | ERROR
```

Each startup creates `<log_base_dir>/server_log-YYYY-MM-DD_HH-MM-SS/ulre-server.log`. Rotated archives get a `.NNNN.log` suffix.

---

## 2. Build & Run the Linux Enforcement Agent

```bash
cd linux-agent
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ulre-agent ./cmd/ulre-agent

# Verify host cgroup v2 and PSI readiness before deploying
./ulre-agent detect

# Connect to Control Plane (using initial registration token)
sudo ./ulre-agent enforce \
  --control-plane http://<control-plane-host>:8080 \
  --agent-token "$ULRE_AGENT_TOKEN" \
  --state-dir /var/lib/ulre
```

> **One-time registration:** The agent token is consumed on first successful contact and exchanged for a rotating host-bound JWT (24-hour TTL). After that, the agent rotates its own token automatically. Reusing an expired or already-consumed token is rejected by the control plane.

### Agent state files

The agent writes the following files to `--state-dir`:

| File | Purpose |
|------|---------|
| `audit.jsonl` | Append-only structured audit log of every enforcement action |
| `ownership-state.json` | Applied limits + drift status per managed target |
| `systemd-checkpoints.json` | Pre-ULRE property snapshots for rollback on policy removal |

### Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `--feature-systemd-scope` | `true` | Use `systemd` D-Bus (`SetUnitProperties` / `StartTransientUnit`) for systemd-managed processes. Set `false` only on systemd < 239 to fall back to raw cgroup file writes. |

---

## 3. Optional: Install as a systemd Service

See [`deployments/systemd/ulre-agent.service`](../deployments/systemd/ulre-agent.service) for a ready-to-use unit file, or [`deployments/cloud/install-agent.sh`](../deployments/cloud/install-agent.sh) for a one-step install on bare-metal servers and cloud Linux VMs.
