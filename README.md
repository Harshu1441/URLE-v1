# ULRE — Unified Linux Resource Enforcement Platform

[![Linux cgroup v2](https://img.shields.io/badge/Platform-Linux%20cgroup%20v2-FCC624?logo=linux&logoColor=black)](https://docs.kernel.org/admin-guide/cgroup-v2.html)
[![Environments](https://img.shields.io/badge/Supports-Bare--Metal%20%7C%20systemd%20%7C%20Docker%20%7C%20Cloud%20VMs-1D4ED8)](#supported-vs-not-yet-supported)
[![Kernel](https://img.shields.io/badge/Kernel-Linux%204.18%2B%20%28cgroup%20v2%29-0F766E)](#requirements)

**ULRE (Unified Linux Resource Enforcement Platform)** is an active Linux workload resource enforcement, cgroup v2 isolation, and intelligent Out-Of-Memory (OOM) remediation platform for production servers, VMs, and Docker hosts.

Instead of acting as another passive monitoring dashboard, ULRE **actively enforces** CPU, memory, swap, I/O, and process limits from a centralized policy engine while coordinating cleanly with `systemd` and `Docker` through their native management APIs — without competing with them.

---

## Supported vs. Not Yet Supported

### Supported
- **Bare-Metal & Non-Service Processes:** Enforces resource policies using transient `systemd` `.scope` units via D-Bus (`StartTransientUnit`) under `ulre.slice`, or delegated cgroup v2 subtrees when scope mode is disabled.
- **`systemd` Services:** Enforces runtime resource properties (`MemoryMax`, `MemoryHigh`, `MemoryLow`, `MemoryMin`, `MemorySwapMax`, `CPUQuotaPerSecUSec`, `CPUWeight`, `IOReadBandwidthMax`, `IOWriteBandwidthMax`, `TasksMax`) via D-Bus `SetUnitProperties(runtime=true)` — without migrating PIDs or touching unit files — with checkpoint rollback when policies are removed.
- **Docker Containers:** Discovers containers and enforces supported limits (`memory.max`, `memory.low`, `memory.swap.max`, `cpu.max`, `cpu.weight`, `pids.max`) through Docker Engine API (`ContainerUpdate`) with drift detection and restart/recreate re-application.
- **Cloud Linux VMs (AWS, Azure, GCP) & Virtualization:** Automatically tags host cloud/VM metadata while enforcing all limits locally on the kernel with zero cloud IAM dependency.
- **Intelligent Pre-OOM & OOM Remediation:** Evaluates memory %, PSI pressure (kernel 4.20+ optional), and `memory.events` counters to execute configurable action chains (alert → throttle → limit reduction → service restart → isolation → authorized termination → kernel OOM fallback) with cooldowns and retry limits.
- **Ownership & Drift Detection:** Records applied limits per target and raises drift events rather than silently overwriting external manual changes.
- **Central Control Plane & Web Console:** Multi-host management, live process-tree lineage explorer, policy conflict & capability validation, RBAC, one-time agent registration + rotating host-bound tokens, audit trail, and rotating server logs.

### Not Yet Supported
- **Kubernetes Workloads:** Kubernetes (`kubepods` cgroups) is **not supported**. The agent detects and skips kubepods workloads with `unsupported: Kubernetes workload`, and protects `kubelet`, `containerd`, and `cri-o` processes from modification.
- **Live Host eBPF Attachment:** Control-plane ELF/BTF inspection and `kernel_admin` approval are implemented; live host `bpf()` loading/attachment is gated behind future work.

---

## Known Limitations

- **Docker Field Coverage:** Docker's `ContainerUpdate` API does **not** support `memory.high`, `memory.min`, `memory.oom.group`, or `io.max`. Policies using those fields against Docker targets are **rejected with an explicit error** at validation time — never silently ignored. `memory.low` maps to `MemoryReservation` (soft hint only), and `cpu.weight` scales to `CpuShares`.
- **`systemd` Runtime-Only Properties:** `SetUnitProperties(runtime=true)` applies limits in memory only — they revert on host reboot until the agent re-syncs on startup. No permanent drop-ins are written to disk.
- **`systemd` 239 Gaps:** `memory.oom.group` is not settable via D-Bus at runtime on systemd 239; `io.max` supports bandwidth (`rbps`/`wbps`) only — not IOPS (`riops`/`wiops`).
- **PSI is Optional:** Pressure Stall Information (`/proc/pressure/memory`) requires kernel 4.20+ with `CONFIG_PSI=y`. Without it, OOM policies using PSI conditions are simply not triggered; `memory %` and `memory.events` conditions work on any cgroup v2 host.

---

## Requirements

| Component | Minimum | Notes |
|-----------|---------|-------|
| **Managed Linux Hosts** | Kernel **4.18+** with cgroup v2 | Kernel 5.10+ recommended; PSI requires 4.20+ with `CONFIG_PSI=y` |
| **systemd** | systemd **239+** | Required for D-Bus adapter; older versions fall back to raw cgroup file writes |
| **Docker enforcement** | Docker Engine **20.10+** | Socket at `/var/run/docker.sock` |
| **Control Plane** | Go **1.23+**, Node.js **20+** | For building the Web Console |

---

## High-Level Architecture

```
+-------------------------------------------------------------------+
|                     ULRE CENTRAL CONTROL PLANE                    |
|   Web Console   |   Policy & Capability Check   |   RBAC & Audit  |
+---------------------------------+---------------------------------+
                                  | Secure Agent Sync (Rotating JWT)
               +------------------+------------------+
               v                                     v
+------------------------------+      +------------------------------+
| Bare-Metal / Cloud Linux VM  |      | Docker Hosts                 |
| systemd D-Bus (SetUnitProps  |      | Docker Engine API            |
| & StartTransientUnit)        |      | (ContainerUpdate)            |
+--------------+---------------+      +--------------+---------------+
               |                                     |
               +------------------+------------------+
                                  v
+-------------------------------------------------------------------+
|                   LINUX KERNEL (cgroup v2 / OOM)                  |
+-------------------------------------------------------------------+
```

---

## Security Principles

- **Server-Side RBAC & Approval Gates:** Destructive termination and runtime-override policies require server-verified `admin` role — enforced on the server regardless of UI state.
- **Scoped Agent Credentials:** One-time registration tokens (single-use, 15-minute TTL), host-bound rotating 24-hour JWTs, and mTLS support. A token from one host cannot authenticate another.
- **Fail-Closed Adapters:** If the `systemd` D-Bus socket or Docker socket is unavailable, or a field is unsupported by the target adapter, ULRE logs the error and does nothing — no silent fallback to PID migration.
- **No Remote Shell & Path Safety:** Exposes declarative policy operations only. All cgroup paths and policy names are validated against traversal characters (`..`, `/`, `\`, `;`, `|`, `&`, `$`, null bytes) before any file write.

---

## Installation

See [Installation Guide](docs/installation.md) for setup instructions.
