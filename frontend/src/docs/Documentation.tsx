const ARCHITECTURE_PRINCIPLES: [string, string][] = [
  ['One Policy Engine + Multiple Adapters', 'Policies are defined once and enforced natively on Bare-Metal (transient systemd scopes via D-Bus StartTransientUnit, or delegated cgroup v2 subtrees), systemd services (D-Bus SetUnitProperties runtime=true), Docker (Engine API ContainerUpdate), and Cloud VMs (AWS/Azure/GCP metadata tagged automatically). Kubernetes kubepods workloads are explicitly skipped as unsupported.'],
  ['systemd D-Bus — No PID Migration', 'For systemd-managed services, ULRE applies limits by calling SetUnitProperties(runtime=true) over D-Bus — the PID stays in its own service slice. For bare-metal non-service processes, ULRE creates a transient scope (StartTransientUnit) under ulre.slice. PIDs are never forcibly migrated out of their runtime-owned hierarchy.'],
  ['Rollback Checkpoints', 'Before applying limits to a systemd unit for the first time, ULRE snapshots the current property values into a checkpoint file (systemd-checkpoints.json). When a policy is removed or disabled, those original values are restored via D-Bus, returning the unit to its pre-ULRE state.'],
  ['Ownership & Drift Detection', 'After each successful apply, ULRE records what it wrote into an ownership store (ownership-state.json). On every reconcile tick it reads back live values and compares them. If another actor (admin, manual docker update, another tool) changed the values, ULRE raises an ownership.drift_detected audit event and skips the overwrite instead of silently fighting for control.'],
  ['PID-Reuse Safety', 'Every process is uniquely tracked by (PID, StartTimeTicks) from /proc/<pid>/stat. Before signaling or migrating a process, the agent re-verifies StartTimeTicks so recycled PIDs can never be accidentally harmed.'],
  ['Protected System Guardrails', 'PID 1, kernel threads, and essential host services (systemd-*, init.scope, dbus, sshd, dockerd, containerd, crio, kubelet, ulre-agent) are always skipped. kubelet-managed kubepods workloads are detected by cgroup path and skipped even when allow_runtime_override=true.'],
  ['Fail-Closed Adapters', 'If the systemd D-Bus socket is unavailable, or the Docker Engine socket is absent, or a policy field is not supported by the target adapter, ULRE logs the error and does nothing. It never falls back to a competing mechanism or silently skips the error.'],
];

const CGROUP_CONTROLS: [string, string][] = [
  ['memory.max', 'Hard memory ceiling (bytes; entered in MB/GB in UI). Allocations beyond this trigger kernel reclaim and, if exhausted, cgroup OOM kill (exit 137 / OOMKilled=true). Default baseline: 256 MB.'],
  ['memory.high', 'Soft memory throttling threshold (~75% of memory.max recommended). When exceeded, the kernel aggressively throttles and reclaims memory before hitting memory.max. Default baseline: 192 MB.'],
  ['memory.low', 'Best-effort memory protection (~25% of memory.max recommended). The kernel avoids reclaiming below this floor unless global memory pressure is critical. Default baseline: 64 MB.'],
  ['memory.min', 'Hard memory protection floor for high/critical workloads (kernel >= 4.19). The kernel never reclaims below this, regardless of global pressure.'],
  ['memory.swap.max', 'Maximum swap usage for the cgroup. Set to 0 MB to prevent swap thrashing on latency-sensitive or OOM-guarded workloads. Default baseline: 0 MB.'],
  ['memory.oom.group', 'When enabled (1), a kernel OOM kill terminates all processes in the cgroup together as an atomic unit. Note: not settable at runtime on systemd 239 or via Docker ContainerUpdate — bare-metal (cgroup v2 file write) only.'],
  ['cpu.max / cpu.weight', 'cpu.max sets CFS bandwidth quota/period (e.g. 50000 100000 = 50% of 1 vCPU). cpu.weight (1–10000) sets proportional CPU shares under contention. Default baseline: 25% quota, weight 100.'],
  ['io.max / pids.max', 'io.max caps block device read/write throughput (rbps/wbps on systemd; unsupported by Docker Update). pids.max prevents fork bombs by limiting max tasks inside the cgroup.'],
];

const COLUMN_DOCS: [string, string][] = [
  ['Host / Actor', 'Identifies who initiated the action — either an authenticated user (admin, kernel_admin, operator, viewer) or a Linux host agent (agent:<hostname>).'],
  ['Policy', 'The ULRE resource/OOM policy rule name that matched the workload and triggered the event.'],
  ['Target cgroup / PID', 'Exact target acted upon: delegated cgroup (ulre.slice/<group>), transient scope (ulre.slice/ulre-<name>-<pid>.scope), systemd unit, container ID, or pid:<pid>(<comm>).'],
  ['Action', 'Specific control-plane, cgroup v2, Docker API, systemd D-Bus, or OOM remediation operation executed.'],
  ['Outcome / Result', 'applied = enforced on kernel/runtime; dry_run = simulated without mutation; blocked = stopped by safety guard (PID 1, kubepods, unauthorized terminate); skipped = cooldown or precondition not met; error = kernel or API error (adapter fails closed).'],
];

const OOM_AND_ACTION_DOCS: [string, string][] = [
  ['cgroup.apply_limit', 'Writes cgroup v2 control files idempotently under /sys/fs/cgroup/ulre.slice/<group> (bare-metal path).'],
  ['cgroup.move_pid', 'Re-verifies (PID, StartTimeTicks), then writes the PID into <cgroup>/cgroup.procs (bare-metal only; never used for systemd or Docker workloads).'],
  ['systemd.set_properties', 'Calls D-Bus SetUnitProperties(runtime=true) to apply MemoryMax, MemoryHigh, MemoryLow, MemoryMin, MemorySwapMax, CPUQuotaPerSecUSec, CPUWeight, IOReadBandwidthMax, IOWriteBandwidthMax, TasksMax on a live systemd service without restarting it.'],
  ['systemd.start_scope', 'Calls D-Bus StartTransientUnit to create a transient ulre.slice/<name>-<pid>.scope and move a bare-metal non-service PID into it with limits applied at scope creation.'],
  ['systemd.rollback', 'Restores pre-ULRE property values from the checkpoint file (systemd-checkpoints.json) via SetUnitProperties when a policy is removed or disabled.'],
  ['docker.update_container', 'Enforces container CPU, memory, swap, and PID caps safely via Docker Engine API POST /containers/{id}/update without competing with dockerd.'],
  ['ownership.drift_detected', 'Raised when live values on a managed target no longer match what ULRE last applied, indicating an external change. ULRE does not overwrite — it logs and waits for the next policy cycle or a new container/service instance.'],
  ['policy.skip_runtime_owned', 'Safety guard: refuses to modify Docker workloads unless allow_runtime_override=true is explicitly authorized in the policy.'],
  ['policy.skip_unsupported_k8s', 'Safety guard: skips kubelet-managed kubepods workloads and logs "unsupported: Kubernetes workload" always, even if allow_runtime_override=true.'],
  ['oom.alert / oom.escalate', 'Records memory pressure / OOM threshold breach (memory %, PSI some/full avg10, or memory.events delta) and pushes real-time alerts over WebSocket.'],
  ['oom.throttle', 'Dynamically lowers memory.high by 15% (to a 4 MiB floor) to induce kernel allocation throttling before an OOM kill occurs.'],
  ['oom.reduce_limits', 'Reduces memory.max by 10% (within safe bounds) to contain runaway memory consumption.'],
  ['oom.restart_service', 'Restarts an eligible non-critical systemd unit via systemctl restart within the configured remediation timeout.'],
  ['oom.isolate', 'Moves eligible non-protected PIDs into a constrained quarantine cgroup (ulre.slice/ulre-quarantine).'],
  ['oom.terminate', 'Authorized destructive kill (requires allow_destructive=true and non-critical workload): sends SIGTERM, waits remediation timeout, then SIGKILL after re-verifying PID start time.'],
  ['oom.kernel_oom_fallback', 'Enables memory.oom.group=1 so the Linux kernel OOM killer terminates the workload cleanly if memory.max is exhausted (exit 137, OOMKilled=true). Bare-metal only.'],
  ['memory.events (high / max / oom / oom_kill)', 'Kernel cgroup v2 counters: high = memory.high throttles; max = hit memory.max; oom = OOM killer invoked; oom_kill = process killed by kernel OOM.'],
  ['PSI (some avg10 / full avg10)', 'Pressure Stall Information (/proc/pressure/memory, kernel >= 4.20): percentage of time some or all tasks stalled waiting for memory.'],
];

const ADAPTER_CAPABILITY_MATRIX: [string, string, string, string, string][] = [
  ['memory.max',      'supported',   'supported',   'supported',   'Hard memory ceiling (MemoryMax / Docker Memory)'],
  ['memory.high',     'supported',   'supported',   'unsupported', 'Soft reclaim throttle; Docker ContainerUpdate does not expose this field'],
  ['memory.low',      'supported',   'supported',   'partial',     'Mapped to Docker MemoryReservation (soft hint, not a hard floor)'],
  ['memory.min',      'supported',   'supported',   'unsupported', 'Hard protection floor; not in Docker ContainerUpdate'],
  ['memory.swap.max', 'supported',   'supported',   'supported',   'Docker requires memory.max to also be set when capping swap'],
  ['memory.oom.group','supported',   'unsupported', 'unsupported', 'Bare-metal cgroup file write only; not settable via D-Bus at runtime (systemd 239) or Docker Update'],
  ['cpu.max',         'supported',   'supported',   'supported',   'CPUQuotaPerSecUSec on systemd; CpuPeriod+CpuQuota on Docker'],
  ['cpu.weight',      'supported',   'supported',   'partial',     'Native CPUWeight on systemd/cgroup; scaled to CpuShares (weight×1024/100) on Docker'],
  ['io.max',          'supported',   'partial',     'unsupported', 'systemd supports rbps/wbps bandwidth only (no IOPS); Docker Update has no io.max field'],
  ['pids.max',        'supported',   'supported',   'supported',   'TasksMax on systemd; PidsLimit on Docker'],
];

const SECURITY_DOCS: [string, string][] = [
  ['Server-Side RBAC & Approval Gates', 'Destructive termination (allow_destructive=true) and runtime-override policies in enforce mode require a server-verified admin role JWT. The UI hides buttons for lower roles, but the 403 is enforced on the server regardless.'],
  ['One-Time Registration Tokens', 'An admin generates a single-use 15-minute registration token (POST /api/v1/auth/agent-bootstrap). The agent sends it once; the control plane invalidates it on first use and issues a 24-hour host-bound JWT. Reuse or expiry returns 401.'],
  ['Rotating Host-Bound Agent JWTs', 'Agents rotate their token before expiry via POST /api/v1/agents/rotate-token. The token is scoped to the host ID; a token from one host cannot authenticate another host\'s sub-routes.'],
  ['Path & Name Safety', 'Policy names and groups are validated against traversal characters (.., /, \\, ;, |, &, $, null bytes) — returning 422 on violation. cgroup paths are validated in the manager before any file write.'],
  ['No Remote Shell', 'ULRE exposes declarative policy operations only. No endpoint accepts or executes arbitrary commands or shell strings. All cgroup path segments are validated against traversal before writes.'],
  ['Fail-Closed on Adapter Errors', 'If the systemd D-Bus socket is unavailable or Docker socket is absent, the agent logs a typed audit event (systemd.error or docker.error) and skips the target — it never falls back to raw PID moves into another cgroup.'],
];

const KNOWN_LIMITATIONS: [string, string][] = [
  ['Docker: memory.high, memory.min, io.max, memory.oom.group', 'Docker\'s ContainerUpdate API does not support these fields. Policies using them on Docker targets are rejected with an explicit error at validation time — never silently skipped.'],
  ['Docker: memory.low', 'Mapped to MemoryReservation (a soft hint). Docker does not enforce a hard protection floor the way cgroup v2 memory.low does.'],
  ['Docker: cpu.weight', 'Scaled from cgroup weight (1–10000) to legacy CpuShares (2–1024) using weight×1024/100, capped at 1024. The mapping is approximate.'],
  ['systemd: runtime-only properties', 'SetUnitProperties(runtime=true) applies limits in memory only; they revert on host reboot until the agent re-syncs on startup. No permanent drop-ins are written to disk.'],
  ['systemd 239: memory.oom.group', 'memory.oom.group is not a settable runtime D-Bus property on systemd 239. Use bare-metal cgroup file writes or the oom.kernel_oom_fallback action instead.'],
  ['systemd: io.max IOPS', 'D-Bus IOReadBandwidthMax / IOWriteBandwidthMax expose byte-rate limits only. IOPS (riops/wiops) are not settable via runtime D-Bus on the tested systemd/kernel versions.'],
  ['PSI is optional', 'Pressure Stall Information (/proc/pressure/memory) requires kernel 4.20+ with CONFIG_PSI=y. Without it, PSI-based OOM conditions simply never trigger; memory % and memory.events conditions work on any cgroup v2 host (kernel 4.18+).'],
  ['Kubernetes workloads', 'Not supported. Kubepods cgroups are detected by path and always skipped, even with allow_runtime_override=true. kubelet, containerd, and cri-o are protected.'],
];

const LOGGING_DOCS: [string, string][] = [
  ['Per-Run Session Directory', 'Each Control Plane startup creates <log_base_dir>/server_log-YYYY-MM-DD_HH-MM-SS/ulre-server.log containing HTTP requests, 4xx/5xx diagnostics, panic stack traces, and WebSocket events.'],
  ['Size-Based Rotation (log.conf)', 'Configured via control-plane/log.conf (or --log-config). Default max_size_mb=500 rotates the active file into numbered archives (.0001.log, .0002.log…) every 500 MB; retains up to max_files=10 archives. Both values are configurable.'],
  ['Log Levels', 'Set level=DEBUG | INFO | WARN | ERROR in log.conf. 4xx responses log at WARN; 5xx responses and recovered panics (with full stack trace) log at ERROR.'],
  ['Agent State Files (--state-dir)', 'audit.jsonl — append-only structured audit log of every enforcement action. ownership-state.json — applied limits and drift status per managed target. systemd-checkpoints.json — pre-ULRE property snapshots used for rollback when a policy is removed or disabled.'],
];

function DocTable({ title, rows, keyHeader = 'Item', valHeader = 'Definition' }: { title: string; rows: [string, string][]; keyHeader?: string; valHeader?: string }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <span>{title}</span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th style={{ width: 280 }}>{keyHeader}</th>
              <th>{valHeader}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([k, v]) => (
              <tr key={k}>
                <td className="mono" style={{ fontSize: 12, fontWeight: 600 }}>
                  {k}
                </td>
                <td style={{ color: 'var(--ink-secondary)' }}>{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function Documentation() {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Platform Documentation &amp; Glossary</h1>
          <p className="page-desc">
            Reference guide for ULRE architecture, adapter capability matrix, cgroup v2 resource controls,
            drift detection, security model, audit fields, OOM remediation mechanics, known limitations, and log rotation.
          </p>
        </div>
      </div>

      <DocTable title="Core Architecture & Safety Principles" rows={ARCHITECTURE_PRINCIPLES} keyHeader="Principle" valHeader="How ULRE Enforces It" />

      <div className="panel">
        <div className="panel-header">
          <span>Adapter Capability Matrix (Bare-Metal, systemd D-Bus, Docker Engine API)</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Policy Field</th>
                <th>bare_metal</th>
                <th>systemd (D-Bus)</th>
                <th>docker (Engine API)</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {ADAPTER_CAPABILITY_MATRIX.map(([field, bm, sd, dk, notes]) => (
                <tr key={field}>
                  <td className="mono" style={{ fontSize: 12, fontWeight: 600 }}>{field}</td>
                  <td><span className={`badge ${bm === 'supported' ? 'badge-ok' : bm === 'partial' ? 'badge-warn' : 'badge-danger'}`}>{bm}</span></td>
                  <td><span className={`badge ${sd === 'supported' ? 'badge-ok' : sd === 'partial' ? 'badge-warn' : 'badge-danger'}`}>{sd}</span></td>
                  <td><span className={`badge ${dk === 'supported' ? 'badge-ok' : dk === 'partial' ? 'badge-warn' : 'badge-danger'}`}>{dk}</span></td>
                  <td style={{ color: 'var(--ink-secondary)' }}>{notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <DocTable title="Linux cgroup v2 Resource Controls" rows={CGROUP_CONTROLS} keyHeader="Control File" valHeader="Behavior & Recommended Usage" />
      <DocTable title="Audit Trail & OOM Center — Field Definitions" rows={COLUMN_DOCS} keyHeader="Field" valHeader="Definition" />
      <DocTable title="Enforcement Actions & OOM Kill Glossary" rows={OOM_AND_ACTION_DOCS} keyHeader="Action / Kernel Event" valHeader="Behavior & Kernel Meaning" />
      <DocTable title="Security & Authentication" rows={SECURITY_DOCS} keyHeader="Mechanism" valHeader="How It Works" />
      <DocTable title="Known Limitations" rows={KNOWN_LIMITATIONS} keyHeader="Area" valHeader="Detail" />
      <DocTable title="Production Application Logging (log.conf)" rows={LOGGING_DOCS} keyHeader="Setting / Behavior" valHeader="Details" />
    </div>
  );
}
