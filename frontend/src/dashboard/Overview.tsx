import type { AuditRecord, Host, OOMEvent, OverviewStats, Policy } from '../types';

interface Props {
  overview: OverviewStats | null;
  hosts: Host[];
  policies: Policy[];
  oomEvents: OOMEvent[];
  auditLogs: AuditRecord[];
  onNavigate: (section: 'hosts' | 'workloads' | 'policies' | 'oom-center' | 'audit') => void;
}

export function Overview({ overview, hosts, policies, oomEvents, auditLogs, onNavigate }: Props) {
  const stats = overview ?? {
    total_hosts: 0,
    active_agents: 0,
    total_workloads: 0,
    enforced_workloads: 0,
    memory_pressure_events: 0,
    oom_events: 0,
    enforcement_actions: 0,
    policy_violations: 0,
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Fleet Enforcement Overview</h1>
          <p className="page-desc">
            Live Linux cgroup v2 policy enforcement, workload isolation, and OOM remediation across registered hosts.
          </p>
        </div>
        <div className="toolbar">
          <button className="btn" onClick={() => onNavigate('workloads')}>
            Explore Workloads
          </button>
          <button className="btn btn-primary" onClick={() => onNavigate('policies')}>
            Configure Policy
          </button>
        </div>
      </div>

      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label">Registered Hosts</div>
          <div className="kpi-value">{stats.total_hosts}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Active Agents</div>
          <div className="kpi-value" style={{ color: 'var(--ok)' }}>
            {stats.active_agents}
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Discovered Workloads</div>
          <div className="kpi-value">{stats.total_workloads}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Under Enforcement</div>
          <div className="kpi-value" style={{ color: 'var(--accent)' }}>
            {stats.enforced_workloads}
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Pressure Incidents</div>
          <div className="kpi-value" style={{ color: 'var(--warn)' }}>
            {stats.memory_pressure_events}
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">OOM Events</div>
          <div className="kpi-value" style={{ color: stats.oom_events > 0 ? 'var(--danger)' : undefined }}>
            {stats.oom_events}
          </div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Enforcement Actions</div>
          <div className="kpi-value">{stats.enforcement_actions}</div>
        </div>
        <div className="kpi-card">
          <div className="kpi-label">Safety Blocks / Violations</div>
          <div className="kpi-value">{stats.policy_violations}</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: 16 }}>
        <div className="panel">
          <div className="panel-header">
            <span>Connected Enforcement Agents ({hosts.length})</span>
            <button className="btn btn-sm" onClick={() => onNavigate('hosts')}>
              All Hosts
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Kernel</th>
                  <th>cgroup v2</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {hosts.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ color: 'var(--ink-muted)' }}>
                      No Linux agents registered yet. Start ulre-agent with --control-plane to connect a host.
                    </td>
                  </tr>
                ) : (
                  hosts.map((h) => (
                    <tr key={h.id}>
                      <td>
                        <strong>{h.hostname}</strong>
                        <div className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
                          {h.os_name}
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {h.kernel_version}
                      </td>
                      <td>
                        <span className={`badge ${h.cgroup_v2 ? 'badge-ok' : 'badge-warn'}`}>
                          {h.cgroup_v2 ? 'Unified v2' : 'v1 / Disabled'}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`badge ${
                            h.status === 'online' ? 'badge-ok' : h.status === 'degraded' ? 'badge-warn' : 'badge-danger'
                          }`}
                        >
                          {h.status}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <span>Active Policies ({policies.length})</span>
            <button className="btn btn-sm" onClick={() => onNavigate('policies')}>
              Manage
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Policy</th>
                  <th>Selector</th>
                  <th>Limits</th>
                  <th>Mode</th>
                </tr>
              </thead>
              <tbody>
                {policies.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={{ color: 'var(--ink-muted)' }}>
                      No policies configured. Create a cgroup v2 policy to begin active workload enforcement.
                    </td>
                  </tr>
                ) : (
                  policies.slice(0, 8).map((p) => (
                    <tr key={p.id || p.name}>
                      <td>
                        <strong>{p.name}</strong>
                        <div style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>Priority {p.priority}</div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {p.selectors.process_name || p.selectors.systemd_unit || p.selectors.exe_path || '*'}
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {[p.limits['memory.max'] && `mem=${p.limits['memory.max']}`, p.limits['cpu.max'] && `cpu=${p.limits['cpu.max']}`]
                          .filter(Boolean)
                          .join(' ') || 'OOM-only'}
                      </td>
                      <td>
                        <span className={`badge ${p.mode === 'enforce' ? 'badge-info' : 'badge-neutral'}`}>{p.mode}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Recent Enforcement & OOM Activity</span>
          <button className="btn btn-sm" onClick={() => onNavigate('audit')}>
            Full Audit Log
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Policy</th>
                <th>Target</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.length === 0 && oomEvents.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ color: 'var(--ink-muted)' }}>
                    No live events recorded yet.
                  </td>
                </tr>
              ) : (
                auditLogs.slice(0, 10).map((a) => (
                  <tr key={a.id}>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {new Date(a.created_at).toLocaleTimeString()}
                    </td>
                    <td>{a.actor}</td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {a.action}
                    </td>
                    <td>{a.policy_name || '—'}</td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {a.target}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          a.result === 'applied' ? 'badge-ok' : a.result === 'dry_run' ? 'badge-info' : 'badge-danger'
                        }`}
                      >
                        {a.result}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
