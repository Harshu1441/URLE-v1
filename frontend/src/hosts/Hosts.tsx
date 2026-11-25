import { formatBytes } from '../api/client';
import type { Host, Role } from '../types';

interface Props {
  hosts: Host[];
  role: Role;
  onInspectWorkloads: (hostId: string) => void;
  onDeleteHost: (hostId: string) => void;
}

export function Hosts({ hosts, role, onInspectWorkloads, onDeleteHost }: Props) {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Host Management</h1>
          <p className="page-desc">
            Registered bare-metal servers, VMs, cloud Linux instances, and Docker hosts reporting cgroup v2 & kernel capabilities.
          </p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Registered Linux Hosts ({hosts.length})</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Hostname & OS</th>
                <th>Kernel Version</th>
                <th>Capacity</th>
                <th>cgroup v2 & Controllers</th>
                <th>Kernel Capabilities</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {hosts.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ color: 'var(--ink-muted)' }}>
                    No hosts registered. Run <span className="mono">ulre-agent enforce --control-plane &lt;url&gt;</span> on a Linux host.
                  </td>
                </tr>
              ) : (
                hosts.map((h) => (
                  <tr key={h.id}>
                    <td>
                      <strong>{h.hostname}</strong>
                      <div style={{ fontSize: 12, color: 'var(--ink-secondary)' }}>{h.os_name}</div>
                      {h.environment?.provider && (
                        <div className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>
                          {h.environment.provider}
                          {h.environment.region ? ` · ${h.environment.region}` : ''}
                          {h.environment.product ? ` · ${h.environment.product}` : ''}
                          {h.environment.instance_id ? ` (${h.environment.instance_id})` : ''}
                        </div>
                      )}
                      <div className="mono" style={{ fontSize: 11, color: 'var(--ink-muted)' }}>
                        id={h.id}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {h.kernel_version}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {h.cpu_cores} vCPU · {formatBytes(h.memory_bytes)}
                    </td>
                    <td>
                      <span className={`badge ${h.cgroup_v2 ? 'badge-ok' : 'badge-warn'}`}>
                        {h.cgroup_v2 ? 'cgroup v2 unified' : 'cgroup v1 (read-only)'}
                      </span>
                      <div className="mono" style={{ fontSize: 11.5, color: 'var(--ink-secondary)', marginTop: 4 }}>
                        {(h.controllers || []).join(', ') || 'none'}
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        <span className={`badge ${h.psi_supported ? 'badge-ok' : 'badge-neutral'}`}>
                          PSI: {h.psi_supported ? 'yes' : 'no'}
                        </span>
                        <span className={`badge ${h.swap_accounting ? 'badge-ok' : 'badge-neutral'}`}>
                          Swap: {h.swap_accounting ? 'yes' : 'no'}
                        </span>
                        <span className={`badge ${h.btf_supported ? 'badge-info' : 'badge-neutral'}`}>
                          BTF: {h.btf_supported ? 'yes' : 'no'}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          h.status === 'online' ? 'badge-ok' : h.status === 'degraded' ? 'badge-warn' : 'badge-danger'
                        }`}
                      >
                        {h.status}
                      </span>
                      <div style={{ fontSize: 11, color: 'var(--ink-muted)', marginTop: 3 }}>
                        {new Date(h.last_seen_at).toLocaleTimeString()}
                      </div>
                    </td>
                    <td>
                      <div className="toolbar">
                        <button className="btn btn-sm" onClick={() => onInspectWorkloads(h.id)}>
                          Workloads
                        </button>
                        {role === 'admin' && (
                          <button className="btn btn-sm btn-danger" onClick={() => onDeleteHost(h.id)}>
                            Remove
                          </button>
                        )}
                      </div>
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
