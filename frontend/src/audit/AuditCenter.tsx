import { useMemo, useState } from 'react';
import type { AuditRecord } from '../types';

interface Props {
  logs: AuditRecord[];
  onOpenDocs?: () => void;
}

export function AuditCenter({ logs, onOpenDocs }: Props) {
  const [filter, setFilter] = useState('');

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return logs;
    return logs.filter((r) =>
      `${r.actor} ${r.action} ${r.policy_name || ''} ${r.target} ${r.result}`.toLowerCase().includes(q),
    );
  }, [logs, filter]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Audit Center</h1>
          <p className="page-desc">
            Immutable operational log of policy mutations, cgroup v2 writes, OOM remediations, safety blocks, and eBPF approvals.
          </p>
        </div>
        <div className="toolbar">
          {onOpenDocs && (
            <button className="btn" onClick={onOpenDocs}>
              Field & OOM Definitions
            </button>
          )}
          <div style={{ width: 260 }}>
            <input placeholder="Filter by actor, action, target..." value={filter} onChange={(e) => setFilter(e.target.value)} />
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Audit Trail ({filtered.length})</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor (Role)</th>
                <th>Action</th>
                <th>Policy</th>
                <th>Target cgroup / PID</th>
                <th>Outcome</th>
                <th>Metadata</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ color: 'var(--ink-muted)' }}>
                    No matching audit records.
                  </td>
                </tr>
              ) : (
                filtered.map((a) => (
                  <tr key={a.id}>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td>
                      {a.actor}{' '}
                      <span className="badge badge-neutral" style={{ marginLeft: 4 }}>
                        {a.actor_role}
                      </span>
                    </td>
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
                    <td className="mono" style={{ fontSize: 11.5, color: 'var(--ink-secondary)' }}>
                      {a.details ? Object.entries(a.details).map(([k, v]) => `${k}=${v}`).join(' · ') : '—'}
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
