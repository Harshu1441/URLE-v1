import type { OOMEvent } from '../types';

interface Props {
  events: OOMEvent[];
}

export function OOMCenter({ events }: Props) {
  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">OOM Remediation Center</h1>
          <p className="page-desc">
            Real-time memory pressure incidents, cgroup memory.events triggers, throttling, isolation, and termination recovery outcomes.
          </p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Recorded OOM & Pressure Events ({events.length})</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Host</th>
                <th>Policy</th>
                <th>Target cgroup / PID</th>
                <th>Action</th>
                <th>Outcome</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ color: 'var(--ink-muted)' }}>
                    No OOM or memory pressure remediation events recorded yet.
                  </td>
                </tr>
              ) : (
                events.map((ev) => (
                  <tr key={ev.id}>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {new Date(ev.occurred_at).toLocaleString()}
                    </td>
                    <td>
                      <strong>{ev.hostname || ev.host_id}</strong>
                    </td>
                    <td>{ev.policy_name || '—'}</td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {ev.target}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {ev.action}
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          ev.result === 'applied' ? 'badge-ok' : ev.result === 'dry_run' ? 'badge-info' : 'badge-danger'
                        }`}
                      >
                        {ev.result}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 11.5, color: 'var(--ink-secondary)' }}>
                      {ev.details ? Object.entries(ev.details).map(([k, v]) => `${k}=${v}`).join(' · ') : '—'}
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
