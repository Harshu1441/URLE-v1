import { useMemo } from 'react';
import { formatBytes, formatLimitBytesHuman } from '../api/client';
import type { Host, Policy, Workload } from '../types';

interface Props {
  hosts: Host[];
  workloads: Workload[];
  policies: Policy[];
  selectedHostId: string;
  onSelectHost: (id: string) => void;
  onInspectTree: (w: Workload) => void;
  onCapContainer: (w: Workload) => void;
}

interface ContainerGroup {
  key: string;
  name: string;
  subtitle: string;
  runtimeId: string;
  hostId: string;
  processes: Workload[];
  totalRSS: number;
  policies: string[];
  representative: Workload;
}

export function ContainersPods({
  hosts,
  workloads,
  policies,
  selectedHostId,
  onSelectHost,
  onInspectTree,
  onCapContainer,
}: Props) {
  const hostNames = useMemo(() => {
    const m = new Map<string, string>();
    for (const h of hosts) m.set(h.id, h.hostname);
    return m;
  }, [hosts]);

  const policyMap = useMemo(() => {
    const m = new Map<string, Policy>();
    for (const p of policies) m.set(p.name, p);
    return m;
  }, [policies]);

  const groups = useMemo(() => {
    const map = new Map<string, ContainerGroup>();
    for (const w of workloads) {
      if (selectedHostId && w.host_id !== selectedHostId) continue;
      if (w.owner_runtime !== 'docker') continue;

      const idPart = w.container_id || w.cgroup_path;
      const key = `${w.host_id}:docker:${idPart}`;
      let grp = map.get(key);
      if (!grp) {
        grp = {
          key,
          name: w.container_name || (w.container_id ? w.container_id.slice(0, 12) : w.comm),
          subtitle: w.container_image || w.cgroup_path,
          runtimeId: w.container_id ? w.container_id.slice(0, 12) : '—',
          hostId: w.host_id,
          processes: [],
          totalRSS: 0,
          policies: [],
          representative: w,
        };
        map.set(key, grp);
      }
      grp.processes.push(w);
      grp.totalRSS += w.rss_bytes;
      if (w.matched_policy && !grp.policies.includes(w.matched_policy)) {
        grp.policies.push(w.matched_policy);
      }
    }
    return Array.from(map.values());
  }, [workloads, selectedHostId]);

  const renderCap = (polName?: string) => {
    if (!polName) return <span style={{ color: 'var(--ink-muted)', fontSize: 12 }}>unmanaged</span>;
    const pol = policyMap.get(polName);
    const summary = pol
      ? [
          pol.limits['memory.max'] && `mem=${formatLimitBytesHuman(pol.limits['memory.max'])}`,
          pol.limits['cpu.max'] && `cpu=${pol.limits['cpu.max']}`,
          pol.limits['pids.max'] && `pids=${pol.limits['pids.max']}`,
        ]
          .filter(Boolean)
          .join(' · ')
      : '';
    return (
      <div>
        <span className="badge badge-info">{polName}</span>
        {summary && (
          <div className="mono" style={{ fontSize: 11, color: 'var(--ink-secondary)', marginTop: 2 }}>
            {summary}
          </div>
        )}
      </div>
    );
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Docker Containers</h1>
          <p className="page-desc">
            Detected Docker containers across registered hosts, with live RSS totals and active resource caps.
          </p>
        </div>
        <div style={{ width: 200 }}>
          <select value={selectedHostId} onChange={(e) => onSelectHost(e.target.value)}>
            <option value="">All Hosts</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.hostname}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <span>Detected Docker Containers ({groups.length})</span>
        </div>
        {groups.length === 0 ? (
          <div className="panel-body" style={{ color: 'var(--ink-muted)' }}>
            No running Docker containers detected on the selected host(s).
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Container</th>
                  <th>Runtime & ID</th>
                  <th>Image / cgroup</th>
                  <th>Processes & RSS</th>
                  <th>Active Resource Cap</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.key}>
                    <td>
                      <strong>{g.name}</strong>
                      <div style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>{hostNames.get(g.hostId) || g.hostId}</div>
                    </td>
                    <td>
                      <span className="badge badge-ok">docker</span>
                      <div className="mono" style={{ fontSize: 11.5, color: 'var(--ink-secondary)', marginTop: 3 }}>
                        {g.runtimeId}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {g.subtitle}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {g.processes.length} proc(s) · {formatBytes(g.totalRSS)}
                    </td>
                    <td>{renderCap(g.policies[0])}</td>
                    <td>
                      <div className="toolbar">
                        <button className="btn btn-sm" onClick={() => onInspectTree(g.representative)}>
                          Process Tree
                        </button>
                        <button className="btn btn-sm btn-primary" onClick={() => onCapContainer(g.representative)}>
                          Cap Container
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
