import { useEffect, useMemo, useState } from 'react';
import { formatBytes, formatLimitBytesHuman } from '../api/client';
import type { Host, Policy, Workload } from '../types';
import { ProcessTreeInspector } from './ProcessTreeInspector';

interface Props {
  hosts: Host[];
  workloads: Workload[];
  policies: Policy[];
  selectedHostId: string;
  initialSelectedProc?: Workload | null;
  onSelectHost: (id: string) => void;
  onCreatePolicyForProcess: (w: Workload) => void;
}

export function Workloads({
  hosts,
  workloads,
  policies,
  selectedHostId,
  initialSelectedProc,
  onSelectHost,
  onCreatePolicyForProcess,
}: Props) {
  const [query, setQuery] = useState('');
  const [runtime, setRuntime] = useState('');
  const [includeKernel, setIncludeKernel] = useState(false);
  const [selectedProc, setSelectedProc] = useState<Workload | null>(initialSelectedProc ?? null);

  useEffect(() => {
    if (initialSelectedProc) setSelectedProc(initialSelectedProc);
  }, [initialSelectedProc]);

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

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return workloads.filter((w) => {
      if (selectedHostId && w.host_id !== selectedHostId) return false;
      if (!includeKernel && w.owner_runtime === 'kernel') return false;
      if (runtime && w.owner_runtime !== runtime) return false;
      if (!q) return true;
      return `${w.pid} ${w.comm} ${w.exe} ${w.cmdline} ${w.cgroup_path} ${w.systemd_unit || ''} ${w.container_id || ''} ${w.container_name || ''} ${w.container_image || ''}`
        .toLowerCase()
        .includes(q);
    });
  }, [workloads, selectedHostId, includeKernel, runtime, query]);

  const activeTreeTarget = useMemo(() => {
    if (selectedProc) {
      const latest = workloads.find((w) => w.host_id === selectedProc.host_id && w.pid === selectedProc.pid);
      if (latest) return latest;
    }
    if (query.trim() !== '' && filtered.length > 0) {
      return filtered[0];
    }
    return null;
  }, [selectedProc, workloads, query, filtered]);

  const renderPolicyCap = (polName?: string) => {
    if (!polName) return <span style={{ color: 'var(--ink-muted)', fontSize: 12 }}>unmanaged</span>;
    const pol = policyMap.get(polName);
    const summary = pol
      ? [
          pol.limits['memory.max'] && `mem=${formatLimitBytesHuman(pol.limits['memory.max'])}`,
          pol.limits['cpu.max'] && `cpu=${pol.limits['cpu.max']}`,
          pol.limits['pids.max'] && `pids=${pol.limits['pids.max']}`,
        ]
          .filter(Boolean)
          .join(' ')
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
          <h1 className="page-title">Workload Explorer</h1>
          <p className="page-desc">
            Search live processes across hosts, inspect exact parent-child process trees to PID 1, and assign resource policies.
          </p>
        </div>
      </div>

      <div className="panel">
        <div className="panel-body toolbar">
          <div style={{ flex: '1 1 260px' }}>
            <input
              placeholder="Search process, exe, container name/ID, image, systemd unit, or cgroup..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <div style={{ width: 180 }}>
            <select value={selectedHostId} onChange={(e) => onSelectHost(e.target.value)}>
              <option value="">All Hosts</option>
              {hosts.map((h) => (
                <option key={h.id} value={h.id}>
                  {h.hostname}
                </option>
              ))}
            </select>
          </div>
          <div style={{ width: 160 }}>
            <select value={runtime} onChange={(e) => setRuntime(e.target.value)}>
              <option value="">All Runtimes</option>
              <option value="docker">docker</option>
              <option value="systemd">systemd</option>
              <option value="bare_metal">bare_metal</option>
              <option value="kubernetes">kubernetes (unsupported)</option>
              <option value="kernel">kernel</option>
            </select>
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, cursor: 'pointer' }}>
            <input
              type="checkbox"
              style={{ width: 'auto' }}
              checked={includeKernel}
              onChange={(e) => setIncludeKernel(e.target.checked)}
            />
            Show kernel threads
          </label>
        </div>
      </div>

      <ProcessTreeInspector
        allWorkloads={workloads}
        target={activeTreeTarget}
        hostname={activeTreeTarget ? hostNames.get(activeTreeTarget.host_id) : undefined}
        onSelectProcess={(w) => setSelectedProc(w)}
        onAssignPolicy={onCreatePolicyForProcess}
      />

      <div className="panel">
        <div className="panel-header">
          <span>Discovered Processes ({filtered.length})</span>
          <span style={{ fontSize: 12, color: 'var(--ink-muted)', fontWeight: 400 }}>
            Click any row to inspect its exact host process tree above
          </span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>PID / PPID</th>
                <th>Process & Exe</th>
                <th>UID:GID</th>
                <th>Runtime / Container / Pod</th>
                <th>cgroup v2 Path</th>
                <th>RSS</th>
                <th>Active Cap</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ color: 'var(--ink-muted)' }}>
                    No processes match current filters.
                  </td>
                </tr>
              ) : (
                filtered.slice(0, 250).map((w) => {
                  const isSel = activeTreeTarget?.host_id === w.host_id && activeTreeTarget?.pid === w.pid;
                  return (
                    <tr
                      key={`${w.host_id}-${w.pid}-${w.start_time_ticks}`}
                      style={{ background: isSel ? 'var(--accent-soft)' : undefined, cursor: 'pointer' }}
                      onClick={() => setSelectedProc(w)}
                    >
                      <td className="mono" style={{ fontSize: 12 }}>
                        {w.pid} / {w.ppid}
                      </td>
                      <td>
                        <strong>{w.comm}</strong>
                        <div className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
                          {w.exe || w.cmdline || '—'}
                        </div>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {w.uid}:{w.gid}
                      </td>
                      <td>
                        <span className="badge badge-neutral">{w.owner_runtime}</span>
                        {w.container_name && (
                          <div className="mono" style={{ fontSize: 11.5, marginTop: 3 }}>
                            {w.container_name} ({w.container_image || w.container_id?.slice(0, 12)})
                          </div>
                        )}
                        {!w.container_name && (w.systemd_unit || w.container_id) && (
                          <div className="mono" style={{ fontSize: 11.5, marginTop: 3 }}>
                            {w.systemd_unit || w.container_id?.slice(0, 12)}
                          </div>
                        )}
                      </td>
                      <td className="mono" style={{ fontSize: 11.5, maxWidth: 240, wordBreak: 'break-all' }}>
                        {w.cgroup_path || '/'}
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {formatBytes(w.rss_bytes)}
                      </td>
                      <td>{renderPolicyCap(w.matched_policy)}</td>
                      <td onClick={(e) => e.stopPropagation()}>
                        <button
                          className="btn btn-sm"
                          disabled={w.pid <= 1 || w.owner_runtime === 'kernel' || w.owner_runtime === 'kubernetes'}
                          onClick={() => onCreatePolicyForProcess(w)}
                        >
                          Assign Policy
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
