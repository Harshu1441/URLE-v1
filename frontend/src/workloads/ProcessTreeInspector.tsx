import { useMemo } from 'react';
import { formatBytes } from '../api/client';
import type { Workload } from '../types';

interface Props {
  allWorkloads: Workload[];
  target: Workload | null;
  hostname?: string;
  onSelectProcess?: (w: Workload) => void;
  onAssignPolicy?: (w: Workload) => void;
}

interface DescendantNode {
  proc: Workload;
  children: DescendantNode[];
}

/**
 * Computes the exact process lineage on a single host using (host_id, pid, ppid):
 * 1) Full ancestor chain walking PPID -> PID up to PID 1 / root.
 * 2) Full recursive descendant subtree rooted at the target process.
 * 3) Same-container / same-pod / same-cgroup sibling processes sharing any cap.
 */
export function ProcessTreeInspector({ allWorkloads, target, hostname, onSelectProcess, onAssignPolicy }: Props) {
  const analysis = useMemo(() => {
    if (!target) return null;

    const hostProcs = allWorkloads.filter((w) => w.host_id === target.host_id);
    const byPid = new Map<number, Workload>();
    const childrenMap = new Map<number, Workload[]>();

    for (const p of hostProcs) {
      byPid.set(p.pid, p);
      if (p.ppid !== p.pid) {
        const list = childrenMap.get(p.ppid) || [];
        list.push(p);
        childrenMap.set(p.ppid, list);
      }
    }
    for (const list of childrenMap.values()) {
      list.sort((a, b) => a.pid - b.pid);
    }

    // Walk PPID chain up to root with cycle guard.
    const ancestors: Workload[] = [];
    const seenUp = new Set<number>([target.pid]);
    let curPPID = target.ppid;
    while (curPPID > 0 && !seenUp.has(curPPID)) {
      const parent = byPid.get(curPPID);
      if (!parent) break;
      ancestors.unshift(parent);
      seenUp.add(parent.pid);
      curPPID = parent.ppid;
    }

    // Build exact recursive descendant tree from target.
    const seenDown = new Set<number>();
    const buildDesc = (proc: Workload): DescendantNode => {
      seenDown.add(proc.pid);
      const kids = (childrenMap.get(proc.pid) || [])
        .filter((k) => !seenDown.has(k.pid))
        .map((k) => buildDesc(k));
      return { proc, children: kids };
    };
    const subtree = buildDesc(target);

    // Processes sharing the same container or cgroup path.
    const coLocated = hostProcs.filter((p) => {
      if (p.pid === target.pid) return false;
      if (target.container_id && p.container_id === target.container_id) return true;
      if (target.cgroup_path && target.cgroup_path !== '/' && p.cgroup_path === target.cgroup_path) return true;
      return false;
    });

    return { ancestors, subtree, coLocated };
  }, [allWorkloads, target]);

  if (!target || !analysis) {
    return (
      <div className="panel">
        <div className="panel-header">
          <span>Process Tree & Lineage Inspector (100% Host-Exact)</span>
        </div>
        <div className="panel-body" style={{ color: 'var(--ink-muted)' }}>
          Select any process, container, or pod above (or enter a search query) to inspect its exact PPID ancestor chain to PID 1, all child processes, and co-located cgroup siblings.
        </div>
      </div>
    );
  }

  const renderNodeRow = (proc: Workload, depth: number, kind: 'ancestor' | 'target' | 'child') => {
    const isTarget = kind === 'target';
    return (
      <div
        key={`${kind}-${proc.pid}-${proc.start_time_ticks}`}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
          padding: '7px 12px',
          paddingLeft: 14 + depth * 22,
          borderBottom: '1px solid var(--border-hairline)',
          background: isTarget ? 'var(--accent-soft)' : undefined,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flexWrap: 'wrap' }}>
          <span className="mono" style={{ fontSize: 12, color: isTarget ? 'var(--accent)' : 'var(--ink-muted)' }}>
            {depth > 0 ? '└─ ' : ''}PID {proc.pid}
          </span>
          <span className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
            (PPID {proc.ppid})
          </span>
          <strong
            style={{ cursor: onSelectProcess && !isTarget ? 'pointer' : 'default', textDecoration: onSelectProcess && !isTarget ? 'underline' : 'none' }}
            onClick={() => !isTarget && onSelectProcess?.(proc)}
          >
            {proc.comm}
          </strong>
          {isTarget && <span className="badge badge-info">Selected</span>}
          <span className="badge badge-neutral">{proc.owner_runtime}</span>
          {proc.container_name && (
            <span className="badge badge-ok">
              container: {proc.container_name}
            </span>
          )}
          {proc.matched_policy && <span className="badge badge-info">cap: {proc.matched_policy}</span>}
          <span className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
            {proc.exe || proc.cmdline || proc.cgroup_path}
          </span>
        </div>
        <div className="toolbar">
          <span className="mono" style={{ fontSize: 12, color: 'var(--ink-secondary)' }}>
            uid={proc.uid} · {formatBytes(proc.rss_bytes)}
          </span>
          {onAssignPolicy && proc.pid > 1 && proc.owner_runtime !== 'kernel' && (
            <button className="btn btn-sm" onClick={() => onAssignPolicy(proc)}>
              Cap / Policy
            </button>
          )}
        </div>
      </div>
    );
  };

  const renderSubtree = (node: DescendantNode, depth: number, isRoot: boolean): React.ReactNode => (
    <div key={`sub-${node.proc.pid}`}>
      {renderNodeRow(node.proc, depth, isRoot ? 'target' : 'child')}
      {node.children.map((ch) => renderSubtree(ch, depth + 1, false))}
    </div>
  );

  return (
    <div className="panel">
      <div className="panel-header">
        <span>
          Process Tree & Lineage — <span className="mono">{target.comm}</span> (PID {target.pid}
          {hostname ? ` on ${hostname}` : ''})
        </span>
        <span className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
          start_ticks={target.start_time_ticks} · cgroup={target.cgroup_path || '/'}
        </span>
      </div>

      <div>
        {analysis.ancestors.map((anc, idx) => renderNodeRow(anc, idx, 'ancestor'))}
        {renderSubtree(analysis.subtree, analysis.ancestors.length, true)}
      </div>

      {analysis.coLocated.length > 0 && (
        <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderTop: '1px solid var(--border-hairline)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink-secondary)', marginBottom: 6 }}>
            Co-located Processes in Same Container / Pod / cgroup ({analysis.coLocated.length})
          </div>
          <div className="toolbar">
            {analysis.coLocated.map((sib) => (
              <button
                key={sib.pid}
                className="btn btn-sm"
                onClick={() => onSelectProcess?.(sib)}
              >
                <span className="mono">
                  {sib.pid} {sib.comm} ({formatBytes(sib.rss_bytes)})
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
