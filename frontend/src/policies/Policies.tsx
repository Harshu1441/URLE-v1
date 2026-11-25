import { useEffect, useMemo, useState } from 'react';
import { Info } from 'lucide-react';
import { formatBytes, formatLimitBytesHuman, parseMemoryToBytes } from '../api/client';
import type { Host, Policy, Role, Workload } from '../types';
import { ProcessTreeInspector } from '../workloads/ProcessTreeInspector';

interface Props {
  policies: Policy[];
  workloads: Workload[];
  hosts: Host[];
  role: Role;
  prefillWorkload: Workload | null;
  onClearPrefill: () => void;
  onCreatePolicy: (p: Policy) => Promise<void>;
  onUpdatePolicy: (id: string, p: Policy) => Promise<void>;
  onValidatePolicy: (p: Policy) => Promise<{ valid: boolean; errors?: string[]; warnings?: string[] }>;
  onApprovePolicy: (id: string) => Promise<void>;
  onDeletePolicy: (id: string) => Promise<void>;
  onExportBackup: () => Promise<{ format: string; exported_at: string; exported_by: string; policies: Policy[] }>;
  onRestoreBackup: (policies: Policy[]) => Promise<{ restored: number }>;
}

interface LocalSnapshot {
  id: string;
  label: string;
  savedAt: string;
  policies: Policy[];
}

const SNAPSHOT_STORAGE_KEY = 'ulre_policy_snapshots_v1';

const ALL_OOM_ACTIONS = [
  'alert',
  'throttle',
  'reduce_limits',
  'restart_service',
  'isolate',
  'terminate',
  'escalate',
  'kernel_oom_fallback',
];

function globToRegex(glob: string): RegExp | null {
  try {
    const esc = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp(`^${esc}$`);
  } catch {
    return null;
  }
}

function loadSnapshots(): LocalSnapshot[] {
  try {
    const raw = localStorage.getItem(SNAPSHOT_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as LocalSnapshot[]) : [];
  } catch {
    return [];
  }
}

function computeOptimalMemoryMB(rssBytes: number, hostMemBytes: number, crit: string) {
  const rssMB = Math.max(8, Math.ceil(rssBytes / (1024 * 1024)));
  const hostMB = hostMemBytes > 0 ? Math.floor(hostMemBytes / (1024 * 1024)) : 4096;
  const rawTarget = Math.max(128, Math.ceil((rssMB * 2.5) / 64) * 64);
  const maxMB = Math.min(rawTarget, Math.max(128, Math.floor(hostMB * 0.7)));
  const highMB = Math.max(64, Math.round(maxMB * 0.75));
  const lowMB = Math.max(16, Math.round(maxMB * 0.25));
  const minMB = crit === 'critical' || crit === 'high' ? Math.max(16, Math.round(maxMB * 0.125)) : 0;
  return { rssMB, hostMB, maxMB, highMB, lowMB, minMB };
}

function bytesToEditableUnit(raw?: string, unit: 'MB' | 'GB' = 'MB'): string {
  if (!raw) return '';
  if (raw === 'max' || raw === '0') return raw;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return raw;
  const div = unit === 'GB' ? 1024 * 1024 * 1024 : 1024 * 1024;
  return String(Number((n / div).toFixed(2)));
}

export function Policies({
  policies,
  workloads,
  hosts,
  role,
  prefillWorkload,
  onClearPrefill,
  onCreatePolicy,
  onUpdatePolicy,
  onValidatePolicy,
  onApprovePolicy,
  onDeletePolicy,
  onExportBackup,
  onRestoreBackup,
}: Props) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingVersion, setEditingVersion] = useState<number>(1);
  const [name, setName] = useState('');
  const [group, setGroup] = useState('');
  const [priority, setPriority] = useState(100);
  const [mode, setMode] = useState<'enforce' | 'dry_run' | 'disabled'>('enforce');
  const [criticality, setCriticality] = useState<'critical' | 'high' | 'normal' | 'best_effort'>('normal');
  const [allowDestructive, setAllowDestructive] = useState(false);
  const [allowRuntimeOverride, setAllowRuntimeOverride] = useState(false);

  const [targetSearch, setTargetSearch] = useState('');
  const [selectedTargetKey, setSelectedTargetKey] = useState('');
  const [treeTarget, setTreeTarget] = useState<Workload | null>(null);

  const [processName, setProcessName] = useState('');
  const [exePath, setExePath] = useState('');
  const [systemdUnit, setSystemdUnit] = useState('');
  const [containerId, setContainerId] = useState('');
  const [uid, setUid] = useState('');

  const [memUnit, setMemUnit] = useState<'MB' | 'GB'>('MB');
  const [memMax, setMemMax] = useState('256');
  const [memHigh, setMemHigh] = useState('192');
  const [memLow, setMemLow] = useState('64');
  const [memMin, setMemMin] = useState('');
  const [memSwapMax, setMemSwapMax] = useState('0');
  const [optimalHint, setOptimalHint] = useState(
    'Optimal baseline defaults: memory.max=256 MB, memory.high=192 MB (75% soft throttle), memory.low=64 MB (25% protection), swap=0 MB.',
  );

  const [oomGroup, setOomGroup] = useState(true);
  const [cpuMax, setCpuMax] = useState('50000 100000');
  const [cpuWeight, setCpuWeight] = useState('100');
  const [ioMax, setIoMax] = useState('');
  const [pidsMax, setPidsMax] = useState('64');

  const [memPct, setMemPct] = useState('85');
  const [psiSome, setPsiSome] = useState('15');
  const [cooldownSec, setCooldownSec] = useState('30');
  const [maxRetries, setMaxRetries] = useState('3');
  const [actions, setActions] = useState<string[]>(['alert', 'throttle']);

  const [validationMsg, setValidationMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [snapshots, setSnapshots] = useState<LocalSnapshot[]>(() => loadSnapshots());
  const [snapshotLabel, setSnapshotLabel] = useState('');

  const hostMap = useMemo(() => {
    const m = new Map<string, Host>();
    for (const h of hosts) m.set(h.id, h);
    return m;
  }, [hosts]);

  const targetOptions = useMemo(() => {
    const q = targetSearch.trim().toLowerCase();
    const seen = new Set<string>();
    const opts: { key: string; label: string; workload: Workload }[] = [];
    for (const w of workloads) {
      if (w.pid <= 1 || w.owner_runtime === 'kernel' || w.owner_runtime === 'kubernetes') continue;
      const key = `${w.owner_runtime}|${w.comm}|${w.container_id || ''}|${w.systemd_unit || ''}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const tag = w.container_name
        ? `[${w.owner_runtime}] ${w.container_name} (${w.comm} · ${w.container_image || w.container_id?.slice(0, 12)})`
        : w.systemd_unit
        ? `[systemd] ${w.systemd_unit} (${w.comm})`
        : `[${w.owner_runtime}] ${w.comm} (${w.exe || `pid ${w.pid}`})`;

      if (q && !tag.toLowerCase().includes(q) && !`${w.pid} ${w.cgroup_path}`.toLowerCase().includes(q)) {
        continue;
      }
      opts.push({ key, label: tag, workload: w });
    }
    return opts.sort((a, b) => a.label.localeCompare(b.label));
  }, [workloads, targetSearch]);

  const applyOptimalForWorkload = (w: Workload | null, crit = criticality) => {
    const hostMem = w ? hostMap.get(w.host_id)?.memory_bytes || 0 : hosts[0]?.memory_bytes || 0;
    const rss = w?.rss_bytes || 32 * 1024 * 1024;
    const opt = computeOptimalMemoryMB(rss, hostMem, crit);
    setMemUnit('MB');
    setMemMax(String(opt.maxMB));
    setMemHigh(String(opt.highMB));
    setMemLow(String(opt.lowMB));
    setMemMin(opt.minMB > 0 ? String(opt.minMB) : '');
    setMemSwapMax('0');
    setOptimalHint(
      w
        ? `Target RSS: ${(w.rss_bytes / (1024 * 1024)).toFixed(1)} MB · Host RAM: ${opt.hostMB} MB -> Optimal: max=${opt.maxMB} MB, high=${opt.highMB} MB (75%), low=${opt.lowMB} MB (25%), swap=0 MB`
        : `Optimal baseline defaults: memory.max=${opt.maxMB} MB, memory.high=${opt.highMB} MB (75% soft throttle), memory.low=${opt.lowMB} MB (25% protection), swap=0 MB.`,
    );
  };

  const applyWorkloadSelection = (w: Workload) => {
    setEditingId(null);
    const baseName = w.container_name || w.comm;
    setName(`${baseName}-cap`);
    setGroup(baseName);
    setProcessName(w.comm);
    setExePath(w.exe || '');
    setSystemdUnit(w.owner_runtime === 'systemd' ? w.systemd_unit || '' : '');
    setContainerId(w.container_id ? w.container_id.slice(0, 12) : '');
    setAllowRuntimeOverride(w.owner_runtime === 'docker');
    setTreeTarget(w);
    applyOptimalForWorkload(w, criticality);
    if (w.owner_runtime === 'docker') {
      // Docker ContainerUpdate does not support memory.high, memory.min, or memory.oom.group.
      setMemHigh('');
      setMemMin('');
      setOomGroup(false);
    }
  };

  const startEditingPolicy = (p: Policy) => {
    setErrorMsg(null);
    setValidationMsg(null);
    setEditingId(p.id || null);
    setEditingVersion(p.version || 1);
    setName(p.name);
    setGroup(p.group || '');
    setPriority(p.priority);
    setMode(p.mode);
    setCriticality(p.criticality);
    setAllowDestructive(Boolean(p.allow_destructive));
    setAllowRuntimeOverride(Boolean(p.allow_runtime_override));
    setProcessName(p.selectors.process_name || '');
    setExePath(p.selectors.exe_path || '');
    setSystemdUnit(p.selectors.systemd_unit || '');
    setContainerId(p.selectors.container_id || '');
    setUid(p.selectors.uid !== undefined ? String(p.selectors.uid) : '');
    setMemUnit('MB');
    setMemMax(bytesToEditableUnit(p.limits['memory.max'], 'MB'));
    setMemHigh(bytesToEditableUnit(p.limits['memory.high'], 'MB'));
    setMemLow(bytesToEditableUnit(p.limits['memory.low'], 'MB'));
    setMemMin(bytesToEditableUnit(p.limits['memory.min'], 'MB'));
    setMemSwapMax(bytesToEditableUnit(p.limits['memory.swap.max'], 'MB'));
    setOomGroup(p.limits['memory.oom.group'] ?? true);
    setCpuMax(p.limits['cpu.max'] || '');
    setCpuWeight(p.limits['cpu.weight'] !== undefined ? String(p.limits['cpu.weight']) : '');
    setIoMax(p.limits['io.max'] || '');
    setPidsMax(p.limits['pids.max'] || '');
    setMemPct(p.oom?.conditions?.memory_percent !== undefined ? String(p.oom.conditions.memory_percent) : '');
    setPsiSome(p.oom?.conditions?.psi_some_avg10 !== undefined ? String(p.oom.conditions.psi_some_avg10) : '');
    setCooldownSec(p.oom?.cooldown_sec !== undefined ? String(p.oom.cooldown_sec) : '30');
    setMaxRetries(p.oom?.max_retries !== undefined ? String(p.oom.max_retries) : '3');
    setActions(p.oom?.actions?.length ? p.oom.actions : ['alert']);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const resetForm = () => {
    setEditingId(null);
    setName('');
    setGroup('');
    setSelectedTargetKey('');
  };

  useEffect(() => {
    if (!prefillWorkload) return;
    applyWorkloadSelection(prefillWorkload);
    onClearPrefill();
  }, [prefillWorkload, onClearPrefill]);

  const relatedPreview = useMemo(() => {
    const pName = processName.trim();
    const exePat = exePath.trim();
    const unit = systemdUnit.trim();
    const cid = containerId.trim();
    const uidNum = uid.trim() !== '' ? Number(uid) : null;
    const hasSelector = !!(pName || exePat || unit || cid || uidNum !== null);
    if (!hasSelector) return { direct: [] as Workload[], related: [] as Workload[] };

    const exeRe = exePat ? globToRegex(exePat) : null;
    const direct: Workload[] = [];
    const directKeys = new Set<string>();

    for (const w of workloads) {
      if (w.owner_runtime === 'kernel' || w.owner_runtime === 'kubernetes') continue;
      if (pName && w.comm !== pName) continue;
      if (exePat && (!exeRe || !exeRe.test(w.exe))) continue;
      if (unit && w.systemd_unit !== unit) continue;
      if (cid && !(w.container_id || '').startsWith(cid) && w.container_name !== cid) continue;
      if (uidNum !== null && w.uid !== uidNum) continue;
      direct.push(w);
      directKeys.add(`${w.host_id}:${w.pid}`);
    }

    const related: Workload[] = [];
    const relKeys = new Set<string>(directKeys);
    for (const d of direct) {
      for (const w of workloads) {
        if (w.host_id !== d.host_id || w.owner_runtime === 'kernel') continue;
        const k = `${w.host_id}:${w.pid}`;
        if (relKeys.has(k)) continue;
        const isParentOrChild = w.pid === d.ppid || w.ppid === d.pid;
        const sameGroup =
          (d.container_id && w.container_id === d.container_id) ||
          (d.systemd_unit && w.systemd_unit === d.systemd_unit) ||
          (d.cgroup_path && d.cgroup_path !== '/' && w.cgroup_path === d.cgroup_path);
        if (isParentOrChild || sameGroup) {
          relKeys.add(k);
          related.push(w);
        }
      }
    }
    return { direct, related };
  }, [workloads, processName, exePath, systemdUnit, containerId, uid]);

  const buildPolicy = (): Policy => ({
    name: name.trim(),
    group: group.trim() || undefined,
    priority: Number(priority),
    mode,
    criticality,
    allow_destructive: allowDestructive,
    allow_runtime_override: allowRuntimeOverride,
    selectors: {
      process_name: processName.trim() || undefined,
      exe_path: exePath.trim() || undefined,
      systemd_unit: systemdUnit.trim() || undefined,
      container_id: containerId.trim() || undefined,
      uid: uid.trim() !== '' ? Number(uid) : undefined,
    },
    limits: {
      'memory.max': parseMemoryToBytes(memMax, memUnit) || undefined,
      'memory.high': parseMemoryToBytes(memHigh, memUnit) || undefined,
      'memory.low': parseMemoryToBytes(memLow, memUnit) || undefined,
      'memory.min': parseMemoryToBytes(memMin, memUnit) || undefined,
      'memory.swap.max': parseMemoryToBytes(memSwapMax, memUnit) || undefined,
      'memory.oom.group': oomGroup,
      'cpu.max': cpuMax.trim() || undefined,
      'cpu.weight': cpuWeight.trim() !== '' ? Number(cpuWeight) : undefined,
      'io.max': ioMax.trim() || undefined,
      'pids.max': pidsMax.trim() || undefined,
    },
    oom: {
      conditions: {
        memory_percent: memPct.trim() !== '' ? Number(memPct) : undefined,
        psi_some_avg10: psiSome.trim() !== '' ? Number(psiSome) : undefined,
      },
      actions,
      cooldown_sec: Number(cooldownSec) || 30,
      max_retries: Number(maxRetries) || 3,
      remediation_timeout_sec: 10,
    },
  });

  const toggleAction = (act: string) => {
    setActions((prev) => (prev.includes(act) ? prev.filter((a) => a !== act) : [...prev, act]));
  };

  const handleValidate = async () => {
    setErrorMsg(null);
    setValidationMsg(null);
    try {
      const res = await onValidatePolicy(buildPolicy());
      if (res.valid) {
        const warnText = res.warnings && res.warnings.length > 0 ? ` Warnings: ${res.warnings.join(' | ')}` : '';
        setValidationMsg('Policy syntax, safety invariants, and capability checks passed.' + warnText);
      } else {
        setErrorMsg((res.errors || ['Validation failed']).join(' | '));
      }
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : 'Validation failed');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErrorMsg(null);
    setValidationMsg(null);
    try {
      const pol = buildPolicy();
      if (editingId) {
        await onUpdatePolicy(editingId, pol);
        setValidationMsg(`Policy "${pol.name}" updated (v${editingVersion + 1}) and distributed to agents.`);
      } else {
        await onCreatePolicy(pol);
        setValidationMsg('Policy saved, signed, and queued for agent distribution.');
      }
      resetForm();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to save policy');
    } finally {
      setBusy(false);
    }
  };

  const handleDownloadBackup = async () => {
    setErrorMsg(null);
    try {
      const data = await onExportBackup();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ulre-policies-backup-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setValidationMsg(`Exported ${data.policies.length} policy/policies to JSON backup file.`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Export failed');
    }
  };

  const handleSaveSnapshot = () => {
    const snap: LocalSnapshot = {
      id: `${Date.now()}`,
      label: snapshotLabel.trim() || `Checkpoint (${policies.length} policies)`,
      savedAt: new Date().toISOString(),
      policies,
    };
    const next = [snap, ...snapshots].slice(0, 10);
    setSnapshots(next);
    localStorage.setItem(SNAPSHOT_STORAGE_KEY, JSON.stringify(next));
    setSnapshotLabel('');
    setValidationMsg(`Saved rollback checkpoint "${snap.label}".`);
  };

  const handleRestoreSnapshot = async (snap: LocalSnapshot) => {
    setErrorMsg(null);
    try {
      const res = await onRestoreBackup(snap.policies);
      setValidationMsg(`Restored ${res.restored} policy/policies from checkpoint "${snap.label}".`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Rollback failed');
    }
  };

  const handleRestoreFile = async (file: File | null) => {
    if (!file) return;
    setErrorMsg(null);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text) as { policies?: Policy[] } | Policy[];
      const list = Array.isArray(parsed) ? parsed : parsed.policies;
      if (!Array.isArray(list)) {
        throw new Error('Backup JSON must contain a "policies" array');
      }
      const res = await onRestoreBackup(list);
      setValidationMsg(`Restored ${res.restored} policy/policies from ${file.name}.`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Restore failed');
    }
  };

  const canWrite = role === 'operator' || role === 'admin';

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Policy Management</h1>
          <p className="page-desc">
            Create or update cgroup v2 & OOM policies, search live targets, inspect relatable processes, and manage backups.
          </p>
        </div>
      </div>

      {errorMsg && <div className="error-banner">{errorMsg}</div>}
      {validationMsg && <div className="info-banner">{validationMsg}</div>}

      {canWrite && (
        <form className="panel" onSubmit={handleSubmit}>
          <div className="panel-header">
            <span>{editingId ? `Edit Policy: ${name} (v${editingVersion} → v${editingVersion + 1})` : 'Create Enforcement Policy'}</span>
            <div className="toolbar">
              {editingId && (
                <button type="button" className="btn btn-sm" onClick={resetForm}>
                  Cancel Edit
                </button>
              )}
              <button type="button" className="btn btn-sm" onClick={() => applyOptimalForWorkload(treeTarget, criticality)}>
                Fill Optimal Values
              </button>
              {!editingId && (
                <button type="button" className="btn btn-sm" onClick={handleValidate}>
                  Check Conflicts
                </button>
              )}
              <button type="submit" className="btn btn-sm btn-primary" disabled={busy}>
                {busy ? 'Saving...' : editingId ? 'Update Policy' : 'Create & Distribute Policy'}
              </button>
            </div>
          </div>
          <div className="panel-body">
            <div
              style={{
                padding: 12,
                background: 'var(--bg-subtle)',
                border: '1px solid var(--border-hairline)',
                borderRadius: 6,
                marginBottom: 14,
              }}
            >
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink-secondary)', marginBottom: 8 }}>
                Search & Pick Live Workload Target (Process, Container, Pod, or systemd Unit)
              </div>
              <div className="form-grid">
                <div className="field">
                  <label>Search Live Targets</label>
                  <input
                    placeholder="Filter dropdown by process, container name, image, pod, or unit..."
                    value={targetSearch}
                    onChange={(e) => setTargetSearch(e.target.value)}
                  />
                </div>
                <div className="field">
                  <label>Select Discovered Workload ({targetOptions.length})</label>
                  <select
                    value={selectedTargetKey}
                    onChange={(e) => {
                      const k = e.target.value;
                      setSelectedTargetKey(k);
                      const found = targetOptions.find((o) => o.key === k);
                      if (found) applyWorkloadSelection(found.workload);
                    }}
                  >
                    <option value="">-- Choose a live process, container, or pod --</option>
                    {targetOptions.map((opt) => (
                      <option key={opt.key} value={opt.key}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            <div className="form-grid" style={{ marginBottom: 14 }}>
              <div className="field">
                <label>Policy Name *</label>
                <input required value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. redis-docker-cap" />
              </div>
              <div className="field">
                <label>Delegated cgroup Name</label>
                <input value={group} onChange={(e) => setGroup(e.target.value)} placeholder="defaults to policy name" />
              </div>
              <div className="field">
                <label>Priority</label>
                <input type="number" value={priority} onChange={(e) => setPriority(Number(e.target.value))} />
              </div>
              <div className="field">
                <label>Mode</label>
                <select value={mode} onChange={(e) => setMode(e.target.value as typeof mode)}>
                  <option value="enforce">enforce</option>
                  <option value="dry_run">dry_run</option>
                  <option value="disabled">disabled</option>
                </select>
              </div>
              <div className="field">
                <label>Criticality</label>
                <select value={criticality} onChange={(e) => setCriticality(e.target.value as typeof criticality)}>
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="normal">normal</option>
                  <option value="best_effort">best_effort</option>
                </select>
              </div>
            </div>

            <div className="form-grid" style={{ marginBottom: 14 }}>
              <div className="field">
                <label>Selector: Process Name (comm)</label>
                <input value={processName} onChange={(e) => setProcessName(e.target.value)} placeholder="e.g. redis-server" />
              </div>
              <div className="field">
                <label>Selector: Executable Path / Glob</label>
                <input value={exePath} onChange={(e) => setExePath(e.target.value)} placeholder="/usr/bin/*" />
              </div>
              <div className="field">
                <label>Selector: Container ID / Name</label>
                <input value={containerId} onChange={(e) => setContainerId(e.target.value)} placeholder="e.g. a83d6918824f or ulre-redis-test" />
              </div>
              <div className="field">
                <label>Selector: systemd Unit</label>
                <input value={systemdUnit} onChange={(e) => setSystemdUnit(e.target.value)} placeholder="worker.service" />
              </div>
              <div className="field">
                <label>Selector: UID</label>
                <input value={uid} onChange={(e) => setUid(e.target.value)} placeholder="optional numeric UID" />
              </div>
            </div>

            {(relatedPreview.direct.length > 0 || relatedPreview.related.length > 0) && (
              <div
                style={{
                  border: '1px solid var(--border-hairline)',
                  borderRadius: 6,
                  marginBottom: 14,
                  overflow: 'hidden',
                }}
              >
                <div className="panel-header">
                  <span>
                    Matched ({relatedPreview.direct.length}) & Relatable Sibling/Parent/Child Processes ({relatedPreview.related.length})
                  </span>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Relation</th>
                        <th>PID / PPID</th>
                        <th>Process & Container/Unit</th>
                        <th>Runtime</th>
                        <th>RSS</th>
                        <th>Inspect Tree</th>
                      </tr>
                    </thead>
                    <tbody>
                      {relatedPreview.direct.map((w) => (
                        <tr key={`d-${w.host_id}-${w.pid}`}>
                          <td>
                            <span className="badge badge-info">Direct Match</span>
                          </td>
                          <td className="mono" style={{ fontSize: 12 }}>
                            {w.pid} / {w.ppid}
                          </td>
                          <td>
                            <strong>{w.comm}</strong>{' '}
                            <span className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
                              {w.container_name || w.systemd_unit || w.exe}
                            </span>
                          </td>
                          <td>
                            <span className="badge badge-neutral">{w.owner_runtime}</span>
                            {w.owner_runtime === 'docker' && !allowRuntimeOverride && (
                              <span className="badge badge-warn" style={{ marginLeft: 4 }}>
                                needs override
                              </span>
                            )}
                          </td>
                          <td className="mono" style={{ fontSize: 12 }}>
                            {formatBytes(w.rss_bytes)}
                          </td>
                          <td>
                            <button type="button" className="btn btn-sm" onClick={() => setTreeTarget(w)}>
                              Check Process Tree
                            </button>
                          </td>
                        </tr>
                      ))}
                      {relatedPreview.related.slice(0, 12).map((w) => (
                        <tr key={`r-${w.host_id}-${w.pid}`}>
                          <td>
                            <span className="badge badge-neutral">Related (Lineage/Group)</span>
                          </td>
                          <td className="mono" style={{ fontSize: 12 }}>
                            {w.pid} / {w.ppid}
                          </td>
                          <td>
                            <strong>{w.comm}</strong>{' '}
                            <span className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
                              {w.container_name || w.systemd_unit || w.cgroup_path}
                            </span>
                          </td>
                          <td>
                            <span className="badge badge-neutral">{w.owner_runtime}</span>
                          </td>
                          <td className="mono" style={{ fontSize: 12 }}>
                            {formatBytes(w.rss_bytes)}
                          </td>
                          <td>
                            <button type="button" className="btn btn-sm" onClick={() => setTreeTarget(w)}>
                              Check Process Tree
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                marginBottom: 8,
                paddingBottom: 6,
                borderBottom: '1px solid var(--border-hairline)',
              }}
            >
              <div className="toolbar" style={{ gap: 8 }}>
                <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--ink-secondary)' }}>
                  Resource Limits
                </span>
                <span className="info-tip-wrap">
                  <button
                    type="button"
                    className="info-tip-btn"
                    aria-label="Optimal memory recommendation"
                    title={optimalHint}
                  >
                    <Info size={13} />
                  </button>
                  <span className="info-tip-popover" role="tooltip">
                    {optimalHint}
                  </span>
                </span>
              </div>
              <div className="toolbar" style={{ gap: 6 }}>
                <span style={{ fontSize: 12, color: 'var(--ink-muted)' }}>Unit:</span>
                <select
                  aria-label="Default memory unit"
                  style={{ width: 72, padding: '3px 6px' }}
                  value={memUnit}
                  onChange={(e) => setMemUnit(e.target.value as 'MB' | 'GB')}
                >
                  <option value="MB">MB</option>
                  <option value="GB">GB</option>
                </select>
              </div>
            </div>

            <div className="form-grid" style={{ marginBottom: 14 }}>
              <div className="field">
                <label>memory.max ({memUnit}, or 512M / 2G)</label>
                <input className="mono" value={memMax} onChange={(e) => setMemMax(e.target.value)} placeholder="e.g. 256 or 1.5 GB" />
              </div>
              <div className="field">
                <label>memory.high ({memUnit} soft limit)</label>
                <input className="mono" value={memHigh} onChange={(e) => setMemHigh(e.target.value)} placeholder="e.g. 192" />
              </div>
              <div className="field">
                <label>memory.low ({memUnit} best-effort protect)</label>
                <input className="mono" value={memLow} onChange={(e) => setMemLow(e.target.value)} placeholder="optional (e.g. 64)" />
              </div>
              <div className="field">
                <label>memory.min ({memUnit} hard protect)</label>
                <input className="mono" value={memMin} onChange={(e) => setMemMin(e.target.value)} placeholder="optional (e.g. 32)" />
              </div>
              <div className="field">
                <label>memory.swap.max ({memUnit}, 0 = no swap)</label>
                <input className="mono" value={memSwapMax} onChange={(e) => setMemSwapMax(e.target.value)} placeholder="0" />
              </div>
              <div className="field">
                <label>cpu.max (quota period)</label>
                <input className="mono" value={cpuMax} onChange={(e) => setCpuMax(e.target.value)} />
              </div>
              <div className="field">
                <label>cpu.weight (1..10000)</label>
                <input className="mono" value={cpuWeight} onChange={(e) => setCpuWeight(e.target.value)} />
              </div>
              <div className="field">
                <label>io.max</label>
                <input className="mono" value={ioMax} onChange={(e) => setIoMax(e.target.value)} placeholder="8:0 rbps=10485760" />
              </div>
              <div className="field">
                <label>pids.max</label>
                <input className="mono" value={pidsMax} onChange={(e) => setPidsMax(e.target.value)} />
              </div>
            </div>

            <div className="form-grid" style={{ marginBottom: 14 }}>
              <div className="field">
                <label>OOM Memory % Threshold</label>
                <input value={memPct} onChange={(e) => setMemPct(e.target.value)} />
              </div>
              <div className="field">
                <label>PSI some avg10 Threshold</label>
                <input value={psiSome} onChange={(e) => setPsiSome(e.target.value)} />
              </div>
              <div className="field">
                <label>Cooldown (sec)</label>
                <input value={cooldownSec} onChange={(e) => setCooldownSec(e.target.value)} />
              </div>
              <div className="field">
                <label>Max Retries</label>
                <input value={maxRetries} onChange={(e) => setMaxRetries(e.target.value)} />
              </div>
            </div>

            <div style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--ink-secondary)', marginBottom: 6 }}>
                OOM Remediation Actions
              </div>
              <div className="toolbar">
                {ALL_OOM_ACTIONS.map((act) => (
                  <label key={act} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12.5, cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      style={{ width: 'auto' }}
                      checked={actions.includes(act)}
                      onChange={() => toggleAction(act)}
                    />
                    <span className="mono">{act}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="toolbar">
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                <input type="checkbox" style={{ width: 'auto' }} checked={oomGroup} onChange={(e) => setOomGroup(e.target.checked)} />
                Enable memory.oom.group
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                <input
                  type="checkbox"
                  style={{ width: 'auto' }}
                  checked={allowDestructive}
                  onChange={(e) => setAllowDestructive(e.target.checked)}
                />
                Allow destructive termination (requires admin approval)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13 }}>
                <input
                  type="checkbox"
                  style={{ width: 'auto' }}
                  checked={allowRuntimeOverride}
                  onChange={(e) => setAllowRuntimeOverride(e.target.checked)}
                />
                Allow Docker runtime override
              </label>
            </div>
          </div>
        </form>
      )}

      {treeTarget && (
        <ProcessTreeInspector
          allWorkloads={workloads}
          target={treeTarget}
          hostname={hostMap.get(treeTarget.host_id)?.hostname}
          onSelectProcess={(w) => setTreeTarget(w)}
        />
      )}

      <div className="panel">
        <div className="panel-header">
          <span>Active & Staged Policies ({policies.length})</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Policy</th>
                <th>Selectors</th>
                <th>cgroup v2 Limits</th>
                <th>OOM Chain</th>
                <th>Mode & Safety</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ color: 'var(--ink-muted)' }}>
                    No policies defined yet.
                  </td>
                </tr>
              ) : (
                policies.map((p) => (
                  <tr key={p.id || p.name}>
                    <td>
                      <strong>{p.name}</strong>
                      <div style={{ fontSize: 12, color: 'var(--ink-muted)' }}>
                        v{p.version || 1} · priority {p.priority} · {p.criticality}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {[
                        p.selectors.process_name && `comm=${p.selectors.process_name}`,
                        p.selectors.exe_path && `exe=${p.selectors.exe_path}`,
                        p.selectors.container_id && `container=${p.selectors.container_id}`,
                        p.selectors.systemd_unit && `unit=${p.selectors.systemd_unit}`,
                        p.selectors.uid !== undefined && `uid=${p.selectors.uid}`,
                      ]
                        .filter(Boolean)
                        .join(', ')}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {[
                        p.limits['memory.max'] && `mem.max=${formatLimitBytesHuman(p.limits['memory.max'])}`,
                        p.limits['memory.high'] && `mem.high=${formatLimitBytesHuman(p.limits['memory.high'])}`,
                        p.limits['memory.low'] && `mem.low=${formatLimitBytesHuman(p.limits['memory.low'])}`,
                        p.limits['cpu.max'] && `cpu.max=${p.limits['cpu.max']}`,
                        p.limits['pids.max'] && `pids.max=${p.limits['pids.max']}`,
                      ]
                        .filter(Boolean)
                        .join(' | ')}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      {(p.oom?.actions || []).join(' → ') || 'none'}
                    </td>
                    <td>
                      <span className={`badge ${p.mode === 'enforce' ? 'badge-info' : 'badge-neutral'}`}>{p.mode}</span>
                      {p.approved_by && <div style={{ fontSize: 11, color: 'var(--ok)', marginTop: 3 }}>Approved by {p.approved_by}</div>}
                    </td>
                    <td>
                      <div className="toolbar">
                        {canWrite && p.id && (
                          <button className="btn btn-sm" onClick={() => startEditingPolicy(p)}>
                            Edit
                          </button>
                        )}
                        {role === 'admin' && p.id && !p.approved_by && (p.allow_destructive || p.allow_runtime_override) && (
                          <button className="btn btn-sm" onClick={() => onApprovePolicy(p.id!)}>
                            Approve
                          </button>
                        )}
                        {role === 'admin' && p.id && (
                          <button className="btn btn-sm btn-danger" onClick={() => onDeletePolicy(p.id!)}>
                            Delete
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

      <div className="panel">
        <div className="panel-header">
          <span>Configuration Backup, Export & Restore</span>
          <button type="button" className="btn btn-sm btn-primary" onClick={handleDownloadBackup}>
            Export JSON Backup ({policies.length})
          </button>
        </div>
        <div className="panel-body">
          <div className="form-grid" style={{ marginBottom: 12 }}>
            <div className="field">
              <label>Save Quick Rollback Checkpoint (Before Risky Edits)</label>
              <div className="toolbar">
                <input
                  style={{ flex: 1 }}
                  placeholder="Checkpoint name (e.g. before-redis-tuning)"
                  value={snapshotLabel}
                  onChange={(e) => setSnapshotLabel(e.target.value)}
                />
                <button type="button" className="btn" onClick={handleSaveSnapshot}>
                  Save Snapshot
                </button>
              </div>
            </div>
            {role === 'admin' && (
              <div className="field">
                <label>Restore Policies from Exported Backup (.json)</label>
                <input
                  type="file"
                  accept=".json,application/json"
                  onChange={(e) => void handleRestoreFile(e.target.files?.[0] || null)}
                />
              </div>
            )}
          </div>

          {snapshots.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Saved Checkpoint</th>
                    <th>Timestamp</th>
                    <th>Policies</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {snapshots.map((snap) => (
                    <tr key={snap.id}>
                      <td>
                        <strong>{snap.label}</strong>
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {new Date(snap.savedAt).toLocaleString()}
                      </td>
                      <td className="mono" style={{ fontSize: 12 }}>
                        {snap.policies.length}
                      </td>
                      <td>
                        {role === 'admin' ? (
                          <button type="button" className="btn btn-sm" onClick={() => void handleRestoreSnapshot(snap)}>
                            Restore Snapshot
                          </button>
                        ) : (
                          <span style={{ fontSize: 12, color: 'var(--ink-muted)' }}>Admin role required</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
