import { useState } from 'react';
import type { EBPFProgram, Role } from '../types';

interface Props {
  programs: EBPFProgram[];
  role: Role;
  onUpload: (name: string, file: File) => Promise<void>;
  onAction: (id: string, action: 'approve' | 'deploy' | 'rollback') => Promise<void>;
}

export function EBPFManager({ programs, role, onUpload, onAction }: Props) {
  const [name, setName] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const canUpload = role === 'admin' || role === 'kernel_admin';
  const canApprove = role === 'kernel_admin';

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setErr(null);
    setBusy(true);
    try {
      await onUpload(name.trim() || file.name, file);
      setName('');
      setFile(null);
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : 'ELF upload failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">eBPF Program Manager</h1>
          <p className="page-desc">
            Inspect compiled ELF64 EM_BPF (.o) sections and BTF metadata, enforce kernel_admin approval, and manage versioned rollouts.
          </p>
        </div>
      </div>

      <div className="info-banner">
        Control-plane ELF/BTF inspection, SHA-256 verification, approval gating, and version history are active. Live host{' '}
        <span className="mono">bpf()</span> kernel attachment is gated behind Phase 4 agent <span className="mono">--feature-ebpf</span>.
      </div>

      {err && <div className="error-banner">{err}</div>}

      {canUpload && (
        <form className="panel" onSubmit={handleUpload}>
          <div className="panel-header">
            <span>Upload Compiled eBPF Object (.o)</span>
            <button type="submit" className="btn btn-sm btn-primary" disabled={!file || busy}>
              {busy ? 'Inspecting ELF...' : 'Upload & Inspect ELF'}
            </button>
          </div>
          <div className="panel-body form-grid">
            <div className="field">
              <label>Program Name</label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. oom_probe.o" />
            </div>
            <div className="field">
              <label>ELF64 BPF Object File (.o)</label>
              <input type="file" accept=".o,.elf,application/octet-stream" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            </div>
          </div>
        </form>
      )}

      <div className="panel">
        <div className="panel-header">
          <span>ELF Objects & Deployment History ({programs.length})</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Program</th>
                <th>Type & Attach Section</th>
                <th>ELF Sections & BTF</th>
                <th>Min Kernel</th>
                <th>SHA-256</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {programs.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ color: 'var(--ink-muted)' }}>
                    No eBPF ELF objects uploaded yet.
                  </td>
                </tr>
              ) : (
                programs.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <strong>{p.name}</strong>
                      <div className="mono" style={{ fontSize: 11.5, color: 'var(--ink-muted)' }}>
                        v{p.version} · {p.size_bytes} B
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      <div>{p.program_type}</div>
                      <div style={{ color: 'var(--ink-muted)' }}>{p.attach_target}</div>
                    </td>
                    <td className="mono" style={{ fontSize: 11.5 }}>
                      <span className={`badge ${p.has_btf ? 'badge-ok' : 'badge-warn'}`}>
                        BTF: {p.has_btf ? 'present' : 'absent'}
                      </span>
                      <div style={{ marginTop: 4 }}>{p.sections.join(', ')}</div>
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {p.min_kernel}
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>
                      {p.sha256.slice(0, 16)}…
                    </td>
                    <td>
                      <span
                        className={`badge ${
                          p.status === 'deployed_staged'
                            ? 'badge-info'
                            : p.status === 'approved'
                            ? 'badge-ok'
                            : p.status === 'pending_approval'
                            ? 'badge-warn'
                            : 'badge-neutral'
                        }`}
                      >
                        {p.status}
                      </span>
                      {p.verifier_note && (
                        <div style={{ fontSize: 11, color: 'var(--ink-muted)', marginTop: 3, maxWidth: 220 }}>
                          {p.verifier_note}
                        </div>
                      )}
                    </td>
                    <td>
                      <div className="toolbar">
                        {canApprove && p.status === 'pending_approval' && (
                          <button className="btn btn-sm" onClick={() => onAction(p.id, 'approve')}>
                            Approve
                          </button>
                        )}
                        {canUpload && p.status === 'approved' && (
                          <button className="btn btn-sm btn-primary" onClick={() => onAction(p.id, 'deploy')}>
                            Stage Deploy
                          </button>
                        )}
                        {canUpload && p.status === 'deployed_staged' && (
                          <button className="btn btn-sm btn-danger" onClick={() => onAction(p.id, 'rollback')}>
                            Rollback
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
