import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  BookOpen,
  Box,
  Cpu,
  FileCheck2,
  HardDrive,
  Layers,
  LogOut,
  RefreshCw,
  Server,
  Shield,
} from 'lucide-react';
import { api, loadSavedSession, saveSession } from './api/client';
import { AuditCenter } from './audit/AuditCenter';
import { ContainersPods } from './containers/ContainersPods';
import { Overview } from './dashboard/Overview';
import { Documentation } from './docs/Documentation';
import { EBPFManager } from './ebpf-manager/EBPFManager';
import { Hosts } from './hosts/Hosts';
import { OOMCenter } from './oom-center/OOMCenter';
import { Policies } from './policies/Policies';
import type {
  AuditRecord,
  AuthSession,
  EBPFProgram,
  Host,
  NavSection,
  OOMEvent,
  OverviewStats,
  Policy,
  Workload,
} from './types';
import { Workloads } from './workloads/Workloads';

const NAV_ITEMS: { id: NavSection; label: string; icon: typeof Activity }[] = [
  { id: 'overview', label: 'Overview', icon: Activity },
  { id: 'hosts', label: 'Hosts', icon: Server },
  { id: 'containers', label: 'Containers', icon: Box },
  { id: 'workloads', label: 'Workload Explorer', icon: Cpu },
  { id: 'policies', label: 'Policies', icon: Shield },
  { id: 'oom-center', label: 'OOM Center', icon: AlertTriangle },
  { id: 'ebpf-manager', label: 'eBPF Manager', icon: Layers },
  { id: 'audit', label: 'Audit Center', icon: FileCheck2 },
  { id: 'docs', label: 'Documentation', icon: BookOpen },
];

export default function App() {
  const [session, setSession] = useState<AuthSession | null>(() => loadSavedSession());
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin');
  const [loginErr, setLoginErr] = useState<string | null>(null);

  const [section, setSection] = useState<NavSection>('overview');
  const [wsConnected, setWsConnected] = useState(false);
  const [syncErr, setSyncErr] = useState<string | null>(null);

  const [overview, setOverview] = useState<OverviewStats | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [workloads, setWorkloads] = useState<Workload[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [oomEvents, setOomEvents] = useState<OOMEvent[]>([]);
  const [ebpfPrograms, setEbpfPrograms] = useState<EBPFProgram[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditRecord[]>([]);

  const [selectedHostId, setSelectedHostId] = useState('');
  const [selectedTreeProc, setSelectedTreeProc] = useState<Workload | null>(null);
  const [prefillWorkload, setPrefillWorkload] = useState<Workload | null>(null);

  const refreshAll = useCallback(async (tok: string) => {
    try {
      const [ov, h, w, p, o, eb, au] = await Promise.all([
        api.overview(tok),
        api.hosts(tok),
        api.workloads(tok),
        api.policies(tok),
        api.oomEvents(tok),
        api.ebpfPrograms(tok),
        api.auditLogs(tok),
      ]);
      setOverview(ov);
      setHosts(Array.isArray(h) ? h : []);
      setWorkloads(Array.isArray(w) ? w : []);
      setPolicies(Array.isArray(p) ? p : []);
      setOomEvents(Array.isArray(o) ? o : []);
      setEbpfPrograms(Array.isArray(eb) ? eb : []);
      setAuditLogs(Array.isArray(au) ? au : []);
      setSyncErr(null);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to sync with Control Plane';
      setSyncErr(msg);
      if (msg.toLowerCase().includes('authentication')) {
        saveSession(null);
        setSession(null);
      }
    }
  }, []);

  useEffect(() => {
    if (!session) return;
    void refreshAll(session.token);

    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/stream?token=${encodeURIComponent(session.token)}`);
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onmessage = () => {
      void refreshAll(session.token);
    };

    const timer = window.setInterval(() => void refreshAll(session.token), 8000);
    return () => {
      window.clearInterval(timer);
      ws.close();
    };
  }, [session, refreshAll]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginErr(null);
    try {
      const s = await api.login(username.trim(), password);
      saveSession(s);
      setSession(s);
    } catch (err) {
      setLoginErr(err instanceof Error ? err.message : 'Authentication failed');
    }
  };

  const handleLogout = () => {
    saveSession(null);
    setSession(null);
  };

  if (!session) {
    return (
      <div className="login-wrap">
        <form className="login-card" onSubmit={handleLogin}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <HardDrive size={22} color="var(--accent)" />
            <h1 style={{ margin: 0, fontSize: 18 }}>ULRE Control Plane</h1>
          </div>
          <p style={{ margin: '0 0 18px', color: 'var(--ink-secondary)', fontSize: 13 }}>
            Unified Linux Resource Enforcement & OOM Policy Management
          </p>
          {loginErr && <div className="error-banner">{loginErr}</div>}
          <div className="field" style={{ marginBottom: 12 }}>
            <label>Username (admin / kernel / operator / viewer)</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} required />
          </div>
          <div className="field" style={{ marginBottom: 16 }}>
            <label>Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <button type="submit" className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }}>
            Sign In
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-title">
            <HardDrive size={18} color="var(--accent)" />
            <span>ULRE Platform</span>
          </div>
          <div className="brand-sub">cgroup v2 & OOM Control Plane</div>
        </div>

        <nav className="nav-list" aria-label="Primary Navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={`nav-item ${section === item.id ? 'active' : ''}`}
                onClick={() => setSection(item.id)}
              >
                <Icon size={16} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        <div style={{ borderTop: '1px solid var(--border-hairline)', paddingTop: 12, marginTop: 12 }}>
          <div style={{ fontSize: 12, color: 'var(--ink-secondary)', marginBottom: 8 }}>
            Signed in as <strong>{session.username}</strong>{' '}
            <span className="badge badge-neutral" style={{ marginLeft: 4 }}>
              {session.role}
            </span>
          </div>
          <button className="btn btn-sm" style={{ width: '100%', justifyContent: 'center' }} onClick={handleLogout}>
            <LogOut size={14} />
            Sign Out
          </button>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="toolbar">
            <span className={`badge ${wsConnected ? 'badge-ok' : 'badge-warn'}`}>
              {wsConnected ? 'Live Stream Connected' : 'Polling Fallback'}
            </span>
            <span className="mono" style={{ fontSize: 12, color: 'var(--ink-muted)' }}>
              {hosts.filter((h) => h.status === 'online').length}/{hosts.length} agents online
            </span>
          </div>
          <button className="btn btn-sm" onClick={() => void refreshAll(session.token)}>
            <RefreshCw size={13} />
            Refresh
          </button>
        </header>

        <main className="content">
          {syncErr && <div className="error-banner">{syncErr}</div>}

          {section === 'overview' && (
            <Overview
              overview={overview}
              hosts={hosts}
              policies={policies}
              oomEvents={oomEvents}
              auditLogs={auditLogs}
              onNavigate={(s) => setSection(s)}
            />
          )}

          {section === 'hosts' && (
            <Hosts
              hosts={hosts}
              role={session.role}
              onInspectWorkloads={(id) => {
                setSelectedHostId(id);
                setSection('workloads');
              }}
              onDeleteHost={async (id) => {
                await api.deleteHost(session.token, id);
                await refreshAll(session.token);
              }}
            />
          )}

          {section === 'containers' && (
            <ContainersPods
              hosts={hosts}
              workloads={workloads}
              policies={policies}
              selectedHostId={selectedHostId}
              onSelectHost={setSelectedHostId}
              onInspectTree={(w) => {
                setSelectedTreeProc(w);
                setSection('workloads');
              }}
              onCapContainer={(w) => {
                setPrefillWorkload(w);
                setSection('policies');
              }}
            />
          )}

          {section === 'workloads' && (
            <Workloads
              hosts={hosts}
              workloads={workloads}
              policies={policies}
              selectedHostId={selectedHostId}
              initialSelectedProc={selectedTreeProc}
              onSelectHost={setSelectedHostId}
              onCreatePolicyForProcess={(w) => {
                setPrefillWorkload(w);
                setSection('policies');
              }}
            />
          )}

          {section === 'policies' && (
            <Policies
              policies={policies}
              workloads={workloads}
              hosts={hosts}
              role={session.role}
              prefillWorkload={prefillWorkload}
              onClearPrefill={() => setPrefillWorkload(null)}
              onValidatePolicy={(p) => api.validatePolicy(session.token, p)}
              onCreatePolicy={async (p) => {
                await api.createPolicy(session.token, p);
                await refreshAll(session.token);
              }}
              onUpdatePolicy={async (id, p) => {
                await api.updatePolicy(session.token, id, p);
                await refreshAll(session.token);
              }}
              onApprovePolicy={async (id) => {
                await api.approvePolicy(session.token, id);
                await refreshAll(session.token);
              }}
              onDeletePolicy={async (id) => {
                await api.deletePolicy(session.token, id);
                await refreshAll(session.token);
              }}
              onExportBackup={() => api.exportBackup(session.token)}
              onRestoreBackup={async (pols) => {
                const res = await api.restoreBackup(session.token, { policies: pols });
                await refreshAll(session.token);
                return res;
              }}
            />
          )}

          {section === 'oom-center' && <OOMCenter events={oomEvents} />}

          {section === 'ebpf-manager' && (
            <EBPFManager
              programs={ebpfPrograms}
              role={session.role}
              onUpload={async (n, f) => {
                await api.uploadEBPF(session.token, n, f);
                await refreshAll(session.token);
              }}
              onAction={async (id, act) => {
                await api.ebpfAction(session.token, id, act);
                await refreshAll(session.token);
              }}
            />
          )}

          {section === 'audit' && <AuditCenter logs={auditLogs} onOpenDocs={() => setSection('docs')} />}

          {section === 'docs' && <Documentation />}
        </main>
      </div>
    </div>
  );
}
