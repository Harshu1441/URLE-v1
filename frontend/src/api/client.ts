import type {
  AuditRecord,
  AuthSession,
  EBPFProgram,
  Host,
  OOMEvent,
  OverviewStats,
  Policy,
  Workload,
} from '../types';

const STORAGE_KEY = 'ulre_session';

export function loadSavedSession(): AuthSession | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as AuthSession) : null;
  } catch {
    return null;
  }
}

export function saveSession(s: AuthSession | null) {
  if (!s) {
    localStorage.removeItem(STORAGE_KEY);
  } else {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
  }
}

async function request<T>(path: string, token?: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  if (!(init?.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<AuthSession>('/api/v1/auth/login', undefined, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  overview: (token: string) => request<OverviewStats>('/api/v1/overview', token),
  hosts: (token: string) => request<Host[]>('/api/v1/hosts', token),
  deleteHost: (token: string, id: string) =>
    request<{ deleted: string }>(`/api/v1/hosts/${id}`, token, { method: 'DELETE' }),
  workloads: (token: string, hostId?: string, q?: string, runtime?: string) => {
    const params = new URLSearchParams();
    if (hostId) params.set('host_id', hostId);
    if (q) params.set('q', q);
    if (runtime) params.set('runtime', runtime);
    const qs = params.toString();
    return request<Workload[]>(`/api/v1/workloads${qs ? '?' + qs : ''}`, token);
  },
  policies: (token: string) => request<Policy[]>('/api/v1/policies', token),
  validatePolicy: (token: string, p: Policy) =>
    request<{ valid: boolean; errors?: string[]; warnings?: string[] }>('/api/v1/policies/validate', token, {
      method: 'POST',
      body: JSON.stringify(p),
    }),
  createPolicy: (token: string, p: Policy) =>
    request<Policy>('/api/v1/policies', token, { method: 'POST', body: JSON.stringify(p) }),
  updatePolicy: (token: string, id: string, p: Policy) =>
    request<Policy>(`/api/v1/policies/${id}`, token, { method: 'PUT', body: JSON.stringify(p) }),
  approvePolicy: (token: string, id: string) =>
    request<Policy>(`/api/v1/policies/${id}/approve`, token, { method: 'POST' }),
  deletePolicy: (token: string, id: string) =>
    request<{ deleted: string }>(`/api/v1/policies/${id}`, token, { method: 'DELETE' }),
  oomEvents: (token: string) => request<OOMEvent[]>('/api/v1/oom-events', token),
  ebpfPrograms: (token: string) => request<EBPFProgram[]>('/api/v1/ebpf/programs', token),
  uploadEBPF: (token: string, name: string, file: File) => {
    const fd = new FormData();
    fd.append('name', name || file.name);
    fd.append('object', file);
    return request<EBPFProgram>('/api/v1/ebpf/programs', token, { method: 'POST', body: fd });
  },
  ebpfAction: (token: string, id: string, action: 'approve' | 'deploy' | 'rollback') =>
    request<EBPFProgram>(`/api/v1/ebpf/programs/${id}/${action}`, token, { method: 'POST' }),
  auditLogs: (token: string) => request<AuditRecord[]>('/api/v1/audit-logs', token),
  exportBackup: (token: string) =>
    request<{ format: string; exported_at: string; exported_by: string; policies: Policy[] }>('/api/v1/backup/export', token),
  restoreBackup: (token: string, payload: { policies: Policy[] }) =>
    request<{ restored: number; policies: Policy[] }>('/api/v1/backup/restore', token, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};

export function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function formatLimitBytesHuman(raw?: string): string {
  if (!raw) return '';
  if (raw === 'max' || raw === '0') return raw === '0' ? '0 MB' : 'max';
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return raw;
  const gb = 1024 * 1024 * 1024;
  const mb = 1024 * 1024;
  if (n >= gb && n % gb === 0) return `${n / gb} GB`;
  if (n >= gb) return `${(n / gb).toFixed(2)} GB`;
  return `${Math.round(n / mb)} MB`;
}

export function parseMemoryToBytes(input: string, defaultUnit: 'MB' | 'GB'): string {
  const s = input.trim().toLowerCase();
  if (!s) return '';
  if (s === 'max' || s === '0') return s;
  const m = s.match(/^(\d+(?:\.\d+)?)\s*(gb|g|mb|m|kb|k|b)?$/i);
  if (!m) return input.trim();
  const num = parseFloat(m[1]);
  const unit = (m[2] || defaultUnit).toLowerCase();
  let mult = 1024 * 1024;
  if (unit === 'gb' || unit === 'g') mult = 1024 * 1024 * 1024;
  else if (unit === 'kb' || unit === 'k') mult = 1024;
  else if (unit === 'b') mult = 1;
  return String(Math.round(num * mult));
}
