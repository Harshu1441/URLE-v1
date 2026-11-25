export type Role = 'viewer' | 'operator' | 'admin' | 'kernel_admin';

export interface AuthSession {
  token: string;
  username: string;
  role: Role;
}

export interface OverviewStats {
  total_hosts: number;
  active_agents: number;
  total_workloads: number;
  enforced_workloads: number;
  memory_pressure_events: number;
  oom_events: number;
  enforcement_actions: number;
  policy_violations: number;
}

export interface HostEnvironment {
  provider: string;
  instance_id?: string;
  instance_type?: string;
  region?: string;
  zone?: string;
  vendor?: string;
  product?: string;
}

export interface Host {
  id: string;
  hostname: string;
  machine_id: string;
  os_name: string;
  kernel_version: string;
  cpu_cores: number;
  memory_bytes: number;
  cgroup_v2: boolean;
  controllers: string[];
  psi_supported: boolean;
  swap_accounting: boolean;
  oom_group_supported: boolean;
  btf_supported: boolean;
  environment?: HostEnvironment;
  agent_version: string;
  status: 'online' | 'degraded' | 'offline';
  last_seen_at: string;
}

export interface Workload {
  host_id: string;
  pid: number;
  ppid: number;
  start_time_ticks: number;
  comm: string;
  exe: string;
  cmdline: string;
  uid: number;
  gid: number;
  cgroup_path: string;
  systemd_unit?: string;
  container_id?: string;
  container_name?: string;
  container_image?: string;
  owner_runtime: 'bare_metal' | 'systemd' | 'docker' | 'kubernetes' | 'kernel';
  matched_policy?: string;
  rss_bytes: number;
}

export interface CgroupLimits {
  'memory.max'?: string;
  'memory.high'?: string;
  'memory.low'?: string;
  'memory.min'?: string;
  'memory.swap.max'?: string;
  'memory.oom.group'?: boolean;
  'cpu.max'?: string;
  'cpu.weight'?: number;
  'io.max'?: string;
  'pids.max'?: string;
}

export interface PolicySelectors {
  exe_path?: string;
  process_name?: string;
  uid?: number;
  gid?: number;
  systemd_unit?: string;
  container_id?: string;
}

export interface OOMConditions {
  memory_percent?: number;
  psi_some_avg10?: number;
  psi_full_avg10?: number;
  swap_percent?: number;
  events_high_delta?: number;
  events_max_delta?: number;
  events_oom_delta?: number;
  events_oom_kill_delta?: number;
  repeated_violations?: number;
  violation_window_sec?: number;
}

export interface OOMPolicy {
  conditions: OOMConditions;
  actions: string[];
  cooldown_sec?: number;
  max_retries?: number;
  remediation_timeout_sec?: number;
}

export interface Policy {
  id?: string;
  name: string;
  group?: string;
  version?: number;
  priority: number;
  mode: 'enforce' | 'dry_run' | 'disabled';
  criticality: 'critical' | 'high' | 'normal' | 'best_effort';
  allow_destructive?: boolean;
  allow_runtime_override?: boolean;
  approved_by?: string;
  approved_at?: string;
  selectors: PolicySelectors;
  limits: CgroupLimits;
  oom: OOMPolicy;
  updated_at?: string;
}

export interface OOMEvent {
  id: string;
  host_id: string;
  hostname: string;
  policy_name?: string;
  target: string;
  action: string;
  result: string;
  dry_run: boolean;
  details?: Record<string, string>;
  occurred_at: string;
}

export interface EBPFProgram {
  id: string;
  name: string;
  version: number;
  sha256: string;
  size_bytes: number;
  program_type: string;
  attach_target: string;
  sections: string[];
  map_sections: string[];
  has_btf: boolean;
  min_kernel: string;
  status: string;
  verifier_note?: string;
  approved_by?: string;
  approved_at?: string;
  created_at: string;
}

export interface AuditRecord {
  id: string;
  actor: string;
  actor_role: string;
  host_id?: string;
  action: string;
  policy_name?: string;
  target: string;
  dry_run: boolean;
  result: string;
  details?: Record<string, string>;
  created_at: string;
}

export type NavSection =
  | 'overview'
  | 'hosts'
  | 'workloads'
  | 'containers'
  | 'policies'
  | 'oom-center'
  | 'ebpf-manager'
  | 'audit'
  | 'docs';
