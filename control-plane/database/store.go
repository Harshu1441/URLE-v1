package database

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ulre/ulre/control-plane/ebpf"
	"github.com/ulre/ulre/control-plane/policyengine"
)

type HostEnvironment struct {
	Provider     string `json:"provider"`
	InstanceID   string `json:"instance_id,omitempty"`
	InstanceType string `json:"instance_type,omitempty"`
	Region       string `json:"region,omitempty"`
	Zone         string `json:"zone,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	Product      string `json:"product,omitempty"`
}

type Host struct {
	ID                string          `json:"id"`
	Hostname          string          `json:"hostname"`
	MachineID         string          `json:"machine_id"`
	OSName            string          `json:"os_name"`
	KernelVersion     string          `json:"kernel_version"`
	CPUCores          int             `json:"cpu_cores"`
	MemoryBytes       uint64          `json:"memory_bytes"`
	CgroupV2          bool            `json:"cgroup_v2"`
	Controllers       []string        `json:"controllers"`
	PSISupported      bool            `json:"psi_supported"`
	SwapAccounting    bool            `json:"swap_accounting"`
	OOMGroupSupported bool            `json:"oom_group_supported"`
	BTFSupported      bool            `json:"btf_supported"`
	Environment       HostEnvironment `json:"environment"`
	AgentVersion      string          `json:"agent_version"`
	Status            string          `json:"status"` // online | degraded | offline
	LastSeenAt        time.Time       `json:"last_seen_at"`
}

type Workload struct {
	HostID         string `json:"host_id"`
	PID            int    `json:"pid"`
	PPID           int    `json:"ppid"`
	StartTimeTicks uint64 `json:"start_time_ticks"`
	Comm           string `json:"comm"`
	Exe            string `json:"exe"`
	Cmdline        string `json:"cmdline"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	CgroupPath     string `json:"cgroup_path"`
	SystemdUnit    string `json:"systemd_unit,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	ContainerImage string `json:"container_image,omitempty"`
	OwnerRuntime   string `json:"owner_runtime"`
	MatchedPolicy  string `json:"matched_policy,omitempty"`
	RSSBytes       uint64 `json:"rss_bytes"`
}

type OOMEvent struct {
	ID         string            `json:"id"`
	HostID     string            `json:"host_id"`
	Hostname   string            `json:"hostname"`
	PolicyName string            `json:"policy_name,omitempty"`
	Target     string            `json:"target"`
	Action     string            `json:"action"`
	Result     string            `json:"result"`
	DryRun     bool              `json:"dry_run"`
	Details    map[string]string `json:"details,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}

type AuditRecord struct {
	ID         string            `json:"id"`
	Actor      string            `json:"actor"`
	ActorRole  string            `json:"actor_role"`
	HostID     string            `json:"host_id,omitempty"`
	Action     string            `json:"action"`
	PolicyName string            `json:"policy_name,omitempty"`
	Target     string            `json:"target"`
	DryRun     bool              `json:"dry_run"`
	Result     string            `json:"result"`
	Details    map[string]string `json:"details,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
}

type Overview struct {
	TotalHosts           int `json:"total_hosts"`
	ActiveAgents         int `json:"active_agents"`
	TotalWorkloads       int `json:"total_workloads"`
	EnforcedWorkloads    int `json:"enforced_workloads"`
	MemoryPressureEvents int `json:"memory_pressure_events"`
	OOMEvents            int `json:"oom_events"`
	EnforcementActions   int `json:"enforcement_actions"`
	PolicyViolations     int `json:"policy_violations"`
}

type snapshot struct {
	Hosts        map[string]Host                `json:"hosts"`
	Workloads    map[string][]Workload          `json:"workloads"`
	Policies     map[string]policyengine.Policy `json:"policies"`
	OOMEvents    []OOMEvent                     `json:"oom_events"`
	EBPFPrograms []ebpf.ProgramRecord           `json:"ebpf_programs"`
	AuditLogs    []AuditRecord                  `json:"audit_logs"`
}

type Store struct {
	mu           sync.RWMutex
	dataPath     string
	hosts        map[string]Host
	workloads    map[string][]Workload
	policies     map[string]policyengine.Policy
	oomEvents    []OOMEvent
	ebpfPrograms []ebpf.ProgramRecord
	auditLogs    []AuditRecord
}

func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		hosts:     map[string]Host{},
		workloads: map[string][]Workload{},
		policies:  map[string]policyengine.Policy{},
	}
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0o750); err != nil {
			return nil, err
		}
		s.dataPath = filepath.Join(dataDir, "control-plane-state.json")
		if b, err := os.ReadFile(s.dataPath); err == nil {
			var snap snapshot
			if jerr := json.Unmarshal(b, &snap); jerr == nil {
				if snap.Hosts != nil {
					s.hosts = snap.Hosts
				}
				if snap.Workloads != nil {
					s.workloads = snap.Workloads
				}
				if snap.Policies != nil {
					s.policies = snap.Policies
				}
				s.oomEvents = snap.OOMEvents
				s.ebpfPrograms = snap.EBPFPrograms
				s.auditLogs = snap.AuditLogs
			}
		}
	}
	return s, nil
}

func (s *Store) persistLocked() {
	if s.dataPath == "" {
		return
	}
	snap := snapshot{
		Hosts:        s.hosts,
		Workloads:    s.workloads,
		Policies:     s.policies,
		OOMEvents:    s.oomEvents,
		EBPFPrograms: s.ebpfPrograms,
		AuditLogs:    s.auditLogs,
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return
	}
	tmp := s.dataPath + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		_ = os.Rename(tmp, s.dataPath)
	}
}

func (s *Store) RegisterHost(h Host) Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.hosts {
		if existing.MachineID == h.MachineID && h.MachineID != "" {
			h.ID = id
			break
		}
	}
	if h.ID == "" {
		h.ID = NewID()
	}
	h.Status = "online"
	h.LastSeenAt = time.Now().UTC()
	s.hosts[h.ID] = h
	s.persistLocked()
	return h
}

func (s *Store) Heartbeat(hostID string) (Host, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.hosts[hostID]
	if !ok {
		return Host{}, false
	}
	h.Status = "online"
	h.LastSeenAt = time.Now().UTC()
	s.hosts[hostID] = h
	s.persistLocked()
	return h, true
}

func (s *Store) ListHosts() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		if now.Sub(h.LastSeenAt) > 30*time.Second {
			h.Status = "offline"
		} else if !h.CgroupV2 {
			h.Status = "degraded"
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out
}

func (s *Store) GetHost(id string) (Host, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.hosts[id]
	if ok && time.Since(h.LastSeenAt) > 30*time.Second {
		h.Status = "offline"
	}
	return h, ok
}

func (s *Store) DeleteHost(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hosts[id]; !ok {
		return false
	}
	delete(s.hosts, id)
	delete(s.workloads, id)
	s.persistLocked()
	return true
}

func (s *Store) SetHostWorkloads(hostID string, items []Workload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range items {
		items[i].HostID = hostID
	}
	s.workloads[hostID] = items
	if h, ok := s.hosts[hostID]; ok {
		h.LastSeenAt = time.Now().UTC()
		h.Status = "online"
		s.hosts[hostID] = h
	}
	s.persistLocked()
}

func (s *Store) ListWorkloads(hostID string) []Workload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if hostID != "" {
		out := make([]Workload, len(s.workloads[hostID]))
		copy(out, s.workloads[hostID])
		return out
	}
	all := make([]Workload, 0)
	for _, list := range s.workloads {
		all = append(all, list...)
	}
	return all
}

func (s *Store) ListPolicies() []policyengine.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policyengine.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *Store) UpsertPolicy(p policyengine.Policy, isCreate bool) (policyengine.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	candidate := make([]policyengine.Policy, 0, len(s.policies)+1)
	if isCreate {
		p.ID = NewID()
		p.Version = 1
	} else {
		existing, ok := s.policies[p.ID]
		if !ok {
			return policyengine.Policy{}, fmt.Errorf("policy %q not found", p.ID)
		}
		p.Version = existing.Version + 1
		if existing.ApprovedBy != "" && p.AllowDestructive == existing.AllowDestructive && p.AllowRuntimeOverride == existing.AllowRuntimeOverride {
			p.ApprovedBy = existing.ApprovedBy
			p.ApprovedAt = existing.ApprovedAt
		}
	}
	p.UpdatedAt = time.Now().UTC()

	for id, existing := range s.policies {
		if id != p.ID {
			candidate = append(candidate, existing)
		}
	}
	candidate = append(candidate, p)
	if errs := policyengine.ValidatePolicies(candidate); len(errs) > 0 {
		return policyengine.Policy{}, fmt.Errorf("%s", errs[0])
	}

	s.policies[p.ID] = p
	s.persistLocked()
	return p, nil
}

func (s *Store) ApprovePolicy(id, approver string) (policyengine.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	if !ok {
		return policyengine.Policy{}, fmt.Errorf("policy not found")
	}
	now := time.Now().UTC()
	p.ApprovedBy = approver
	p.ApprovedAt = &now
	p.Version++
	p.UpdatedAt = now
	s.policies[id] = p
	s.persistLocked()
	return p, nil
}

func (s *Store) DeletePolicy(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[id]; !ok {
		return false
	}
	delete(s.policies, id)
	s.persistLocked()
	return true
}

func (s *Store) ReplacePolicies(policies []policyengine.Policy, restorer string) ([]policyengine.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	prepared := make([]policyengine.Policy, len(policies))
	now := time.Now().UTC()
	for i, p := range policies {
		if p.ID == "" {
			p.ID = NewID()
		}
		if p.Version <= 0 {
			p.Version = 1
		} else {
			p.Version++
		}
		if (p.AllowDestructive || p.AllowRuntimeOverride) && p.Mode == "enforce" && p.ApprovedBy == "" {
			p.ApprovedBy = restorer
			p.ApprovedAt = &now
		}
		p.UpdatedAt = now
		prepared[i] = p
	}

	if len(prepared) > 0 {
		if errs := policyengine.ValidatePolicies(prepared); len(errs) > 0 {
			return nil, fmt.Errorf("%s", errs[0])
		}
	}

	next := make(map[string]policyengine.Policy, len(prepared))
	for _, p := range prepared {
		next[p.ID] = p
	}
	s.policies = next
	s.persistLocked()
	return prepared, nil
}

func (s *Store) AddOOMEvent(ev OOMEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.ID == "" {
		ev.ID = NewID()
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = time.Now().UTC()
	}
	s.oomEvents = append([]OOMEvent{ev}, s.oomEvents...)
	if len(s.oomEvents) > 1000 {
		s.oomEvents = s.oomEvents[:1000]
	}
	s.persistLocked()
}

func (s *Store) ListOOMEvents() []OOMEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]OOMEvent, len(s.oomEvents))
	copy(out, s.oomEvents)
	return out
}

func (s *Store) AddAudit(rec AuditRecord) AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.ID == "" {
		rec.ID = NewID()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	s.auditLogs = append([]AuditRecord{rec}, s.auditLogs...)
	if len(s.auditLogs) > 2000 {
		s.auditLogs = s.auditLogs[:2000]
	}
	s.persistLocked()
	return rec
}

func (s *Store) ListAuditLogs() []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditRecord, len(s.auditLogs))
	copy(out, s.auditLogs)
	return out
}

func (s *Store) AddEBPFProgram(rec ebpf.ProgramRecord) ebpf.ProgramRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	maxVer := 0
	for _, p := range s.ebpfPrograms {
		if p.Name == rec.Name && p.Version > maxVer {
			maxVer = p.Version
		}
	}
	rec.ID = NewID()
	rec.Version = maxVer + 1
	s.ebpfPrograms = append([]ebpf.ProgramRecord{rec}, s.ebpfPrograms...)
	s.persistLocked()
	return rec
}

func (s *Store) ListEBPFPrograms() []ebpf.ProgramRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ebpf.ProgramRecord, len(s.ebpfPrograms))
	copy(out, s.ebpfPrograms)
	return out
}

func (s *Store) UpdateEBPFStatus(id, status, approver string) (ebpf.ProgramRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.ebpfPrograms {
		if s.ebpfPrograms[i].ID == id {
			now := time.Now().UTC()
			if status == "approved" {
				s.ebpfPrograms[i].ApprovedBy = approver
				s.ebpfPrograms[i].ApprovedAt = &now
				s.ebpfPrograms[i].VerifierNote = "Approved by " + approver + "; ready for Phase 4 host bpf() attachment"
			} else if status == "deployed_staged" {
				if s.ebpfPrograms[i].ApprovedBy == "" {
					return ebpf.ProgramRecord{}, fmt.Errorf("eBPF program must be approved by kernel_admin before deployment")
				}
				// Mark previous deployed version of same name as rolled_back
				for j := range s.ebpfPrograms {
					if j != i && s.ebpfPrograms[j].Name == s.ebpfPrograms[i].Name && s.ebpfPrograms[j].Status == "deployed_staged" {
						s.ebpfPrograms[j].Status = "superseded"
					}
				}
				s.ebpfPrograms[i].VerifierNote = "Staged for deployment; host-side kernel bpf() attachment requires Phase 4 agent --feature-ebpf"
			} else if status == "rolled_back" {
				s.ebpfPrograms[i].VerifierNote = "Rolled back by " + approver
			}
			s.ebpfPrograms[i].Status = status
			s.persistLocked()
			return s.ebpfPrograms[i], nil
		}
	}
	return ebpf.ProgramRecord{}, fmt.Errorf("eBPF program not found")
}

func (s *Store) Overview() Overview {
	hosts := s.ListHosts()
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ov Overview
	ov.TotalHosts = len(hosts)
	for _, h := range hosts {
		if h.Status == "online" {
			ov.ActiveAgents++
		}
	}
	for _, list := range s.workloads {
		ov.TotalWorkloads += len(list)
		for _, w := range list {
			if w.MatchedPolicy != "" {
				ov.EnforcedWorkloads++
			}
		}
	}
	for _, ev := range s.oomEvents {
		if ev.Action == "oom.throttle" || ev.Action == "oom.alert" {
			ov.MemoryPressureEvents++
		}
		ov.OOMEvents++
	}
	for _, a := range s.auditLogs {
		if a.Result == "applied" {
			ov.EnforcementActions++
		}
		if a.Result == "blocked" || a.Result == "error" {
			ov.PolicyViolations++
		}
	}
	return ov
}

func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
