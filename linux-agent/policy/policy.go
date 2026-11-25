package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/discovery"
)

type Mode string

const (
	ModeEnforce  Mode = "enforce"
	ModeDryRun   Mode = "dry_run"
	ModeDisabled Mode = "disabled"
)

type Criticality string

const (
	CritCritical   Criticality = "critical"
	CritHigh       Criticality = "high"
	CritNormal     Criticality = "normal"
	CritBestEffort Criticality = "best_effort"
)

type ActionType string

const (
	ActionAlert             ActionType = "alert"
	ActionThrottle          ActionType = "throttle"
	ActionReduceLimits      ActionType = "reduce_limits"
	ActionRestartService    ActionType = "restart_service"
	ActionTerminate         ActionType = "terminate"
	ActionIsolate           ActionType = "isolate"
	ActionEscalate          ActionType = "escalate"
	ActionKernelOOMFallback ActionType = "kernel_oom_fallback"
)

// Selectors specifies workload matching criteria. All non-empty fields must match (AND).
type Selectors struct {
	ExePath     string `json:"exe_path,omitempty"` // supports filepath.Match glob
	ProcessName string `json:"process_name,omitempty"`
	UID         *int   `json:"uid,omitempty"`
	GID         *int   `json:"gid,omitempty"`
	SystemdUnit string `json:"systemd_unit,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
}

func (s Selectors) IsEmpty() bool {
	return s.ExePath == "" && s.ProcessName == "" && s.UID == nil && s.GID == nil &&
		s.SystemdUnit == "" && s.ContainerID == ""
}

// OOMConditions defines thresholds that trigger intelligent OOM remediation.
type OOMConditions struct {
	MemoryPercent      float64 `json:"memory_percent,omitempty"`
	PSISomeAvg10       float64 `json:"psi_some_avg10,omitempty"`
	PSIFullAvg10       float64 `json:"psi_full_avg10,omitempty"`
	SwapPercent        float64 `json:"swap_percent,omitempty"`
	EventsHighDelta    uint64  `json:"events_high_delta,omitempty"`
	EventsMaxDelta     uint64  `json:"events_max_delta,omitempty"`
	EventsOOMDelta     uint64  `json:"events_oom_delta,omitempty"`
	EventsOOMKillDelta uint64  `json:"events_oom_kill_delta,omitempty"`
	RepeatedViolations int     `json:"repeated_violations,omitempty"`
	ViolationWindowSec int     `json:"violation_window_sec,omitempty"`
}

// OOMPolicy configures automated OOM remediation behavior.
type OOMPolicy struct {
	Conditions            OOMConditions `json:"conditions"`
	Actions               []ActionType  `json:"actions"`
	CooldownSec           int           `json:"cooldown_sec,omitempty"`
	MaxRetries            int           `json:"max_retries,omitempty"`
	RemediationTimeoutSec int           `json:"remediation_timeout_sec,omitempty"`
}

// Policy defines a workload selection, cgroup v2 limits, and OOM remediation plan.
type Policy struct {
	Name                 string        `json:"name"`
	Group                string        `json:"group,omitempty"`
	Priority             int           `json:"priority"`
	Mode                 Mode          `json:"mode"`
	Criticality          Criticality   `json:"criticality"`
	AllowDestructive     bool          `json:"allow_destructive,omitempty"`
	AllowRuntimeOverride bool          `json:"allow_runtime_override,omitempty"`
	Selectors            Selectors     `json:"selectors"`
	Limits               cgroup.Limits `json:"limits"`
	OOM                  OOMPolicy     `json:"oom"`
}

// EffectiveGroup returns the delegated cgroup name for this policy.
func (p Policy) EffectiveGroup() string {
	if strings.TrimSpace(p.Group) != "" {
		return p.Group
	}
	return p.Name
}

// Bundle is a versioned collection of policies (loaded from file or synced from control plane).
type Bundle struct {
	Version  int      `json:"version"`
	Policies []Policy `json:"policies"`
}

// LoadBundle reads and validates a JSON policy bundle from disk.
func LoadBundle(path string) (Bundle, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("read policy file %s: %w", path, err)
	}
	var bundle Bundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("parse policy JSON %s: %w", path, err)
	}
	if err := ValidateBundle(bundle); err != nil {
		return bundle, err
	}
	return bundle, nil
}

// ValidateBundle checks policy syntax, safety invariants, and policy conflicts.
func ValidateBundle(bundle Bundle) error {
	if len(bundle.Policies) == 0 {
		return fmt.Errorf("policy bundle contains no policies")
	}

	seenNames := map[string]bool{}
	groupLimits := map[string]cgroup.Limits{}
	var errs []string

	for i, p := range bundle.Policies {
		if strings.TrimSpace(p.Name) == "" {
			errs = append(errs, fmt.Sprintf("policy[%d]: name is required", i))
			continue
		}
		if seenNames[p.Name] {
			errs = append(errs, fmt.Sprintf("duplicate policy name %q", p.Name))
		}
		seenNames[p.Name] = true

		if p.Mode != ModeEnforce && p.Mode != ModeDryRun && p.Mode != ModeDisabled {
			errs = append(errs, fmt.Sprintf("policy %q: invalid mode %q", p.Name, p.Mode))
		}
		if p.Criticality == "" {
			errs = append(errs, fmt.Sprintf("policy %q: criticality is required", p.Name))
		}
		if p.Selectors.IsEmpty() {
			errs = append(errs, fmt.Sprintf("policy %q: at least one selector is required", p.Name))
		}
		if p.Selectors.ExePath != "" {
			if _, err := filepath.Match(p.Selectors.ExePath, "/bin/sh"); err != nil {
				errs = append(errs, fmt.Sprintf("policy %q: invalid exe_path glob %q: %v", p.Name, p.Selectors.ExePath, err))
			}
		}

		for _, act := range p.OOM.Actions {
			if !isValidAction(act) {
				errs = append(errs, fmt.Sprintf("policy %q: unknown OOM action %q", p.Name, act))
			}
			if act == ActionTerminate {
				if !p.AllowDestructive {
					errs = append(errs, fmt.Sprintf("policy %q: terminate action requires allow_destructive=true", p.Name))
				}
				if p.Criticality == CritCritical {
					errs = append(errs, fmt.Sprintf("policy %q: terminate action forbidden on criticality=critical workloads", p.Name))
				}
			}
		}

		if p.Mode == ModeDisabled {
			continue
		}

		// Adapter capability compatibility check when selectors target Docker or systemd.
		if p.Selectors.ContainerID != "" || p.Selectors.SystemdUnit != "" {
			adapterErrs, _ := CheckAdapterCompatibility(p, InferTargetAdapter(p))
			errs = append(errs, adapterErrs...)
		}

		grp := p.EffectiveGroup()
		if prev, ok := groupLimits[grp]; ok && prev != p.Limits {
			errs = append(errs, fmt.Sprintf("policy conflict: policies sharing cgroup %q define conflicting resource limits", grp))
		}
		groupLimits[grp] = p.Limits
	}

	// Detect priority + selector ambiguity between active policies.
	for i := 0; i < len(bundle.Policies); i++ {
		a := bundle.Policies[i]
		if a.Mode == ModeDisabled {
			continue
		}
		for j := i + 1; j < len(bundle.Policies); j++ {
			b := bundle.Policies[j]
			if b.Mode == ModeDisabled {
				continue
			}
			if a.Priority == b.Priority && selectorsOverlap(a.Selectors, b.Selectors) {
				errs = append(errs, fmt.Sprintf("policy conflict: %q and %q have equal priority (%d) and overlapping selectors", a.Name, b.Name, a.Priority))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("policy validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// IsProtectedProcess guards PID 1, kernel threads, and essential host services.
func IsProtectedProcess(p discovery.Process) (bool, string) {
	if p.PID <= 1 {
		return true, "PID 1 (init) is always protected"
	}
	if p.IsKernelThread || p.OwnerRuntime == discovery.RuntimeKernel {
		return true, "kernel thread is protected"
	}
	protectedUnits := []string{
		"init.scope",
		"dbus.service",
		"dbus-broker.service",
		"sshd.service",
		"ssh.service",
		"docker.service",
		"containerd.service",
		"crio.service",
		"cri-o.service",
		"kubelet.service",
		"ulre-agent.service",
	}
	if strings.HasPrefix(p.SystemdUnit, "systemd-") {
		return true, fmt.Sprintf("essential unit %s is protected", p.SystemdUnit)
	}
	for _, u := range protectedUnits {
		if p.SystemdUnit == u {
			return true, fmt.Sprintf("essential unit %s is protected", p.SystemdUnit)
		}
	}
	return false, ""
}

// MatchProcess returns the highest-priority enabled policy matching p, or nil.
func MatchProcess(policies []Policy, p discovery.Process) (*Policy, string) {
	if p.OwnerRuntime == discovery.RuntimeKubernetes || strings.Contains(p.CgroupPath, "kubepods") {
		return nil, "unsupported: Kubernetes workload"
	}
	if protected, reason := IsProtectedProcess(p); protected {
		return nil, reason
	}

	sorted := make([]Policy, 0, len(policies))
	for _, pol := range policies {
		if pol.Mode != ModeDisabled {
			sorted = append(sorted, pol)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		return sorted[i].Name < sorted[j].Name
	})

	for i := range sorted {
		pol := &sorted[i]
		if !matchesSelectors(pol.Selectors, p) {
			continue
		}
		if p.OwnerRuntime == discovery.RuntimeDocker && !pol.AllowRuntimeOverride {
			return nil, fmt.Sprintf("matched %q but skipping %s-managed workload without allow_runtime_override", pol.Name, p.OwnerRuntime)
		}
		return pol, ""
	}
	return nil, ""
}

func matchesSelectors(s Selectors, p discovery.Process) bool {
	if s.ProcessName != "" && p.Comm != s.ProcessName {
		return false
	}
	if s.ExePath != "" {
		ok, err := filepath.Match(s.ExePath, p.Exe)
		if err != nil || !ok {
			return false
		}
	}
	if s.UID != nil && p.UID != *s.UID {
		return false
	}
	if s.GID != nil && p.GID != *s.GID {
		return false
	}
	if s.SystemdUnit != "" && p.SystemdUnit != s.SystemdUnit {
		return false
	}
	if s.ContainerID != "" && !strings.HasPrefix(p.ContainerID, s.ContainerID) && p.ContainerName != s.ContainerID {
		return false
	}
	return true
}

func selectorsOverlap(a, b Selectors) bool {
	if a.ProcessName != "" && b.ProcessName != "" && a.ProcessName != b.ProcessName {
		return false
	}
	if a.UID != nil && b.UID != nil && *a.UID != *b.UID {
		return false
	}
	if a.GID != nil && b.GID != nil && *a.GID != *b.GID {
		return false
	}
	if a.SystemdUnit != "" && b.SystemdUnit != "" && a.SystemdUnit != b.SystemdUnit {
		return false
	}
	if a.ContainerID != "" && b.ContainerID != "" && a.ContainerID != b.ContainerID {
		return false
	}
	if a.ExePath != "" && b.ExePath != "" && a.ExePath != b.ExePath &&
		!strings.ContainsAny(a.ExePath, "*?[") && !strings.ContainsAny(b.ExePath, "*?[") {
		return false
	}
	return true
}

func isValidAction(a ActionType) bool {
	switch a {
	case ActionAlert, ActionThrottle, ActionReduceLimits, ActionRestartService,
		ActionTerminate, ActionIsolate, ActionEscalate, ActionKernelOOMFallback:
		return true
	default:
		return false
	}
}
