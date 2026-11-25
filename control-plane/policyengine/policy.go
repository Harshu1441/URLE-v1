package policyengine

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type Limits struct {
	MemoryMax      string `json:"memory.max,omitempty"`
	MemoryHigh     string `json:"memory.high,omitempty"`
	MemoryLow      string `json:"memory.low,omitempty"`
	MemoryMin      string `json:"memory.min,omitempty"`
	MemorySwapMax  string `json:"memory.swap.max,omitempty"`
	MemoryOOMGroup *bool  `json:"memory.oom.group,omitempty"`
	CPUMax         string `json:"cpu.max,omitempty"`
	CPUWeight      *int   `json:"cpu.weight,omitempty"`
	IOMax          string `json:"io.max,omitempty"`
	PIDsMax        string `json:"pids.max,omitempty"`
}

type Selectors struct {
	ExePath     string `json:"exe_path,omitempty"`
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

type OOMPolicy struct {
	Conditions            OOMConditions `json:"conditions"`
	Actions               []string      `json:"actions"`
	CooldownSec           int           `json:"cooldown_sec,omitempty"`
	MaxRetries            int           `json:"max_retries,omitempty"`
	RemediationTimeoutSec int           `json:"remediation_timeout_sec,omitempty"`
}

type Policy struct {
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Group                string     `json:"group,omitempty"`
	Version              int        `json:"version"`
	Priority             int        `json:"priority"`
	Mode                 string     `json:"mode"` // enforce | dry_run | disabled
	Criticality          string     `json:"criticality"`
	AllowDestructive     bool       `json:"allow_destructive,omitempty"`
	AllowRuntimeOverride bool       `json:"allow_runtime_override,omitempty"`
	ApprovedBy           string     `json:"approved_by,omitempty"`
	ApprovedAt           *time.Time `json:"approved_at,omitempty"`
	Selectors            Selectors  `json:"selectors"`
	Limits               Limits     `json:"limits"`
	OOM                  OOMPolicy  `json:"oom"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type SignedBundle struct {
	Version   int      `json:"version"`
	PublicKey string   `json:"public_key"`
	Signature string   `json:"signature"`
	Policies  []Policy `json:"policies"`
}

var validActions = map[string]bool{
	"alert": true, "throttle": true, "reduce_limits": true, "restart_service": true,
	"terminate": true, "isolate": true, "escalate": true, "kernel_oom_fallback": true,
}

// ValidatePolicies checks syntax, safety gates, and inter-policy conflicts.
func ValidatePolicies(policies []Policy) []string {
	var errs []string
	seen := map[string]bool{}
	groupLimits := map[string]Limits{}

	for i, p := range policies {
		if strings.TrimSpace(p.Name) == "" {
			errs = append(errs, fmt.Sprintf("policy[%d]: name is required", i))
			continue
		}
		if hasUnsafePathOrShellChars(p.Name) {
			errs = append(errs, fmt.Sprintf("policy %q: name contains unsafe path/shell characters", p.Name))
		}
		if p.Group != "" && hasUnsafePathOrShellChars(p.Group) {
			errs = append(errs, fmt.Sprintf("policy %q: group %q contains unsafe path/shell characters", p.Name, p.Group))
		}
		if seen[p.Name] {
			errs = append(errs, fmt.Sprintf("duplicate policy name %q", p.Name))
		}
		seen[p.Name] = true

		if p.Mode != "enforce" && p.Mode != "dry_run" && p.Mode != "disabled" {
			errs = append(errs, fmt.Sprintf("policy %q: invalid mode %q", p.Name, p.Mode))
		}
		if p.Criticality != "critical" && p.Criticality != "high" && p.Criticality != "normal" && p.Criticality != "best_effort" {
			errs = append(errs, fmt.Sprintf("policy %q: invalid criticality %q", p.Name, p.Criticality))
		}
		if p.Selectors.IsEmpty() {
			errs = append(errs, fmt.Sprintf("policy %q: at least one selector is required", p.Name))
		}
		if p.Selectors.ExePath != "" {
			if _, err := filepath.Match(p.Selectors.ExePath, "/bin/sh"); err != nil {
				errs = append(errs, fmt.Sprintf("policy %q: invalid exe_path glob %q", p.Name, p.Selectors.ExePath))
			}
		}

		for _, act := range p.OOM.Actions {
			if !validActions[act] {
				errs = append(errs, fmt.Sprintf("policy %q: unknown OOM action %q", p.Name, act))
			}
			if act == "terminate" {
				if !p.AllowDestructive {
					errs = append(errs, fmt.Sprintf("policy %q: terminate requires allow_destructive=true", p.Name))
				}
				if p.Criticality == "critical" {
					errs = append(errs, fmt.Sprintf("policy %q: terminate forbidden on critical workloads", p.Name))
				}
			}
		}
		if (p.AllowDestructive || p.AllowRuntimeOverride) && p.Mode == "enforce" && p.ApprovedBy == "" {
			errs = append(errs, fmt.Sprintf("policy %q: destructive/runtime-override enforce policy requires admin approval before activation", p.Name))
		}
		if p.Mode == "disabled" {
			continue
		}
		compatErrs, _ := CheckPolicyCompatibility(p)
		errs = append(errs, compatErrs...)
		grp := p.Group
		if grp == "" {
			grp = p.Name
		}
		if prev, ok := groupLimits[grp]; ok && prev != p.Limits {
			errs = append(errs, fmt.Sprintf("policy conflict: policies sharing group %q have conflicting limits", grp))
		}
		groupLimits[grp] = p.Limits
	}

	for i := 0; i < len(policies); i++ {
		if policies[i].Mode == "disabled" {
			continue
		}
		for j := i + 1; j < len(policies); j++ {
			if policies[j].Mode == "disabled" {
				continue
			}
			if policies[i].Priority == policies[j].Priority && selectorsOverlap(policies[i].Selectors, policies[j].Selectors) {
				errs = append(errs, fmt.Sprintf("policy conflict: %q and %q share priority %d with overlapping selectors", policies[i].Name, policies[j].Name, policies[i].Priority))
			}
		}
	}
	return errs
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
	return true
}

func hasUnsafePathOrShellChars(s string) bool {
	if strings.Contains(s, "..") || strings.ContainsAny(s, "/\\;|&$`\x00\n\r") {
		return true
	}
	return false
}
