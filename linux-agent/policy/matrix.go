package policy

import (
	"fmt"
	"strings"
)

type AdapterKind string

const (
	AdapterBareMetal AdapterKind = "bare_metal"
	AdapterSystemd   AdapterKind = "systemd"
	AdapterDocker    AdapterKind = "docker"
)

type FieldSupport struct {
	Field     string `json:"field"`
	BareMetal string `json:"bare_metal"` // supported | partial | unsupported
	Systemd   string `json:"systemd"`
	Docker    string `json:"docker"`
	Notes     string `json:"notes"`
}

// CapabilityMatrix defines exact field support per enforcement adapter.
func CapabilityMatrix() []FieldSupport {
	return []FieldSupport{
		{Field: "memory.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "Hard memory limit (MemoryMax / Docker Memory)"},
		{Field: "memory.high", BareMetal: "supported", Systemd: "supported", Docker: "unsupported", Notes: "Soft reclaim throttle; Docker Engine Update API does not expose memory.high"},
		{Field: "memory.low", BareMetal: "supported", Systemd: "supported", Docker: "partial", Notes: "Mapped to Docker MemoryReservation on cgroup v2"},
		{Field: "memory.min", BareMetal: "supported", Systemd: "supported", Docker: "unsupported", Notes: "Hard memory floor; unsupported by Docker ContainerUpdate"},
		{Field: "memory.swap.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "Requires memory.max to also be set on Docker"},
		{Field: "memory.oom.group", BareMetal: "supported", Systemd: "unsupported", Docker: "unsupported", Notes: "Native cgroup v2 file only; not settable at runtime on systemd 239 or Docker Update API"},
		{Field: "cpu.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "CPUQuotaPerSecUSec on systemd; CpuPeriod+CpuQuota on Docker"},
		{Field: "cpu.weight", BareMetal: "supported", Systemd: "supported", Docker: "partial", Notes: "Native CPUWeight on systemd/cgroup; scaled to CpuShares (2..262144) on Docker"},
		{Field: "io.max", BareMetal: "supported", Systemd: "partial", Docker: "unsupported", Notes: "systemd supports rbps/wbps bandwidths (not riops/wiops); Docker Update API has no io.max"},
		{Field: "pids.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "TasksMax on systemd; PidsLimit on Docker"},
	}
}

// InferTargetAdapter infers the primary adapter from policy selectors.
func InferTargetAdapter(p Policy) AdapterKind {
	if p.Selectors.ContainerID != "" {
		return AdapterDocker
	}
	if p.Selectors.SystemdUnit != "" {
		return AdapterSystemd
	}
	return AdapterBareMetal
}

// CheckAdapterCompatibility returns blocking errors and non-blocking warnings
// for fields unsupported by the target adapter.
func CheckAdapterCompatibility(p Policy, adapter AdapterKind) (errs []string, warns []string) {
	l := p.Limits
	switch adapter {
	case AdapterDocker:
		if l.MemoryHigh != "" {
			errs = append(errs, fmt.Sprintf("policy %q: memory.high is unsupported by the Docker adapter (ContainerUpdate API)", p.Name))
		}
		if l.MemoryMin != "" {
			errs = append(errs, fmt.Sprintf("policy %q: memory.min is unsupported by the Docker adapter (ContainerUpdate API)", p.Name))
		}
		if l.MemoryOOMGroup != nil {
			errs = append(errs, fmt.Sprintf("policy %q: memory.oom.group is unsupported by the Docker adapter", p.Name))
		}
		if l.IOMax != "" {
			errs = append(errs, fmt.Sprintf("policy %q: io.max is unsupported by the Docker adapter", p.Name))
		}
		if l.MemorySwapMax != "" && l.MemoryMax == "" {
			errs = append(errs, fmt.Sprintf("policy %q: Docker requires memory.max when setting memory.swap.max", p.Name))
		}
		if l.MemoryLow != "" {
			warns = append(warns, fmt.Sprintf("policy %q: memory.low maps to Docker MemoryReservation", p.Name))
		}
	case AdapterSystemd:
		if l.MemoryOOMGroup != nil {
			warns = append(warns, fmt.Sprintf("policy %q: memory.oom.group is not applied via systemd runtime SetUnitProperties", p.Name))
		}
		if strings.Contains(l.IOMax, "riops=") || strings.Contains(l.IOMax, "wiops=") {
			errs = append(errs, fmt.Sprintf("policy %q: systemd D-Bus supports rbps/wbps only (riops/wiops unsupported)", p.Name))
		}
	}
	return errs, warns
}
