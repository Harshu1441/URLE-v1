package policyengine

import (
	"fmt"
	"strings"
)

type FieldSupport struct {
	Field     string `json:"field"`
	BareMetal string `json:"bare_metal"`
	Systemd   string `json:"systemd"`
	Docker    string `json:"docker"`
	Notes     string `json:"notes"`
}

func CapabilityMatrix() []FieldSupport {
	return []FieldSupport{
		{Field: "memory.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "Hard memory limit (MemoryMax / Docker Memory)"},
		{Field: "memory.high", BareMetal: "supported", Systemd: "supported", Docker: "unsupported", Notes: "Soft reclaim throttle; unsupported by Docker ContainerUpdate"},
		{Field: "memory.low", BareMetal: "supported", Systemd: "supported", Docker: "partial", Notes: "Mapped to Docker MemoryReservation on cgroup v2"},
		{Field: "memory.min", BareMetal: "supported", Systemd: "supported", Docker: "unsupported", Notes: "Hard memory floor; unsupported by Docker ContainerUpdate"},
		{Field: "memory.swap.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "Requires memory.max to also be set on Docker"},
		{Field: "memory.oom.group", BareMetal: "supported", Systemd: "unsupported", Docker: "unsupported", Notes: "Native cgroup v2 file only; not settable at runtime via systemd D-Bus or Docker Update API"},
		{Field: "cpu.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "CPUQuotaPerSecUSec on systemd; CpuPeriod+CpuQuota on Docker"},
		{Field: "cpu.weight", BareMetal: "supported", Systemd: "supported", Docker: "partial", Notes: "Native CPUWeight on systemd/cgroup; scaled to CpuShares on Docker"},
		{Field: "io.max", BareMetal: "supported", Systemd: "partial", Docker: "unsupported", Notes: "systemd supports rbps/wbps only; Docker ContainerUpdate has no io.max"},
		{Field: "pids.max", BareMetal: "supported", Systemd: "supported", Docker: "supported", Notes: "TasksMax on systemd; PidsLimit on Docker"},
	}
}

func CheckPolicyCompatibility(p Policy) (errs []string, warns []string) {
	if p.Selectors.ContainerID != "" {
		if p.Limits.MemoryHigh != "" {
			errs = append(errs, fmt.Sprintf("policy %q: memory.high is unsupported for Docker container targets", p.Name))
		}
		if p.Limits.MemoryMin != "" {
			errs = append(errs, fmt.Sprintf("policy %q: memory.min is unsupported for Docker container targets", p.Name))
		}
		if p.Limits.MemoryOOMGroup != nil {
			errs = append(errs, fmt.Sprintf("policy %q: memory.oom.group is unsupported for Docker container targets", p.Name))
		}
		if p.Limits.IOMax != "" {
			errs = append(errs, fmt.Sprintf("policy %q: io.max is unsupported for Docker container targets", p.Name))
		}
		if p.Limits.MemorySwapMax != "" && p.Limits.MemoryMax == "" {
			errs = append(errs, fmt.Sprintf("policy %q: Docker requires memory.max when setting memory.swap.max", p.Name))
		}
		if p.Limits.MemoryLow != "" {
			warns = append(warns, fmt.Sprintf("policy %q: memory.low maps to Docker MemoryReservation", p.Name))
		}
	} else if p.AllowRuntimeOverride {
		if p.Limits.MemoryHigh != "" || p.Limits.MemoryMin != "" || p.Limits.IOMax != "" {
			warns = append(warns, fmt.Sprintf("policy %q: allow_runtime_override=true can match Docker containers which do not support memory.high, memory.min, or io.max", p.Name))
		}
	}
	if p.Selectors.SystemdUnit != "" {
		if p.Limits.MemoryOOMGroup != nil {
			warns = append(warns, fmt.Sprintf("policy %q: memory.oom.group is not applied via systemd runtime SetUnitProperties", p.Name))
		}
		if strings.Contains(p.Limits.IOMax, "riops=") || strings.Contains(p.Limits.IOMax, "wiops=") {
			errs = append(errs, fmt.Sprintf("policy %q: systemd D-Bus supports rbps/wbps only (riops/wiops unsupported)", p.Name))
		}
	}
	return errs, warns
}
