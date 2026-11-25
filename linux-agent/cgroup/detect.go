package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FeatureFlags gates experimental or kernel-version-dependent capabilities.
type FeatureFlags struct {
	PSI          bool `json:"psi"`
	SystemdScope bool `json:"systemd_scope"`
	EBPF         bool `json:"ebpf"`
}

// DefaultFeatureFlags returns safe production defaults.
func DefaultFeatureFlags() FeatureFlags {
	return FeatureFlags{
		PSI:          true,
		SystemdScope: true,
		EBPF:         false,
	}
}

// Capabilities describes the host Linux kernel and cgroup v2 readiness.
type Capabilities struct {
	OS                string       `json:"os"`
	KernelVersion     string       `json:"kernel_version"`
	CgroupRoot        string       `json:"cgroup_root"`
	CgroupV2Available bool         `json:"cgroup_v2_available"`
	Controllers       []string     `json:"controllers"`
	PSISupported      bool         `json:"psi_supported"`
	SwapAccounting    bool         `json:"swap_accounting"`
	OOMGroupSupported bool         `json:"oom_group_supported"`
	BTFSupported      bool         `json:"btf_supported"`
	FeatureFlags      FeatureFlags `json:"feature_flags"`
	Warnings          []string     `json:"warnings,omitempty"`
}

// HasController reports whether controller c (e.g. "memory", "cpu") is enabled at root.
func (c Capabilities) HasController(name string) bool {
	for _, ctrl := range c.Controllers {
		if ctrl == name {
			return true
		}
	}
	return false
}

// Detect inspects the host cgroup v2 hierarchy, kernel version, PSI, and feature support.
func Detect(cgroupRoot, procPSIMemory string, flags FeatureFlags) (Capabilities, error) {
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	if procPSIMemory == "" {
		procPSIMemory = "/proc/pressure/memory"
	}

	caps := Capabilities{
		CgroupRoot:   cgroupRoot,
		FeatureFlags: flags,
	}
	detectPlatform(&caps)

	ctrlPath := filepath.Join(cgroupRoot, "cgroup.controllers")
	data, err := os.ReadFile(ctrlPath)
	if err != nil {
		caps.Warnings = append(caps.Warnings, fmt.Sprintf("cgroup.controllers unreadable (%v); enforcement disabled", err))
		return caps, nil
	}

	if !caps.CgroupV2Available {
		// Allow non-Linux test sysfs roots only when explicit test flag isn't blocked,
		// while still warning on non-Linux hosts.
		if caps.OS != "linux" {
			caps.Warnings = append(caps.Warnings, fmt.Sprintf("host OS is %s; Linux kernel required for live cgroup v2 enforcement", caps.OS))
		}
	}

	for _, f := range strings.Fields(string(data)) {
		caps.Controllers = append(caps.Controllers, f)
	}

	if flags.PSI {
		if _, err := os.Stat(procPSIMemory); err == nil {
			caps.PSISupported = true
		} else {
			caps.Warnings = append(caps.Warnings, "PSI enabled by flag but /proc/pressure/memory not present (requires CONFIG_PSI=y, kernel >= 4.20)")
		}
	}

	if _, err := os.Stat(filepath.Join(cgroupRoot, "init.scope", "memory.swap.max")); err == nil {
		caps.SwapAccounting = true
	} else if _, err := os.Stat(filepath.Join(cgroupRoot, "memory.swap.max")); err == nil {
		caps.SwapAccounting = true
	}

	if _, err := os.Stat(filepath.Join(cgroupRoot, "init.scope", "memory.oom.group")); err == nil {
		caps.OOMGroupSupported = true
	}

	return caps, nil
}
