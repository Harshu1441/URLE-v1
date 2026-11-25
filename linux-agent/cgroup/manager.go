package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const DefaultDelegatedSlice = "ulre.slice"

// Limits defines the 10 supported native cgroup v2 resource controls.
// Empty strings or nil pointers leave that control unmanaged.
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

// RequiredControllers returns the cgroup v2 controllers needed for the configured limits.
func (l Limits) RequiredControllers() []string {
	var out []string
	if l.MemoryMax != "" || l.MemoryHigh != "" || l.MemoryLow != "" || l.MemoryMin != "" || l.MemorySwapMax != "" || l.MemoryOOMGroup != nil {
		out = append(out, "memory")
	}
	if l.CPUMax != "" || l.CPUWeight != nil {
		out = append(out, "cpu")
	}
	if l.IOMax != "" {
		out = append(out, "io")
	}
	if l.PIDsMax != "" {
		out = append(out, "pids")
	}
	return out
}

// Change records an applied or dry-run cgroup control file mutation.
type Change struct {
	CgroupPath string `json:"cgroup_path"`
	File       string `json:"file"`
	OldValue   string `json:"old_value"`
	NewValue   string `json:"new_value"`
	Applied    bool   `json:"applied"`
	DryRun     bool   `json:"dry_run"`
}

// MemoryEvents mirrors cgroup v2 memory.events counters.
type MemoryEvents struct {
	Low          uint64 `json:"low"`
	High         uint64 `json:"high"`
	Max          uint64 `json:"max"`
	OOM          uint64 `json:"oom"`
	OOMKill      uint64 `json:"oom_kill"`
	OOMGroupKill uint64 `json:"oom_group_kill"`
}

// MemoryStats snapshots current cgroup v2 memory accounting and events.
type MemoryStats struct {
	CurrentBytes uint64       `json:"current_bytes"`
	MaxBytes     uint64       `json:"max_bytes"` // 0 if "max" (unlimited)
	Unlimited    bool         `json:"unlimited"`
	HighBytes    uint64       `json:"high_bytes"`
	SwapCurrent  uint64       `json:"swap_current_bytes"`
	SwapMax      uint64       `json:"swap_max_bytes"`
	Events       MemoryEvents `json:"events"`
}

// UsagePercent returns current usage as a percentage of memory.max, or 0 if unlimited.
func (m MemoryStats) UsagePercent() float64 {
	if m.Unlimited || m.MaxBytes == 0 {
		return 0
	}
	return (float64(m.CurrentBytes) / float64(m.MaxBytes)) * 100.0
}

// PSIStats represents Linux Pressure Stall Information for memory.
type PSIStats struct {
	SomeAvg10 float64 `json:"some_avg10"`
	SomeAvg60 float64 `json:"some_avg60"`
	FullAvg10 float64 `json:"full_avg10"`
	FullAvg60 float64 `json:"full_avg60"`
}

// Manager safely manages delegated cgroup v2 subtrees and enforces limits.
type Manager struct {
	Root                 string
	DelegatedSlice       string
	DryRun               bool
	AllowRuntimeOverride bool
	AvailableControllers []string
}

// NewManager constructs a cgroup v2 Manager rooted at caps.CgroupRoot.
func NewManager(caps Capabilities, dryRun, allowRuntimeOverride bool) *Manager {
	return &Manager{
		Root:                 caps.CgroupRoot,
		DelegatedSlice:       DefaultDelegatedSlice,
		DryRun:               dryRun,
		AllowRuntimeOverride: allowRuntimeOverride,
		AvailableControllers: caps.Controllers,
	}
}

// IsRuntimeManaged returns true for cgroup paths owned by init, systemd core, Docker, or Kubernetes.
func IsRuntimeManaged(relPath string) bool {
	norm := strings.Trim(filepath.ToSlash(relPath), "/")
	if norm == "" || norm == "." {
		return true // root cgroup is always protected
	}
	protectedPrefixes := []string{
		"init.scope",
		"system.slice",
		"user.slice",
		"docker",
		"kubepods",
		"kubepods.slice",
	}
	for _, p := range protectedPrefixes {
		if norm == p || strings.HasPrefix(norm, p+"/") {
			return true
		}
	}
	return false
}

// GroupRelPath returns the delegated relative cgroup path for a policy group,
// rejecting path traversal attempts.
func (m *Manager) GroupRelPath(group string) string {
	safe := sanitizeCgroupName(group)
	return filepath.ToSlash(filepath.Join(m.DelegatedSlice, safe))
}

// ValidateRelPath verifies relPath does not contain traversal segments and stays under Root.
func (m *Manager) ValidateRelPath(relPath string) (string, error) {
	if strings.ContainsRune(relPath, 0) {
		return "", fmt.Errorf("invalid cgroup path containing NUL byte")
	}
	clean := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(relPath, "/")))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", fmt.Errorf("unsafe cgroup path traversal %q", relPath)
	}
	abs := filepath.Join(m.Root, clean)
	rootClean := filepath.Clean(m.Root)
	if abs != rootClean && !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
		return "", fmt.Errorf("cgroup path %q escapes root %q", relPath, m.Root)
	}
	return abs, nil
}

// EnsureGroup creates /sys/fs/cgroup/<DelegatedSlice>/<group> and enables required controllers.
func (m *Manager) EnsureGroup(group string, requiredControllers []string) (string, error) {
	rel := m.GroupRelPath(group)
	sliceAbs := filepath.Join(m.Root, m.DelegatedSlice)
	groupAbs := filepath.Join(m.Root, filepath.FromSlash(rel))

	if m.DryRun {
		return rel, nil
	}

	if err := os.MkdirAll(groupAbs, 0o755); err != nil {
		return "", fmt.Errorf("mkdir delegated cgroup %s: %w", groupAbs, err)
	}

	ctrls := m.filterAvailable(requiredControllers)
	if len(ctrls) > 0 {
		if err := enableSubtreeControllers(m.Root, ctrls); err != nil {
			return "", fmt.Errorf("enable root subtree_control: %w", err)
		}
		if err := enableSubtreeControllers(sliceAbs, ctrls); err != nil {
			return "", fmt.Errorf("enable slice subtree_control: %w", err)
		}
	}
	return rel, nil
}

// ApplyLimits writes configured cgroup v2 limits idempotently.
func (m *Manager) ApplyLimits(relPath string, limits Limits) ([]Change, error) {
	abs, err := m.ValidateRelPath(relPath)
	if err != nil {
		return nil, err
	}
	if IsRuntimeManaged(relPath) && !m.AllowRuntimeOverride {
		return nil, fmt.Errorf("refusing to modify runtime-managed cgroup %q without explicit allow_runtime_override authorization", relPath)
	}

	pairs := limitsToControlPairs(limits)
	var changes []Change

	for _, kv := range pairs {
		filePath := filepath.Join(abs, kv.file)
		oldBytes, err := os.ReadFile(filePath)
		oldVal := ""
		if err == nil {
			oldVal = strings.TrimSpace(string(oldBytes))
		} else if !errors.Is(err, os.ErrNotExist) {
			return changes, fmt.Errorf("read %s: %w", filePath, err)
		}

		if oldVal == kv.value {
			continue
		}

		ch := Change{
			CgroupPath: relPath,
			File:       kv.file,
			OldValue:   oldVal,
			NewValue:   kv.value,
			DryRun:     m.DryRun,
		}
		if !m.DryRun {
			if err := os.WriteFile(filePath, []byte(kv.value), 0o644); err != nil {
				return changes, fmt.Errorf("write %s=%q: %w", filePath, kv.value, err)
			}
			ch.Applied = true
		}
		changes = append(changes, ch)
	}
	return changes, nil
}

// MovePID migrates a PID into the target cgroup by writing cgroup.procs.
func (m *Manager) MovePID(relPath string, pid int) error {
	if pid <= 1 {
		return fmt.Errorf("refusing to move protected PID %d", pid)
	}
	abs, err := m.ValidateRelPath(relPath)
	if err != nil {
		return err
	}
	if IsRuntimeManaged(relPath) && !m.AllowRuntimeOverride {
		return fmt.Errorf("refusing to move PID %d into runtime-managed cgroup %q", pid, relPath)
	}
	if m.DryRun {
		return nil
	}
	procsFile := filepath.Join(abs, "cgroup.procs")
	if err := os.WriteFile(procsFile, []byte(strconv.Itoa(pid)), 0o644); err != nil {
		return fmt.Errorf("write %s for pid %d: %w", procsFile, pid, err)
	}
	return nil
}

// ReadMemoryStats reads current memory usage, limits, and memory.events from a cgroup.
func (m *Manager) ReadMemoryStats(relPath string) (MemoryStats, error) {
	abs := filepath.Join(m.Root, filepath.FromSlash(strings.TrimPrefix(relPath, "/")))
	var stats MemoryStats

	if cur, err := readUint64File(filepath.Join(abs, "memory.current")); err == nil {
		stats.CurrentBytes = cur
	} else {
		return stats, err
	}

	if maxRaw, err := os.ReadFile(filepath.Join(abs, "memory.max")); err == nil {
		s := strings.TrimSpace(string(maxRaw))
		if s == "max" {
			stats.Unlimited = true
		} else if v, perr := strconv.ParseUint(s, 10, 64); perr == nil {
			stats.MaxBytes = v
		}
	}

	if highRaw, err := os.ReadFile(filepath.Join(abs, "memory.high")); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(highRaw)), 10, 64); perr == nil {
			stats.HighBytes = v
		}
	}

	if swapCur, err := readUint64File(filepath.Join(abs, "memory.swap.current")); err == nil {
		stats.SwapCurrent = swapCur
	}
	if swapRaw, err := os.ReadFile(filepath.Join(abs, "memory.swap.max")); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(swapRaw)), 10, 64); perr == nil {
			stats.SwapMax = v
		}
	}

	if ev, err := ReadMemoryEvents(filepath.Join(abs, "memory.events")); err == nil {
		stats.Events = ev
	}
	return stats, nil
}

// ReadMemoryEvents parses a cgroup v2 memory.events file.
func ReadMemoryEvents(path string) (MemoryEvents, error) {
	var ev MemoryEvents
	f, err := os.Open(path)
	if err != nil {
		return ev, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "low":
			ev.Low = v
		case "high":
			ev.High = v
		case "max":
			ev.Max = v
		case "oom":
			ev.OOM = v
		case "oom_kill":
			ev.OOMKill = v
		case "oom_group_kill":
			ev.OOMGroupKill = v
		}
	}
	return ev, sc.Err()
}

// ReadPSI parses a Linux PSI memory.pressure file (cgroup or /proc/pressure/memory).
func ReadPSI(path string) (PSIStats, error) {
	var psi PSIStats
	data, err := os.ReadFile(path)
	if err != nil {
		return psi, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kind := fields[0]
		for _, kv := range fields[1:] {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val, err := strconv.ParseFloat(parts[1], 64)
			if err != nil {
				continue
			}
			switch kind + ":" + parts[0] {
			case "some:avg10":
				psi.SomeAvg10 = val
			case "some:avg60":
				psi.SomeAvg60 = val
			case "full:avg10":
				psi.FullAvg10 = val
			case "full:avg60":
				psi.FullAvg60 = val
			}
		}
	}
	return psi, nil
}

type controlPair struct {
	file  string
	value string
}

func limitsToControlPairs(l Limits) []controlPair {
	var pairs []controlPair
	add := func(file, val string) {
		if strings.TrimSpace(val) != "" {
			pairs = append(pairs, controlPair{file: file, value: strings.TrimSpace(val)})
		}
	}
	// Apply memory protection/soft limits before hard limits.
	add("memory.min", l.MemoryMin)
	add("memory.low", l.MemoryLow)
	add("memory.high", l.MemoryHigh)
	add("memory.max", l.MemoryMax)
	add("memory.swap.max", l.MemorySwapMax)
	if l.MemoryOOMGroup != nil {
		if *l.MemoryOOMGroup {
			add("memory.oom.group", "1")
		} else {
			add("memory.oom.group", "0")
		}
	}
	add("cpu.max", l.CPUMax)
	if l.CPUWeight != nil {
		add("cpu.weight", strconv.Itoa(*l.CPUWeight))
	}
	add("io.max", l.IOMax)
	add("pids.max", l.PIDsMax)
	return pairs
}

func (m *Manager) filterAvailable(req []string) []string {
	if len(m.AvailableControllers) == 0 {
		return req
	}
	avail := make(map[string]bool, len(m.AvailableControllers))
	for _, c := range m.AvailableControllers {
		avail[c] = true
	}
	var out []string
	for _, r := range req {
		if avail[r] {
			out = append(out, r)
		}
	}
	return out
}

func enableSubtreeControllers(dir string, ctrls []string) error {
	path := filepath.Join(dir, "cgroup.subtree_control")
	existing := map[string]bool{}
	if b, err := os.ReadFile(path); err == nil {
		for _, f := range strings.Fields(string(b)) {
			existing[f] = true
		}
	}
	var toAdd []string
	for _, c := range ctrls {
		if !existing[c] {
			toAdd = append(toAdd, "+"+c)
		}
	}
	if len(toAdd) == 0 {
		return nil
	}
	return os.WriteFile(path, []byte(strings.Join(toAdd, " ")), 0o644)
}

func readUint64File(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}

func sanitizeCgroupName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}
