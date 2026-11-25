package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// OwnerRuntime identifies the system or container manager owning a process.
type OwnerRuntime string

const (
	RuntimeBareMetal  OwnerRuntime = "bare_metal"
	RuntimeSystemd    OwnerRuntime = "systemd"
	RuntimeDocker     OwnerRuntime = "docker"
	RuntimeKubernetes OwnerRuntime = "kubernetes"
	RuntimeKernel     OwnerRuntime = "kernel"
)

// Process represents a discovered Linux process with identity and cgroup context.
type Process struct {
	PID            int          `json:"pid"`
	PPID           int          `json:"ppid"`
	StartTimeTicks uint64       `json:"start_time_ticks"`
	Comm           string       `json:"comm"`
	Exe            string       `json:"exe"`
	Cmdline        string       `json:"cmdline"`
	UID            int          `json:"uid"`
	GID            int          `json:"gid"`
	CgroupPath     string       `json:"cgroup_path"`
	SystemdUnit    string       `json:"systemd_unit,omitempty"`
	ContainerID    string       `json:"container_id,omitempty"`
	ContainerName  string       `json:"container_name,omitempty"`
	ContainerImage string       `json:"container_image,omitempty"`
	OwnerRuntime   OwnerRuntime `json:"owner_runtime"`
	RSSBytes       uint64       `json:"rss_bytes"`
	IsKernelThread bool         `json:"is_kernel_thread"`
	Children       []*Process   `json:"children,omitempty"`
}

// Scanner discovers running processes and their cgroup membership from procfs.
type Scanner struct {
	ProcRoot string
}

// NewScanner returns a Scanner reading from /proc (or a custom root for testing).
func NewScanner(procRoot string) *Scanner {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &Scanner{ProcRoot: procRoot}
}

// Scan enumerates all readable processes under ProcRoot.
func (s *Scanner) Scan() ([]Process, error) {
	entries, err := os.ReadDir(s.ProcRoot)
	if err != nil {
		return nil, fmt.Errorf("read proc root %s: %w", s.ProcRoot, err)
	}

	var procs []Process
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, err := s.ReadProcess(pid)
		if err != nil {
			continue // process may have exited mid-scan
		}
		procs = append(procs, p)
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

// ReadProcess inspects /proc/<pid>/{stat,status,cmdline,exe,cgroup}.
func (s *Scanner) ReadProcess(pid int) (Process, error) {
	pidDir := filepath.Join(s.ProcRoot, strconv.Itoa(pid))
	statBytes, err := os.ReadFile(filepath.Join(pidDir, "stat"))
	if err != nil {
		return Process{}, err
	}
	comm, ppid, startTicks, err := parseProcStat(string(statBytes))
	if err != nil {
		return Process{}, err
	}

	p := Process{
		PID:            pid,
		PPID:           ppid,
		StartTimeTicks: startTicks,
		Comm:           comm,
	}

	if statusBytes, err := os.ReadFile(filepath.Join(pidDir, "status")); err == nil {
		p.UID, p.GID, p.RSSBytes = parseProcStatus(string(statusBytes))
	}
	if cmdBytes, err := os.ReadFile(filepath.Join(pidDir, "cmdline")); err == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmdBytes), "\x00", " "))
	}
	if exe, err := os.Readlink(filepath.Join(pidDir, "exe")); err == nil {
		p.Exe = exe
	}
	if cgBytes, err := os.ReadFile(filepath.Join(pidDir, "cgroup")); err == nil {
		p.CgroupPath = parseCgroupV2Path(string(cgBytes))
	}

	if pid == 2 || ppid == 2 || (p.Cmdline == "" && p.Exe == "" && pid != 1) {
		p.IsKernelThread = true
		p.OwnerRuntime = RuntimeKernel
		return p, nil
	}

	p.SystemdUnit, p.ContainerID, p.OwnerRuntime = classifyCgroup(p.CgroupPath)
	return p, nil
}

// VerifyIdentity confirms that pid still exists with the exact expected start time,
// preventing PID-reuse races before cgroup migration or signal delivery.
func (s *Scanner) VerifyIdentity(pid int, expectedStartTicks uint64) error {
	statBytes, err := os.ReadFile(filepath.Join(s.ProcRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return fmt.Errorf("process %d no longer accessible: %w", pid, err)
	}
	_, _, actual, err := parseProcStat(string(statBytes))
	if err != nil {
		return err
	}
	if actual != expectedStartTicks {
		return fmt.Errorf("PID %d was reused (expected start=%d, got=%d)", pid, expectedStartTicks, actual)
	}
	return nil
}

// BuildTree links discovered processes by PPID and returns top-level roots.
func BuildTree(procs []Process) []*Process {
	byPID := make(map[int]*Process, len(procs))
	ordered := make([]*Process, 0, len(procs))
	for i := range procs {
		cp := procs[i]
		cp.Children = nil
		byPID[cp.PID] = &cp
		ordered = append(ordered, &cp)
	}
	var roots []*Process
	for _, p := range ordered {
		if parent, ok := byPID[p.PPID]; ok && p.PPID != p.PID {
			parent.Children = append(parent.Children, p)
		} else {
			roots = append(roots, p)
		}
	}
	return roots
}

// parseProcStat parses /proc/<pid>/stat safely even if comm contains spaces or ')'.
// Field layout (1-indexed): 1=pid, 2=(comm), 3=state, 4=ppid, ..., 22=starttime.
func parseProcStat(raw string) (comm string, ppid int, startTime uint64, err error) {
	open := strings.IndexByte(raw, '(')
	closeIdx := strings.LastIndexByte(raw, ')')
	if open < 0 || closeIdx <= open {
		return "", 0, 0, fmt.Errorf("malformed /proc/pid/stat")
	}
	comm = raw[open+1 : closeIdx]
	rest := strings.Fields(raw[closeIdx+1:])
	// rest[0] is field 3 (state); rest[1] is field 4 (ppid); rest[19] is field 22 (starttime).
	if len(rest) < 20 {
		return "", 0, 0, fmt.Errorf("truncated /proc/pid/stat: %d fields after comm", len(rest))
	}
	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid ppid %q: %w", rest[1], err)
	}
	startTime, err = strconv.ParseUint(rest[19], 10, 64)
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid starttime %q: %w", rest[19], err)
	}
	return comm, ppid, startTime, nil
}

func parseProcStatus(raw string) (uid, gid int, rssBytes uint64) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			uid, _ = strconv.Atoi(fields[1])
		case "Gid:":
			gid, _ = strconv.Atoi(fields[1])
		case "VmRSS:":
			if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				rssBytes = kb * 1024
			}
		}
	}
	return uid, gid, rssBytes
}

func parseCgroupV2Path(raw string) string {
	var fallback string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		// Unified cgroup v2 entry is "0::<path>"
		if strings.HasPrefix(line, "0::") {
			return strings.TrimSpace(strings.TrimPrefix(line, "0::"))
		}
		// Fallback on cgroup v1 / hybrid hosts so discovery still identifies systemd/docker/k8s paths.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[2] != "" {
			if strings.Contains(parts[1], "systemd") || strings.Contains(parts[1], "memory") {
				fallback = strings.TrimSpace(parts[2])
			} else if fallback == "" {
				fallback = strings.TrimSpace(parts[2])
			}
		}
	}
	return fallback
}

func classifyCgroup(cgPath string) (unit, containerID string, runtime OwnerRuntime) {
	if cgPath == "" || cgPath == "/" {
		return "", "", RuntimeBareMetal
	}
	segs := strings.Split(strings.Trim(cgPath, "/"), "/")
	for _, seg := range segs {
		if strings.HasPrefix(seg, "kubepods") || strings.Contains(seg, "-pod") {
			runtime = RuntimeKubernetes
		}
		if strings.HasPrefix(seg, "docker-") && strings.HasSuffix(seg, ".scope") {
			containerID = strings.TrimSuffix(strings.TrimPrefix(seg, "docker-"), ".scope")
			if runtime == "" {
				runtime = RuntimeDocker
			}
		} else if strings.HasPrefix(seg, "cri-containerd-") && strings.HasSuffix(seg, ".scope") {
			containerID = strings.TrimSuffix(strings.TrimPrefix(seg, "cri-containerd-"), ".scope")
			if runtime == "" {
				runtime = RuntimeKubernetes
			}
		} else if strings.HasPrefix(seg, "crio-") && strings.HasSuffix(seg, ".scope") {
			containerID = strings.TrimSuffix(strings.TrimPrefix(seg, "crio-"), ".scope")
			if runtime == "" {
				runtime = RuntimeKubernetes
			}
		} else if seg == "docker" {
			if runtime == "" {
				runtime = RuntimeDocker
			}
		}
		if strings.HasSuffix(seg, ".service") || seg == "init.scope" {
			unit = seg
		}
	}
	if runtime == "" {
		if unit != "" {
			runtime = RuntimeSystemd
		} else {
			runtime = RuntimeBareMetal
		}
	}
	return unit, containerID, runtime
}
