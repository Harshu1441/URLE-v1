package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ulre/ulre/linux-agent/cgroup"
)

func TestReconcileOnceEndToEndSysfsAndProcfs(t *testing.T) {
	tmp := t.TempDir()
	cgRoot := filepath.Join(tmp, "cgroup")
	procRoot := filepath.Join(tmp, "proc")
	stateDir := filepath.Join(tmp, "state")

	_ = os.MkdirAll(cgRoot, 0o755)
	_ = os.WriteFile(filepath.Join(cgRoot, "cgroup.controllers"), []byte("cpu memory pids\n"), 0o644)
	_ = os.WriteFile(filepath.Join(cgRoot, "cgroup.subtree_control"), []byte(""), 0o644)

	// Fake bare-metal process 777 named "stress-ng"
	p777 := filepath.Join(procRoot, "777")
	_ = os.MkdirAll(p777, 0o755)
	_ = os.WriteFile(filepath.Join(p777, "stat"), []byte("777 (stress-ng) R 1 1 1 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 12345 1024 10\n"), 0o644)
	_ = os.WriteFile(filepath.Join(p777, "status"), []byte("Uid:\t1000\t1000\nGid:\t1000\t1000\nVmRSS:\t4096 kB\n"), 0o644)
	_ = os.WriteFile(filepath.Join(p777, "cmdline"), []byte("/usr/bin/stress-ng\x00--vm\x001\x00"), 0o644)
	_ = os.WriteFile(filepath.Join(p777, "cgroup"), []byte("0::/user.slice/app\n"), 0o644)

	polPath := filepath.Join(tmp, "policies.json")
	_ = os.WriteFile(polPath, []byte(`{
	  "version": 1,
	  "policies": [{
	    "name": "stress-limit",
	    "group": "stress",
	    "priority": 100,
	    "mode": "enforce",
	    "criticality": "normal",
	    "selectors": {"process_name": "stress-ng"},
	    "limits": {"memory.max": "67108864", "cpu.max": "25000 100000", "pids.max": "32"}
	  }]
	}`), 0o644)

	ag, err := New(Config{
		PolicyPath: polPath,
		StateDir:   stateDir,
		CgroupRoot: cgRoot,
		ProcRoot:   procRoot,
		Flags:      cgroup.DefaultFeatureFlags(),
	})
	if err != nil {
		t.Fatal(err)
	}
	// TempDir resides on host tmpfs/xfs rather than cgroup2fs; mark test fixture as cgroup2-capable.
	ag.caps.CgroupV2Available = true

	sum, err := ag.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.ProcessesScanned != 1 || sum.ProcessesMatched != 1 || sum.ChangesApplied != 3 {
		t.Fatalf("unexpected summary: %+v", sum)
	}

	memMax, _ := os.ReadFile(filepath.Join(cgRoot, "ulre.slice", "stress", "memory.max"))
	if string(memMax) != "67108864" {
		t.Fatalf("expected memory.max=67108864, got %q", string(memMax))
	}
	procs, _ := os.ReadFile(filepath.Join(cgRoot, "ulre.slice", "stress", "cgroup.procs"))
	if string(procs) != "777" {
		t.Fatalf("expected cgroup.procs=777, got %q", string(procs))
	}

	// Verify offline policy cache was written.
	if _, err := os.Stat(filepath.Join(stateDir, "policies.cache.json")); err != nil {
		t.Fatalf("expected offline policy cache: %v", err)
	}
}
