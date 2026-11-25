package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagerApplyLimitsAndSafetyGuards(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory io pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	caps := Capabilities{
		CgroupRoot:  root,
		Controllers: []string{"cpu", "memory", "io", "pids"},
	}
	mgr := NewManager(caps, false, false)

	// Protected runtime-managed cgroup must be rejected without AllowRuntimeOverride.
	if _, err := mgr.ApplyLimits("docker/abc123", Limits{MemoryMax: "1048576"}); err == nil {
		t.Fatalf("expected error modifying docker runtime-managed cgroup")
	}
	if err := mgr.MovePID("ulre.slice/workers", 1); err == nil {
		t.Fatalf("expected error moving PID 1")
	}

	rel, err := mgr.EnsureGroup("workers", []string{"cpu", "memory", "pids"})
	if err != nil {
		t.Fatalf("EnsureGroup failed: %v", err)
	}
	if rel != "ulre.slice/workers" {
		t.Fatalf("unexpected rel path: %s", rel)
	}

	oomGroup := true
	weight := 200
	lim := Limits{
		MemoryMin:      "1048576",
		MemoryLow:      "2097152",
		MemoryHigh:     "4194304",
		MemoryMax:      "8388608",
		MemorySwapMax:  "0",
		MemoryOOMGroup: &oomGroup,
		CPUMax:         "50000 100000",
		CPUWeight:      &weight,
		IOMax:          "8:0 rbps=1048576",
		PIDsMax:        "64",
	}

	changes, err := mgr.ApplyLimits(rel, lim)
	if err != nil {
		t.Fatalf("ApplyLimits failed: %v", err)
	}
	if len(changes) != 10 {
		t.Fatalf("expected 10 cgroup control writes, got %d", len(changes))
	}

	// Second apply must be idempotent (0 changes).
	changes2, err := mgr.ApplyLimits(rel, lim)
	if err != nil {
		t.Fatalf("second ApplyLimits failed: %v", err)
	}
	if len(changes2) != 0 {
		t.Fatalf("expected 0 idempotent changes, got %d", len(changes2))
	}

	// Verify MovePID writes cgroup.procs.
	if err := mgr.MovePID(rel, 4242); err != nil {
		t.Fatalf("MovePID failed: %v", err)
	}
	gotProc, _ := os.ReadFile(filepath.Join(root, "ulre.slice", "workers", "cgroup.procs"))
	if string(gotProc) != "4242" {
		t.Fatalf("expected cgroup.procs=4242, got %q", string(gotProc))
	}
}

func TestReadMemoryStatsAndPSI(t *testing.T) {
	root := t.TempDir()
	grp := filepath.Join(root, "ulre.slice", "app")
	if err := os.MkdirAll(grp, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"memory.current":      "52428800\n",
		"memory.max":          "104857600\n",
		"memory.high":         "83886080\n",
		"memory.swap.current": "1048576\n",
		"memory.swap.max":     "10485760\n",
		"memory.events":       "low 0\nhigh 4\nmax 1\noom 0\noom_kill 0\noom_group_kill 0\n",
		"memory.pressure":     "some avg10=12.50 avg60=3.10 avg300=1.00 total=420\nfull avg10=2.25 avg60=0.50 avg300=0.10 total=90\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(grp, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mgr := NewManager(Capabilities{CgroupRoot: root}, false, false)
	st, err := mgr.ReadMemoryStats("ulre.slice/app")
	if err != nil {
		t.Fatal(err)
	}
	if st.UsagePercent() != 50.0 || st.Events.High != 4 || st.Events.Max != 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}

	psi, err := ReadPSI(filepath.Join(grp, "memory.pressure"))
	if err != nil {
		t.Fatal(err)
	}
	if psi.SomeAvg10 != 12.50 || psi.FullAvg10 != 2.25 {
		t.Fatalf("unexpected PSI: %+v", psi)
	}
}
