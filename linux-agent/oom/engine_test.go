package oom

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ulre/ulre/linux-agent/audit"
	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/discovery"
	"github.com/ulre/ulre/linux-agent/policy"
)

func TestEngineRepeatedViolationsThrottleAndCooldown(t *testing.T) {
	root := t.TempDir()
	grp := filepath.Join(root, "ulre.slice", "batch")
	if err := os.MkdirAll(grp, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(grp, "memory.current"), []byte("90000000"), 0o644)
	_ = os.WriteFile(filepath.Join(grp, "memory.max"), []byte("100000000"), 0o644)
	_ = os.WriteFile(filepath.Join(grp, "memory.high"), []byte("80000000"), 0o644)
	_ = os.WriteFile(filepath.Join(grp, "memory.events"), []byte("high 1\nmax 0\noom 0\noom_kill 0\n"), 0o644)
	_ = os.WriteFile(filepath.Join(grp, "memory.pressure"), []byte("some avg10=20.00 avg60=5.00\n"), 0o644)

	stateDir := t.TempDir()
	logger, err := audit.NewLogger(stateDir)
	if err != nil {
		t.Fatal(err)
	}

	mgr := cgroup.NewManager(cgroup.Capabilities{CgroupRoot: root}, false, false)
	eng := NewEngine(mgr, discovery.NewScanner(t.TempDir()), logger, false)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	eng.nowFn = func() time.Time { return now }

	pol := policy.Policy{
		Name:        "batch-oom",
		Mode:        policy.ModeEnforce,
		Criticality: policy.CritNormal,
		OOM: policy.OOMPolicy{
			Conditions: policy.OOMConditions{
				MemoryPercent:      85,
				PSISomeAvg10:       15,
				RepeatedViolations: 2,
				ViolationWindowSec: 60,
			},
			Actions:     []policy.ActionType{policy.ActionAlert, policy.ActionThrottle},
			CooldownSec: 30,
			MaxRetries:  2,
		},
	}

	// 1st violation: does not trigger yet (RepeatedViolations=2).
	tr1, err := eng.Evaluate(context.Background(), pol, "ulre.slice/batch", nil)
	if err != nil || tr1.Triggered {
		t.Fatalf("expected no trigger on 1st violation, got tr=%+v err=%v", tr1, err)
	}

	// 2nd violation 5s later: triggers alert + throttle (80MB * 0.85 = 68MB).
	now = now.Add(5 * time.Second)
	tr2, err := eng.Evaluate(context.Background(), pol, "ulre.slice/batch", nil)
	if err != nil || !tr2.Triggered {
		t.Fatalf("expected trigger on 2nd violation, got tr=%+v err=%v", tr2, err)
	}

	gotHigh, _ := os.ReadFile(filepath.Join(grp, "memory.high"))
	if string(gotHigh) != "68000000" {
		t.Fatalf("expected throttled memory.high=68000000, got %q", string(gotHigh))
	}

	// 3rd violation 5s later (inside 30s cooldown): throttled by cooldown so memory.high stays 68000000.
	now = now.Add(5 * time.Second)
	_, err = eng.Evaluate(context.Background(), pol, "ulre.slice/batch", nil)
	if err != nil {
		t.Fatal(err)
	}
	gotHigh2, _ := os.ReadFile(filepath.Join(grp, "memory.high"))
	if string(gotHigh2) != "68000000" {
		t.Fatalf("expected cooldown to skip repeat throttle, got %q", string(gotHigh2))
	}
}
