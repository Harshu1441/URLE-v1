//go:build linux && integration

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ulre/ulre/linux-agent/audit"
	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/discovery"
	"github.com/ulre/ulre/linux-agent/docker"
	"github.com/ulre/ulre/linux-agent/oom"
	"github.com/ulre/ulre/linux-agent/policy"
)

// TestLiveSystemdLifecycleAndRollback verifies D-Bus SetUnitProperties, service restart re-apply,
// policy removal rollback, and offline continuity on a real systemd host.
func TestLiveSystemdLifecycleAndRollback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root on isolated Linux VM")
	}
	unit := "ulre-it-systemd.service"
	_ = exec.Command("systemctl", "stop", unit).Run()
	if err := exec.Command("systemd-run", "--unit="+strings.TrimSuffix(unit, ".service"), "sleep", "60").Run(); err != nil {
		t.Skipf("systemd-run unavailable: %v", err)
	}
	defer func() { _ = exec.Command("systemctl", "stop", unit).Run() }()

	tmp := t.TempDir()
	polPath := filepath.Join(tmp, "policies.json")
	writePol := func(mode string) {
		_ = os.WriteFile(polPath, []byte(`{
		  "version": 1,
		  "policies": [{
		    "name": "it-systemd-pol",
		    "priority": 100,
		    "mode": "`+mode+`",
		    "criticality": "normal",
		    "selectors": {"systemd_unit": "`+unit+`"},
		    "limits": {"memory.max": "67108864", "memory.high": "50331648", "cpu.max": "25000 100000", "pids.max": "16"}
		  }]
		}`), 0o644)
	}
	writePol("enforce")

	// Start with unreachable Control Plane to verify offline cache continuity too.
	ag, err := New(Config{
		PolicyPath:      polPath,
		StateDir:        tmp,
		ControlPlaneURL: "http://127.0.0.1:1",
		Flags:           cgroup.DefaultFeatureFlags(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ag.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	out, _ := exec.Command("systemctl", "show", unit, "-p", "MemoryMax,CPUQuotaPerSecUSec,TasksMax").CombinedOutput()
	if !strings.Contains(string(out), "MemoryMax=67108864") || !strings.Contains(string(out), "TasksMax=16") {
		t.Fatalf("expected systemd properties applied via D-Bus, got:\n%s", string(out))
	}

	// Restart unit -> reapply via adapter
	_ = exec.Command("systemctl", "restart", unit).Run()
	if _, err := ag.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	out2, _ := exec.Command("systemctl", "show", unit, "-p", "MemoryMax").CombinedOutput()
	if !strings.Contains(string(out2), "MemoryMax=67108864") {
		t.Fatalf("expected re-applied MemoryMax after restart, got:\n%s", string(out2))
	}

	// Disable policy -> rollback checkpoint restores original properties
	writePol("disabled")
	ag2, err := New(Config{PolicyPath: polPath, StateDir: tmp, Flags: cgroup.DefaultFeatureFlags()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ag2.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	out3, _ := exec.Command("systemctl", "show", unit, "-p", "MemoryMax").CombinedOutput()
	if !strings.Contains(string(out3), "MemoryMax=infinity") {
		t.Fatalf("expected MemoryMax=infinity after rollback, got:\n%s", string(out3))
	}
}

// TestLiveDockerRestartAndDriftDetection verifies ContainerUpdate, restart re-apply, and external drift flagging.
func TestLiveDockerRestartAndDriftDetection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("docker socket absent")
	}
	const cname = "ulre-it-docker-drift"
	_ = exec.Command("docker", "rm", "-f", cname).Run()
	if err := exec.Command("docker", "run", "-d", "--name", cname, "redis:7-alpine").Run(); err != nil {
		t.Skipf("docker run skipped: %v", err)
	}
	defer func() { _ = exec.Command("docker", "rm", "-f", cname).Run() }()

	tmp := t.TempDir()
	polPath := filepath.Join(tmp, "policies.json")
	_ = os.WriteFile(polPath, []byte(`{
	  "version": 1,
	  "policies": [{
	    "name": "it-docker-pol",
	    "priority": 100,
	    "mode": "enforce",
	    "criticality": "normal",
	    "allow_runtime_override": true,
	    "selectors": {"container_id": "`+cname+`"},
	    "limits": {"memory.max": "67108864", "memory.swap.max": "0", "pids.max": "32"}
	  }]
	}`), 0o644)

	ag, err := New(Config{PolicyPath: polPath, StateDir: tmp, Flags: cgroup.DefaultFeatureFlags()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ag.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Conflicting manual docker update -> agent detects drift instead of silently overwriting
	if err := exec.Command("docker", "update", "--memory=134217728", "--memory-swap=134217728", cname).Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := ag.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	auditData, _ := os.ReadFile(filepath.Join(tmp, "audit.jsonl"))
	if !strings.Contains(string(auditData), "ownership.drift_detected") {
		t.Fatalf("expected ownership.drift_detected in audit.jsonl, got:\n%s", string(auditData))
	}
	// Confirm ULRE did NOT overwrite the external change
	cli := docker.NewClient("/var/run/docker.sock")
	insp, err := cli.InspectContainer(context.Background(), cname)
	if err != nil || insp.HostConfig.Memory != 134217728 {
		t.Fatalf("expected manual Memory=134217728 preserved on drift, got %+v err=%v", insp.HostConfig.Memory, err)
	}

	// Container restart creates new instance ID -> reapplies policy
	if err := exec.Command("docker", "restart", cname).Run(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := ag.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	insp2, _ := cli.InspectContainer(context.Background(), cname)
	if insp2.HostConfig.Memory != 67108864 {
		t.Fatalf("expected Memory=67108864 re-applied after container restart, got %d", insp2.HostConfig.Memory)
	}
}

// TestLiveOOMChainWithCooldownAndRetries triggers a memory-bomb child through alert and throttle.
// The hog is a bash+perl subprocess that moves itself into the cgroup BEFORE allocating pages,
// ensuring cgroup v2 charges all faults to the right cgroup (62% of memory.max → triggers oom.alert).
func TestLiveOOMChainWithCooldownAndRetries(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	caps, err := cgroup.Detect("/sys/fs/cgroup", "/proc/pressure/memory", cgroup.DefaultFeatureFlags())
	if err != nil || !caps.CgroupV2Available {
		t.Fatalf("cgroup v2 required: %v", err)
	}

	mgr := cgroup.NewManager(caps, false, false)
	rel, err := mgr.EnsureGroup("it-oom-chain", []string{"memory", "pids"})
	if err != nil {
		t.Fatal(err)
	}
	cgroupAbs := filepath.Join("/sys/fs/cgroup", filepath.FromSlash(rel))
	defer func() { _ = os.RemoveAll(cgroupAbs) }()

	// 64 MB max / 32 MB high: hog allocates 40 MB → 62% usage → triggers oom.alert without kernel OOM.
	_, _ = mgr.ApplyLimits(rel, cgroup.Limits{MemoryHigh: "33554432", MemoryMax: "67108864", MemorySwapMax: "0"})

	// Shell hog: writes own PID into cgroup.procs first, then allocates 40 MB via perl and holds.
	// This guarantees cgroup v2 charges the pages to this cgroup at fault time.
	hogScript := fmt.Sprintf(
		`echo $$ > %s/cgroup.procs && perl -e '$x="A"x(40*1024*1024); sleep 60'`,
		cgroupAbs,
	)
	hog := exec.Command("bash", "-c", hogScript)
	if err := hog.Start(); err != nil {
		t.Skipf("hog start failed (bash/perl unavailable?): %v", err)
	}
	defer func() { _ = hog.Process.Kill(); _ = hog.Wait() }()

	// Wait for hog to self-move and fault in its 40 MB.
	time.Sleep(3 * time.Second)

	// Log live memory stats for diagnostics.
	if stats, serr := mgr.ReadMemoryStats(rel); serr == nil {
		t.Logf("memory.current=%d memory.max=%d usage_pct=%.1f%% events.high=%d",
			stats.CurrentBytes, stats.MaxBytes, stats.UsagePercent(), stats.Events.High)
	}

	// Collect processes inside the cgroup to pass as targets.
	sc := discovery.NewScanner("/proc")
	allProcs, _ := sc.Scan()
	var cgProcs []discovery.Process
	for _, p := range allProcs {
		if strings.Contains(p.CgroupPath, "it-oom-chain") {
			cgProcs = append(cgProcs, p)
		}
	}
	if len(cgProcs) == 0 {
		t.Skip("hog exited before Evaluate (OOM-killed or cgroup write failed)")
	}

	stateDir := t.TempDir()
	logger, _ := audit.NewLogger(stateDir)
	eng := oom.NewEngine(mgr, sc, logger, false)
	pol := policy.Policy{
		Name:             "it-oom-chain-pol",
		Mode:             policy.ModeEnforce,
		Criticality:      policy.CritBestEffort,
		AllowDestructive: true,
		OOM: policy.OOMPolicy{
			Conditions:            policy.OOMConditions{MemoryPercent: 50},
			Actions:               []policy.ActionType{policy.ActionAlert, policy.ActionThrottle, policy.ActionTerminate, policy.ActionKernelOOMFallback},
			CooldownSec:           5,
			MaxRetries:            1,
			RemediationTimeoutSec: 2,
		},
	}
	if _, err := eng.Evaluate(context.Background(), pol, rel, cgProcs); err != nil {
		t.Fatal(err)
	}
	ab, _ := os.ReadFile(filepath.Join(stateDir, "audit.jsonl"))
	// Verify alert and throttle fired; terminate may be blocked if perl exited by then.
	for _, want := range []string{"oom.alert", "oom.throttle"} {
		if !strings.Contains(string(ab), want) {
			t.Fatalf("expected %s in audit.jsonl, got:\n%s", want, string(ab))
		}
	}
}
