package policy

import (
	"testing"

	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/discovery"
)

func TestValidateBundleConflictsAndSafety(t *testing.T) {
	// Reject terminate without allow_destructive.
	bad := Bundle{
		Version: 1,
		Policies: []Policy{{
			Name:        "kill-without-auth",
			Priority:    10,
			Mode:        ModeEnforce,
			Criticality: CritNormal,
			Selectors:   Selectors{ProcessName: "stress"},
			OOM:         OOMPolicy{Actions: []ActionType{ActionTerminate}},
		}},
	}
	if err := ValidateBundle(bad); err == nil {
		t.Fatalf("expected validation error for unauthorized terminate")
	}

	// Reject equal-priority overlapping policies.
	conflict := Bundle{
		Version: 1,
		Policies: []Policy{
			{Name: "p1", Priority: 50, Mode: ModeEnforce, Criticality: CritNormal, Selectors: Selectors{ProcessName: "worker"}},
			{Name: "p2", Priority: 50, Mode: ModeEnforce, Criticality: CritNormal, Selectors: Selectors{SystemdUnit: "worker.service"}},
		},
	}
	if err := ValidateBundle(conflict); err == nil {
		t.Fatalf("expected conflict error for equal-priority overlapping policies")
	}

	// Valid bundle with distinct priorities.
	ok := Bundle{
		Version: 1,
		Policies: []Policy{
			{Name: "p1", Priority: 100, Mode: ModeEnforce, Criticality: CritNormal, Selectors: Selectors{ProcessName: "worker"}, Limits: cgroup.Limits{MemoryMax: "100M"}},
			{Name: "p2", Priority: 50, Mode: ModeDryRun, Criticality: CritBestEffort, AllowDestructive: true, Selectors: Selectors{ProcessName: "batch"}, OOM: OOMPolicy{Actions: []ActionType{ActionAlert, ActionTerminate}}},
		},
	}
	if err := ValidateBundle(ok); err != nil {
		t.Fatalf("expected valid bundle, got %v", err)
	}
}

func TestProtectedAndRuntimeOwnedMatching(t *testing.T) {
	policies := []Policy{{
		Name:        "catch-all-worker",
		Priority:    10,
		Mode:        ModeEnforce,
		Criticality: CritNormal,
		Selectors:   Selectors{ProcessName: "worker"},
	}}

	// PID 1 protected
	if m, reason := MatchProcess(policies, discovery.Process{PID: 1, Comm: "worker"}); m != nil || reason == "" {
		t.Fatalf("PID 1 must be protected")
	}
	// Docker container skipped unless allow_runtime_override=true
	if m, reason := MatchProcess(policies, discovery.Process{PID: 500, Comm: "worker", OwnerRuntime: discovery.RuntimeDocker}); m != nil || reason == "" {
		t.Fatalf("docker workload must be skipped without allow_runtime_override")
	}
	// kubepods / Kubernetes workloads must ALWAYS be skipped, even if allow_runtime_override=true
	overridePol := []Policy{{
		Name:                 "override-all",
		Priority:             100,
		Mode:                 ModeEnforce,
		Criticality:          CritNormal,
		AllowRuntimeOverride: true,
		Selectors:            Selectors{ProcessName: "kube-app"},
	}}
	if m, reason := MatchProcess(overridePol, discovery.Process{PID: 600, Comm: "kube-app", CgroupPath: "/kubepods.slice/kubepods-burstable.slice/pod123.scope", OwnerRuntime: discovery.RuntimeKubernetes}); m != nil || reason != "unsupported: Kubernetes workload" {
		t.Fatalf("expected kubepods workload to be skipped with unsupported reason, got m=%v reason=%q", m, reason)
	}
	for _, unit := range []string{"kubelet.service", "containerd.service", "crio.service", "cri-o.service"} {
		if prot, _ := IsProtectedProcess(discovery.Process{PID: 700, Comm: "daemon", SystemdUnit: unit}); !prot {
			t.Fatalf("expected %s to remain protected", unit)
		}
	}
	// Bare-metal process matches
	if m, _ := MatchProcess(policies, discovery.Process{PID: 501, Comm: "worker", OwnerRuntime: discovery.RuntimeBareMetal}); m == nil || m.Name != "catch-all-worker" {
		t.Fatalf("expected bare-metal process to match")
	}

	// Adapter capability matrix rejects unsupported Docker fields
	dockerBad := Policy{
		Name:                 "docker-bad",
		Priority:             10,
		Mode:                 ModeEnforce,
		Criticality:          CritNormal,
		AllowRuntimeOverride: true,
		Selectors:            Selectors{ContainerID: "abc123"},
		Limits:               cgroup.Limits{MemoryHigh: "1048576", IOMax: "8:0 rbps=100"},
	}
	if errs, _ := CheckAdapterCompatibility(dockerBad, AdapterDocker); len(errs) != 2 {
		t.Fatalf("expected 2 docker compatibility errors, got %v", errs)
	}
}
