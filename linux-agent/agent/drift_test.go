package agent

import (
	"testing"

	"github.com/ulre/ulre/linux-agent/cgroup"
)

func TestDriftDetectionAndCgroupPathTraversal(t *testing.T) {
	// Drift detection
	applied := map[string]string{"Memory": "67108864", "PidsLimit": "32"}
	actualSame := map[string]string{"Memory": "67108864", "PidsLimit": "32"}
	if diffs := DetectDrift(applied, actualSame); len(diffs) != 0 {
		t.Fatalf("expected no drift, got %v", diffs)
	}
	actualChanged := map[string]string{"Memory": "134217728", "PidsLimit": "32"}
	if diffs := DetectDrift(applied, actualChanged); len(diffs) != 1 {
		t.Fatalf("expected 1 drift diff, got %v", diffs)
	}

	// OwnershipStore persistence
	tmp := t.TempDir()
	st, err := LoadOwnershipStore(tmp)
	if err != nil {
		t.Fatal(err)
	}
	st.Records["docker:abc"] = AppliedRecord{TargetKey: "docker:abc", PolicyName: "p1", Adapter: "docker", Applied: applied}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	st2, err := LoadOwnershipStore(tmp)
	if err != nil || st2.Records["docker:abc"].PolicyName != "p1" {
		t.Fatalf("reload ownership failed: %v %+v", err, st2)
	}

	// Path traversal validation
	mgr := cgroup.NewManager(cgroup.Capabilities{CgroupRoot: tmp}, false, false)
	for _, bad := range []string{"../etc/passwd", "../../root", "ulre.slice/../../escape", "bad\x00path", "/etc"} {
		if _, err := mgr.ApplyLimits(bad, cgroup.Limits{MemoryMax: "1048576"}); err == nil {
			t.Fatalf("expected path traversal rejection for %q", bad)
		}
	}
}
