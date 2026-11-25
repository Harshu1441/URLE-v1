package systemd

import (
	"math"
	"testing"

	"github.com/ulre/ulre/linux-agent/cgroup"
)

func TestLimitsToPropertiesAndCheckpoints(t *testing.T) {
	w := 150
	lim := cgroup.Limits{
		MemoryMin:     "1048576",
		MemoryLow:     "2097152",
		MemoryHigh:    "8388608",
		MemoryMax:     "16777216",
		MemorySwapMax: "0",
		CPUMax:        "25000 100000",
		CPUWeight:     &w,
		IOMax:         "/dev/sda rbps=10485760 wbps=5242880",
		PIDsMax:       "64",
	}

	props, err := LimitsToProperties(lim)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]any{}
	for _, p := range props {
		got[p.Name] = p.Value
	}

	if got["MemoryMax"] != uint64(16777216) || got["MemoryHigh"] != uint64(8388608) ||
		got["MemoryLow"] != uint64(2097152) || got["MemoryMin"] != uint64(1048576) ||
		got["MemorySwapMax"] != uint64(0) {
		t.Fatalf("unexpected memory properties: %+v", got)
	}
	if got["CPUQuotaPerSecUSec"] != uint64(250000) || got["CPUWeight"] != uint64(150) {
		t.Fatalf("unexpected CPU properties: %+v", got)
	}
	if got["TasksMax"] != uint64(64) {
		t.Fatalf("unexpected TasksMax: %+v", got["TasksMax"])
	}
	rbps, ok := got["IOReadBandwidthMax"].([]IOBandwidth)
	if !ok || len(rbps) != 1 || rbps[0].Path != "/dev/sda" || rbps[0].Bandwidth != 10485760 {
		t.Fatalf("unexpected IOReadBandwidthMax: %+v", got["IOReadBandwidthMax"])
	}

	// Test "max" -> MaxUint64
	maxProps, err := LimitsToProperties(cgroup.Limits{MemoryMax: "max", PIDsMax: "max"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range maxProps {
		if (p.Name == "MemoryMax" || p.Name == "TasksMax") && p.Value != uint64(math.MaxUint64) {
			t.Fatalf("expected MaxUint64 for %s, got %v", p.Name, p.Value)
		}
	}

	// Test checkpoint store persistence
	tmp := t.TempDir()
	cs, err := LoadCheckpoints(tmp)
	if err != nil {
		t.Fatal(err)
	}
	cs.Data["demo.service"] = RollbackCheckpoint{
		PolicyName: "demo-pol",
		UnitName:   "demo.service",
		Previous:   map[string]any{"MemoryMax": uint64(math.MaxUint64)},
	}
	if err := cs.Save(); err != nil {
		t.Fatal(err)
	}
	cs2, err := LoadCheckpoints(tmp)
	if err != nil || cs2.Data["demo.service"].PolicyName != "demo-pol" {
		t.Fatalf("checkpoint reload failed: %v %+v", err, cs2)
	}
}
