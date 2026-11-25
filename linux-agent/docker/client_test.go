package docker

import (
	"testing"

	"github.com/ulre/ulre/linux-agent/cgroup"
)

func TestDesiredFieldsMappingAndExplicitUnsupportedErrors(t *testing.T) {
	w := 200
	desired, err := DesiredFields(cgroup.Limits{
		MemoryMax:     "134217728",
		MemoryLow:     "33554432",
		MemorySwapMax: "0",
		CPUMax:        "50000 100000",
		CPUWeight:     &w,
		PIDsMax:       "64",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if desired["Memory"] != 134217728 || desired["MemoryReservation"] != 33554432 ||
		desired["MemorySwap"] != 134217728 || desired["CpuQuota"] != 50000 ||
		desired["CpuPeriod"] != 100000 || desired["CpuShares"] != 2048 || desired["PidsLimit"] != 64 {
		t.Fatalf("unexpected Docker fields: %+v", desired)
	}

	// Unsupported fields must fail with explicit errors rather than silent skip.
	oomGrp := true
	badCases := []cgroup.Limits{
		{MemoryHigh: "67108864"},
		{MemoryMin: "16777216"},
		{MemoryOOMGroup: &oomGrp},
		{IOMax: "8:0 rbps=1048576"},
		{MemorySwapMax: "0"}, // without MemoryMax
	}
	for i, bc := range badCases {
		if _, err := DesiredFields(bc); err == nil {
			t.Fatalf("case %d: expected explicit error for unsupported Docker limit %+v", i, bc)
		}
	}
}
