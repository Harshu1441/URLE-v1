package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppliedRecord records what ULRE explicitly applied to a managed workload target
// so subsequent ticks detect external drift instead of silently overwriting.
type AppliedRecord struct {
	TargetKey    string            `json:"target_key"`
	PolicyName   string            `json:"policy_name"`
	Adapter      string            `json:"adapter"` // docker | systemd | cgroup
	InstanceID   string            `json:"instance_id,omitempty"`
	Applied      map[string]string `json:"applied"`
	DriftFlagged bool              `json:"drift_flagged,omitempty"`
}

type OwnershipStore struct {
	path    string
	Records map[string]AppliedRecord `json:"records"`
}

func LoadOwnershipStore(stateDir string) (*OwnershipStore, error) {
	osStore := &OwnershipStore{Records: map[string]AppliedRecord{}}
	if stateDir == "" {
		return osStore, nil
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}
	osStore.path = filepath.Join(stateDir, "ownership-state.json")
	if b, err := os.ReadFile(osStore.path); err == nil {
		_ = json.Unmarshal(b, &osStore.Records)
		if osStore.Records == nil {
			osStore.Records = map[string]AppliedRecord{}
		}
	}
	return osStore, nil
}

func (o *OwnershipStore) Save() error {
	if o.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(o.Records, "", "  ")
	if err != nil {
		return err
	}
	tmp := o.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, o.path)
}

// DetectDrift compares previously applied values against actual live values on the same instance.
// Returns a slice of human-readable mismatches (empty if in sync).
func DetectDrift(applied map[string]string, actual map[string]string) []string {
	var diffs []string
	for k, want := range applied {
		if want == "" {
			continue
		}
		got, ok := actual[k]
		if !ok {
			continue
		}
		if strings.TrimSpace(got) != strings.TrimSpace(want) {
			diffs = append(diffs, fmt.Sprintf("%s: expected=%s actual=%s", k, want, got))
		}
	}
	return diffs
}
