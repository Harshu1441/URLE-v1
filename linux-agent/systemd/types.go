package systemd

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ulre/ulre/linux-agent/cgroup"
)

// IOBandwidth matches systemd's D-Bus a(st) structure for IOReadBandwidthMax / IOWriteBandwidthMax.
type IOBandwidth struct {
	Path      string
	Bandwidth uint64
}

// UnitProp represents a typed systemd D-Bus property name/value pair.
type UnitProp struct {
	Name  string
	Value any
}

// RollbackCheckpoint records the prior systemd unit properties before ULRE applied a policy.
type RollbackCheckpoint struct {
	PolicyName       string         `json:"policy_name"`
	UnitName         string         `json:"unit_name"`
	IsTransientScope bool           `json:"is_transient_scope"`
	Previous         map[string]any `json:"previous"`
}

// LimitsToProperties maps ULRE cgroup.Limits fields to systemd D-Bus properties.
func LimitsToProperties(l cgroup.Limits) ([]UnitProp, error) {
	var props []UnitProp

	parseU64 := func(raw string) (uint64, error) {
		s := strings.TrimSpace(raw)
		if s == "max" || s == "infinity" {
			return math.MaxUint64, nil
		}
		return strconv.ParseUint(s, 10, 64)
	}

	hasMem := false
	addU64 := func(prop, raw string) error {
		if strings.TrimSpace(raw) == "" {
			return nil
		}
		v, err := parseU64(raw)
		if err != nil {
			return fmt.Errorf("%s=%q: %w", prop, raw, err)
		}
		hasMem = true
		props = append(props, UnitProp{Name: prop, Value: v})
		return nil
	}

	if err := addU64("MemoryMin", l.MemoryMin); err != nil {
		return nil, err
	}
	if err := addU64("MemoryLow", l.MemoryLow); err != nil {
		return nil, err
	}
	if err := addU64("MemoryHigh", l.MemoryHigh); err != nil {
		return nil, err
	}
	if err := addU64("MemoryMax", l.MemoryMax); err != nil {
		return nil, err
	}
	if err := addU64("MemorySwapMax", l.MemorySwapMax); err != nil {
		return nil, err
	}
	if hasMem {
		props = append(props, UnitProp{Name: "MemoryAccounting", Value: true})
	}

	if strings.TrimSpace(l.CPUMax) != "" {
		fields := strings.Fields(l.CPUMax)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid cpu.max %q (expected '<quota> <period>')", l.CPUMax)
		}
		var quotaUSec uint64 = math.MaxUint64
		if fields[0] != "max" {
			q, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid cpu.max quota %q: %w", fields[0], err)
			}
			p, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || p == 0 {
				return nil, fmt.Errorf("invalid cpu.max period %q", fields[1])
			}
			// systemd CPUQuotaPerSecUSec is microseconds of CPU time per 1s (1_000_000 us).
			quotaUSec = (q * 1_000_000) / p
			if quotaUSec == 0 {
				quotaUSec = 1000
			}
		}
		props = append(props,
			UnitProp{Name: "CPUAccounting", Value: true},
			UnitProp{Name: "CPUQuotaPerSecUSec", Value: quotaUSec},
		)
	}

	if l.CPUWeight != nil {
		if *l.CPUWeight < 1 || *l.CPUWeight > 10000 {
			return nil, fmt.Errorf("cpu.weight %d out of range [1,10000]", *l.CPUWeight)
		}
		props = append(props,
			UnitProp{Name: "CPUAccounting", Value: true},
			UnitProp{Name: "CPUWeight", Value: uint64(*l.CPUWeight)},
		)
	}

	if strings.TrimSpace(l.IOMax) != "" {
		rbps, wbps, err := parseIOMaxToBandwidth(l.IOMax)
		if err != nil {
			return nil, err
		}
		if len(rbps) > 0 || len(wbps) > 0 {
			props = append(props, UnitProp{Name: "IOAccounting", Value: true})
		}
		if len(rbps) > 0 {
			props = append(props, UnitProp{Name: "IOReadBandwidthMax", Value: rbps})
		}
		if len(wbps) > 0 {
			props = append(props, UnitProp{Name: "IOWriteBandwidthMax", Value: wbps})
		}
	}

	if strings.TrimSpace(l.PIDsMax) != "" {
		v, err := parseU64(l.PIDsMax)
		if err != nil {
			return nil, fmt.Errorf("TasksMax=%q: %w", l.PIDsMax, err)
		}
		props = append(props,
			UnitProp{Name: "TasksAccounting", Value: true},
			UnitProp{Name: "TasksMax", Value: v},
		)
	}

	return props, nil
}

// parseIOMaxToBandwidth parses "<dev-or-maj:min> rbps=<N> wbps=<M>" into systemd IOBandwidth slices.
func parseIOMaxToBandwidth(raw string) (rbps, wbps []IOBandwidth, err error) {
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		devPath := resolveBlockDevice(fields[0])
		for _, kv := range fields[1:] {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			var bw uint64 = math.MaxUint64
			if parts[1] != "max" {
				v, perr := strconv.ParseUint(parts[1], 10, 64)
				if perr != nil {
					return nil, nil, fmt.Errorf("invalid io.max value %q: %w", kv, perr)
				}
				bw = v
			}
			switch parts[0] {
			case "rbps":
				rbps = append(rbps, IOBandwidth{Path: devPath, Bandwidth: bw})
			case "wbps":
				wbps = append(wbps, IOBandwidth{Path: devPath, Bandwidth: bw})
			case "riops", "wiops":
				return nil, nil, fmt.Errorf("systemd D-Bus adapter maps rbps/wbps bandwidths; %s is not supported via SetUnitProperties", parts[0])
			}
		}
	}
	return rbps, wbps, nil
}

func resolveBlockDevice(dev string) string {
	if strings.HasPrefix(dev, "/dev/") {
		return dev
	}
	if target, err := os.Readlink(filepath.Join("/sys/dev/block", dev)); err == nil {
		return filepath.Join("/dev", filepath.Base(target))
	}
	return dev
}

// CheckpointStore persists systemd rollback checkpoints under <stateDir>/systemd-checkpoints.json.
type CheckpointStore struct {
	path string
	Data map[string]RollbackCheckpoint
}

func LoadCheckpoints(stateDir string) (*CheckpointStore, error) {
	cs := &CheckpointStore{Data: map[string]RollbackCheckpoint{}}
	if stateDir == "" {
		return cs, nil
	}
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}
	cs.path = filepath.Join(stateDir, "systemd-checkpoints.json")
	if b, err := os.ReadFile(cs.path); err == nil {
		_ = json.Unmarshal(b, &cs.Data)
		if cs.Data == nil {
			cs.Data = map[string]RollbackCheckpoint{}
		}
	}
	return cs, nil
}

func (cs *CheckpointStore) Save() error {
	if cs.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(cs.Data, "", "  ")
	if err != nil {
		return err
	}
	tmp := cs.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, cs.path)
}
