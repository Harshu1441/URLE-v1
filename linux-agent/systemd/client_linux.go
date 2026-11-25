//go:build linux

package systemd

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

// Client manages systemd units and transient scopes over the system D-Bus socket.
type Client struct {
	conn *dbus.Conn
}

func NewClient(ctx context.Context) (*Client, error) {
	c, err := dbus.NewSystemConnectionContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("connect systemd D-Bus: %w", err)
	}
	return &Client{conn: c}, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// ResolveUnitByPID resolves a PID to its systemd unit via D-Bus GetUnitNameByPID,
// falling back to /proc/<pid>/cgroup if D-Bus lookup fails.
func (c *Client) ResolveUnitByPID(ctx context.Context, pid int) (string, error) {
	if unit, err := c.conn.GetUnitNameByPID(ctx, uint32(pid)); err == nil && unit != "" {
		return unit, nil
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, "0::") {
			cg := strings.TrimPrefix(line, "0::")
			parts := strings.Split(strings.Trim(cg, "/"), "/")
			for i := len(parts) - 1; i >= 0; i-- {
				if strings.HasSuffix(parts[i], ".service") || strings.HasSuffix(parts[i], ".scope") {
					return parts[i], nil
				}
			}
		}
	}
	return "", fmt.Errorf("pid %d has no systemd unit", pid)
}

// SnapshotProperties reads the current property values of a unit before ULRE modifies them.
func (c *Client) SnapshotProperties(ctx context.Context, unitName string, propNames []string) (map[string]any, error) {
	all, err := c.getUnitTypedProps(ctx, unitName)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(propNames))
	for _, name := range propNames {
		if v, ok := all[name]; ok {
			out[name] = v
		}
	}
	return out, nil
}

// ReadProperties returns live systemd D-Bus property values for drift comparison.
func (c *Client) ReadProperties(ctx context.Context, unitName string) (map[string]any, error) {
	return c.getUnitTypedProps(ctx, unitName)
}

// ApplyToUnit applies properties to an existing unit with runtime=true (no permanent disk mutation).
func (c *Client) ApplyToUnit(ctx context.Context, unitName string, props []UnitProp) error {
	if len(props) == 0 {
		return nil
	}
	return c.conn.SetUnitPropertiesContext(ctx, unitName, true, toDBusProps(props)...)
}

// StartTransientScope creates a transient systemd scope under slice (e.g. ulre.slice)
// wrapping the given PIDs instead of manually creating cgroup directories.
func (c *Client) StartTransientScope(ctx context.Context, scopeName, slice string, pids []uint32, props []UnitProp) error {
	if !strings.HasSuffix(scopeName, ".scope") {
		scopeName += ".scope"
	}
	if slice == "" {
		slice = "ulre.slice"
	}
	all := []dbus.Property{
		dbus.PropDescription("ULRE Managed Workload Scope: " + scopeName),
		dbus.PropSlice(slice),
		dbus.PropPids(pids...),
	}
	all = append(all, toDBusProps(props)...)

	done := make(chan string, 1)
	if _, err := c.conn.StartTransientUnitContext(ctx, scopeName, "replace", all, done); err != nil {
		return fmt.Errorf("StartTransientUnit(%s): %w", scopeName, err)
	}
	select {
	case res := <-done:
		if res != "done" {
			return fmt.Errorf("StartTransientUnit(%s) job status=%s", scopeName, res)
		}
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// RollbackUnit restores saved prior property values (or clears limits on transient scopes).
func (c *Client) RollbackUnit(ctx context.Context, cp RollbackCheckpoint) error {
	if len(cp.Previous) == 0 {
		return nil
	}
	var restore []dbus.Property
	for k, raw := range cp.Previous {
		if k == "MemoryAccounting" || k == "CPUAccounting" || k == "IOAccounting" || k == "TasksAccounting" {
			continue
		}
		if v, ok := coerceDBusRestoreValue(k, raw); ok {
			restore = append(restore, dbus.Property{Name: k, Value: godbus.MakeVariant(v)})
		}
	}
	if len(restore) == 0 {
		return nil
	}
	return c.conn.SetUnitPropertiesContext(ctx, cp.UnitName, true, restore...)
}

func (c *Client) getUnitTypedProps(ctx context.Context, unitName string) (map[string]any, error) {
	unitType := "Service"
	switch {
	case strings.HasSuffix(unitName, ".scope"):
		unitType = "Scope"
	case strings.HasSuffix(unitName, ".slice"):
		unitType = "Slice"
	}
	return c.conn.GetUnitTypePropertiesContext(ctx, unitName, unitType)
}

func toDBusProps(props []UnitProp) []dbus.Property {
	out := make([]dbus.Property, 0, len(props))
	for _, p := range props {
		out = append(out, dbus.Property{Name: p.Name, Value: godbus.MakeVariant(p.Value)})
	}
	return out
}

func coerceDBusRestoreValue(name string, raw any) (any, bool) {
	toU64 := func(v any) (uint64, bool) {
		switch n := v.(type) {
		case uint64:
			return n, true
		case float64:
			if n < 0 || n >= 1.844674407370955e+19 {
				return math.MaxUint64, true
			}
			return uint64(n), true
		case int:
			if n < 0 {
				return math.MaxUint64, true
			}
			return uint64(n), true
		}
		return 0, false
	}

	switch name {
	case "CPUWeight":
		if u, ok := toU64(raw); ok {
			if u < 1 || u > 10000 {
				return uint64(100), true // systemd default weight when unset
			}
			return u, true
		}
	case "MemoryMin", "MemoryLow", "MemoryHigh", "MemoryMax", "MemorySwapMax", "CPUQuotaPerSecUSec", "TasksMax":
		return toU64(raw)
	case "IOReadBandwidthMax", "IOWriteBandwidthMax":
		if list, ok := raw.([]IOBandwidth); ok {
			return list, true
		}
		return []IOBandwidth{}, true
	}
	_ = filepath.Separator
	return nil, false
}
