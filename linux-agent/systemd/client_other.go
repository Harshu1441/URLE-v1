//go:build !linux

package systemd

import (
	"context"
	"fmt"
	"runtime"
)

type Client struct{}

func NewClient(_ context.Context) (*Client, error) {
	return nil, fmt.Errorf("systemd D-Bus is only available on Linux (current OS: %s)", runtime.GOOS)
}

func (c *Client) Close() {}

func (c *Client) ResolveUnitByPID(_ context.Context, _ int) (string, error) {
	return "", fmt.Errorf("systemd D-Bus unavailable on %s", runtime.GOOS)
}

func (c *Client) SnapshotProperties(_ context.Context, _ string, _ []string) (map[string]any, error) {
	return nil, fmt.Errorf("systemd D-Bus unavailable on %s", runtime.GOOS)
}

func (c *Client) ReadProperties(_ context.Context, _ string) (map[string]any, error) {
	return nil, fmt.Errorf("systemd D-Bus unavailable on %s", runtime.GOOS)
}

func (c *Client) ApplyToUnit(_ context.Context, _ string, _ []UnitProp) error {
	return fmt.Errorf("systemd D-Bus unavailable on %s", runtime.GOOS)
}

func (c *Client) StartTransientScope(_ context.Context, _, _ string, _ []uint32, _ []UnitProp) error {
	return fmt.Errorf("systemd D-Bus unavailable on %s", runtime.GOOS)
}

func (c *Client) RollbackUnit(_ context.Context, _ RollbackCheckpoint) error {
	return fmt.Errorf("systemd D-Bus unavailable on %s", runtime.GOOS)
}
