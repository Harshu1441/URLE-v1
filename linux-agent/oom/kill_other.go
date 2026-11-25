//go:build !linux

package oom

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/ulre/ulre/linux-agent/discovery"
)

func WatchMemoryEvents(_ context.Context, _ string) (<-chan struct{}, error) {
	return nil, fmt.Errorf("memory.events POLLPRI is only supported on Linux (current OS: %s)", runtime.GOOS)
}

func terminateProcess(_ context.Context, _ *discovery.Scanner, pid int, _ uint64, _ time.Duration) error {
	return fmt.Errorf("cannot send POSIX SIGTERM/SIGKILL to pid %d on non-Linux OS (%s)", pid, runtime.GOOS)
}
