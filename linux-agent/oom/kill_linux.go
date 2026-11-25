//go:build linux

package oom

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/ulre/ulre/linux-agent/discovery"
)

const pollPRI = 0x0002

type pollFd struct {
	Fd      int32
	Events  int16
	Revents int16
}

// WatchMemoryEvents blocks on Linux POLLPRI notifications on <cgroup>/memory.events
// and emits a signal on the returned channel whenever the kernel updates OOM/pressure counters.
func WatchMemoryEvents(ctx context.Context, memoryEventsPath string) (<-chan struct{}, error) {
	f, err := os.Open(memoryEventsPath)
	if err != nil {
		return nil, err
	}
	// Read initial contents so kernfs POLLPRI only wakes on subsequent counter changes.
	var initBuf [256]byte
	_, _ = f.Read(initBuf[:])

	ch := make(chan struct{}, 1)
	go func() {
		defer f.Close()
		defer close(ch)
		fd := int32(f.Fd())
		for {
			if ctx.Err() != nil {
				return
			}
			pfd := pollFd{Fd: fd, Events: pollPRI}
			n, _, errno := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(&pfd)), 1, 1000)
			if errno != 0 && errno != syscall.EINTR {
				return
			}
			if n > 0 && (pfd.Revents&pollPRI != 0) {
				_, _ = f.Seek(0, 0)
				var buf [256]byte
				_, _ = f.Read(buf[:])
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return ch, nil
}

func terminateProcess(ctx context.Context, scanner *discovery.Scanner, pid int, startTicks uint64, grace time.Duration) error {
	if err := scanner.VerifyIdentity(pid, startTicks); err != nil {
		return err
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("SIGTERM pid %d: %w", pid, err)
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := scanner.VerifyIdentity(pid, startTicks); err != nil {
			return nil // exited cleanly
		}
		time.Sleep(150 * time.Millisecond)
	}
	if err := scanner.VerifyIdentity(pid, startTicks); err != nil {
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("SIGKILL pid %d: %w", pid, err)
	}
	return nil
}
