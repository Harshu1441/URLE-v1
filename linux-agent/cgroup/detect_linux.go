//go:build linux

package cgroup

import (
	"os"
	"strings"
	"syscall"
)

const cgroup2SuperMagic = 0x63677270

func detectPlatform(caps *Capabilities) {
	caps.OS = "linux"

	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err == nil {
		b := make([]byte, 0, len(uts.Release))
		for _, c := range uts.Release {
			if c == 0 {
				break
			}
			b = append(b, byte(c))
		}
		caps.KernelVersion = strings.TrimSpace(string(b))
	}

	var st syscall.Statfs_t
	if err := syscall.Statfs(caps.CgroupRoot, &st); err == nil {
		caps.CgroupV2Available = uint64(st.Type) == cgroup2SuperMagic
	}

	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		caps.BTFSupported = true
	}
}
