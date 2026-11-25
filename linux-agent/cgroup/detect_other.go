//go:build !linux

package cgroup

import "runtime"

func detectPlatform(caps *Capabilities) {
	caps.OS = runtime.GOOS
	caps.KernelVersion = "unavailable-on-" + runtime.GOOS
	caps.CgroupV2Available = false
}
