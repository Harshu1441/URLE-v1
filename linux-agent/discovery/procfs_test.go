package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProcfsScanTreeAndIdentityVerification(t *testing.T) {
	proc := t.TempDir()

	writeProc := func(pid, comm, state string, ppid int, start uint64, uid, gid int, cg string, cmd string) {
		dir := filepath.Join(proc, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// 22+ fields after (comm): field 3=state, 4=ppid, ..., 22=starttime (index 19 after ')').
		stat := pid + " (" + comm + ") " + state + " " + itoa(ppid) + " 1 1 0 -1 4194304 10 0 0 0 1 1 0 0 20 0 1 0 " + uitoa(start) + " 1024 10\n"
		_ = os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "status"), []byte("Uid:\t"+itoa(uid)+"\t"+itoa(uid)+"\nGid:\t"+itoa(gid)+"\t"+itoa(gid)+"\nVmRSS:\t2048 kB\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmd), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cg+"\n"), 0o644)
	}

	writeProc("1", "systemd", "S", 0, 1, 0, 0, "/init.scope", "/sbin/init\x00")
	writeProc("100", "worker (v1)", "S", 1, 55500, 1000, 1000, "/system.slice/batch.service", "/usr/bin/worker\x00--fast\x00")
	writeProc("200", "docker-app", "S", 1, 66600, 0, 0, "/system.slice/docker-0123456789abcdef.scope", "/app\x00")
	writeProc("300", "kube-app", "S", 1, 77700, 1000, 1000, "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc123456789.slice/cri-containerd-fedcba9876543210.scope", "/server\x00")

	sc := NewScanner(proc)
	procs, err := sc.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(procs) != 4 {
		t.Fatalf("expected 4 processes, got %d", len(procs))
	}

	// Verify comm with spaces/parens parsed accurately, runtime classified, and RSS converted.
	p100 := procs[1]
	if p100.Comm != "worker (v1)" || p100.StartTimeTicks != 55500 || p100.SystemdUnit != "batch.service" || p100.OwnerRuntime != RuntimeSystemd || p100.RSSBytes != 2048*1024 {
		t.Fatalf("unexpected p100: %+v", p100)
	}
	if procs[2].OwnerRuntime != RuntimeDocker || procs[2].ContainerID != "0123456789abcdef" {
		t.Fatalf("unexpected docker proc: %+v", procs[2])
	}
	if procs[3].OwnerRuntime != RuntimeKubernetes || procs[3].ContainerID != "fedcba9876543210" {
		t.Fatalf("unexpected k8s proc: %+v", procs[3])
	}

	roots := BuildTree(procs)
	if len(roots) != 1 || roots[0].PID != 1 || len(roots[0].Children) != 3 {
		t.Fatalf("unexpected tree roots: %+v", roots)
	}

	if err := sc.VerifyIdentity(100, 55500); err != nil {
		t.Fatalf("expected valid identity: %v", err)
	}
	if err := sc.VerifyIdentity(100, 99999); err == nil {
		t.Fatalf("expected PID reuse error on mismatched start time")
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func uitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
