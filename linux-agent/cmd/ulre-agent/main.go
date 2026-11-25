package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ulre/ulre/linux-agent/agent"
	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/discovery"
	"github.com/ulre/ulre/linux-agent/policy"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "detect":
		err = cmdDetect(os.Args[2:])
	case "discover":
		err = cmdDiscover(os.Args[2:])
	case "validate":
		err = cmdValidate(os.Args[2:])
	case "enforce":
		err = cmdEnforce(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}

	if err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`ulre-agent — Unified Linux Resource Enforcement Agent (Phase 1 MVP)

Usage:
  ulre-agent detect   [--cgroup-root PATH] [--feature-psi] [--feature-ebpf]
  ulre-agent discover [--proc-root PATH] [--tree] [--json]
  ulre-agent validate -c <policies.json>
  ulre-agent enforce  -c <policies.json> [--dry-run] [--once] [--interval 5s] [--state-dir DIR]
  ulre-agent status   [--cgroup-root PATH] [--state-dir DIR]`)
}

func cmdDetect(args []string) error {
	fs := flag.NewFlagSet("detect", flag.ExitOnError)
	cgRoot := fs.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount path")
	flags := cgroup.DefaultFeatureFlags()
	fs.BoolVar(&flags.PSI, "feature-psi", true, "enable PSI memory pressure checks")
	fs.BoolVar(&flags.SystemdScope, "feature-systemd-scope", true, "enable native systemd D-Bus unit/scope enforcement")
	fs.BoolVar(&flags.EBPF, "feature-ebpf", false, "experimental eBPF hook support (Phase 4)")
	_ = fs.Parse(args)

	caps, err := cgroup.Detect(*cgRoot, "", flags)
	if err != nil {
		return err
	}
	return writeJSON(caps)
}

func cmdDiscover(args []string) error {
	fs := flag.NewFlagSet("discover", flag.ExitOnError)
	procRoot := fs.String("proc-root", "/proc", "procfs root path")
	tree := fs.Bool("tree", false, "display process parent-child tree")
	asJSON := fs.Bool("json", false, "output JSON")
	_ = fs.Parse(args)

	procs, err := discovery.NewScanner(*procRoot).Scan()
	if err != nil {
		return err
	}
	if *asJSON {
		if *tree {
			return writeJSON(discovery.BuildTree(procs))
		}
		return writeJSON(procs)
	}
	if *tree {
		for _, root := range discovery.BuildTree(procs) {
			printTree(root, 0)
		}
		return nil
	}
	fmt.Printf("%-7s %-7s %-18s %-12s %-24s %s\n", "PID", "PPID", "COMM", "RUNTIME", "UNIT/CONTAINER", "CGROUP")
	for _, p := range procs {
		id := p.SystemdUnit
		if p.ContainerID != "" && len(p.ContainerID) >= 12 {
			id = p.ContainerID[:12]
		}
		fmt.Printf("%-7d %-7d %-18s %-12s %-24s %s\n", p.PID, p.PPID, p.Comm, p.OwnerRuntime, id, p.CgroupPath)
	}
	return nil
}

func printTree(p *discovery.Process, depth int) {
	indent := strings.Repeat("  ", depth)
	fmt.Printf("%s|- %d %s [%s] (%s)\n", indent, p.PID, p.Comm, p.OwnerRuntime, p.CgroupPath)
	for _, c := range p.Children {
		printTree(c, depth+1)
	}
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("c", "", "policy bundle JSON path")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		return fmt.Errorf("-c <policies.json> is required")
	}
	bundle, err := policy.LoadBundle(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("valid policy bundle: version=%d policies=%d\n", bundle.Version, len(bundle.Policies))
	return nil
}

func cmdEnforce(args []string) error {
	fs := flag.NewFlagSet("enforce", flag.ExitOnError)
	cfgPath := fs.String("c", "", "policy bundle JSON path")
	cgRoot := fs.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 root")
	procRoot := fs.String("proc-root", "/proc", "procfs root")
	stateDir := fs.String("state-dir", "", "local state & audit directory")
	controlPlane := fs.String("control-plane", "", "optional Control Plane URL (e.g. http://192.168.56.1:8080)")
	agentToken := fs.String("agent-token", "ulre-dev-agent-token", "agent authentication token")
	hostname := fs.String("hostname", "", "override reported hostname")
	dryRun := fs.Bool("dry-run", false, "simulate enforcement without writing cgroup files or signaling")
	once := fs.Bool("once", false, "run one reconciliation pass and exit")
	allowOverride := fs.Bool("allow-runtime-override", false, "allow modifying runtime-managed cgroups")
	interval := fs.Duration("interval", 5*time.Second, "reconciliation interval")
	flags := cgroup.DefaultFeatureFlags()
	fs.BoolVar(&flags.PSI, "feature-psi", true, "enable PSI checks")
	fs.BoolVar(&flags.SystemdScope, "feature-systemd-scope", true, "enable native systemd D-Bus unit/scope enforcement")
	_ = fs.Parse(args)

	ag, err := agent.New(agent.Config{
		PolicyPath:           *cfgPath,
		StateDir:             *stateDir,
		CgroupRoot:           *cgRoot,
		ProcRoot:             *procRoot,
		ControlPlaneURL:      *controlPlane,
		AgentToken:           *agentToken,
		Hostname:             *hostname,
		DryRun:               *dryRun,
		AllowRuntimeOverride: *allowOverride,
		Interval:             *interval,
		Flags:                flags,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *once {
		sum, err := ag.ReconcileOnce(ctx)
		if err != nil {
			return err
		}
		return writeJSON(sum)
	}
	return ag.Run(ctx)
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cgRoot := fs.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 root")
	stateDir := fs.String("state-dir", "/var/lib/ulre", "local state directory")
	_ = fs.Parse(args)

	sliceDir := filepath.Join(*cgRoot, cgroup.DefaultDelegatedSlice)
	entries, err := os.ReadDir(sliceDir)
	if err != nil {
		fmt.Printf("no delegated groups found at %s (%v)\n", sliceDir, err)
	} else {
		mgr := cgroup.NewManager(cgroup.Capabilities{CgroupRoot: *cgRoot}, true, false)
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			rel := filepath.ToSlash(filepath.Join(cgroup.DefaultDelegatedSlice, e.Name()))
			st, serr := mgr.ReadMemoryStats(rel)
			if serr != nil {
				continue
			}
			fmt.Printf("%s: current=%d max=%d (%.1f%%) oom=%d oom_kill=%d\n",
				rel, st.CurrentBytes, st.MaxBytes, st.UsagePercent(), st.Events.OOM, st.Events.OOMKill)
		}
	}

	auditFile := filepath.Join(*stateDir, "audit.jsonl")
	if b, err := os.ReadFile(auditFile); err == nil {
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		start := 0
		if len(lines) > 10 {
			start = len(lines) - 10
		}
		fmt.Printf("\nRecent audit records (%s):\n", auditFile)
		for _, l := range lines[start:] {
			fmt.Println(" ", l)
		}
	}
	return nil
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
