package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ulre/ulre/linux-agent/audit"
	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/discovery"
	"github.com/ulre/ulre/linux-agent/docker"
	"github.com/ulre/ulre/linux-agent/oom"
	"github.com/ulre/ulre/linux-agent/policy"
	syncclient "github.com/ulre/ulre/linux-agent/sync"
	"github.com/ulre/ulre/linux-agent/systemd"
)

// Config controls the Phase 1/2 enforcement agent loop.
type Config struct {
	PolicyPath           string
	StateDir             string
	CgroupRoot           string
	ProcRoot             string
	ControlPlaneURL      string
	AgentToken           string
	Hostname             string
	TLSCA                string
	TLSCert              string
	TLSKey               string
	DryRun               bool
	AllowRuntimeOverride bool
	Interval             time.Duration
	Flags                cgroup.FeatureFlags
}

// ReconcileSummary reports one pass of discovery, cgroup enforcement, and OOM checks.
type ReconcileSummary struct {
	ProcessesScanned int `json:"processes_scanned"`
	ProcessesMatched int `json:"processes_matched"`
	ChangesApplied   int `json:"changes_applied"`
	OOMTriggered     int `json:"oom_triggered"`
}

// Agent coordinates workload discovery, policy enforcement, and OOM remediation.
type Agent struct {
	cfg         Config
	caps        cgroup.Capabilities
	cg          *cgroup.Manager
	scanner     *discovery.Scanner
	dockerCli   *docker.Client
	systemdCli  *systemd.Client
	checkpoints *systemd.CheckpointStore
	ownership   *OwnershipStore
	audit       *audit.Logger
	oomEng      *oom.Engine
	bundle      policy.Bundle
	syncCli     *syncclient.Client
	evMu        sync.Mutex
	pendingEv   []audit.Record
}

// New initializes the Agent, validates capabilities & policy bundle, and caches policy locally.
func New(cfg Config) (*Agent, error) {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	caps, err := cgroup.Detect(cfg.CgroupRoot, "", cfg.Flags)
	if err != nil {
		return nil, err
	}

	var syncCli *syncclient.Client
	var bundle policy.Bundle
	if cfg.ControlPlaneURL != "" {
		syncCli, err = syncclient.NewClient(cfg.ControlPlaneURL, cfg.AgentToken, cfg.TLSCA, cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, err
		}
		if rerr := syncCli.Register(context.Background(), caps, cfg.Hostname); rerr == nil {
			if fetched, raw, ferr := syncCli.FetchPolicies(context.Background()); ferr == nil {
				bundle = fetched
				_ = audit.SavePolicyCache(cfg.StateDir, raw)
			}
		}
	}
	if len(bundle.Policies) == 0 && (cfg.PolicyPath != "" || cfg.StateDir != "") {
		b, lerr := loadPolicyWithOfflineFallback(cfg.PolicyPath, cfg.StateDir)
		if lerr == nil {
			bundle = b
		} else if cfg.ControlPlaneURL == "" {
			return nil, lerr
		}
	}

	logger, err := audit.NewLogger(cfg.StateDir)
	if err != nil {
		return nil, err
	}

	cgMgr := cgroup.NewManager(caps, cfg.DryRun, cfg.AllowRuntimeOverride)
	scanner := discovery.NewScanner(cfg.ProcRoot)
	oomEng := oom.NewEngine(cgMgr, scanner, logger, cfg.DryRun)
	var dockerCli *docker.Client
	var systemdCli *systemd.Client
	if cfg.CgroupRoot == "" || cfg.CgroupRoot == "/sys/fs/cgroup" {
		if _, serr := os.Stat("/var/run/docker.sock"); serr == nil {
			dockerCli = docker.NewClient("/var/run/docker.sock")
		}
		if cfg.Flags.SystemdScope {
			systemdCli, _ = systemd.NewClient(context.Background())
		}
	}
	checkpoints, err := systemd.LoadCheckpoints(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	ownership, err := LoadOwnershipStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}

	ag := &Agent{
		cfg:         cfg,
		caps:        caps,
		cg:          cgMgr,
		scanner:     scanner,
		dockerCli:   dockerCli,
		systemdCli:  systemdCli,
		checkpoints: checkpoints,
		ownership:   ownership,
		audit:       logger,
		oomEng:      oomEng,
		bundle:      bundle,
		syncCli:     syncCli,
	}
	if syncCli != nil {
		logger.OnLog = func(rec audit.Record) {
			ag.evMu.Lock()
			ag.pendingEv = append(ag.pendingEv, rec)
			ag.evMu.Unlock()
		}
	}
	return ag, nil
}

// ReconcileOnce runs a single discovery -> match -> cgroup enforce -> OOM check pass.
func (a *Agent) ReconcileOnce(ctx context.Context) (ReconcileSummary, error) {
	var sum ReconcileSummary

	if !a.caps.CgroupV2Available && !a.cfg.DryRun && a.caps.OS == "linux" {
		return sum, fmt.Errorf("cgroup v2 unified hierarchy not available at %s", a.caps.CgroupRoot)
	}

	// Roll back any systemd unit checkpoints whose policies were removed or disabled.
	if a.systemdCli != nil && a.checkpoints != nil {
		a.rollbackRemovedPolicies(ctx)
	}

	if a.syncCli != nil {
		if a.syncCli.HostID() == "" {
			_ = a.syncCli.Register(ctx, a.caps, a.cfg.Hostname)
		}
		if fetched, raw, ferr := a.syncCli.FetchPolicies(ctx); ferr == nil {
			a.bundle = fetched
			_ = audit.SavePolicyCache(a.cfg.StateDir, raw)
		}
	}

	procs, err := a.scanner.Scan()
	if err != nil {
		return sum, err
	}
	if a.dockerCli != nil {
		if containers, derr := a.dockerCli.ListContainers(ctx); derr == nil {
			byID := make(map[string]docker.Container, len(containers))
			for _, c := range containers {
				byID[c.ID] = c
			}
			for i := range procs {
				if procs[i].ContainerID == "" {
					continue
				}
				if c, ok := byID[procs[i].ContainerID]; ok {
					if len(c.Names) > 0 {
						procs[i].ContainerName = c.Names[0]
					}
					procs[i].ContainerImage = c.Image
				}
			}
		}
	}
	sum.ProcessesScanned = len(procs)

	grouped := map[string][]discovery.Process{}
	policyByGroup := map[string]policy.Policy{}
	matchedByPID := map[int]string{}

	for _, p := range procs {
		pol, reason := policy.MatchProcess(a.bundle.Policies, p)
		if pol == nil {
			if reason == "unsupported: Kubernetes workload" {
				_ = a.audit.Log(audit.Record{
					Action:  "policy.skip_unsupported_k8s",
					Target:  fmt.Sprintf("pid:%d(%s)", p.PID, p.Comm),
					DryRun:  a.cfg.DryRun,
					Result:  "blocked",
					Details: map[string]string{"reason": reason, "cgroup": p.CgroupPath},
				})
			} else if reason != "" && strings.Contains(reason, "skipping") {
				_ = a.audit.Log(audit.Record{
					Action: "policy.skip_runtime_owned",
					Target: fmt.Sprintf("pid:%d(%s)", p.PID, p.Comm),
					DryRun: a.cfg.DryRun,
					Result: "blocked",
					Details: map[string]string{
						"reason": reason,
					},
				})
			}
			continue
		}
		sum.ProcessesMatched++
		matchedByPID[p.PID] = pol.Name

		// Docker containers with allow_runtime_override are enforced via Docker Engine API
		// rather than migrating PIDs out of Docker's managed cgroup subtree.
		if p.OwnerRuntime == discovery.RuntimeDocker && p.ContainerID != "" {
			if a.dockerCli == nil {
				_ = a.audit.Log(audit.Record{
					Action: "docker.error", Policy: pol.Name, Target: p.ContainerID[:min(12, len(p.ContainerID))],
					Result: "error", Details: map[string]string{"error": "docker socket adapter unavailable; failing closed"},
				})
				continue
			}
			dry := a.cfg.DryRun || pol.Mode == policy.ModeDryRun
			if !dry {
				a.enforceDockerWithDrift(ctx, *pol, p, &sum)
			} else {
				if _, cerr := docker.DesiredFields(pol.Limits); cerr != nil {
					_ = a.audit.Log(audit.Record{
						Action: "docker.update_container", Policy: pol.Name, Target: p.ContainerID[:min(12, len(p.ContainerID))],
						DryRun: true, Result: "error", Details: map[string]string{"error": cerr.Error()},
					})
				} else {
					_ = a.audit.Log(audit.Record{
						Action: "docker.update_container", Policy: pol.Name, Target: p.ContainerID[:min(12, len(p.ContainerID))],
						DryRun: true, Result: "dry_run",
					})
				}
			}
			if len(pol.OOM.Actions) > 0 && p.CgroupPath != "" {
				if tr, oerr := a.oomEng.Evaluate(ctx, *pol, p.CgroupPath, []discovery.Process{p}); oerr == nil && tr.Triggered {
					sum.OOMTriggered++
				}
			}
			continue
		}

		// Native systemd D-Bus coordination when enabled:
		// - Existing .service units: SetUnitProperties(runtime=true) with rollback checkpoint (no PID move!).
		// - Non-service bare-metal processes: StartTransientUnit(.scope) under ulre.slice.
		if a.cfg.Flags.SystemdScope && a.systemdCli != nil {
			if err := a.enforceViaSystemd(ctx, *pol, p, &sum); err != nil {
				_ = a.audit.Log(audit.Record{
					Action: "systemd.enforce", Policy: pol.Name, Target: fmt.Sprintf("pid:%d(%s)", p.PID, p.Comm),
					DryRun: a.cfg.DryRun || pol.Mode == policy.ModeDryRun, Result: "error",
					Details: map[string]string{"error": err.Error()},
				})
			}
			continue
		}
		// Fail closed for systemd services if D-Bus adapter is unavailable.
		if p.OwnerRuntime == discovery.RuntimeSystemd && (a.cfg.CgroupRoot == "" || a.cfg.CgroupRoot == "/sys/fs/cgroup") {
			_ = a.audit.Log(audit.Record{
				Action: "systemd.error", Policy: pol.Name, Target: p.SystemdUnit,
				Result: "error", Details: map[string]string{"error": "systemd D-Bus adapter unavailable; failing closed without moving PID"},
			})
			continue
		}

		grp := pol.EffectiveGroup()
		grouped[grp] = append(grouped[grp], p)
		policyByGroup[grp] = *pol
	}

	for grp, members := range grouped {
		pol := policyByGroup[grp]
		dry := a.cfg.DryRun || pol.Mode == policy.ModeDryRun
		mgr := a.cg
		if dry != a.cg.DryRun || pol.AllowRuntimeOverride != a.cg.AllowRuntimeOverride {
			mgr = cgroup.NewManager(a.caps, dry, pol.AllowRuntimeOverride || a.cfg.AllowRuntimeOverride)
		}

		rel, err := mgr.EnsureGroup(grp, pol.Limits.RequiredControllers())
		if err != nil {
			return sum, err
		}

		changes, err := mgr.ApplyLimits(rel, pol.Limits)
		if err != nil {
			return sum, err
		}
		sum.ChangesApplied += len(changes)
		for _, ch := range changes {
			res := "applied"
			if ch.DryRun {
				res = "dry_run"
			}
			_ = a.audit.Log(audit.Record{
				Action: "cgroup.apply_limit",
				Policy: pol.Name,
				Target: ch.CgroupPath,
				DryRun: ch.DryRun,
				Result: res,
				Details: map[string]string{
					"file":      ch.File,
					"old_value": ch.OldValue,
					"new_value": ch.NewValue,
				},
			})
		}

		expectedCgroup := "/" + strings.TrimPrefix(rel, "/")
		for _, p := range members {
			if p.CgroupPath == expectedCgroup {
				continue
			}
			// Re-verify process identity right before writing cgroup.procs (PID reuse safety).
			if err := a.scanner.VerifyIdentity(p.PID, p.StartTimeTicks); err != nil {
				continue
			}
			if err := mgr.MovePID(rel, p.PID); err != nil {
				_ = a.audit.Log(audit.Record{
					Action:  "cgroup.move_pid",
					Policy:  pol.Name,
					Target:  fmt.Sprintf("pid:%d(%s)", p.PID, p.Comm),
					DryRun:  dry,
					Result:  "error",
					Details: map[string]string{"error": err.Error()},
				})
				continue
			}
			res := "applied"
			if dry {
				res = "dry_run"
			}
			_ = a.audit.Log(audit.Record{
				Action:  "cgroup.move_pid",
				Policy:  pol.Name,
				Target:  fmt.Sprintf("pid:%d(%s)", p.PID, p.Comm),
				DryRun:  dry,
				Result:  res,
				Details: map[string]string{"cgroup": rel},
			})
		}

		if len(pol.OOM.Actions) > 0 {
			tr, err := a.oomEng.Evaluate(ctx, pol, rel, members)
			if err == nil && tr.Triggered {
				sum.OOMTriggered++
			}
		}
	}

	// Roll back any systemd unit checkpoints whose policies were removed or disabled.
	if a.systemdCli != nil && a.checkpoints != nil {
		a.rollbackRemovedPolicies(ctx)
	}

	if a.syncCli != nil {
		_ = a.syncCli.PushWorkloads(ctx, procs, matchedByPID)
		a.evMu.Lock()
		batch := a.pendingEv
		a.pendingEv = nil
		a.evMu.Unlock()
		if len(batch) > 0 {
			if perr := a.syncCli.PushEvents(ctx, batch); perr != nil {
				// Requeue unsent events when control plane is temporarily unavailable.
				a.evMu.Lock()
				a.pendingEv = append(batch, a.pendingEv...)
				a.evMu.Unlock()
			}
		}
	}

	return sum, nil
}

// Run loops ReconcileOnce until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if _, err := a.ReconcileOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(a.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := a.ReconcileOnce(ctx); err != nil {
				_ = a.audit.Log(audit.Record{
					Action:  "agent.reconcile_error",
					Target:  "agent",
					DryRun:  a.cfg.DryRun,
					Result:  "error",
					Details: map[string]string{"error": err.Error()},
				})
			}
		}
	}
}

func (a *Agent) enforceViaSystemd(ctx context.Context, pol policy.Policy, p discovery.Process, sum *ReconcileSummary) error {
	props, err := systemd.LimitsToProperties(pol.Limits)
	if err != nil {
		return err
	}
	dry := a.cfg.DryRun || pol.Mode == policy.ModeDryRun
	isService := p.OwnerRuntime == discovery.RuntimeSystemd && strings.HasSuffix(p.SystemdUnit, ".service")

	if isService {
		unit, uerr := a.systemdCli.ResolveUnitByPID(ctx, p.PID)
		if uerr != nil || unit == "" {
			unit = p.SystemdUnit
		}
		if dry {
			_ = a.audit.Log(audit.Record{
				Action: "systemd.set_unit_properties", Policy: pol.Name, Target: unit,
				DryRun: true, Result: "dry_run",
			})
			return nil
		}
		if _, exists := a.checkpoints.Data[unit]; !exists {
			names := make([]string, 0, len(props))
			for _, pr := range props {
				names = append(names, pr.Name)
			}
			if prev, serr := a.systemdCli.SnapshotProperties(ctx, unit, names); serr == nil {
				a.checkpoints.Data[unit] = systemd.RollbackCheckpoint{
					PolicyName: pol.Name,
					UnitName:   unit,
					Previous:   prev,
				}
				_ = a.checkpoints.Save()
			}
		}
		targetKey := "systemd:" + unit
		instID := fmt.Sprintf("pid:%d:%d", p.PID, p.StartTimeTicks)
		desiredStr := propsToStringMap(props)

		if rec, ok := a.ownership.Records[targetKey]; ok && rec.PolicyName == pol.Name && rec.InstanceID == instID && mapsEqual(rec.Applied, desiredStr) {
			// Check for external drift on same unit instance.
			if live, lerr := a.systemdCli.ReadProperties(ctx, unit); lerr == nil {
				actualStr := liveSystemdToStringMap(live, desiredStr)
				if diffs := DetectDrift(rec.Applied, actualStr); len(diffs) > 0 {
					if !rec.DriftFlagged {
						rec.DriftFlagged = true
						a.ownership.Records[targetKey] = rec
						_ = a.ownership.Save()
						_ = a.audit.Log(audit.Record{
							Action: "ownership.drift_detected", Policy: pol.Name, Target: unit,
							Result: "blocked", Details: map[string]string{"drift": strings.Join(diffs, "; ")},
						})
					}
					return nil
				}
			}
			return nil
		}

		if err := a.systemdCli.ApplyToUnit(ctx, unit, props); err != nil {
			return err
		}
		a.ownership.Records[targetKey] = AppliedRecord{
			TargetKey: targetKey, PolicyName: pol.Name, Adapter: "systemd", InstanceID: instID, Applied: desiredStr,
		}
		_ = a.ownership.Save()
		sum.ChangesApplied++
		_ = a.audit.Log(audit.Record{
			Action: "systemd.set_unit_properties", Policy: pol.Name, Target: unit,
			Result: "applied", Details: map[string]string{"runtime": "true"},
		})
		if len(pol.OOM.Actions) > 0 && p.CgroupPath != "" {
			if tr, oerr := a.oomEng.Evaluate(ctx, pol, p.CgroupPath, []discovery.Process{p}); oerr == nil && tr.Triggered {
				sum.OOMTriggered++
			}
		}
		return nil
	}

	// Non-service bare-metal process: place into a transient systemd .scope under ulre.slice.
	scopeName := fmt.Sprintf("ulre-%s-%d.scope", sanitizeScopePart(pol.EffectiveGroup()), p.PID)
	inTargetScope := strings.HasSuffix(p.CgroupPath, "/"+scopeName)
	if dry {
		_ = a.audit.Log(audit.Record{
			Action: "systemd.start_transient_scope", Policy: pol.Name, Target: scopeName,
			DryRun: true, Result: "dry_run",
		})
		return nil
	}
	if err := a.scanner.VerifyIdentity(p.PID, p.StartTimeTicks); err != nil {
		return err
	}
	if !inTargetScope {
		if err := a.systemdCli.StartTransientScope(ctx, scopeName, "ulre.slice", []uint32{uint32(p.PID)}, props); err != nil {
			return err
		}
		a.checkpoints.Data[scopeName] = systemd.RollbackCheckpoint{
			PolicyName:       pol.Name,
			UnitName:         scopeName,
			IsTransientScope: true,
		}
		_ = a.checkpoints.Save()
		sum.ChangesApplied++
		_ = a.audit.Log(audit.Record{
			Action: "systemd.start_transient_scope", Policy: pol.Name, Target: scopeName,
			Result: "applied", Details: map[string]string{"pid": strconv.Itoa(p.PID), "slice": "ulre.slice"},
		})
	} else {
		if err := a.systemdCli.ApplyToUnit(ctx, scopeName, props); err != nil {
			return err
		}
	}
	if len(pol.OOM.Actions) > 0 && p.CgroupPath != "" {
		if tr, oerr := a.oomEng.Evaluate(ctx, pol, p.CgroupPath, []discovery.Process{p}); oerr == nil && tr.Triggered {
			sum.OOMTriggered++
		}
	}
	return nil
}

func (a *Agent) rollbackRemovedPolicies(ctx context.Context) {
	active := map[string]bool{}
	for _, pol := range a.bundle.Policies {
		if pol.Mode != policy.ModeDisabled {
			active[pol.Name] = true
		}
	}
	changed := false
	for key, cp := range a.checkpoints.Data {
		if active[cp.PolicyName] {
			continue
		}
		if !cp.IsTransientScope && len(cp.Previous) > 0 {
			if err := a.systemdCli.RollbackUnit(ctx, cp); err != nil {
				_ = a.audit.Log(audit.Record{
					Action: "systemd.rollback", Policy: cp.PolicyName, Target: cp.UnitName,
					Result: "error", Details: map[string]string{"error": err.Error()},
				})
				continue
			}
			_ = a.audit.Log(audit.Record{
				Action: "systemd.rollback", Policy: cp.PolicyName, Target: cp.UnitName,
				Result: "applied",
			})
		}
		delete(a.checkpoints.Data, key)
		changed = true
	}
	if changed {
		_ = a.checkpoints.Save()
	}
}

func (a *Agent) enforceDockerWithDrift(ctx context.Context, pol policy.Policy, p discovery.Process, sum *ReconcileSummary) {
	shortID := p.ContainerID[:min(12, len(p.ContainerID))]
	desired, err := docker.DesiredFields(pol.Limits)
	if err != nil {
		_ = a.audit.Log(audit.Record{
			Action: "docker.update_container", Policy: pol.Name, Target: shortID,
			Result: "error", Details: map[string]string{"error": err.Error()},
		})
		return
	}
	cur, err := a.dockerCli.InspectContainer(ctx, p.ContainerID)
	if err != nil {
		_ = a.audit.Log(audit.Record{
			Action: "docker.update_container", Policy: pol.Name, Target: shortID,
			Result: "error", Details: map[string]string{"error": err.Error()},
		})
		return
	}
	instID := fmt.Sprintf("%s#%d#%s", p.ContainerID, cur.RestartCount, cur.State.StartedAt)
	desiredStr := int64MapToStrings(desired)
	actualStr := int64MapToStrings(docker.ReadActualMap(cur.HostConfig))
	targetKey := "docker:" + p.ContainerID

	if rec, ok := a.ownership.Records[targetKey]; ok && rec.PolicyName == pol.Name && rec.InstanceID == instID && mapsEqual(rec.Applied, desiredStr) {
		if diffs := DetectDrift(rec.Applied, actualStr); len(diffs) > 0 {
			if !rec.DriftFlagged {
				rec.DriftFlagged = true
				a.ownership.Records[targetKey] = rec
				_ = a.ownership.Save()
				_ = a.audit.Log(audit.Record{
					Action: "ownership.drift_detected", Policy: pol.Name, Target: shortID,
					Result: "blocked", Details: map[string]string{"drift": strings.Join(diffs, "; ")},
				})
			}
		}
		return
	}

	changed, desiredMap, uerr := a.dockerCli.UpdateLimits(ctx, p.ContainerID, pol.Limits)
	if uerr != nil {
		_ = a.audit.Log(audit.Record{
			Action: "docker.update_container", Policy: pol.Name, Target: shortID,
			Result: "error", Details: map[string]string{"error": uerr.Error()},
		})
		return
	}
	a.ownership.Records[targetKey] = AppliedRecord{
		TargetKey: targetKey, PolicyName: pol.Name, Adapter: "docker", InstanceID: instID, Applied: int64MapToStrings(desiredMap),
	}
	_ = a.ownership.Save()
	if changed {
		sum.ChangesApplied++
		_ = a.audit.Log(audit.Record{
			Action: "docker.update_container", Policy: pol.Name, Target: shortID,
			Result: "applied", Details: map[string]string{"memory.max": pol.Limits.MemoryMax, "cpu.max": pol.Limits.CPUMax, "pids.max": pol.Limits.PIDsMax},
		})
	}
}

func int64MapToStrings(m map[string]int64) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = strconv.FormatInt(v, 10)
	}
	return out
}

func propsToStringMap(props []systemd.UnitProp) map[string]string {
	out := make(map[string]string, len(props))
	for _, pr := range props {
		if strings.HasSuffix(pr.Name, "Accounting") {
			continue
		}
		out[pr.Name] = fmt.Sprint(pr.Value)
	}
	return out
}

func liveSystemdToStringMap(live map[string]any, keys map[string]string) map[string]string {
	out := make(map[string]string, len(keys))
	for k := range keys {
		if v, ok := live[k]; ok {
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func sanitizeScopePart(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "workload"
	}
	return b.String()
}

func loadPolicyWithOfflineFallback(policyPath, stateDir string) (policy.Bundle, error) {
	if policyPath != "" {
		raw, err := os.ReadFile(policyPath)
		if err == nil {
			var b policy.Bundle
			if jerr := json.Unmarshal(raw, &b); jerr != nil {
				return b, jerr
			}
			if verr := policy.ValidateBundle(b); verr != nil {
				return b, verr
			}
			_ = audit.SavePolicyCache(stateDir, raw)
			return b, nil
		}
		if stateDir == "" {
			return policy.Bundle{}, err
		}
	}
	if stateDir != "" {
		cachePath := filepath.Join(stateDir, "policies.cache.json")
		if b, err := policy.LoadBundle(cachePath); err == nil {
			return b, nil
		}
	}
	return policy.Bundle{}, fmt.Errorf("no valid policy file or local policy cache found")
}
