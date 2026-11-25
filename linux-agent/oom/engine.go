package oom

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ulre/ulre/linux-agent/audit"
	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/discovery"
	"github.com/ulre/ulre/linux-agent/policy"
)

// TriggerReason describes why an OOM policy fired.
type TriggerReason struct {
	Triggered bool
	Reasons   []string
	MemPct    float64
	PSI       cgroup.PSIStats
	Events    cgroup.MemoryEvents
}

type groupState struct {
	prevEvents      cgroup.MemoryEvents
	hasPrev         bool
	violationTimes  []time.Time
	lastActionAt    time.Time
	retriesInWindow int
}

// Engine evaluates cgroup memory/PSI telemetry against OOMPolicy rules and executes remediations.
type Engine struct {
	cg      *cgroup.Manager
	scanner *discovery.Scanner
	audit   *audit.Logger
	dryRun  bool
	nowFn   func() time.Time
	states  map[string]*groupState
}

// NewEngine constructs an OOM remediation Engine.
func NewEngine(cg *cgroup.Manager, scanner *discovery.Scanner, logger *audit.Logger, dryRun bool) *Engine {
	return &Engine{
		cg:      cg,
		scanner: scanner,
		audit:   logger,
		dryRun:  dryRun,
		nowFn:   time.Now,
		states:  map[string]*groupState{},
	}
}

// Evaluate inspects a managed cgroup and runs configured remediation actions if triggered.
func (e *Engine) Evaluate(ctx context.Context, pol policy.Policy, relCgroup string, procs []discovery.Process) (TriggerReason, error) {
	stats, err := e.cg.ReadMemoryStats(relCgroup)
	if err != nil {
		return TriggerReason{}, err
	}
	psiPath := filepath.Join(e.cg.Root, filepath.FromSlash(relCgroup), "memory.pressure")
	psi, _ := cgroup.ReadPSI(psiPath)

	st := e.states[relCgroup]
	if st == nil {
		st = &groupState{}
		e.states[relCgroup] = st
	}

	now := e.nowFn()
	cond := pol.OOM.Conditions
	var reasons []string

	memPct := stats.UsagePercent()
	if cond.MemoryPercent > 0 && memPct >= cond.MemoryPercent {
		reasons = append(reasons, fmt.Sprintf("memory_usage=%.1f%%>=%.1f%%", memPct, cond.MemoryPercent))
	}
	if cond.PSISomeAvg10 > 0 && psi.SomeAvg10 >= cond.PSISomeAvg10 {
		reasons = append(reasons, fmt.Sprintf("psi_some_avg10=%.2f>=%.2f", psi.SomeAvg10, cond.PSISomeAvg10))
	}
	if cond.PSIFullAvg10 > 0 && psi.FullAvg10 >= cond.PSIFullAvg10 {
		reasons = append(reasons, fmt.Sprintf("psi_full_avg10=%.2f>=%.2f", psi.FullAvg10, cond.PSIFullAvg10))
	}
	if cond.SwapPercent > 0 && stats.SwapMax > 0 {
		swapPct := (float64(stats.SwapCurrent) / float64(stats.SwapMax)) * 100.0
		if swapPct >= cond.SwapPercent {
			reasons = append(reasons, fmt.Sprintf("swap_usage=%.1f%%>=%.1f%%", swapPct, cond.SwapPercent))
		}
	}

	if st.hasPrev {
		highDelta := safeDelta(stats.Events.High, st.prevEvents.High)
		maxDelta := safeDelta(stats.Events.Max, st.prevEvents.Max)
		oomDelta := safeDelta(stats.Events.OOM, st.prevEvents.OOM)
		killDelta := safeDelta(stats.Events.OOMKill, st.prevEvents.OOMKill)

		if cond.EventsHighDelta > 0 && highDelta >= cond.EventsHighDelta {
			reasons = append(reasons, fmt.Sprintf("memory.events.high+=%d", highDelta))
		}
		if cond.EventsMaxDelta > 0 && maxDelta >= cond.EventsMaxDelta {
			reasons = append(reasons, fmt.Sprintf("memory.events.max+=%d", maxDelta))
		}
		if cond.EventsOOMDelta > 0 && oomDelta >= cond.EventsOOMDelta {
			reasons = append(reasons, fmt.Sprintf("memory.events.oom+=%d", oomDelta))
		}
		if cond.EventsOOMKillDelta > 0 && killDelta >= cond.EventsOOMKillDelta {
			reasons = append(reasons, fmt.Sprintf("memory.events.oom_kill+=%d", killDelta))
		}
	}
	st.prevEvents = stats.Events
	st.hasPrev = true

	tr := TriggerReason{
		MemPct: memPct,
		PSI:    psi,
		Events: stats.Events,
	}
	if len(reasons) == 0 {
		return tr, nil
	}

	// Track repeated violations within configured window.
	win := time.Duration(cond.ViolationWindowSec) * time.Second
	if win <= 0 {
		win = 60 * time.Second
	}
	st.violationTimes = pruneWindow(append(st.violationTimes, now), now.Add(-win))
	if cond.RepeatedViolations > 1 && len(st.violationTimes) < cond.RepeatedViolations {
		return tr, nil
	}

	tr.Triggered = true
	tr.Reasons = reasons

	cooldown := time.Duration(pol.OOM.CooldownSec) * time.Second
	if cooldown > 0 && !st.lastActionAt.IsZero() && now.Sub(st.lastActionAt) < cooldown {
		return tr, nil
	}

	if pol.OOM.MaxRetries > 0 && st.retriesInWindow >= pol.OOM.MaxRetries {
		_ = e.audit.Log(audit.Record{
			Action: "oom.max_retries_escalate",
			Policy: pol.Name,
			Target: relCgroup,
			DryRun: e.dryRun,
			Result: "blocked",
			Details: map[string]string{
				"reasons": strings.Join(reasons, "; "),
				"retries": strconv.Itoa(st.retriesInWindow),
			},
		})
		return tr, nil
	}

	st.lastActionAt = now
	st.retriesInWindow++

	for _, act := range pol.OOM.Actions {
		if err := e.executeAction(ctx, act, pol, relCgroup, stats, procs, reasons); err != nil {
			return tr, err
		}
	}
	return tr, nil
}

func (e *Engine) executeAction(ctx context.Context, act policy.ActionType, pol policy.Policy, relCgroup string, stats cgroup.MemoryStats, procs []discovery.Process, reasons []string) error {
	dry := e.dryRun || pol.Mode == policy.ModeDryRun
	details := map[string]string{"reasons": strings.Join(reasons, "; ")}
	resStr := "applied"
	if dry {
		resStr = "dry_run"
	}

	switch act {
	case policy.ActionAlert, policy.ActionEscalate:
		return e.audit.Log(audit.Record{
			Action:  "oom." + string(act),
			Policy:  pol.Name,
			Target:  relCgroup,
			DryRun:  dry,
			Result:  resStr,
			Details: details,
		})

	case policy.ActionThrottle:
		base := stats.HighBytes
		if base == 0 {
			base = stats.CurrentBytes
		}
		if base == 0 {
			return nil
		}
		throttled := uint64(float64(base) * 0.85)
		const floor = 4 * 1024 * 1024
		if throttled < floor {
			throttled = floor
		}
		details["new_memory_high"] = strconv.FormatUint(throttled, 10)
		if !dry {
			_, err := e.cg.ApplyLimits(relCgroup, cgroup.Limits{MemoryHigh: strconv.FormatUint(throttled, 10)})
			if err != nil {
				return err
			}
		}
		return e.audit.Log(audit.Record{Action: "oom.throttle", Policy: pol.Name, Target: relCgroup, DryRun: dry, Result: resStr, Details: details})

	case policy.ActionReduceLimits:
		if stats.MaxBytes > 0 {
			reduced := uint64(float64(stats.MaxBytes) * 0.90)
			if reduced < 8*1024*1024 {
				reduced = 8 * 1024 * 1024
			}
			details["new_memory_max"] = strconv.FormatUint(reduced, 10)
			if !dry {
				if _, err := e.cg.ApplyLimits(relCgroup, cgroup.Limits{MemoryMax: strconv.FormatUint(reduced, 10)}); err != nil {
					return err
				}
			}
		}
		return e.audit.Log(audit.Record{Action: "oom.reduce_limits", Policy: pol.Name, Target: relCgroup, DryRun: dry, Result: resStr, Details: details})

	case policy.ActionRestartService:
		unit := pol.Selectors.SystemdUnit
		if unit == "" {
			for _, p := range procs {
				if p.SystemdUnit != "" {
					unit = p.SystemdUnit
					break
				}
			}
		}
		if unit == "" {
			return e.audit.Log(audit.Record{Action: "oom.restart_service", Policy: pol.Name, Target: relCgroup, DryRun: dry, Result: "skipped", Details: map[string]string{"reason": "no systemd unit associated"}})
		}
		details["unit"] = unit
		if !dry {
			timeout := time.Duration(pol.OOM.RemediationTimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 15 * time.Second
			}
			rctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			if err := exec.CommandContext(rctx, "systemctl", "restart", unit).Run(); err != nil {
				_ = e.audit.Log(audit.Record{Action: "oom.restart_service", Policy: pol.Name, Target: unit, DryRun: false, Result: "error", Details: map[string]string{"error": err.Error()}})
				return err
			}
		}
		return e.audit.Log(audit.Record{Action: "oom.restart_service", Policy: pol.Name, Target: unit, DryRun: dry, Result: resStr, Details: details})

	case policy.ActionIsolate:
		qRel, err := e.cg.EnsureGroup("ulre-quarantine", []string{"memory", "cpu", "pids"})
		if err != nil {
			return err
		}
		if !dry {
			_, _ = e.cg.ApplyLimits(qRel, cgroup.Limits{MemoryHigh: "67108864", CPUWeight: intPtr(10)})
			for _, p := range procs {
				if prot, _ := policy.IsProtectedProcess(p); prot {
					continue
				}
				if err := e.scanner.VerifyIdentity(p.PID, p.StartTimeTicks); err == nil {
					_ = e.cg.MovePID(qRel, p.PID)
				}
			}
		}
		details["quarantine_cgroup"] = qRel
		return e.audit.Log(audit.Record{Action: "oom.isolate", Policy: pol.Name, Target: relCgroup, DryRun: dry, Result: resStr, Details: details})

	case policy.ActionTerminate:
		if !pol.AllowDestructive || pol.Criticality == policy.CritCritical {
			return e.audit.Log(audit.Record{Action: "oom.terminate", Policy: pol.Name, Target: relCgroup, DryRun: dry, Result: "blocked", Details: map[string]string{"reason": "destructive action not authorized or workload critical"}})
		}
		victim := selectHighestRSSVictim(procs)
		if victim == nil {
			return nil
		}
		details["pid"] = strconv.Itoa(victim.PID)
		details["comm"] = victim.Comm
		if !dry {
			if err := e.scanner.VerifyIdentity(victim.PID, victim.StartTimeTicks); err != nil {
				return e.audit.Log(audit.Record{Action: "oom.terminate", Policy: pol.Name, Target: relCgroup, DryRun: false, Result: "blocked", Details: map[string]string{"reason": err.Error()}})
			}
			timeout := time.Duration(pol.OOM.RemediationTimeoutSec) * time.Second
			if timeout <= 0 {
				timeout = 5 * time.Second
			}
			if err := terminateProcess(ctx, e.scanner, victim.PID, victim.StartTimeTicks, timeout); err != nil {
				return err
			}
		}
		return e.audit.Log(audit.Record{Action: "oom.terminate", Policy: pol.Name, Target: fmt.Sprintf("pid:%d(%s)", victim.PID, victim.Comm), DryRun: dry, Result: resStr, Details: details})

	case policy.ActionKernelOOMFallback:
		one := true
		if !dry {
			_, _ = e.cg.ApplyLimits(relCgroup, cgroup.Limits{MemoryOOMGroup: &one})
		}
		return e.audit.Log(audit.Record{Action: "oom.kernel_oom_fallback", Policy: pol.Name, Target: relCgroup, DryRun: dry, Result: resStr, Details: details})
	}
	return nil
}

func selectHighestRSSVictim(procs []discovery.Process) *discovery.Process {
	var best *discovery.Process
	for i := range procs {
		if prot, _ := policy.IsProtectedProcess(procs[i]); prot {
			continue
		}
		if best == nil || procs[i].RSSBytes > best.RSSBytes {
			best = &procs[i]
		}
	}
	return best
}

func safeDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

func pruneWindow(ts []time.Time, cutoff time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if !t.Before(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func intPtr(v int) *int { return &v }
