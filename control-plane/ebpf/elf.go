package ebpf

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const elfMachineBPF = elf.Machine(247) // EM_BPF

type ProgramRecord struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Version      int        `json:"version"`
	SHA256       string     `json:"sha256"`
	SizeBytes    int        `json:"size_bytes"`
	ProgramType  string     `json:"program_type"`
	AttachTarget string     `json:"attach_target"`
	Sections     []string   `json:"sections"`
	MapSections  []string   `json:"map_sections"`
	HasBTF       bool       `json:"has_btf"`
	MinKernel    string     `json:"min_kernel"`
	Status       string     `json:"status"` // pending_approval | approved | deployed_staged | rolled_back | rejected
	VerifierNote string     `json:"verifier_note,omitempty"`
	ApprovedBy   string     `json:"approved_by,omitempty"`
	ApprovedAt   *time.Time `json:"approved_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// InspectELF parses a compiled eBPF ELF object (.o) using Go's debug/elf
// and extracts real sections, BTF presence, map sections, and kernel requirements.
func InspectELF(name string, raw []byte) (ProgramRecord, error) {
	if len(raw) == 0 {
		return ProgramRecord{}, fmt.Errorf("empty eBPF object")
	}
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])

	ef, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return ProgramRecord{}, fmt.Errorf("invalid ELF object: %w", err)
	}
	defer ef.Close()

	if ef.Machine != elfMachineBPF {
		return ProgramRecord{}, fmt.Errorf("ELF machine is %v, expected EM_BPF (247)", ef.Machine)
	}

	var sections []string
	var mapSections []string
	var hasBTF bool
	progType := "unknown"
	attachTarget := ""
	minKernel := "5.8"

	for _, s := range ef.Sections {
		if s.Name == "" {
			continue
		}
		sections = append(sections, s.Name)
		switch {
		case s.Name == ".BTF":
			hasBTF = true
		case s.Name == "maps" || s.Name == ".maps":
			mapSections = append(mapSections, s.Name)
		case strings.HasPrefix(s.Name, "kprobe/") || strings.HasPrefix(s.Name, "kretprobe/"):
			progType = "kprobe"
			attachTarget = s.Name
		case strings.HasPrefix(s.Name, "tracepoint/") || strings.HasPrefix(s.Name, "tp/"):
			progType = "tracepoint"
			attachTarget = s.Name
		case strings.HasPrefix(s.Name, "cgroup/"):
			progType = "cgroup_skb_or_sock"
			attachTarget = s.Name
		case strings.HasPrefix(s.Name, "lsm/"):
			progType = "lsm"
			attachTarget = s.Name
			minKernel = "5.7"
		case strings.HasPrefix(s.Name, "xdp"):
			progType = "xdp"
			attachTarget = s.Name
		case strings.HasPrefix(s.Name, "fentry/") || strings.HasPrefix(s.Name, "fexit/"):
			progType = "tracing"
			attachTarget = s.Name
			minKernel = "5.5"
		}
	}

	if progType == "unknown" {
		return ProgramRecord{}, fmt.Errorf("no recognized BPF program section (kprobe/, tracepoint/, cgroup/, lsm/, xdp, fentry/) found in ELF")
	}
	if !hasBTF {
		minKernel = "4.18 (non-CO-RE)"
	}

	return ProgramRecord{
		Name:         name,
		SHA256:       sha,
		SizeBytes:    len(raw),
		ProgramType:  progType,
		AttachTarget: attachTarget,
		Sections:     sections,
		MapSections:  mapSections,
		HasBTF:       hasBTF,
		MinKernel:    minKernel,
		Status:       "pending_approval",
		VerifierNote: "ELF validated; awaiting kernel_admin approval and Phase 4 host bpf() loader",
		CreatedAt:    time.Now().UTC(),
	}, nil
}
