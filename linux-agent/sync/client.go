package syncclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ulre/ulre/linux-agent/audit"
	"github.com/ulre/ulre/linux-agent/cgroup"
	"github.com/ulre/ulre/linux-agent/cloud"
	"github.com/ulre/ulre/linux-agent/discovery"
	"github.com/ulre/ulre/linux-agent/policy"
)

type HostPayload struct {
	ID                string            `json:"id,omitempty"`
	Hostname          string            `json:"hostname"`
	MachineID         string            `json:"machine_id"`
	OSName            string            `json:"os_name"`
	KernelVersion     string            `json:"kernel_version"`
	CPUCores          int               `json:"cpu_cores"`
	MemoryBytes       uint64            `json:"memory_bytes"`
	CgroupV2          bool              `json:"cgroup_v2"`
	Controllers       []string          `json:"controllers"`
	PSISupported      bool              `json:"psi_supported"`
	SwapAccounting    bool              `json:"swap_accounting"`
	OOMGroupSupported bool              `json:"oom_group_supported"`
	BTFSupported      bool              `json:"btf_supported"`
	Environment       cloud.Environment `json:"environment"`
	AgentVersion      string            `json:"agent_version"`
}

type WorkloadPayload struct {
	PID            int    `json:"pid"`
	PPID           int    `json:"ppid"`
	StartTimeTicks uint64 `json:"start_time_ticks"`
	Comm           string `json:"comm"`
	Exe            string `json:"exe"`
	Cmdline        string `json:"cmdline"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	CgroupPath     string `json:"cgroup_path"`
	SystemdUnit    string `json:"systemd_unit,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	ContainerImage string `json:"container_image,omitempty"`
	OwnerRuntime   string `json:"owner_runtime"`
	MatchedPolicy  string `json:"matched_policy,omitempty"`
	RSSBytes       uint64 `json:"rss_bytes"`
}

type Client struct {
	baseURL string
	token   string
	http    *http.Client
	hostID  string
}

func NewClient(baseURL, token, caFile, certFile, keyFile string) (*Client, error) {
	tr := &http.Transport{}
	if caFile != "" || (certFile != "" && keyFile != "") {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if caFile != "" {
			caPEM, err := os.ReadFile(caFile)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caPEM)
			tlsCfg.RootCAs = pool
		}
		if certFile != "" && keyFile != "" {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return nil, err
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		tr.TLSClientConfig = tlsCfg
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 8 * time.Second, Transport: tr},
	}, nil
}

func (c *Client) HostID() string { return c.hostID }

func (c *Client) Register(ctx context.Context, caps cgroup.Capabilities, customHostname string) error {
	hostname := customHostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	env := cloud.DetectEnvironment(ctx, cloud.DefaultEndpoints())
	payload := HostPayload{
		Hostname:          hostname,
		MachineID:         readMachineID(hostname),
		OSName:            readOSPrettyName(caps.OS),
		KernelVersion:     caps.KernelVersion,
		CPUCores:          runtime.NumCPU(),
		MemoryBytes:       readMemTotalBytes(),
		CgroupV2:          caps.CgroupV2Available,
		Controllers:       caps.Controllers,
		PSISupported:      caps.PSISupported,
		SwapAccounting:    caps.SwapAccounting,
		OOMGroupSupported: caps.OOMGroupSupported,
		BTFSupported:      caps.BTFSupported,
		Environment:       env,
		AgentVersion:      "0.3.0-connectors",
	}
	var out struct {
		ID         string `json:"id"`
		AgentToken string `json:"agent_token"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/register", payload, &out); err != nil {
		return err
	}
	c.hostID = out.ID
	if out.AgentToken != "" {
		c.token = out.AgentToken
	}
	return nil
}

// RotateToken exchanges the current agent token for a fresh host-bound token.
func (c *Client) RotateToken(ctx context.Context) error {
	if c.hostID == "" {
		return fmt.Errorf("host not registered")
	}
	var out struct {
		AgentToken string `json:"agent_token"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/rotate-token", map[string]string{"host_id": c.hostID}, &out); err != nil {
		return err
	}
	if out.AgentToken != "" {
		c.token = out.AgentToken
	}
	return nil
}

func (c *Client) FetchPolicies(ctx context.Context) (policy.Bundle, []byte, error) {
	if c.hostID == "" {
		return policy.Bundle{}, nil, fmt.Errorf("host not registered")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/agents/"+c.hostID+"/bundle", nil)
	if err != nil {
		return policy.Bundle{}, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return policy.Bundle{}, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return policy.Bundle{}, nil, fmt.Errorf("bundle fetch status %d", resp.StatusCode)
	}
	var rawStruct struct {
		Version  int             `json:"version"`
		Policies []policy.Policy `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawStruct); err != nil {
		return policy.Bundle{}, nil, err
	}
	b := policy.Bundle{Version: rawStruct.Version, Policies: rawStruct.Policies}
	if len(b.Policies) > 0 {
		if err := policy.ValidateBundle(b); err != nil {
			return policy.Bundle{}, nil, err
		}
	}
	rawBytes, _ := json.Marshal(b)
	return b, rawBytes, nil
}

func (c *Client) PushWorkloads(ctx context.Context, procs []discovery.Process, matched map[int]string) error {
	if c.hostID == "" {
		return nil
	}
	items := make([]WorkloadPayload, 0, len(procs))
	for _, p := range procs {
		items = append(items, WorkloadPayload{
			PID:            p.PID,
			PPID:           p.PPID,
			StartTimeTicks: p.StartTimeTicks,
			Comm:           p.Comm,
			Exe:            p.Exe,
			Cmdline:        p.Cmdline,
			UID:            p.UID,
			GID:            p.GID,
			CgroupPath:     p.CgroupPath,
			SystemdUnit:    p.SystemdUnit,
			ContainerID:    p.ContainerID,
			ContainerName:  p.ContainerName,
			ContainerImage: p.ContainerImage,
			OwnerRuntime:   string(p.OwnerRuntime),
			MatchedPolicy:  matched[p.PID],
			RSSBytes:       p.RSSBytes,
		})
	}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agents/"+c.hostID+"/workloads", items, nil)
}

func (c *Client) PushEvents(ctx context.Context, events []audit.Record) error {
	if c.hostID == "" || len(events) == 0 {
		return nil
	}
	return c.doJSON(ctx, http.MethodPost, "/api/v1/agents/"+c.hostID+"/events", events, nil)
}

func (c *Client) doJSON(ctx context.Context, method, path string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s returned %d", method, path, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func readMachineID(fallback string) string {
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return "host-" + fallback
}

func readOSPrettyName(fallback string) string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"\r")
			}
		}
	}
	return fallback
}

func readMemTotalBytes() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return kb * 1024
				}
			}
		}
	}
	return 0
}
