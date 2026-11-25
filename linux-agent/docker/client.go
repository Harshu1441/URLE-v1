package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ulre/ulre/linux-agent/cgroup"
)

type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

type HostConfig struct {
	Memory            int64 `json:"Memory"`
	MemoryReservation int64 `json:"MemoryReservation"`
	MemorySwap        int64 `json:"MemorySwap"`
	NanoCpus          int64 `json:"NanoCpus"`
	CpuPeriod         int64 `json:"CpuPeriod"`
	CpuQuota          int64 `json:"CpuQuota"`
	CpuShares         int64 `json:"CpuShares"`
	BlkioWeight       int64 `json:"BlkioWeight"`
	PidsLimit         int64 `json:"PidsLimit"`
}

type InspectResponse struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Pid       int    `json:"Pid"`
		StartedAt string `json:"StartedAt"`
	} `json:"State"`
	HostConfig HostConfig `json:"HostConfig"`
}

type Client struct {
	http *http.Client
}

// NewClient returns a Docker Engine Unix socket client.
func NewClient(sockPath string) *Client {
	if sockPath == "" {
		sockPath = "/var/run/docker.sock"
	}
	return &Client{
		http: &http.Client{
			Timeout: 4 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
				},
			},
		},
	}
}

func (c *Client) ListContainers(ctx context.Context) ([]Container, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?all=false", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("docker list status %d", resp.StatusCode)
	}
	var items []Container
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	for i := range items {
		for j := range items[i].Names {
			items[i].Names[j] = strings.TrimPrefix(items[i].Names[j], "/")
		}
	}
	return items, nil
}

func (c *Client) InspectContainer(ctx context.Context, id string) (InspectResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+id+"/json", nil)
	if err != nil {
		return InspectResponse{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return InspectResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return InspectResponse{}, fmt.Errorf("docker inspect %s status %d", id, resp.StatusCode)
	}
	var out InspectResponse
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// DesiredFields converts cgroup.Limits into expected Docker HostConfig values and rejects unsupported fields.
func DesiredFields(lim cgroup.Limits) (map[string]int64, error) {
	var unsupported []string
	if lim.MemoryHigh != "" {
		unsupported = append(unsupported, "memory.high")
	}
	if lim.MemoryMin != "" {
		unsupported = append(unsupported, "memory.min")
	}
	if lim.MemoryOOMGroup != nil {
		unsupported = append(unsupported, "memory.oom.group")
	}
	if lim.IOMax != "" {
		unsupported = append(unsupported, "io.max")
	}
	if len(unsupported) > 0 {
		return nil, fmt.Errorf("docker ContainerUpdate does not support %s", strings.Join(unsupported, ", "))
	}

	out := map[string]int64{}
	if lim.MemoryMax != "" {
		mem, err := strconv.ParseInt(lim.MemoryMax, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid memory.max %q: %w", lim.MemoryMax, err)
		}
		out["Memory"] = mem
		if lim.MemorySwapMax == "0" {
			out["MemorySwap"] = mem
		} else if lim.MemorySwapMax != "" {
			sw, serr := strconv.ParseInt(lim.MemorySwapMax, 10, 64)
			if serr != nil {
				return nil, fmt.Errorf("invalid memory.swap.max %q: %w", lim.MemorySwapMax, serr)
			}
			out["MemorySwap"] = mem + sw
		} else {
			out["MemorySwap"] = mem * 2
		}
	} else if lim.MemorySwapMax != "" {
		return nil, fmt.Errorf("docker ContainerUpdate requires memory.max when setting memory.swap.max")
	}

	if lim.MemoryLow != "" {
		res, err := strconv.ParseInt(lim.MemoryLow, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid memory.low %q: %w", lim.MemoryLow, err)
		}
		out["MemoryReservation"] = res
	}

	if lim.CPUMax != "" {
		fields := strings.Fields(lim.CPUMax)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid cpu.max %q", lim.CPUMax)
		}
		if fields[0] != "max" {
			quota, qerr := strconv.ParseInt(fields[0], 10, 64)
			period, perr := strconv.ParseInt(fields[1], 10, 64)
			if qerr != nil || perr != nil || period <= 0 {
				return nil, fmt.Errorf("invalid cpu.max %q", lim.CPUMax)
			}
			out["CpuPeriod"] = period
			out["CpuQuota"] = quota
		}
	}

	if lim.CPUWeight != nil {
		// Scale cgroup v2 cpu.weight [1..10000] (default 100) to Docker CpuShares [2..262144] (default 1024).
		shares := int64(*lim.CPUWeight) * 1024 / 100
		if shares < 2 {
			shares = 2
		}
		if shares > 262144 {
			shares = 262144
		}
		out["CpuShares"] = shares
	}

	if lim.PIDsMax != "" && lim.PIDsMax != "max" {
		pids, err := strconv.ParseInt(lim.PIDsMax, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid pids.max %q: %w", lim.PIDsMax, err)
		}
		out["PidsLimit"] = pids
	}

	return out, nil
}

// ReadActualMap extracts the current Docker HostConfig fields comparable against DesiredFields.
func ReadActualMap(hc HostConfig) map[string]int64 {
	return map[string]int64{
		"Memory":            hc.Memory,
		"MemoryReservation": hc.MemoryReservation,
		"MemorySwap":        hc.MemorySwap,
		"CpuPeriod":         hc.CpuPeriod,
		"CpuQuota":          hc.CpuQuota,
		"CpuShares":         hc.CpuShares,
		"PidsLimit":         hc.PidsLimit,
	}
}

// UpdateLimits applies supported policy limits through Docker Engine API POST /containers/{id}/update.
func (c *Client) UpdateLimits(ctx context.Context, id string, lim cgroup.Limits) (bool, map[string]int64, error) {
	desired, err := DesiredFields(lim)
	if err != nil {
		return false, nil, err
	}
	if len(desired) == 0 {
		return false, desired, nil
	}

	cur, err := c.InspectContainer(ctx, id)
	if err != nil {
		return false, nil, err
	}
	actual := ReadActualMap(cur.HostConfig)
	payload := map[string]any{}
	changed := false
	for k, want := range desired {
		if actual[k] != want {
			payload[k] = want
			changed = true
		}
	}
	if !changed {
		return false, desired, nil
	}

	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://docker/containers/"+id+"/update", bytes.NewReader(b))
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return false, nil, fmt.Errorf("docker update %s returned %d: %s", id, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return true, desired, nil
}
