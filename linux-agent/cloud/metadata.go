package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Environment describes the detected infrastructure platform without requiring cloud IAM APIs.
type Environment struct {
	Provider     string `json:"provider"` // aws | azure | gcp | vm | bare_metal
	InstanceID   string `json:"instance_id,omitempty"`
	InstanceType string `json:"instance_type,omitempty"`
	Region       string `json:"region,omitempty"`
	Zone         string `json:"zone,omitempty"`
	Vendor       string `json:"vendor,omitempty"`
	Product      string `json:"product,omitempty"`
}

type Endpoints struct {
	AWSBase   string
	AzureBase string
	GCPBase   string
	DMIRoot   string
}

func DefaultEndpoints() Endpoints {
	return Endpoints{
		AWSBase:   "http://169.254.169.254",
		AzureBase: "http://169.254.169.254",
		GCPBase:   "http://metadata.google.internal",
		DMIRoot:   "/sys/class/dmi/id",
	}
}

// DetectEnvironment probes AWS IMDSv2, Azure IMDS, GCP Metadata, and local DMI tables.
func DetectEnvironment(ctx context.Context, ep Endpoints) Environment {
	client := &http.Client{Timeout: 400 * time.Millisecond}

	if env, ok := detectAWS(ctx, client, ep.AWSBase); ok {
		return env
	}
	if env, ok := detectAzure(ctx, client, ep.AzureBase); ok {
		return env
	}
	if env, ok := detectGCP(ctx, client, ep.GCPBase); ok {
		return env
	}
	return detectDMI(ep.DMIRoot)
}

func detectAWS(ctx context.Context, c *http.Client, base string) (Environment, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/latest/api/token", nil)
	if err != nil {
		return Environment{}, false
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return Environment{}, false
	}
	tokBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	_ = resp.Body.Close()

	docReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/latest/dynamic/instance-identity/document", nil)
	docReq.Header.Set("X-aws-ec2-metadata-token", string(tokBytes))
	docResp, err := c.Do(docReq)
	if err != nil || docResp.StatusCode != http.StatusOK {
		if docResp != nil {
			_ = docResp.Body.Close()
		}
		return Environment{}, false
	}
	defer docResp.Body.Close()
	var doc struct {
		InstanceID       string `json:"instanceId"`
		InstanceType     string `json:"instanceType"`
		Region           string `json:"region"`
		AvailabilityZone string `json:"availabilityZone"`
	}
	if json.NewDecoder(docResp.Body).Decode(&doc) != nil || doc.InstanceID == "" {
		return Environment{}, false
	}
	return Environment{
		Provider:     "aws",
		InstanceID:   doc.InstanceID,
		InstanceType: doc.InstanceType,
		Region:       doc.Region,
		Zone:         doc.AvailabilityZone,
	}, true
}

func detectAzure(ctx context.Context, c *http.Client, base string) (Environment, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		return Environment{}, false
	}
	req.Header.Set("Metadata", "true")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return Environment{}, false
	}
	defer resp.Body.Close()
	var doc struct {
		Compute struct {
			VMID     string `json:"vmId"`
			VMSize   string `json:"vmSize"`
			Location string `json:"location"`
			Zone     string `json:"zone"`
		} `json:"compute"`
	}
	if json.NewDecoder(resp.Body).Decode(&doc) != nil || doc.Compute.VMID == "" {
		return Environment{}, false
	}
	return Environment{
		Provider:     "azure",
		InstanceID:   doc.Compute.VMID,
		InstanceType: doc.Compute.VMSize,
		Region:       doc.Compute.Location,
		Zone:         doc.Compute.Zone,
	}, true
}

func detectGCP(ctx context.Context, c *http.Client, base string) (Environment, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/computeMetadata/v1/instance/?recursive=true", nil)
	if err != nil {
		return Environment{}, false
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return Environment{}, false
	}
	defer resp.Body.Close()
	var doc struct {
		ID          any    `json:"id"`
		MachineType string `json:"machineType"`
		Zone        string `json:"zone"`
	}
	if json.NewDecoder(resp.Body).Decode(&doc) != nil || doc.Zone == "" {
		return Environment{}, false
	}
	zoneParts := strings.Split(doc.Zone, "/")
	mtParts := strings.Split(doc.MachineType, "/")
	zone := zoneParts[len(zoneParts)-1]
	region := zone
	if idx := strings.LastIndex(zone, "-"); idx > 0 {
		region = zone[:idx]
	}
	return Environment{
		Provider:     "gcp",
		InstanceType: mtParts[len(mtParts)-1],
		Region:       region,
		Zone:         zone,
	}, true
}

func detectDMI(dmiRoot string) Environment {
	readTrim := func(name string) string {
		b, err := os.ReadFile(dmiRoot + "/" + name)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	vendor := readTrim("sys_vendor")
	product := readTrim("product_name")
	combined := strings.ToLower(vendor + " " + product)
	provider := "bare_metal"
	if strings.Contains(combined, "virtualbox") || strings.Contains(combined, "qemu") ||
		strings.Contains(combined, "kvm") || strings.Contains(combined, "vmware") ||
		strings.Contains(combined, "hyper-v") || strings.Contains(combined, "xen") {
		provider = "vm"
	}
	return Environment{
		Provider: provider,
		Vendor:   vendor,
		Product:  product,
	}
}
