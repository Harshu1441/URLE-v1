package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDetectEnvironmentProviders(t *testing.T) {
	// 1. AWS IMDSv2
	awsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/api/token":
			_, _ = w.Write([]byte("imds-tok"))
		case "/latest/dynamic/instance-identity/document":
			if r.Header.Get("X-aws-ec2-metadata-token") != "imds-tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"instanceId":"i-0abc123","instanceType":"m6i.large","region":"us-east-1","availabilityZone":"us-east-1a"}`))
		}
	}))
	defer awsSrv.Close()

	env := DetectEnvironment(context.Background(), Endpoints{AWSBase: awsSrv.URL, AzureBase: "http://127.0.0.1:1", GCPBase: "http://127.0.0.1:1"})
	if env.Provider != "aws" || env.InstanceID != "i-0abc123" || env.Region != "us-east-1" {
		t.Fatalf("unexpected AWS env: %+v", env)
	}

	// 2. Azure IMDS
	azSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"compute":{"vmId":"az-vm-1","vmSize":"Standard_D2s_v5","location":"eastus","zone":"1"}}`))
	}))
	defer azSrv.Close()

	envAz := DetectEnvironment(context.Background(), Endpoints{AWSBase: "http://127.0.0.1:1", AzureBase: azSrv.URL, GCPBase: "http://127.0.0.1:1"})
	if envAz.Provider != "azure" || envAz.InstanceID != "az-vm-1" || envAz.Region != "eastus" {
		t.Fatalf("unexpected Azure env: %+v", envAz)
	}

	// 3. GCP Metadata
	gcpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"id":12345,"machineType":"projects/1/machineTypes/e2-standard-2","zone":"projects/1/zones/us-central1-a"}`))
	}))
	defer gcpSrv.Close()

	envGCP := DetectEnvironment(context.Background(), Endpoints{AWSBase: "http://127.0.0.1:1", AzureBase: "http://127.0.0.1:1", GCPBase: gcpSrv.URL})
	if envGCP.Provider != "gcp" || envGCP.InstanceType != "e2-standard-2" || envGCP.Region != "us-central1" || envGCP.Zone != "us-central1-a" {
		t.Fatalf("unexpected GCP env: %+v", envGCP)
	}

	// 4. Local VirtualBox DMI fallback
	dmi := t.TempDir()
	_ = os.WriteFile(filepath.Join(dmi, "sys_vendor"), []byte("innotek GmbH\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dmi, "product_name"), []byte("VirtualBox\n"), 0o644)
	envVM := DetectEnvironment(context.Background(), Endpoints{AWSBase: "http://127.0.0.1:1", AzureBase: "http://127.0.0.1:1", GCPBase: "http://127.0.0.1:1", DMIRoot: dmi})
	if envVM.Provider != "vm" || envVM.Product != "VirtualBox" {
		t.Fatalf("unexpected VM DMI env: %+v", envVM)
	}
}
