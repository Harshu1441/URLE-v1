package api

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ulre/ulre/control-plane/auth"
	"github.com/ulre/ulre/control-plane/database"
)

func TestControlPlaneEndToEndAndEBPFELFInspection(t *testing.T) {
	store, err := database.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, authMgr, "")
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// 1. Login as admin and kernel_admin
	adminTok := loginHelper(t, ts.URL, "admin", "admin")
	kernelTok := loginHelper(t, ts.URL, "kernel", "admin")

	// 2. One-time agent registration token cannot be reused + host-bound rotating JWT
	bootReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/agent-bootstrap", nil)
	bootReq.Header.Set("Authorization", "Bearer "+adminTok)
	bootResp, err := http.DefaultClient.Do(bootReq)
	if err != nil || bootResp.StatusCode != http.StatusOK {
		t.Fatalf("agent bootstrap failed: %v", err)
	}
	var bootOut struct {
		RegistrationToken string `json:"registration_token"`
	}
	_ = json.NewDecoder(bootResp.Body).Decode(&bootOut)
	_ = bootResp.Body.Close()

	regBody := `{"hostname":"rocky-vm","machine_id":"m-123","os_name":"linux","kernel_version":"5.15.0","cpu_cores":2,"memory_bytes":2147483648,"cgroup_v2":true,"controllers":["cpu","memory","pids"]}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/register", bytes.NewBufferString(regBody))
	req.Header.Set("Authorization", "Bearer "+bootOut.RegistrationToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("agent register failed: status=%v err=%v", resp.StatusCode, err)
	}
	var regOut struct {
		ID         string `json:"id"`
		AgentToken string `json:"agent_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&regOut)
	_ = resp.Body.Close()

	// Reuse of one-time registration token MUST fail (401)
	reuseReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/agents/register", bytes.NewBufferString(regBody))
	reuseReq.Header.Set("Authorization", "Bearer "+bootOut.RegistrationToken)
	reuseResp, _ := http.DefaultClient.Do(reuseReq)
	if reuseResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when reusing one-time registration token, got %d", reuseResp.StatusCode)
	}
	_ = reuseResp.Body.Close()

	// Host-bound agent token cannot access another host (403)
	crossReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agents/other-host-id/bundle", nil)
	crossReq.Header.Set("Authorization", "Bearer "+regOut.AgentToken)
	crossResp, _ := http.DefaultClient.Do(crossReq)
	if crossResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-host agent token access, got %d", crossResp.StatusCode)
	}
	_ = crossResp.Body.Close()

	// Server-side RBAC approval gate & path/shell injection rejection
	opTok := loginHelper(t, ts.URL, "operator", "admin")
	bypassReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/policies", bytes.NewBufferString(`{
	  "name":"op-bypass","priority":10,"mode":"enforce","criticality":"normal",
	  "allow_destructive":true,"approved_by":"admin",
	  "selectors":{"process_name":"worker"}
	}`))
	bypassReq.Header.Set("Authorization", "Bearer "+opTok)
	bypassResp, _ := http.DefaultClient.Do(bypassReq)
	if bypassResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when operator tries to bypass destructive approval gate, got %d", bypassResp.StatusCode)
	}
	_ = bypassResp.Body.Close()

	travReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/policies", bytes.NewBufferString(`{
	  "name":"../evil;rm","priority":10,"mode":"dry_run","criticality":"normal",
	  "selectors":{"process_name":"worker"}
	}`))
	travReq.Header.Set("Authorization", "Bearer "+adminTok)
	travResp, _ := http.DefaultClient.Do(travReq)
	if travResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for path/shell injection in policy name, got %d", travResp.StatusCode)
	}
	_ = travResp.Body.Close()

	// 3. Create policy via admin API and verify signed bundle download
	polReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/policies", bytes.NewBufferString(`{
	  "name":"worker-cap","priority":100,"mode":"enforce","criticality":"normal",
	  "selectors":{"process_name":"worker"},
	  "limits":{"memory.max":"134217728","cpu.max":"50000 100000"},
	  "oom":{"conditions":{"memory_percent":85},"actions":["alert","throttle"]}
	}`))
	polReq.Header.Set("Authorization", "Bearer "+adminTok)
	polResp, err := http.DefaultClient.Do(polReq)
	if err != nil || polResp.StatusCode != http.StatusCreated {
		t.Fatalf("create policy failed: %v", polResp.StatusCode)
	}
	_ = polResp.Body.Close()

	// 4. Upload a minimal valid ELF64 EM_BPF object and verify kernel_admin approval gate
	elfBytes := buildMinimalBPFELF(t)
	upBody, _ := json.Marshal(map[string]string{
		"name":          "oom_probe.o",
		"object_base64": base64.StdEncoding.EncodeToString(elfBytes),
	})
	upReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ebpf/programs", bytes.NewReader(upBody))
	upReq.Header.Set("Authorization", "Bearer "+kernelTok)
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil || upResp.StatusCode != http.StatusCreated {
		t.Fatalf("ebpf upload failed: status=%d err=%v", upResp.StatusCode, err)
	}
	var rec map[string]any
	_ = json.NewDecoder(upResp.Body).Decode(&rec)
	_ = upResp.Body.Close()
	if rec["program_type"] != "kprobe" || rec["has_btf"] != true {
		t.Fatalf("unexpected ELF parse result: %+v", rec)
	}

	// Admin cannot approve eBPF (requires kernel_admin)
	badApp, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ebpf/programs/"+rec["id"].(string)+"/approve", nil)
	badApp.Header.Set("Authorization", "Bearer "+adminTok)
	badResp, _ := http.DefaultClient.Do(badApp)
	if badResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for admin approving eBPF, got %d", badResp.StatusCode)
	}
	_ = badResp.Body.Close()

	// 5. Export and restore policy backup
	expReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/backup/export", nil)
	expReq.Header.Set("Authorization", "Bearer "+adminTok)
	expResp, err := http.DefaultClient.Do(expReq)
	if err != nil || expResp.StatusCode != http.StatusOK {
		t.Fatalf("backup export failed: %v", err)
	}
	var exported map[string]any
	_ = json.NewDecoder(expResp.Body).Decode(&exported)
	_ = expResp.Body.Close()
	rawBackup, _ := json.Marshal(exported)

	restReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/backup/restore", bytes.NewReader(rawBackup))
	restReq.Header.Set("Authorization", "Bearer "+adminTok)
	restResp, err := http.DefaultClient.Do(restReq)
	if err != nil || restResp.StatusCode != http.StatusOK {
		t.Fatalf("backup restore failed: status=%d err=%v", restResp.StatusCode, err)
	}
	_ = restResp.Body.Close()
}

func loginHelper(t *testing.T, baseURL, user, pass string) string {
	t.Helper()
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewBufferString(`{"username":"`+user+`","password":"`+pass+`"}`))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login failed for %s: %v", user, err)
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Token
}

// buildMinimalBPFELF constructs a real ELF64 relocatable object with EM_BPF (247),
// a kprobe/oom_kill_process section, and a .BTF section.
func buildMinimalBPFELF(t *testing.T) []byte {
	t.Helper()
	shstrtab := []byte("\x00.shstrtab\x00kprobe/oom_kill_process\x00.BTF\x00")
	// ELF64 header (64 bytes) + 4 section headers (4 * 64 = 256 bytes)
	shoff := uint64(64 + len(shstrtab) + 8)
	var buf bytes.Buffer
	// e_ident[16]
	buf.Write([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))     // ET_REL
	_ = binary.Write(&buf, binary.LittleEndian, uint16(247))   // EM_BPF
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))     // EV_CURRENT
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0))     // e_entry
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0))     // e_phoff
	_ = binary.Write(&buf, binary.LittleEndian, shoff)         // e_shoff
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))     // e_flags
	_ = binary.Write(&buf, binary.LittleEndian, uint16(64))    // e_ehsize
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))     // e_phentsize
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))     // e_phnum
	_ = binary.Write(&buf, binary.LittleEndian, uint16(64))    // e_shentsize
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))     // e_shnum
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))     // e_shstrndx

	strOff := uint64(buf.Len())
	buf.Write(shstrtab)
	progOff := uint64(buf.Len())
	buf.Write(make([]byte, 8)) // 1 dummy BPF instruction

	writeShdr := func(name uint32, typ uint32, flags, off, size uint64) {
		_ = binary.Write(&buf, binary.LittleEndian, name)
		_ = binary.Write(&buf, binary.LittleEndian, typ)
		_ = binary.Write(&buf, binary.LittleEndian, flags)
		_ = binary.Write(&buf, binary.LittleEndian, uint64(0))
		_ = binary.Write(&buf, binary.LittleEndian, off)
		_ = binary.Write(&buf, binary.LittleEndian, size)
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
		_ = binary.Write(&buf, binary.LittleEndian, uint64(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint64(0))
	}
	writeShdr(0, 0, 0, 0, 0)                                          // SHT_NULL
	writeShdr(1, 3, 0, strOff, uint64(len(shstrtab)))                 // .shstrtab (SHT_STRTAB)
	writeShdr(11, 1, 6, progOff, 8)                                   // kprobe/oom_kill_process
	writeShdr(35, 1, 0, progOff, 4)                                   // .BTF
	return buf.Bytes()
}
