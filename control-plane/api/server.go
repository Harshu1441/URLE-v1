package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ulre/ulre/control-plane/auth"
	"github.com/ulre/ulre/control-plane/database"
	"github.com/ulre/ulre/control-plane/ebpf"
	"github.com/ulre/ulre/control-plane/logging"
	"github.com/ulre/ulre/control-plane/policyengine"
)

type Server struct {
	store     *database.Store
	auth      *auth.Manager
	ws        *WSHub
	logger    *logging.RotatingLogger
	staticDir string
	mux       *http.ServeMux
}

func NewServer(store *database.Store, authMgr *auth.Manager, staticDir string, logger ...*logging.RotatingLogger) *Server {
	var lg *logging.RotatingLogger
	if len(logger) > 0 {
		lg = logger[0]
	}
	s := &Server{
		store:     store,
		auth:      authMgr,
		ws:        NewWSHub(),
		logger:    lg,
		staticDir: staticDir,
		mux:       http.NewServeMux(),
	}
	s.routes()
	return s
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// WebSocket upgrades hijack the raw net.Conn; skip response wrapping on /api/v1/stream.
	if r.URL.Path == "/api/v1/stream" {
		if s.logger != nil {
			s.logger.Info("ws", "stream request", "remote", r.RemoteAddr)
		}
		s.mux.ServeHTTP(w, r)
		return
	}

	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		if pv := recover(); pv != nil {
			if s.logger != nil {
				s.logger.Error("http", "panic recovered", "panic", pv, "path", r.URL.Path, "stack", string(debug.Stack()))
			}
			writeErr(rec, http.StatusInternalServerError, "internal server error")
		}
		if s.logger == nil {
			return
		}
		durMs := time.Since(start).Milliseconds()
		lvl := logging.LevelInfo
		if rec.status >= 500 {
			lvl = logging.LevelError
		} else if rec.status >= 400 {
			lvl = logging.LevelWarn
		}
		s.logger.Log(lvl, "http", "request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration_ms", durMs, "bytes", rec.bytes, "remote", r.RemoteAddr)
	}()

	s.mux.ServeHTTP(rec, r)
}

func (s *Server) routes() {
	// Auth
	s.mux.HandleFunc("/api/v1/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/v1/auth/me", s.requireRole(s.handleMe, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/auth/agent-bootstrap", s.requireRole(s.handleAgentBootstrap, auth.RoleAdmin))

	// Agent sync protocol
	s.mux.HandleFunc("/api/v1/agents/register", s.handleAgentRegister)
	s.mux.HandleFunc("/api/v1/agents/rotate-token", s.requireAgent(s.handleAgentRotateToken))
	s.mux.HandleFunc("/api/v1/agents/heartbeat", s.requireAgent(s.handleAgentHeartbeat))
	s.mux.HandleFunc("/api/v1/agents/", s.requireAgent(s.handleAgentSubroutes))

	// Admin UI / CLI REST API
	s.mux.HandleFunc("/api/v1/overview", s.requireRole(s.handleOverview, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/hosts", s.requireRole(s.handleHosts, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/hosts/", s.requireRole(s.handleHostSubroutes, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/workloads", s.requireRole(s.handleAllWorkloads, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))

	s.mux.HandleFunc("/api/v1/policies", s.requireRole(s.handlePolicies, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/policies/validate", s.requireRole(s.handlePolicyValidate, auth.RoleOperator, auth.RoleAdmin))
	s.mux.HandleFunc("/api/v1/policies/capabilities", s.requireRole(s.handleCapabilities, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/policies/", s.requireRole(s.handlePolicySubroutes, auth.RoleOperator, auth.RoleAdmin))
	s.mux.HandleFunc("/api/v1/backup/export", s.requireRole(s.handleBackupExport, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/backup/restore", s.requireRole(s.handleBackupRestore, auth.RoleAdmin))

	s.mux.HandleFunc("/api/v1/oom-events", s.requireRole(s.handleOOMEvents, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/ebpf/programs", s.requireRole(s.handleEBPFPrograms, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/ebpf/programs/", s.requireRole(s.handleEBPFSubroutes, auth.RoleAdmin, auth.RoleKernelAdmin))
	s.mux.HandleFunc("/api/v1/audit-logs", s.requireRole(s.handleAuditLogs, auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin, auth.RoleKernelAdmin))

	// Real-time WebSocket stream (accepts token via query param ?token= for browser WebSocket API)
	s.mux.HandleFunc("/api/v1/stream", s.handleStream)

	// Static SPA frontend
	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	u, ok := s.auth.AuthenticateUser(req.Username, req.Password)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok, err := s.auth.IssueToken(u.Username, u.Role, 12*time.Hour)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":    tok,
		"username": u.Username,
		"role":     u.Role,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	writeJSON(w, http.StatusOK, map[string]any{"username": c.Sub, "role": c.Role})
}

func (s *Server) handleAgentBootstrap(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	tok, err := s.auth.IssueRegistrationToken(15 * time.Minute)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.store.AddAudit(database.AuditRecord{
		Actor: c.Sub, ActorRole: string(c.Role), Action: "auth.issue_agent_bootstrap", Target: "one-time-token", Result: "applied",
	})
	writeJSON(w, http.StatusOK, map[string]any{"registration_token": tok, "expires_in_sec": 900, "one_time": true})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	if _, err := s.auth.VerifyToken(tok); err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized stream")
		return
	}
	s.ws.ServeWS(w, r)
}

func (s *Server) handleOverview(w http.ResponseWriter, _ *http.Request, _ auth.Claims) {
	writeJSON(w, http.StatusOK, s.store.Overview())
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.auth.VerifyAgentRegistration(r) {
		writeErr(w, http.StatusUnauthorized, "invalid or already-used agent registration credential")
		return
	}
	var h database.Host
	if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved := s.store.RegisterHost(h)
	rotatingTok, _ := s.auth.IssueToken(saved.ID, auth.RoleAgent, 24*time.Hour)
	s.store.AddAudit(database.AuditRecord{
		Actor:     "agent:" + saved.Hostname,
		ActorRole: "agent",
		HostID:    saved.ID,
		Action:    "agent.register",
		Target:    saved.Hostname,
		Result:    "applied",
		Details:   map[string]string{"kernel": saved.KernelVersion},
	})
	s.ws.Broadcast("host.updated", saved)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          saved.ID,
		"hostname":    saved.Hostname,
		"agent_token": rotatingTok,
		"host":        saved,
	})
}

func (s *Server) handleAgentRotateToken(w http.ResponseWriter, r *http.Request, boundHostID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		HostID string `json:"host_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	targetHost := boundHostID
	if targetHost == "" {
		targetHost = req.HostID
	}
	if targetHost == "" || (boundHostID != "" && req.HostID != "" && req.HostID != boundHostID) {
		writeErr(w, http.StatusForbidden, "host token mismatch")
		return
	}
	newTok, err := s.auth.IssueToken(targetHost, auth.RoleAgent, 24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_token": newTok, "expires_in_sec": 86400})
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request, boundHostID string) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		HostID string `json:"host_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h, ok := s.store.Heartbeat(req.HostID)
	if !ok {
		writeErr(w, http.StatusNotFound, "host not registered")
		return
	}
	if boundHostID != "" && boundHostID != req.HostID {
		writeErr(w, http.StatusForbidden, "agent token bound to a different host")
		return
	}
	s.ws.Broadcast("host.updated", h)
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleAgentSubroutes(w http.ResponseWriter, r *http.Request, boundHostID string) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	hostID, sub := parts[0], parts[1]
	if boundHostID != "" && boundHostID != hostID {
		writeErr(w, http.StatusForbidden, "agent token cannot access another host")
		return
	}

	switch sub {
	case "bundle":
		if r.Method != http.MethodGet {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		pols := s.store.ListPolicies()
		canon, _ := json.Marshal(pols)
		bundle := policyengine.SignedBundle{
			Version:   len(pols),
			PublicKey: s.auth.PublicKeyHex(),
			Signature: s.auth.SignCanonical(canon),
			Policies:  pols,
		}
		writeJSON(w, http.StatusOK, bundle)

	case "workloads":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var items []database.Workload
		if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.store.SetHostWorkloads(hostID, items)
		s.ws.Broadcast("workloads.updated", map[string]any{"host_id": hostID, "count": len(items)})
		writeJSON(w, http.StatusOK, map[string]any{"ingested": len(items)})

	case "events":
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var events []struct {
			Timestamp time.Time         `json:"timestamp"`
			Action    string            `json:"action"`
			Policy    string            `json:"policy"`
			Target    string            `json:"target"`
			DryRun    bool              `json:"dry_run"`
			Result    string            `json:"result"`
			Details   map[string]string `json:"details"`
		}
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		host, _ := s.store.GetHost(hostID)
		for _, ev := range events {
			rec := s.store.AddAudit(database.AuditRecord{
				Actor:      "agent:" + host.Hostname,
				ActorRole:  "agent",
				HostID:     hostID,
				Action:     ev.Action,
				PolicyName: ev.Policy,
				Target:     ev.Target,
				DryRun:     ev.DryRun,
				Result:     ev.Result,
				Details:    ev.Details,
				CreatedAt:  ev.Timestamp,
			})
			s.ws.Broadcast("audit.event", rec)
			if strings.HasPrefix(ev.Action, "oom.") {
				oomEv := database.OOMEvent{
					HostID:     hostID,
					Hostname:   host.Hostname,
					PolicyName: ev.Policy,
					Target:     ev.Target,
					Action:     ev.Action,
					Result:     ev.Result,
					DryRun:     ev.DryRun,
					Details:    ev.Details,
					OccurredAt: ev.Timestamp,
				}
				s.store.AddOOMEvent(oomEv)
				s.ws.Broadcast("oom.event", oomEv)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"accepted": len(events)})
	default:
		writeErr(w, http.StatusNotFound, "unknown agent endpoint")
	}
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.store.ListHosts())
}

func (s *Server) handleHostSubroutes(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/hosts/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		id := parts[0]
		if r.Method == http.MethodDelete {
			if !s.auth.HasRole(c.Role, auth.RoleAdmin) {
				writeErr(w, http.StatusForbidden, "admin role required")
				return
			}
			if !s.store.DeleteHost(id) {
				writeErr(w, http.StatusNotFound, "host not found")
				return
			}
			s.store.AddAudit(database.AuditRecord{Actor: c.Sub, ActorRole: string(c.Role), HostID: id, Action: "host.delete", Target: id, Result: "applied"})
			writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
			return
		}
		h, ok := s.store.GetHost(id)
		if !ok {
			writeErr(w, http.StatusNotFound, "host not found")
			return
		}
		writeJSON(w, http.StatusOK, h)
		return
	}
	if len(parts) == 2 && parts[1] == "workloads" {
		writeJSON(w, http.StatusOK, filterWorkloads(s.store.ListWorkloads(parts[0]), r))
		return
	}
	writeErr(w, http.StatusNotFound, "not found")
}

func (s *Server) handleAllWorkloads(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	hostID := r.URL.Query().Get("host_id")
	writeJSON(w, http.StatusOK, filterWorkloads(s.store.ListWorkloads(hostID), r))
}

func filterWorkloads(items []database.Workload, r *http.Request) []database.Workload {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	rt := strings.TrimSpace(r.URL.Query().Get("runtime"))
	if q == "" && rt == "" {
		return items
	}
	out := make([]database.Workload, 0)
	for _, w := range items {
		if rt != "" && w.OwnerRuntime != rt {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(w.Comm+" "+w.Exe+" "+w.CgroupPath+" "+w.SystemdUnit+" "+w.ContainerID+" "+w.ContainerName+" "+w.ContainerImage), q) {
			continue
		}
		out = append(out, w)
	}
	return out
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.store.ListPolicies())
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.auth.HasRole(c.Role, auth.RoleOperator, auth.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "operator or admin role required")
		return
	}
	var p policyengine.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// Never trust client-supplied approval fields on create/update; enforce server-side RBAC.
	p.ApprovedBy = ""
	p.ApprovedAt = nil
	if p.AllowDestructive || p.AllowRuntimeOverride {
		if s.auth.HasRole(c.Role, auth.RoleAdmin) && p.Mode == "enforce" {
			now := time.Now().UTC()
			p.ApprovedBy = c.Sub
			p.ApprovedAt = &now
		} else if p.Mode == "enforce" {
			writeErr(w, http.StatusForbidden, "admin approval required before activating destructive or runtime-override enforce policy (save as dry_run then POST /approve as admin)")
			return
		}
	}
	saved, err := s.store.UpsertPolicy(p, true)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	rec := s.store.AddAudit(database.AuditRecord{
		Actor: c.Sub, ActorRole: string(c.Role), Action: "policy.create", PolicyName: saved.Name, Target: saved.Name,
		DryRun: saved.Mode == "dry_run", Result: "applied",
	})
	s.ws.Broadcast("policy.updated", saved)
	s.ws.Broadcast("audit.event", rec)
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request, _ auth.Claims) {
	writeJSON(w, http.StatusOK, policyengine.CapabilityMatrix())
}

func (s *Server) handlePolicyValidate(w http.ResponseWriter, r *http.Request, _ auth.Claims) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var p policyengine.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	all := append(s.store.ListPolicies(), p)
	errs := policyengine.ValidatePolicies(all)
	_, warns := policyengine.CheckPolicyCompatibility(p)
	writeJSON(w, http.StatusOK, map[string]any{"valid": len(errs) == 0, "errors": errs, "warnings": warns})
}

func (s *Server) handlePolicySubroutes(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := parts[0]
	if id == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if len(parts) == 2 && parts[1] == "approve" && r.Method == http.MethodPost {
		if !s.auth.HasRole(c.Role, auth.RoleAdmin) {
			writeErr(w, http.StatusForbidden, "admin role required to approve destructive/override policy")
			return
		}
		p, err := s.store.ApprovePolicy(id, c.Sub)
		if err != nil {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		rec := s.store.AddAudit(database.AuditRecord{Actor: c.Sub, ActorRole: string(c.Role), Action: "policy.approve", PolicyName: p.Name, Target: p.Name, Result: "applied"})
		s.ws.Broadcast("policy.updated", p)
		s.ws.Broadcast("audit.event", rec)
		writeJSON(w, http.StatusOK, p)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPut {
		var p policyengine.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		p.ID = id
		p.ApprovedBy = ""
		p.ApprovedAt = nil
		if p.AllowDestructive || p.AllowRuntimeOverride {
			if s.auth.HasRole(c.Role, auth.RoleAdmin) && p.Mode == "enforce" {
				now := time.Now().UTC()
				p.ApprovedBy = c.Sub
				p.ApprovedAt = &now
			} else if p.Mode == "enforce" {
				writeErr(w, http.StatusForbidden, "admin approval required before activating destructive or runtime-override enforce policy")
				return
			}
		}
		saved, err := s.store.UpsertPolicy(p, false)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		rec := s.store.AddAudit(database.AuditRecord{Actor: c.Sub, ActorRole: string(c.Role), Action: "policy.update", PolicyName: saved.Name, Target: saved.Name, Result: "applied"})
		s.ws.Broadcast("policy.updated", saved)
		s.ws.Broadcast("audit.event", rec)
		writeJSON(w, http.StatusOK, saved)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if !s.auth.HasRole(c.Role, auth.RoleAdmin) {
			writeErr(w, http.StatusForbidden, "admin role required to delete policy")
			return
		}
		if !s.store.DeletePolicy(id) {
			writeErr(w, http.StatusNotFound, "policy not found")
			return
		}
		rec := s.store.AddAudit(database.AuditRecord{Actor: c.Sub, ActorRole: string(c.Role), Action: "policy.delete", Target: id, Result: "applied"})
		s.ws.Broadcast("policy.updated", map[string]string{"deleted": id})
		s.ws.Broadcast("audit.event", rec)
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
		return
	}
	writeErr(w, http.StatusMethodNotAllowed, "unsupported policy operation")
}

func (s *Server) handleOOMEvents(w http.ResponseWriter, _ *http.Request, _ auth.Claims) {
	writeJSON(w, http.StatusOK, s.store.ListOOMEvents())
}

func (s *Server) handleEBPFPrograms(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.store.ListEBPFPrograms())
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.auth.HasRole(c.Role, auth.RoleKernelAdmin, auth.RoleAdmin) {
		writeErr(w, http.StatusForbidden, "kernel_admin or admin role required")
		return
	}

	var raw []byte
	var name string
	if strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(16 << 20); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		name = r.FormValue("name")
		file, hdr, err := r.FormFile("object")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "missing 'object' file")
			return
		}
		defer file.Close()
		if name == "" {
			name = hdr.Filename
		}
		raw, err = io.ReadAll(io.LimitReader(file, 16<<20))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		var req struct {
			Name         string `json:"name"`
			ObjectBase64 string `json:"object_base64"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		name = req.Name
		var err error
		raw, err = base64.StdEncoding.DecodeString(req.ObjectBase64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid base64 object")
			return
		}
	}

	parsed, err := ebpf.InspectELF(name, raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	saved := s.store.AddEBPFProgram(parsed)
	rec := s.store.AddAudit(database.AuditRecord{
		Actor: c.Sub, ActorRole: string(c.Role), Action: "ebpf.upload", Target: saved.Name, Result: "applied",
		Details: map[string]string{"sha256": saved.SHA256, "program_type": saved.ProgramType},
	})
	s.ws.Broadcast("ebpf.updated", saved)
	s.ws.Broadcast("audit.event", rec)
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) handleEBPFSubroutes(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/ebpf/programs/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	id, action := parts[0], parts[1]

	if action == "approve" && !s.auth.HasRole(c.Role, auth.RoleKernelAdmin) {
		writeErr(w, http.StatusForbidden, "kernel_admin role required to approve eBPF objects")
		return
	}

	var status string
	switch action {
	case "approve":
		status = "approved"
	case "deploy":
		status = "deployed_staged"
	case "rollback":
		status = "rolled_back"
	default:
		writeErr(w, http.StatusNotFound, "unknown ebpf action")
		return
	}

	updated, err := s.store.UpdateEBPFStatus(id, status, c.Sub)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	rec := s.store.AddAudit(database.AuditRecord{Actor: c.Sub, ActorRole: string(c.Role), Action: "ebpf." + action, Target: updated.Name, Result: "applied"})
	s.ws.Broadcast("ebpf.updated", updated)
	s.ws.Broadcast("audit.event", rec)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, _ *http.Request, _ auth.Claims) {
	writeJSON(w, http.StatusOK, s.store.ListAuditLogs())
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pols := s.store.ListPolicies()
	bundle := map[string]any{
		"format":      "ulre-policy-backup/v1",
		"exported_at": time.Now().UTC(),
		"exported_by": c.Sub,
		"policies":    pols,
	}
	s.store.AddAudit(database.AuditRecord{
		Actor: c.Sub, ActorRole: string(c.Role), Action: "backup.export", Target: "policies", Result: "applied",
		Details: map[string]string{"count": jsonCount(len(pols))},
	})
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request, c auth.Claims) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		Policies []policyengine.Policy `json:"policies"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	restored, err := s.store.ReplacePolicies(req.Policies, c.Sub)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	rec := s.store.AddAudit(database.AuditRecord{
		Actor: c.Sub, ActorRole: string(c.Role), Action: "backup.restore", Target: "policies", Result: "applied",
		Details: map[string]string{"restored_count": jsonCount(len(restored))},
	})
	s.ws.Broadcast("policy.updated", map[string]any{"restored": len(restored)})
	s.ws.Broadcast("audit.event", rec)
	writeJSON(w, http.StatusOK, map[string]any{"restored": len(restored), "policies": restored})
}

func jsonCount(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if s.staticDir == "" {
		writeJSON(w, http.StatusOK, map[string]string{"service": "ulre-control-plane", "status": "ok"})
		return
	}
	clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	target := filepath.Join(s.staticDir, clean)
	if st, err := os.Stat(target); err == nil && !st.IsDir() {
		http.ServeFile(w, r, target)
		return
	}
	index := filepath.Join(s.staticDir, "index.html")
	if _, err := os.Stat(index); err == nil {
		http.ServeFile(w, r, index)
		return
	}
	writeErr(w, http.StatusNotFound, "frontend bundle not found; build /frontend first")
}

func (s *Server) requireRole(fn func(http.ResponseWriter, *http.Request, auth.Claims), roles ...auth.Role) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := s.auth.VerifyToken(tok)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !s.auth.HasRole(claims.Role, roles...) {
			writeErr(w, http.StatusForbidden, "insufficient permissions for role "+string(claims.Role))
			return
		}
		fn(w, r, claims)
	}
}

func (s *Server) requireAgent(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		boundHostID, ok := s.auth.VerifyAgentRequest(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "agent authentication failed")
			return
		}
		fn(w, r, boundHostID)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
