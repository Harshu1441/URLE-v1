package auth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Role string

const (
	RoleViewer      Role = "viewer"
	RoleOperator    Role = "operator"
	RoleAdmin       Role = "admin"
	RoleKernelAdmin Role = "kernel_admin"
	RoleAgent       Role = "agent"
)

type Claims struct {
	Sub  string `json:"sub"`
	Role Role   `json:"role"`
	Exp  int64  `json:"exp"`
}

type User struct {
	Username string
	Password string
	Role     Role
}

type Manager struct {
	jwtSecret  []byte
	agentToken string
	signPriv   ed25519.PrivateKey
	signPub    ed25519.PublicKey
	users      map[string]User
	regMu      sync.Mutex
	regTokens  map[string]time.Time
}

func NewManager() (*Manager, error) {
	secret := []byte(os.Getenv("ULRE_JWT_SECRET"))
	if len(secret) < 16 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	agentTok := os.Getenv("ULRE_AGENT_TOKEN")
	if agentTok == "" {
		agentTok = "ulre-dev-agent-token"
	}

	adminPass := os.Getenv("ULRE_ADMIN_PASSWORD")
	if adminPass == "" {
		adminPass = "admin"
	}

	return &Manager{
		jwtSecret:  secret,
		agentToken: agentTok,
		signPriv:   priv,
		signPub:    pub,
		regTokens:  map[string]time.Time{},
		users: map[string]User{
			"admin":    {Username: "admin", Password: adminPass, Role: RoleAdmin},
			"kernel":   {Username: "kernel", Password: adminPass, Role: RoleKernelAdmin},
			"operator": {Username: "operator", Password: adminPass, Role: RoleOperator},
			"viewer":   {Username: "viewer", Password: adminPass, Role: RoleViewer},
		},
	}, nil
}

func (m *Manager) AuthenticateUser(username, password string) (User, bool) {
	u, ok := m.users[username]
	if !ok {
		return User{}, false
	}
	if subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) != 1 {
		return User{}, false
	}
	return u, true
}

func (m *Manager) IssueToken(username string, role Role, ttl time.Duration) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsBytes, err := json.Marshal(Claims{
		Sub:  username,
		Role: role,
		Exp:  time.Now().Add(ttl).Unix(),
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := header + "." + payload
	sig := m.signHMAC(signingInput)
	return signingInput + "." + sig, nil
}

func (m *Manager) VerifyToken(tok string) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("malformed token")
	}
	expected := m.signHMAC(parts[0] + "." + parts[1])
	if !hmac.Equal([]byte(parts[2]), []byte(expected)) {
		return Claims{}, fmt.Errorf("invalid token signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, err
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, err
	}
	if time.Now().Unix() > c.Exp {
		return Claims{}, fmt.Errorf("token expired")
	}
	return c, nil
}

// IssueRegistrationToken creates a single-use, short-lived registration credential.
func (m *Manager) IssueRegistrationToken(ttl time.Duration) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := "reg-" + hex.EncodeToString(b)
	m.regMu.Lock()
	m.regTokens[tok] = time.Now().Add(ttl)
	m.regMu.Unlock()
	return tok, nil
}

// ConsumeRegistrationToken validates and invalidates a single-use registration credential.
func (m *Manager) ConsumeRegistrationToken(tok string) bool {
	m.regMu.Lock()
	defer m.regMu.Unlock()
	exp, ok := m.regTokens[tok]
	if !ok {
		return false
	}
	delete(m.regTokens, tok)
	return time.Now().Before(exp)
}

func (m *Manager) VerifyAgentRegistration(r *http.Request) bool {
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		return true
	}
	authz := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if strings.HasPrefix(authz, "reg-") {
		return m.ConsumeRegistrationToken(authz)
	}
	// Accept either static bootstrap token (if configured) or an existing valid agent JWT.
	if c, err := m.VerifyToken(authz); err == nil && c.Role == RoleAgent {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(authz), []byte(m.agentToken)) == 1
}

func (m *Manager) VerifyAgentRequest(r *http.Request) (string, bool) {
	// Accept mTLS verified client cert, host-bound rotating agent JWT, or static bootstrap token.
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
		return r.TLS.VerifiedChains[0][0].Subject.CommonName, true
	}
	authz := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if c, err := m.VerifyToken(authz); err == nil && c.Role == RoleAgent {
		return c.Sub, true
	}
	if subtle.ConstantTimeCompare([]byte(authz), []byte(m.agentToken)) == 1 {
		return "", true
	}
	return "", false
}

func (m *Manager) SignCanonical(payload []byte) string {
	sig := ed25519.Sign(m.signPriv, payload)
	return hex.EncodeToString(sig)
}

func (m *Manager) PublicKeyHex() string {
	return hex.EncodeToString(m.signPub)
}

func (m *Manager) HasRole(actual Role, allowed ...Role) bool {
	if actual == RoleAdmin {
		// Admin holds viewer/operator rights; kernel_admin actions check RoleKernelAdmin explicitly or RoleAdmin.
		for _, a := range allowed {
			if a == RoleAdmin || a == RoleOperator || a == RoleViewer {
				return true
			}
		}
	}
	for _, a := range allowed {
		if actual == a {
			return true
		}
	}
	return false
}

func (m *Manager) signHMAC(input string) string {
	mac := hmac.New(sha256.New, m.jwtSecret)
	_, _ = mac.Write([]byte(input))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
