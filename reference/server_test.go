package reference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

type serverNoCallPolicy struct{ marker byte }

func (*serverNoCallPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	panic("construction invoked authorization")
}

type serverTenantFunc func(context.Context) (identity.TenantID, error)

func (f serverTenantFunc) ResolveTenant(ctx context.Context) (identity.TenantID, error) {
	return f(ctx)
}

func TestReferenceServerTenantAdmissionPrecedesWorkflow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tenant  identity.TenantID
		err     error
		panic   bool
		cancel  bool
		expire  bool
		allowed bool
	}{
		{name: "matching", tenant: "tenant", allowed: true},
		{name: "foreign", tenant: "other"},
		{name: "empty"},
		{name: "unavailable", err: errors.New("sensitive provider failure")},
		{name: "panic", panic: true},
		{name: "canceled", tenant: "tenant", cancel: true},
		{name: "expired-admission", tenant: "tenant", expire: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, d, f := serverFixture(t)
			if tc.expire {
				c.HTTP.HandlerTimeout = 5 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			c.Tenant.Resolver = serverTenantFunc(func(ctx context.Context) (identity.TenantID, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("unbounded tenant callback")
				}
				if tc.panic {
					panic("secret")
				}
				if tc.cancel {
					cancel()
				}
				if tc.expire {
					<-ctx.Done()
				}
				return tc.tenant, tc.err
			})
			s, err := NewServer(c, d, f)
			if err != nil {
				t.Fatal(err)
			}
			network, err := identityhttp.NewNetworkResolver(c.HTTP.Network)
			if err != nil {
				t.Fatal(err)
			}
			dispatched := false
			h := s.guardTenant(network, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { dispatched = true; w.WriteHeader(204) }))
			r := httptest.NewRequest("POST", "https://login.example/test", nil).WithContext(ctx)
			r.RequestURI = "/test"
			r.RemoteAddr = "127.0.0.1:1234"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if dispatched != tc.allowed || (tc.allowed && w.Code != 204) || (!tc.allowed && w.Code != 503) {
				t.Fatalf("dispatch=%v status=%d", dispatched, w.Code)
			}
			if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "sensitive") || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("tenant denial leaked custody")
			}
		})
	}
}

func TestReferenceServerTenantAdmissionDoesNotReplaceWorkflowDeadline(t *testing.T) {
	c, d, f := serverFixture(t)
	c.HTTP.HandlerTimeout = 4 * time.Second
	parent, stop := context.WithTimeout(t.Context(), c.HTTP.HandlerTimeout)
	defer stop()
	var admission context.Context
	c.Tenant.Resolver = serverTenantFunc(func(ctx context.Context) (identity.TenantID, error) {
		admission = ctx
		deadline, ok := ctx.Deadline()
		outer, _ := parent.Deadline()
		if !ok || !deadline.Before(outer) {
			t.Error("tenant resolution lost its own narrower budget")
		}
		return "tenant", nil
	})
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal(err)
	}
	network, err := identityhttp.NewNetworkResolver(c.HTTP.Network)
	if err != nil {
		t.Fatal(err)
	}
	dispatched := false
	h := s.guardTenant(network, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dispatched = true
		outer, _ := parent.Deadline()
		actual, _ := r.Context().Deadline()
		if !actual.Equal(outer) || r.Context() != parent {
			t.Error("tenant callback budget truncated the workflow's router-owned deadline")
		}
		if admission.Err() != context.Canceled {
			t.Error("finished tenant resolution retained its deadline timer")
		}
		w.WriteHeader(204)
	}))
	r := httptest.NewRequest("POST", "https://login.example/test", nil).WithContext(parent)
	r.RequestURI, r.RemoteAddr = "/test", "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !dispatched || w.Code != 204 || parent.Err() != nil {
		t.Fatal("admitted workflow lost live parent cancellation ownership")
	}
}

type serverNoCallTenant struct{}

func (serverNoCallTenant) ResolveTenant(context.Context) (identity.TenantID, error) {
	panic("construction invoked tenant resolver")
}

type serverSecretTenant struct{ private string }

func (serverSecretTenant) ResolveTenant(context.Context) (identity.TenantID, error) {
	return "tenant", nil
}

// This unit isolates pure construction; it does not simulate initialized native
// stores or claim the server's composed browser journey is proven.
func serverFixture(t *testing.T) (ReferenceConfig, ReferenceDependencies, FeatureSet) {
	t.Helper()
	pool, err := database.Connect(t.Context(), database.Config{DSN: "host=127.0.0.1 port=1 user=postgres dbname=identity_test sslmode=disable search_path=public", StartupPolicy: database.StartupLazy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	policy := &serverNoCallPolicy{}
	set := identity.PolicySet{Authorize: policy,
		AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			panic("construction invoked risk")
		},
		MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			panic("construction invoked claims")
		},
		DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			panic("construction invoked retention")
		},
		Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			panic("construction invoked redaction")
		}}
	lifetime, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	drained := make(chan struct{})
	close(drained)
	s := &storeState{pool: pool, lifetime: lifetime, cancel: cancel, drained: drained, tenants: map[string]*tenantRecovery{"tenant": {}}, config: VelocityStoreConfiguration{Schema: "risk_store", PrimaryTimeout: time.Second}, features: &featureState{composed: true, authorize: policy}}
	c := ReferenceConfig{Profile: PostgresWithValkey, Policies: set, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "login.example", TenantID: "tenant"}}, PublicHosts: []string{"health.example"}}, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Reference", Version: "1"}}, Migration: MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: TenantPolicy{Resolver: serverNoCallTenant{}}}
	return c, ReferenceDependencies{PostgreSQL: pool}, FeatureSet{state: s}
}

func TestReferenceServerPureConstructionAndSelectedProbes(t *testing.T) {
	c, d, f := serverFixture(t)
	s, err := NewServer(c, d, f)
	if err != nil || s == nil || s.Handler() == nil {
		t.Fatal("pure server construction", err)
	}
	if len(s.OpenAPI().Operations()) != 2 || strings.Contains(string(s.OpenAPI().JSON()), "preauth-issue") {
		t.Fatal("unselected workflow advertised")
	}
	for _, probe := range []struct {
		path   string
		status int
	}{{"/healthz", 200}, {"/readyz", 503}, {"/v1/healthz", 404}} {
		r := httptest.NewRequest("GET", "https://health.example"+probe.path, nil)
		r.RequestURI = probe.path
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != probe.status {
			t.Fatal("probe selection", probe.path, w.Code)
		}
	}
	if s.Readiness(t.Context()).Ready || !s.Health(t.Context()).Ready {
		t.Fatal("construction manufactured readiness or lost process health")
	}
	c.HTTP.Network.PublicHosts[0] = "changed.example"
	for _, tc := range []struct {
		host   string
		status int
	}{{"health.example", 200}, {"changed.example", 421}} {
		r := httptest.NewRequest("GET", "https://"+tc.host+"/healthz", nil)
		r.RequestURI = "/healthz"
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal("caller mutation changed admission snapshot", w.Code)
		}
	}
}

func TestReferenceServerRejectsInvalidAndForeignGraph(t *testing.T) {
	c, d, f := serverFixture(t)
	for _, mutate := range []func(*ReferenceConfig){
		func(c *ReferenceConfig) { c.Profile = 0 }, func(c *ReferenceConfig) { c.Policies.Redact = nil }, func(c *ReferenceConfig) { c.Policies.Authorize = &serverNoCallPolicy{} }, func(c *ReferenceConfig) { c.Migration.ApplyOnStartup = true }, func(c *ReferenceConfig) { c.Bootstrap.Enabled = true }, func(c *ReferenceConfig) { c.Tenant.Resolver = nil }, func(c *ReferenceConfig) { c.Workers.MaxConcurrency = 0 }, func(c *ReferenceConfig) { c.HTTP.Network.TenantHosts[0].TenantID = "foreign" },
	} {
		bad := c
		bad.HTTP.Network.TenantHosts = append([]identityhttp.TenantHost(nil), c.HTTP.Network.TenantHosts...)
		mutate(&bad)
		if server, err := NewServer(bad, d, f); err == nil || server != nil {
			t.Fatal("invalid server escaped")
		}
	}
	if server, err := NewServer(c, ReferenceDependencies{}, f); err == nil || server != nil {
		t.Fatal("foreign pool accepted")
	}
	if server, err := NewServer(c, d, FeatureSet{}); err == nil || server != nil {
		t.Fatal("zero graph accepted")
	}
}

func TestReferenceServerDiagnosticsDoNotExportCustody(t *testing.T) {
	c, d, f := serverFixture(t)
	c.Tenant.Resolver = serverSecretTenant{private: "server-fixture-private-custody"}
	s, err := NewServer(c, d, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{c, s, *s, HTTPPreAuthConfiguration{}} {
		if !strings.HasSuffix(fmt.Sprintf("%#v", value), "(redacted)") {
			t.Fatal("diagnostic exposed server custody")
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit custody export accepted")
		}
	}
}

func TestReferenceServerHTTPPreAuthRejectsIncompatibleNativeLifetime(t *testing.T) {
	for _, ttl := range []time.Duration{time.Minute, 5 * time.Minute, 10 * time.Minute} {
		c := StoreConfiguration{OTP: &OTPSendConfiguration{PreAuth: &OTPPreAuthConfiguration{FlowTTL: ttl}}, HTTPRate: &HTTPRateConfiguration{}, HTTPPreAuth: &HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}}}
		out, err := composePreAuthHTTP(c)
		if ttl == 5*time.Minute && (err != nil || out == nil) || ttl != 5*time.Minute && (err == nil || out != nil) {
			t.Fatal("incompatible HTTP lifetime accepted", ttl, err)
		}
		c.HTTPPreAuth = nil
		if out, err := composePreAuthHTTP(c); err != nil || out != nil {
			t.Fatal("HTTP profile narrowed direct native issuance", err)
		}
	}
}
