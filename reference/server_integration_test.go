//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

type nativeServerTenant struct{ foreign atomic.Bool }

func (r *nativeServerTenant) ResolveTenant(ctx context.Context) (identity.TenantID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.foreign.Load() {
		return "other", nil
	}
	return otpTenant, nil
}

// This case uses the sole public composition graph, native contributed
// migrations and graph-owned rate/issuer resources. No application handler,
// rate backend or domain-store override supplies the initiation workflow.
func TestReferenceServerNativeOriginalFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	c, deps, worker := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	configureReferencePreAuth(t, &c)
	networkServer := httptest.NewUnstartedServer(nil)
	t.Cleanup(networkServer.Close)
	origin := "https://" + networkServer.Listener.Addr().String()
	c.OTP.PreAuth.Origin = origin
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "reference-server-native", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
	c.HTTPPreAuth = &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := stores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, worker)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	base := c
	baseOTP := *c.OTP
	baseOTP.PreAuth = nil
	base.OTP, base.HTTPPreAuth, base.HTTPRate = &baseOTP, nil, nil
	baseStores, err := reference.ComposeStores(base, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := baseStores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	installOTPGraphFixture(t, ctx, f, baseStores)
	request := applyRequest(t, ctx, stores, []reference.ModuleID{"identity/session/postgres", "rate-limit/postgres"})
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("native selected migration", err)
	}
	tenant := &nativeServerTenant{}
	policies := identity.PolicySet{Authorize: c.OTP.RequestKeys.Policy.Authorization,
		AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			panic("unused risk callback")
		},
		MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			panic("unused claims callback")
		},
		DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			panic("unused retention callback")
		},
		Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			panic("unused redaction callback")
		}}
	config := reference.ReferenceConfig{Profile: reference.PostgresWithValkey, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}}, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Reference native", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: tenant}}
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal("native server construction", err)
	}
	if len(server.OpenAPI().Operations()) != 3 || !strings.Contains(string(server.OpenAPI().JSON()), "/v1/session/preauth-issue") {
		t.Fatal("selected server metadata")
	}
	networkServer.Config.Handler = server.Handler()
	networkServer.StartTLS()
	client := networkServer.Client()
	client.Timeout = 5 * time.Second
	call := func() (*http.Response, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "POST", networkServer.URL+"/v1/session/preauth-issue", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if err != nil || len(payload) > 16384 {
			t.Fatal("bounded response", err)
		}
		return response, payload
	}
	response, _ := call()
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("uninitialized server admitted", response.StatusCode)
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	tenant.foreign.Store(true)
	response, _ = call()
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("conflicting tenant reached workflow", response.StatusCode)
	}
	var count int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM session_store.preauth_transactions").Scan(&count); err != nil || count != 0 {
		t.Fatal("denied tenant wrote flow", err)
	}
	tenant.foreign.Store(false)
	response, payload := call()
	var out sessionhttp.PreAuthResponse
	if response.StatusCode != 200 || json.Unmarshal(payload, &out) != nil || !out.Issued || out.CommitOutcome != "committed" || out.FlowID == "" {
		t.Fatal("native server issuance", response.StatusCode)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-identity_flow" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" || strings.Contains(string(payload), cookies[0].Value) {
		t.Fatal("server credential custody")
	}
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2 AND state='issued'", otpTenant, string(out.FlowID)).Scan(&count); err != nil || count != 1 {
		t.Fatal("server durable issuance", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	response, _ = call()
	if response.StatusCode != 503 || len(response.Cookies()) != 0 {
		t.Fatal("closed server issued credential", response.StatusCode)
	}
}
