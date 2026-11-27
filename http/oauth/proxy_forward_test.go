package oauthhttp_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/go-jose/go-jose/v4"
)

// This port double deliberately returns no forged native success. Its scope is
// transport admission; the real callback owns reservation and encrypted output.
type proxyForwardProbe struct {
	lookupCalls, sourceCalls, handleCalls int
	lookup                                oauthproxy.CallbackLookup
	source                                oauth.CallbackRateContext
	lookupErr, sourceErr, handleErr       error
	beforeSource                          func()
	bounded                               bool
}

func (p *proxyForwardProbe) Lookup(ctx context.Context, _, _ string) (oauthproxy.CallbackLookup, error) {
	p.lookupCalls++
	_, p.bounded = ctx.Deadline()
	return p.lookup, p.lookupErr
}

func (p *proxyForwardProbe) ProxyCallbackRateSource(ctx context.Context, tenant identity.TenantID, lookup oauthproxy.CallbackLookup) (oauth.CallbackRateContext, error) {
	p.sourceCalls++
	if p.beforeSource != nil {
		p.beforeSource()
	}
	if ctx.Err() != nil || tenant != "AQEBAQEBAQEBAQEBAQEBAQ" || lookup != p.lookup {
		return oauth.CallbackRateContext{}, oauthproxy.CallbackReconcile
	}
	return p.source, p.sourceErr
}

func (p *proxyForwardProbe) Handle(context.Context, string, string) (oauthproxy.CallbackResult, error) {
	p.handleCalls++
	return oauthproxy.CallbackResult{}, p.handleErr
}

func proxyForwardFixture(t *testing.T) (oauthhttp.ProxyForwardConfig, *proxyForwardProbe, *signinStartRate, *http.Request) {
	t.Helper()
	base, _, rate, _, _ := signinStartFixture(t)
	base.Provider.RedirectURI = "https://app.example" + oauthhttp.ProxyForwardPath
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	probe := &proxyForwardProbe{
		lookup: oauthproxy.CallbackLookup{StateDigest: sha256.Sum256([]byte(state)), ProductionDeployment: "production-a", ProductionCallback: base.Provider.RedirectURI, ProviderID: base.Provider.ID, ProviderVersion: base.Provider.Version, Issuer: base.Provider.Issuer, ClientID: base.Provider.ClientID},
		source: oauth.CallbackRateContext{ProviderID: base.Provider.ID, TransactionID: "AgICAgICAgICAgICAgICAg", Lifetime: 5 * time.Minute},
	}
	base.Network.TenantHosts[0].TenantID = "AQEBAQEBAQEBAQEBAQEBAQ"
	c := oauthhttp.ProxyForwardConfig{Network: base.Network, Origin: base.Origin, TenantID: base.Network.TenantHosts[0].TenantID, Provider: base.Provider, ProductionDeployment: "production-a", Callback: probe, RateSource: probe, Rate: base.Rate, AllowedTargets: []string{"https://preview.example/complete"}, Now: base.Now, MaximumDuration: time.Second}
	query := url.Values{"state": {state}, "code": {"synthetic-private-code"}, "iss": {base.Provider.Issuer}}
	r := httptest.NewRequest(http.MethodGet, c.Provider.RedirectURI+"?"+query.Encode(), nil)
	r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.1:1234"
	return c, probe, rate, r
}

func serveProxyForward(t *testing.T, c oauthhttp.ProxyForwardConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	handler, err := oauthhttp.NewProxyForwardHandler(c)
	if err != nil {
		t.Fatal("construct proxy transport", err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func requireProxyForwardPrivate(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Location") != "" {
		t.Fatal("failure disclosed browser custody or lost response protection")
	}
	for _, secret := range []string{"synthetic-private-code", "private collaborator", "AgICAgICAgICAgICAgICAg"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private callback material escaped")
		}
	}
}

func TestProxyForwardRejectsMalformedOrSubstitutedTransportBeforeRate(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*http.Request)
	}{
		{"method", func(r *http.Request) { r.Method = http.MethodPost }},
		{"path", func(r *http.Request) { r.URL.Path += "/" }},
		{"escaped path", func(r *http.Request) { r.URL.RawPath = "/oauth2/callback/%70roxy" }},
		{"invalid raw path", func(r *http.Request) { r.URL.RawPath = "/unrelated" }},
		{"force query", func(r *http.Request) { r.URL.ForceQuery = true }},
		{"missing query", func(r *http.Request) { r.URL.RawQuery = "" }},
		{"duplicate state", func(r *http.Request) { r.URL.RawQuery += "&state=duplicate" }},
		{"issuer", func(r *http.Request) {
			r.URL.RawQuery = strings.ReplaceAll(r.URL.RawQuery, "issuer.example", "foreign.example")
		}},
		{"body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("private body")); r.ContentLength = 12 }},
		{"hidden body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("private body")) }},
		{"transfer encoding", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"X-Test": {"private"}} }},
		{"key", func(r *http.Request) { r.Header.Set("Idempotency-Key", "private") }},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer private") }},
		{"foreign host", func(r *http.Request) { r.Host = "foreign.example" }},
		{"plaintext", func(r *http.Request) { r.TLS = nil }},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		{"empty origin", func(r *http.Request) { r.Header["Origin"] = []string{""} }},
		{"duplicate origin", func(r *http.Request) { r.Header["Origin"] = []string{"https://app.example", "https://app.example"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, probe, rate, request := proxyForwardFixture(t)
			tc.alter(request)
			request.RequestURI = request.URL.RequestURI()
			w := serveProxyForward(t, c, request)
			if w.Code < 400 || probe.lookupCalls != 0 || probe.sourceCalls != 0 || probe.handleCalls != 0 || len(rate.requests) != 0 {
				t.Fatal("invalid transport reached native lookup or debited a budget", w.Code)
			}
			requireProxyForwardPrivate(t, w)
		})
	}
}

func TestProxyForwardRetainsIPDebitWhenOriginalCannotAuthenticate(t *testing.T) {
	for _, origin := range []string{"", "https://app.example"} {
		c, probe, rate, request := proxyForwardFixture(t)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		request.Header.Set("Referer", "https://untrusted.example/private")
		request.Header.Set("Cookie", "unparsed-private-cookie")
		probe.sourceErr = errors.New("private collaborator outage")
		probe.beforeSource = func() {
			if len(rate.requests) != 1 {
				t.Fatal("original lookup preceded IP debit")
			}
		}
		w := serveProxyForward(t, c, request)
		if w.Code != 503 || probe.lookupCalls != 1 || probe.sourceCalls != 1 || probe.handleCalls != 0 || len(rate.requests) != 1 || !probe.bounded {
			t.Fatal("original failure bypassed ordered, bounded admission", w.Code)
		}
		requireProxyForwardPrivate(t, w)
	}
}

func TestProxyForwardRejectsForeignNativeLookupBeforeTransactionBudget(t *testing.T) {
	changes := []func(*oauthproxy.CallbackLookup){
		func(q *oauthproxy.CallbackLookup) { q.StateDigest[0] ^= 1 },
		func(q *oauthproxy.CallbackLookup) { q.ProductionDeployment += "-other" },
		func(q *oauthproxy.CallbackLookup) { q.ProductionCallback += "/other" },
		func(q *oauthproxy.CallbackLookup) { q.ProviderID += "-other" },
		func(q *oauthproxy.CallbackLookup) { q.ProviderVersion++ },
		func(q *oauthproxy.CallbackLookup) { q.ClientID += "-other" },
		func(q *oauthproxy.CallbackLookup) { q.Issuer += "/other" },
		func(q *oauthproxy.CallbackLookup) { q.ProviderDenied = true },
	}
	for _, change := range changes {
		c, probe, rate, request := proxyForwardFixture(t)
		change(&probe.lookup)
		w := serveProxyForward(t, c, request)
		if w.Code != 403 || probe.lookupCalls != 1 || probe.sourceCalls != 0 || probe.handleCalls != 0 || len(rate.requests) != 1 {
			t.Fatal("foreign native attribution reached the transaction budget", w.Code)
		}
		requireProxyForwardPrivate(t, w)
	}
}

func TestProxyForwardRequiresCountedAuditedRiskBeforeNativeCompletion(t *testing.T) {
	c, probe, rate, request := proxyForwardFixture(t)
	w := serveProxyForward(t, c, request)
	if w.Code != 503 || probe.handleCalls != 0 || len(rate.requests) != 2 {
		t.Fatal("zero evaluator allowed native completion or skipped ordered budgets", w.Code)
	}
	requireProxyForwardPrivate(t, w)
}

func TestProxyForwardRejectsInvalidConfigurationWithoutIO(t *testing.T) {
	changes := []func(*oauthhttp.ProxyForwardConfig){
		func(c *oauthhttp.ProxyForwardConfig) { c.Callback = nil },
		func(c *oauthhttp.ProxyForwardConfig) { var callback *proxyForwardProbe; c.Callback = callback },
		func(c *oauthhttp.ProxyForwardConfig) { c.RateSource = nil },
		func(c *oauthhttp.ProxyForwardConfig) { c.Rate = nil },
		func(c *oauthhttp.ProxyForwardConfig) { c.Now = nil },
		func(c *oauthhttp.ProxyForwardConfig) { c.MaximumDuration = 0 },
		func(c *oauthhttp.ProxyForwardConfig) { c.MaximumDuration = 31 * time.Second },
		func(c *oauthhttp.ProxyForwardConfig) { c.TenantID = "" },
		func(c *oauthhttp.ProxyForwardConfig) { c.ProductionDeployment = "" },
		func(c *oauthhttp.ProxyForwardConfig) { c.ProductionDeployment = "Production" },
		func(c *oauthhttp.ProxyForwardConfig) { c.Provider.RedirectURI += "/other" },
		func(c *oauthhttp.ProxyForwardConfig) { c.Provider.ResponseMode = "form_post" },
		func(c *oauthhttp.ProxyForwardConfig) { c.Provider.Version = 0 },
		func(c *oauthhttp.ProxyForwardConfig) { c.Origin = "https://App.example" },
		func(c *oauthhttp.ProxyForwardConfig) { c.AllowedTargets = nil },
		func(c *oauthhttp.ProxyForwardConfig) {
			c.AllowedTargets = []string{"https://preview.example/complete?next=elsewhere"}
		},
		func(c *oauthhttp.ProxyForwardConfig) {
			c.AllowedTargets = []string{"https://preview.example/complete", "https://preview.example/complete"}
		},
		func(c *oauthhttp.ProxyForwardConfig) { c.AllowedTargets = []string{"http://preview.example/complete"} },
		func(c *oauthhttp.ProxyForwardConfig) {
			c.AllowedTargets = []string{"https://xn--bcher-kva.example/complete"}
		},
		func(c *oauthhttp.ProxyForwardConfig) { c.AllowedTargets = []string{"https://preview.example/"} },
	}
	for index, change := range changes {
		c, probe, rate, _ := proxyForwardFixture(t)
		change(&c)
		if handler, err := oauthhttp.NewProxyForwardHandler(c); err == nil || handler != nil {
			t.Fatalf("invalid configuration %d produced a handler", index)
		}
		if probe.lookupCalls != 0 || probe.sourceCalls != 0 || probe.handleCalls != 0 || len(rate.requests) != 0 {
			t.Fatal("construction performed runtime admission or provider work")
		}
	}
}

func TestProxyForwardTransactionExhaustionPrecedesRiskAndNativeCompletion(t *testing.T) {
	c, probe, rate, request := proxyForwardFixture(t)
	handler, err := oauthhttp.NewProxyForwardHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		handler.ServeHTTP(httptest.NewRecorder(), request.Clone(t.Context()))
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || probe.lookupCalls != 6 || probe.sourceCalls != 6 || probe.handleCalls != 0 || len(rate.requests) != 12 {
		t.Fatal("exhausted original transaction bypassed native budget or lost earlier IP debit", w.Code)
	}
	requireProxyForwardPrivate(t, w)
}

func TestProxyForwardIPOutageAndExhaustionCannotReachOriginal(t *testing.T) {
	c, probe, rate, request := proxyForwardFixture(t)
	rate.fail = true
	w := serveProxyForward(t, c, request)
	if w.Code != 503 || probe.lookupCalls != 0 || probe.sourceCalls != 0 || probe.handleCalls != 0 {
		t.Fatal("IP outage reached original state", w.Code)
	}
	requireProxyForwardPrivate(t, w)

	c, probe, _, request = proxyForwardFixture(t)
	probe.sourceErr = oauthproxy.ErrOriginalUnavailable
	handler, err := oauthhttp.NewProxyForwardHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		handler.ServeHTTP(httptest.NewRecorder(), request.Clone(t.Context()))
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || probe.lookupCalls != 30 || probe.sourceCalls != 30 || probe.handleCalls != 0 {
		t.Fatal("exhausted IP continued original work or omitted retry guidance", w.Code)
	}
	requireProxyForwardPrivate(t, w)
}

type proxyForwardRiskProbe struct {
	mode           string
	counts, audits int
	last           risk.CounterBinding
	lastAudit      audit.Record
	beforeCounter  func()
}

func (p *proxyForwardRiskProbe) Mutate(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
	p.counts++
	p.last = command.Bindings()
	if p.beforeCounter != nil {
		p.beforeCounter()
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return risk.CounterResult{}, errors.New("unbounded counter")
	}
	if p.mode == "counter outage" {
		return risk.NewCounterResult(command, risk.CounterUnknown, nil)
	}
	value := uint64(1)
	if p.mode == "throttle" {
		value = p.last.Limit + 1
	}
	counters := make([]risk.Counter, 0, len(p.last.Targets))
	for _, target := range p.last.Targets {
		counters = append(counters, risk.Counter{Kind: string(target.Dimension), Value: value, ObservedAt: p.last.PreparedAt, WindowStartedAt: p.last.PreparedAt.Add(-time.Second), WindowExpiresAt: p.last.PreparedAt.Add(p.last.Window - time.Second)})
	}
	return risk.NewCounterResult(command, risk.CounterCommitted, counters)
}

func (p *proxyForwardRiskProbe) Append(_ context.Context, record audit.Record) (audit.AppendResult, error) {
	p.audits++
	p.lastAudit = record
	if p.mode == "audit outage" {
		return audit.AppendResult{}, errors.New("private collaborator audit outage")
	}
	return audit.AppendResult{RecordID: record.ID(), Status: audit.AppendAccepted}, nil
}

func (p *proxyForwardRiskProbe) AppendBatch(context.Context, []audit.Record) (audit.BatchResult, error) {
	return audit.BatchResult{}, errors.New("unexpected batch")
}

func proxyForwardRiskFixture(t *testing.T, c oauthhttp.ProxyForwardConfig, mode string) (risk.Evaluator, *proxyForwardRiskProbe) {
	t.Helper()
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 1, Profiles: profiles, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err = policy.WithOAuthProxyForward()
	if err != nil {
		t.Fatal(err)
	}
	probe := &proxyForwardRiskProbe{mode: mode}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counter, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: probe, Keys: []risk.CounterDigestKey{key}, Clock: c.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: c.Now, Timeout: time.Second, Counters: &counter,
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: "AQEBAQEBAQEBAQEBAQEBAQ", Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: probe, Mode: audit.DeliveryFailClosed}, OnLoss: func(context.Context, risk.DecisionDelivery) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	return evaluator, probe
}

func TestProxyForwardCountedAuditedAdmissionUsesOnlyTrustedOriginalScope(t *testing.T) {
	c, probe, rate, request := proxyForwardFixture(t)
	var counted *proxyForwardRiskProbe
	c.Risk, counted = proxyForwardRiskFixture(t, c, "allow")
	counted.beforeCounter = func() {
		if len(rate.requests) != 2 || probe.sourceCalls != 1 || probe.handleCalls != 0 {
			t.Fatal("risk counter preceded original transaction budget or followed native mutation")
		}
	}
	w := serveProxyForward(t, c, request)
	if w.Code != 503 || probe.handleCalls != 1 || counted.counts != 1 || counted.audits != 1 {
		t.Fatal("counted, audited allowance did not reach scoped zero native result", w.Code)
	}
	if counted.last.Tenant != string(c.TenantID) || counted.last.Operation != "identity.oauth.proxy-forward" || counted.last.Attempt == probe.source.TransactionID {
		t.Fatal("untrusted or correlated attempt replaced internal risk attribution")
	}
	if _, err := identity.ParseCommandID(counted.last.Attempt); err != nil {
		t.Fatal("risk attempt was not a safe internal command identity")
	}
	wantDimensions := []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.ResourceDimension}
	if len(counted.last.Targets) != len(wantDimensions) {
		t.Fatal("missing or fabricated risk dimensions")
	}
	for index, target := range counted.last.Targets {
		if target.Dimension != wantDimensions[index] {
			t.Fatal("device, identifier or subject invented on production hop")
		}
	}
	requireProxyForwardPrivate(t, w)
}

func TestProxyForwardRiskDenialAndAuditOutageNeverReachNativeCompletion(t *testing.T) {
	for _, mode := range []string{"throttle", "counter outage", "audit outage"} {
		t.Run(mode, func(t *testing.T) {
			c, probe, rate, request := proxyForwardFixture(t)
			var counted *proxyForwardRiskProbe
			c.Risk, counted = proxyForwardRiskFixture(t, c, mode)
			w := serveProxyForward(t, c, request)
			if w.Code < 400 || probe.handleCalls != 0 || counted.counts != 1 || counted.audits != 1 || len(rate.requests) != 2 {
				t.Fatal("risk failure reached native completion or skipped required accounting", w.Code)
			}
			if mode == "throttle" && (w.Code != 429 || w.Header().Get("Retry-After") == "") {
				t.Fatal("risk throttle omitted rate guidance", w.Code)
			}
			requireProxyForwardPrivate(t, w)
		})
	}
}

type proxyForwardClock struct{ now time.Time }

func (c *proxyForwardClock) Now() time.Time { return c.now }

type proxyForwardNativeStore struct {
	original    oauthproxy.OriginalCallback
	reserves    int
	finalizes   int
	disposition oauthproxy.CallbackDisposition
	envelope    []byte
	err         error
}

func (s *proxyForwardNativeStore) Reserve(context.Context, oauthproxy.CallbackLookup) (oauthproxy.OriginalCallback, error) {
	s.reserves++
	if s.reserves > 1 {
		return oauthproxy.OriginalCallback{}, oauthproxy.ErrOriginalUnavailable
	}
	return s.original, nil
}

func (s *proxyForwardNativeStore) Finalize(_ context.Context, _ [32]byte, disposition oauthproxy.CallbackDisposition, envelope []byte) error {
	s.finalizes++
	s.disposition, s.envelope = disposition, bytes.Clone(envelope)
	return s.err
}

type proxyForwardNative struct {
	*oauthproxy.ProductionCallback
	after func()
}

func (p proxyForwardNative) Handle(ctx context.Context, uri, query string) (oauthproxy.CallbackResult, error) {
	result, err := p.ProductionCallback.Handle(ctx, uri, query)
	if p.after != nil {
		p.after()
	}
	return result, err
}

func proxyForwardRealFixture(t *testing.T) (oauthhttp.ProxyForwardConfig, *proxyForwardProbe, *proxyForwardNativeStore, *atomic.Int32, *http.Request) {
	t.Helper()
	c, source, _, request := proxyForwardFixture(t)
	clock := &proxyForwardClock{now: c.Now()}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exchanges := new(atomic.Int32)
	var signed atomic.Value
	providerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.Method != http.MethodPost || r.ParseForm() != nil || r.PostForm.Get("code") != "synthetic-private-code" || r.PostForm.Get("redirect_uri") != c.Provider.RedirectURI || r.PostForm.Get("code_verifier") == "" {
			t.Error("provider received an unauthorized request")
			w.WriteHeader(400)
			return
		}
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-private-token", "id_token": signed.Load(), "token_type": "Bearer", "expires_in": 120})
	}))
	t.Cleanup(providerServer.Close)
	state := request.URL.Query().Get("state")
	claims, err := json.Marshal(map[string]any{"iss": providerServer.URL, "sub": "existing-preview-subject", "aud": "client", "nonce": state, "iat": clock.now.Add(-time.Second).Unix(), "exp": clock.now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signature.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	signed.Store(compact)
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{ID: "configured", Version: 1, Issuer: providerServer.URL, ClientID: "client", RedirectURI: c.Provider.RedirectURI, AuthorizationEndpoint: providerServer.URL + "/authorize", TokenEndpoint: providerServer.URL + "/token", ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"}, Clock: clock, HTTPClient: providerServer.Client(), KeySet: &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	exchange, err := oauth.NewOIDCProxyExchange(provider, "")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"test-proxy": bytes.Repeat([]byte{6}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := secretenvelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := oauth.NewProxyOIDCEvidenceCodec(secrets, clock, "test-proxy", nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 43)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verifier.Destroy)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: time.Hour, RefreshAfter: 10 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c.Provider = provider.Profile()
	target := oauthproxy.PreviewTarget{Deployment: "preview-a", Origin: "https://preview.example", Redirect: c.AllowedTargets[0], Recipient: "preview-recipient"}
	binding := oauth.ProxyOIDCEvidenceBinding{TenantID: c.TenantID, CommandID: "AwMDAwMDAwMDAwMDAwMDAw", TransactionID: identity.PreAuthTransactionID(source.source.TransactionID), RequestFingerprint: sha256.Sum256([]byte("original-intent")), StateDigest: sha256.Sum256([]byte(state)), PKCEChallengeDigest: sha256.Sum256([]byte(verifier.Challenge())), ProductionDeployment: c.ProductionDeployment, PreviewDeployment: target.Deployment, PreviewOrigin: target.Origin, PreviewRedirect: target.Redirect, Recipient: target.Recipient, ProviderID: c.Provider.ID, ProviderVersion: c.Provider.Version, Issuer: c.Provider.Issuer, ClientID: c.Provider.ClientID, ClaimsProfile: "minimum", ClaimsVersion: 1, Remember: remember, IssuedAt: clock.now.Add(-time.Second), ExpiresAt: clock.now.Add(time.Minute)}
	store := &proxyForwardNativeStore{original: oauthproxy.OriginalCallback{ID: sha256.Sum256([]byte("native-reservation")), Binding: binding, Verifier: verifier, Nonce: state}}
	native, err := oauthproxy.NewProductionCallback(oauthproxy.ProductionCallbackConfig{ProductionDeployment: c.ProductionDeployment, Provider: exchange, Codec: codec, Store: store, Clock: clock, Targets: []oauthproxy.PreviewTarget{target}})
	if err != nil {
		t.Fatal(err)
	}
	query := request.URL.Query()
	query.Set("iss", c.Provider.Issuer)
	request.URL.RawQuery = query.Encode()
	request.RequestURI = request.URL.RequestURI()
	source.lookup, err = native.Lookup(t.Context(), c.Provider.RedirectURI, request.URL.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	c.Callback = native
	c.Risk, _ = proxyForwardRiskFixture(t, c, "allow")
	return c, source, store, exchanges, request
}

func TestProxyForwardRealNativeProducesOnlyEncryptedExactFragmentHandoff(t *testing.T) {
	c, _, store, exchanges, request := proxyForwardRealFixture(t)
	request.Header.Set("Cookie", "unparsed-private-cookie")
	w := serveProxyForward(t, c, request)
	if w.Code != 303 || w.Body.Len() != 0 || exchanges.Load() != 1 || store.reserves != 1 || store.finalizes != 1 || store.disposition != oauthproxy.CallbackForwarded {
		t.Fatal("native success did not produce one empty redirect", w.Code)
	}
	want := c.AllowedTargets[0] + "#identity-proxy-v1." + string(store.original.Binding.TransactionID) + "." + base64.RawURLEncoding.EncodeToString(store.envelope)
	if w.Header().Get("Location") != want || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("handoff changed target, envelope or browser response protection")
	}
	for _, secret := range []string{"synthetic-private-token", "synthetic-private-code", "existing-preview-subject", "unparsed-private-cookie"} {
		if strings.Contains(w.Header().Get("Location"), secret) || strings.Contains(w.Body.String(), secret) {
			t.Fatal("provider or browser custody escaped encrypted handoff")
		}
	}
	w = serveProxyForward(t, c, request.Clone(t.Context()))
	if w.Code != 403 || exchanges.Load() != 1 || store.finalizes != 1 {
		t.Fatal("native replay repeated provider work or released another handoff", w.Code)
	}
	requireProxyForwardPrivate(t, w)
}

func TestProxyForwardKnownProviderDenialSettlesOriginalWithoutExchangeOrHandoff(t *testing.T) {
	c, source, store, exchanges, request := proxyForwardRealFixture(t)
	query := request.URL.Query()
	query.Del("code")
	query.Set("error", "access_denied")
	query.Set("error_description", "private provider denial")
	request.URL.RawQuery = query.Encode()
	request.RequestURI = request.URL.RequestURI()
	var err error
	source.lookup, err = c.Callback.Lookup(t.Context(), c.Provider.RedirectURI, request.URL.RawQuery)
	if err != nil || !source.lookup.ProviderDenied {
		t.Fatal("denial fixture did not parse as coherent original denial", err)
	}
	w := serveProxyForward(t, c, request)
	if w.Code != 403 || exchanges.Load() != 0 || store.reserves != 1 || store.finalizes != 1 || store.disposition != oauthproxy.CallbackRejected || len(store.envelope) != 0 {
		t.Fatal("known denial exchanged provider credentials or failed original settlement", w.Code)
	}
	if strings.Contains(w.Body.String(), "private provider denial") {
		t.Fatal("provider denial text escaped redaction")
	}
	requireProxyForwardPrivate(t, w)
}

func TestProxyForwardRealNativeWithholdsUnacknowledgedForeignLateOrCancelledResult(t *testing.T) {
	for _, mode := range []string{"settlement outage", "foreign target", "foreign transaction", "original cutoff", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, source, store, exchanges, request := proxyForwardRealFixture(t)
			native := c.Callback.(*oauthproxy.ProductionCallback)
			switch mode {
			case "settlement outage":
				store.err = errors.New("private collaborator settlement outage")
			case "foreign target":
				c.AllowedTargets = []string{"https://other-preview.example/complete"}
			case "foreign transaction":
				source.source.TransactionID = "BAQEBAQEBAQEBAQEBAQEBA"
			case "original cutoff":
				transportNow := c.Now()
				c.Now = func() time.Time { return transportNow }
				c.Callback = proxyForwardNative{ProductionCallback: native, after: func() { transportNow = store.original.Binding.ExpiresAt }}
			case "cancelled":
				ctx, cancel := context.WithCancel(request.Context())
				t.Cleanup(cancel)
				request = request.WithContext(ctx)
				c.Callback = proxyForwardNative{ProductionCallback: native, after: cancel}
			}
			w := serveProxyForward(t, c, request)
			if w.Code < 400 || exchanges.Load() != 1 || store.reserves != 1 || store.finalizes != 1 {
				t.Fatal("invalid result escaped final transport fence", w.Code)
			}
			requireProxyForwardPrivate(t, w)
		})
	}
}
