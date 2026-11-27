package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	authentication "github.com/faustbrian/go-authentication/v2"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestOAuthProxyProductionRejectsMissingNativeOwner(t *testing.T) {
	for _, test := range []struct {
		name string
		pool *database.Pool
	}{
		{name: "nil pool"},
		{name: "zero pool", pool: &database.Pool{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner, err := reference.NewOAuthProxyProduction(test.pool, reference.OAuthProxyProductionConfiguration{})
			if err == nil || owner != nil {
				t.Fatal("missing native owner produced a usable production proxy")
			}
		})
	}
}

func TestOAuthProxyProductionZeroOwnerFailsClosed(t *testing.T) {
	for _, owner := range []*reference.OAuthProxyProduction{nil, {}} {
		result, err := owner.Start(context.Background(), oauthproxy.InitiationRequest{})
		if err == nil {
			t.Fatal("unconfigured production proxy admitted initiation")
		}
		if _, ok := result.Authorization(); ok {
			t.Fatal("failed initiation exposed an authorization request")
		}
		if _, ok := result.Binding(); ok {
			t.Fatal("failed initiation exposed an evidence binding")
		}
		assertOAuthProxyProductionNoRoutes(t, owner)
	}
}

func TestOAuthProxyProductionNativeOnlyDoesNotExposeHTTP(t *testing.T) {
	pool, config := oauthProxyProductionConfiguration(t)
	owner, err := reference.NewOAuthProxyProduction(pool, config)
	if err != nil || owner == nil {
		t.Fatal("valid isolated native composition failed", err)
	}
	assertOAuthProxyProductionNoRoutes(t, owner)
	result, err := owner.Start(context.Background(), oauthproxy.InitiationRequest{})
	if !errors.Is(err, oauthproxy.InitiationInvalid) {
		t.Fatal("native admission did not reject the malformed request", err)
	}
	if _, ok := result.Authorization(); ok {
		t.Fatal("malformed initiation exposed an authorization request")
	}
	if _, ok := result.Binding(); ok {
		t.Fatal("malformed initiation exposed an evidence binding")
	}
}

func TestOAuthProxyProductionSelectedHTTPDispatchesOnlyProductionCallback(t *testing.T) {
	pool, config := oauthProxyProductionConfiguration(t)
	config.HTTP = oauthProxyProductionHTTPConfiguration(t, pool)
	owner, err := reference.NewOAuthProxyProduction(pool, config)
	if err != nil {
		t.Fatal("construct selected production HTTP owner", err)
	}
	operations := owner.OpenAPI().Operations()
	if len(operations) != 1 || operations[0].Record.OperationID != "identity.oauth.proxy-forward" ||
		operations[0].Record.Method != http.MethodGet || operations[0].Record.Path != "/oauth2/callback/proxy" {
		t.Fatal("production composition did not advertise the exact selected GET")
	}
	var wire struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		}
	}
	if err := json.Unmarshal(owner.OpenAPI().JSON(), &wire); err != nil {
		t.Fatal("decode production OpenAPI document", err)
	}
	callback := wire.Paths["/oauth2/callback/proxy"]
	if len(wire.Paths) != 1 || len(callback) != 1 || callback["get"].OperationID != "identity.oauth.proxy-forward" {
		t.Fatal("production OpenAPI exposed an unselected method or path")
	}
	for _, test := range []struct {
		name, method, path string
		status             int
		allow              string
	}{
		{"malformed provider GET", http.MethodGet, "/oauth2/callback/proxy?iss=https%3A%2F%2Fissuer.example", http.StatusBadRequest, ""},
		{"provider POST", http.MethodPost, "/oauth2/callback/proxy", http.StatusMethodNotAllowed, "GET"},
		{"preview completion", http.MethodGet, "/oauth2/proxy/complete", http.StatusNotFound, ""},
		{"preview initiation", http.MethodPost, "/oauth2/proxy/start", http.StatusNotFound, ""},
		{"session", http.MethodGet, "/session", http.StatusNotFound, ""},
		{"unrelated path", http.MethodGet, "/unrelated", http.StatusNotFound, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "https://production.example"+test.path, nil)
			request.RequestURI = request.URL.RequestURI()
			request.RemoteAddr = "192.0.2.17:1234"
			response := httptest.NewRecorder()
			owner.Handler().ServeHTTP(response, request)
			if response.Code != test.status || response.Header().Get("Allow") != test.allow {
				t.Fatalf("unexpected production dispatch: status %d, Allow %q", response.Code, response.Header().Get("Allow"))
			}
			if response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" {
				t.Fatal("rejected production request exposed a cookie or redirect")
			}
		})
	}
}

func oauthProxyProductionHTTPConfiguration(t *testing.T, pool *database.Pool) *reference.HTTPOAuthProxyProductionConfiguration {
	t.Helper()
	const tenant identity.TenantID = "AAAAAAAAAAAAAAAAAAAAAQ"
	backend, err := ratepg.NewStrict(pool.Raw(), ratepg.StrictOptions{
		Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second,
	})
	if err != nil {
		t.Fatal("construct native rate backend", err)
	}
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{
		Shared: backend, Namespace: "synthetic-proxy-http", IdentifierKey: [32]byte{91}, Now: time.Now, MaximumDuration: time.Second,
	})
	if err != nil {
		t.Fatal("construct shared production rate owner", err)
	}
	t.Cleanup(func() { rate.Close() })
	policy, err := risk.NewPolicy(risk.PolicyConfig{
		Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour},
		Profiles: []risk.Profile{
			{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
			{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
			{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
			{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
		},
	})
	if err != nil {
		t.Fatal("construct bounded risk policy", err)
	}
	policy, err = policy.WithOAuthProxyForward()
	if err != nil {
		t.Fatal("select production callback risk policy", err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{92}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{
		Pool: pool, Schema: "risk_store", Namespace: "synthetic-proxy-risk", Policy: policy, Keys: []risk.CounterDigestKey{key},
		ReplayKey: bytes.Repeat([]byte{93}, 32), Tenants: []string{string(tenant)}, MaximumRecords: 100, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal("construct native risk counter owner", err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: store, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{key}})
	if err != nil {
		t.Fatal("construct bounded counter coordinator", err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("construct native decision audit owner", err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{
		Policy: policy, Clock: time.Now, Timeout: time.Second, Counters: &counters,
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: "AAAAAAAAAAAAAAAAAAAABQ", Timeout: time.Second,
			Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed},
			OnLoss: func(context.Context, risk.DecisionDelivery) error {
				return errors.New("synthetic fixture has no audit recovery")
			}},
	})
	if err != nil {
		t.Fatal("construct counted audited risk evaluator", err)
	}
	return &reference.HTTPOAuthProxyProductionConfiguration{
		Origin: "https://production.example", Rate: rate, Risk: evaluator,
		Network: identityhttp.NetworkConfig{
			Limits:               identityhttp.Limits{MaximumHeaderBytes: 16384, MaximumURLBytes: 8192, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 32, MaximumDepth: 8},
			MaximumForwardedHops: 8, TenantHosts: []identityhttp.TenantHost{{Host: "production.example", TenantID: tenant}},
		},
	}
}

func TestOAuthProxyProductionRejectsIncompleteOrConflictingConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*reference.OAuthProxyProductionConfiguration)
	}{
		{"missing codec", func(c *reference.OAuthProxyProductionConfiguration) { c.Codec = nil }},
		{"missing clock", func(c *reference.OAuthProxyProductionConfiguration) { c.Clock = nil }},
		{"missing provider", func(c *reference.OAuthProxyProductionConfiguration) { c.Start.Provider = nil }},
		{"missing native state key", func(c *reference.OAuthProxyProductionConfiguration) { c.Native.StateKeys = nil }},
		{"unknown start state key", func(c *reference.OAuthProxyProductionConfiguration) { c.Start.CurrentStateKeyVersion = 9 }},
		{"preview uses production deployment", func(c *reference.OAuthProxyProductionConfiguration) {
			c.Start.Preview.Target.Deployment = c.Native.ProductionDeployment
		}},
		{"wrong preparation deployment", func(c *reference.OAuthProxyProductionConfiguration) {
			c.Start.CapabilityPreparation.Deployment = "other-production"
		}},
		{"insecure revocation endpoint", func(c *reference.OAuthProxyProductionConfiguration) {
			c.RevocationEndpoint = "http://issuer.example/revoke"
		}},
		{"HTTP without admission owners", func(c *reference.OAuthProxyProductionConfiguration) {
			c.HTTP = &reference.HTTPOAuthProxyProductionConfiguration{}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, config := oauthProxyProductionConfiguration(t)
			test.change(&config)
			owner, err := reference.NewOAuthProxyProduction(pool, config)
			if err == nil || owner != nil {
				t.Fatal("incomplete or conflicting configuration produced a usable production proxy")
			}
		})
	}
}

type oauthProxyProductionRejectAuthentication struct{}

func (oauthProxyProductionRejectAuthentication) Authenticate(context.Context, authentication.Credential) (authentication.Result, error) {
	return authentication.Result{}, authentication.ErrCredentialsRejected
}

type oauthProxyProductionRejectKeySet struct{}

func (oauthProxyProductionRejectKeySet) VerifySignature(context.Context, string) ([]byte, error) {
	return nil, errors.New("synthetic fixture rejects provider evidence")
}

func oauthProxyProductionConfiguration(t *testing.T) (*database.Pool, reference.OAuthProxyProductionConfiguration) {
	t.Helper()
	var dials atomic.Int32
	pool, err := database.Connect(context.Background(), database.Config{
		DSN: "postgres://synthetic@127.0.0.1:1/synthetic?sslmode=disable", StartupPolicy: database.StartupLazy, MaxConns: 1,
		Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
				dials.Add(1)
				return nil, errors.New("synthetic fixture forbids database I/O")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal("construct lazy typed pool", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("close fixture-owned lazy pool", err)
		}
		if dials.Load() != 0 {
			t.Error("startup or malformed initiation attempted database I/O")
		}
	})
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
		ID: "synthetic-provider", Version: 7, Issuer: "https://issuer.example",
		AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: "https://issuer.example/token",
		RedirectURI: "https://production.example/oauth2/callback/proxy", ClientID: "synthetic-client", ClientAuthentication: oauth.PublicClient,
		Scopes: []string{"openid"}, Algorithms: []string{"RS256"}, KeySet: oauthProxyProductionRejectKeySet{}, Clock: clock.System{},
	})
	if err != nil {
		t.Fatal("construct explicit provider profile", err)
	}
	t.Cleanup(provider.Close)
	signing := bytes.Repeat([]byte{72}, 32)
	signer, err := capability.NewHMACSHA256Signer("synthetic-signing", signing)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://production.example", ID: "synthetic-signing", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	wrapping, err := keyring.New(map[string][]byte{"synthetic-binding": bytes.Repeat([]byte{80}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(wrapping)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := oauth.NewProxyOIDCEvidenceCodec(crypto, clock.System{}, "synthetic-binding", nil)
	if err != nil {
		t.Fatal(err)
	}
	return pool, reference.OAuthProxyProductionConfiguration{
		Native: oauthpg.ProxyForwardConfig{
			Schema: "synthetic_oauth", ProductionDeployment: "production-a", Actor: identity.ActorID("AAAAAAAAAAAAAAAAAAAAAw"),
			PolicyID: "synthetic-proxy", GlobalAuthorityID: "synthetic-deployment", PolicyVersion: 9, AuditRetention: 1, MaximumDuration: 3 * time.Second,
			Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute,
				CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {71}}},
			Capability: capabilitypg.IssuerConfig{
				Crypto:   capability.ServiceConfig{Issuer: "https://production.example", Signer: signer, Resolver: keys, Clock: time.Now, Limits: capability.DefaultLimits()},
				Audience: "identity", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {74}}, PreparationTimeout: time.Second,
			},
			StateKeys: map[uint32][32]byte{3: {82}}, CurrentEnvelopeKey: "synthetic-original", EnvelopeKeys: map[string][]byte{"synthetic-original": bytes.Repeat([]byte{81}, 32)},
		},
		Start: oauthpg.ProxyStartConfig{
			Preview: oauthproxy.PreviewInitiationConfig{
				TenantID: identity.TenantID("AAAAAAAAAAAAAAAAAAAAAQ"), ActorID: identity.ActorID("AAAAAAAAAAAAAAAAAAAAAw"),
				Issuer: "https://preview-control.example", Audience: "production-proxy", Authentication: oauthProxyProductionRejectAuthentication{}, MaximumDuration: time.Second,
				Target: oauthproxy.PreviewTarget{Deployment: "preview-a", Origin: "https://preview.example", Redirect: "https://preview.example/oauth/complete", Recipient: "preview-identity"},
			},
			Provider: provider, ClaimsProfile: "synthetic-claims", ClaimsVersion: 11, CurrentStateKeyVersion: 3, StateLifetime: 4 * time.Minute,
			CapabilityPreparation: capabilitypg.IssuancePreparationConfig{Deployment: "production-a", ActiveEnvelopeKey: "synthetic-checkpoint",
				EnvelopeKeys:     map[string][]byte{"synthetic-checkpoint": bytes.Repeat([]byte{75}, 32)},
				VerificationKeys: []capabilitypg.PreparationVerificationKey{{ID: "synthetic-signing", HMAC: signing}}, Clock: time.Now},
		},
		Codec: codec, Clock: clock.System{},
	}
}

func assertOAuthProxyProductionNoRoutes(t *testing.T, owner *reference.OAuthProxyProduction) {
	t.Helper()
	if len(owner.OpenAPI().Operations()) != 0 {
		t.Fatal("unselected transport advertised operations")
	}
	handler := owner.Handler()
	if handler == nil {
		t.Fatal("unselected transport did not supply a closed handler")
	}
	for _, path := range []string{"/oauth2/callback/proxy", "/oauth2/proxy/complete", "/oauth2/proxy/start", "/session"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			request := httptest.NewRequest(method, "https://production.example"+path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || response.Header().Get("Set-Cookie") != "" || response.Header().Get("Location") != "" {
				t.Fatalf("unselected transport exposed %s %s: status %d", method, path, response.Code)
			}
		}
	}
}
