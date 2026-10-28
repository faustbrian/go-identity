//go:build integration

package postgres_test

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	identityhttp "github.com/faustbrian/go-identity/http"
	apikeyhttp "github.com/faustbrian/go-identity/http/apikey"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// The setup is the same genuine public registration/verification/native bearer
// consumer as the SDK suite. Only outbound email/HIBP are controlled. The new
// surface below runs real HTTPS handlers and native SQL/rate owners, not mocks.
func TestGenuinePasswordAPIKeyHTTPLifecycle(t *testing.T) {
	f := setupNativeConsumer(t)
	s, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	backend, err := ratepg.NewStrict(f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "apikey-http-consumer", Key: [32]byte{1}, Now: time.Now, MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	endpoint := "https://" + server.Listener.Addr().String()
	parsed, _ := url.Parse(endpoint)
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 2048, MaximumBodyBytes: 65536, MaximumDecodedBytes: 65536, MaximumFields: 128, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: parsed.Hostname(), TenantID: baselineTenant}}}
	feature, err := apikeyhttp.NewFeature(apikeyhttp.FeatureConfig{Config: apikeyhttp.Config{Network: network, Sessions: f.config.Sessions, Creator: s, Rotator: s, Revoker: s, SecretRate: rate, Now: time.Now, MaximumDuration: 5 * time.Second}, Create: true, Rotate: true, Revoke: true})
	if err != nil {
		t.Fatal("actual HTTP native composition rejected", err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: network, HandlerTimeout: 6 * time.Second, Document: identityhttp.DocumentConfig{Title: "API-key consumer", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = h
	server.StartTLS()
	client := server.Client()
	client.Timeout = 8 * time.Second
	type response struct {
		Committed     bool               `json:"committed"`
		CommitOutcome string             `json:"commitOutcome"`
		CommandID     identity.CommandID `json:"commandID"`
		Secret        string             `json:"secret"`
		Error         string             `json:"error"`
		Key           struct {
			ID          apikey.KeyID `json:"id"`
			Version     uint64       `json:"version"`
			Permissions []string     `json:"permissions"`
			ExpiresAt   time.Time    `json:"expiresAt"`
		} `json:"key"`
	}
	call := func(action, key string, body any) (int, response) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(f.ctx, "POST", endpoint+"/v1/apikey/"+action, strings.NewReader(string(wire)))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+f.caller.Bearer.Token())
		r.Header.Set("Idempotency-Key", key)
		out, err := client.Do(r)
		if err != nil {
			t.Fatal("actual HTTPS request failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(out.Body, 131073))
		closeErr := out.Body.Close()
		var decoded response
		if readErr != nil || closeErr != nil || len(data) > 131072 || json.Unmarshal(data, &decoded) != nil || out.Header.Get("Cache-Control") != "no-store" || len(out.Cookies()) != 0 {
			t.Fatal("actual response violated closed secret/cookie/resource boundary")
		}
		return out.StatusCode, decoded
	}
	expiry := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond)
	create := map[string]any{"name": "HTTP consumer", "permissions": []string{"invoice.read"}, "expiresAt": expiry}
	type attempt struct {
		status int
		result response
	}
	attempts := make(chan attempt, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			status, result := call("create", "http-original-create", create)
			attempts <- attempt{status, result}
		}()
	}
	group.Wait()
	close(attempts)
	var status int
	var created response
	reveals := 0
	for tried := range attempts {
		if tried.result.Secret != "" {
			reveals++
			status, created = tried.status, tried.result
		}
		if tried.result.Secret != "" && !tried.result.Committed {
			t.Fatal("concurrent uncommitted response revealed")
		}
		if tried.status != 200 && tried.status != 409 && tried.status != 503 {
			t.Fatal("concurrent original command lost bounded outcome", tried.status)
		}
	}
	if reveals != 1 {
		t.Fatal("concurrent original HTTP request did not have exactly one reveal", reveals)
	}
	if status != 200 || !created.Committed || created.CommitOutcome != "committed" || created.Secret == "" || created.Key.ID == "" || !created.Key.ExpiresAt.Equal(expiry) {
		t.Fatal("actual HTTP issuance did not commit/reveal", status, created.Error)
	}
	verify := func(wire string, allowed bool) {
		t.Helper()
		secret, err := apikey.ParseSecret(wire)
		if err != nil {
			t.Fatal("issued HTTP credential malformed")
		}
		out, err := s.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: f.config.Configuration.Spec().ID, ConfigurationRevision: 1, Secret: secret, RequiredPermissions: []string{"invoice.read"}})
		if allowed {
			if err != nil || out.Result == nil || out.Result.ValidateAt(f.config.Configuration, time.Now()) != nil {
				t.Fatal("actual HTTP credential could not authenticate", err)
			}
		} else if !errors.Is(err, apikey.ErrDenied) || out.Result != nil {
			t.Fatal("terminal HTTP credential still authenticated", err)
		}
	}
	verify(created.Secret, true)
	status, replayed := call("create", "http-original-create", create)
	if status != 200 || !replayed.Committed || replayed.CommandID != created.CommandID || replayed.Secret != "" {
		t.Fatal("HTTP original retry minted/revealed another key", status)
	}
	status, rotated := call("rotate", "http-original-rotate", map[string]any{"keyID": created.Key.ID, "expectedVersion": created.Key.Version})
	if status != 200 || !rotated.Committed || rotated.Secret == "" || rotated.Key.ID == created.Key.ID || !rotated.Key.ExpiresAt.Equal(expiry) || !slices.Equal(rotated.Key.Permissions, created.Key.Permissions) {
		t.Fatal("HTTP rotation expanded grant/expiry or lost successor", status, rotated.Error)
	}
	verify(created.Secret, false)
	verify(rotated.Secret, true)
	status, revoked := call("delete", "http-original-revoke", map[string]any{"keyID": rotated.Key.ID, "expectedVersion": rotated.Key.Version})
	if status != 200 || !revoked.Committed || revoked.Secret != "" {
		t.Fatal("HTTP revocation failed", status, revoked.Error)
	}
	verify(rotated.Secret, false)
	var commands, keys int
	// Verification attempts retain effects in this same native table. Count
	// these exact management commands, not unrelated verification history.
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.command_effects WHERE tenant_id=$1 AND command_id IN ($2,$3,$4)`, baselineTenant, string(created.CommandID), string(rotated.CommandID), string(revoked.CommandID)).Scan(&commands); err != nil || commands != 3 {
		t.Fatal("HTTP retry or lifecycle duplicated native commands")
	}
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1`, baselineTenant).Scan(&keys); err != nil || keys != 2 {
		t.Fatal("HTTP lifecycle lost predecessor/successor tombstones")
	}

	// Native protected-risk limits differ from HTTP's shared10/10m policy.
	// Exercise the actual shared SQL owner directly after the three genuine
	// management debits, without fabricating another native mutation or actor.
	resolver, err := identityhttp.NewNetworkResolver(network)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/apikey/create", nil)
	r.Host = parsed.Host
	r.RemoteAddr = "127.0.0.1:54321"
	r.TLS = &tls.ConnectionState{}
	facts, err := resolver.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "apikey-http-consumer", Key: [32]byte{1}, Now: time.Now, MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { second.Close() })
	var last identityhttp.KeyedSecretRateRequest
	for i := range 7 {
		key, _ := identity.NewIdempotencyKey([]byte("http-rate-" + strconv.Itoa(i)))
		last = identityhttp.KeyedSecretRateRequest{OperationID: []string{"identity.apikey.create", "identity.apikey.rotate", "identity.apikey.delete"}[i%3], UserID: f.user, IdempotencyKey: key}
		if out, err := second.Admit(f.ctx, facts, last); err != nil || !out.Allowed {
			t.Fatal("shared cross-route rate budget reset or denied early", i, err)
		}
	}
	if out, err := rate.Admit(f.ctx, facts, last); err != nil || !out.Allowed {
		t.Fatal("reconstructed rate owner recounted original debit", err)
	}
	last.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("http-eleventh-rate"))
	if out, err := rate.Admit(f.ctx, facts, last); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter <= 0 {
		t.Fatal("actual shared HTTP budget did not deny eleventh distinct command", err)
	}
}
