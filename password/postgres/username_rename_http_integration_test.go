//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-identity/username"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// A real committed rename has already invalidated the original session. The
// selected route must authenticate original custody and recover that command,
// not demand a newly authenticated session or consume another proof/name.
func testUsernameRenameHTTPRecovery(t *testing.T, ctx context.Context, service *UsernameRenameService, source *ReauthenticationService, request username.RenameRequest, cookie session.CookiePolicy, origin string, expected identity.CommandResult) {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := source.pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("rename HTTP rate migration", err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := source.pool.Raw().Exec(cleanup, migration.Down); err != nil {
				t.Error("rename HTTP rate cleanup", err)
			}
		}()
	}
	backend, err := ratepg.NewStrict(source.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: "username-native-http", Key: [32]byte{111}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: u.Hostname(), TenantID: request.TenantID}}}
	config := passwordhttp.UsernameRenameConfig{Network: network, Service: service, Proofs: source.repository, Rate: rate, Cookie: cookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, PolicyRevision: request.Caller.PolicyRevision, MaximumDuration: 5 * time.Second}
	feature, err := passwordhttp.NewUsernameFeature(passwordhttp.UsernameFeatureConfig{Rename: &config})
	if err != nil {
		t.Fatal("native username rename feature", err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: network, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Native username rename", Version: "1"}}, ops, nil)
	if err != nil || len(document.Operations()) != 1 || document.Version() != "3.1.1" {
		t.Fatal("native username rename router", err)
	}
	csrf, err := request.CSRFToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	cookieAttributes, err := cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		body, err := json.Marshal(map[string]any{"proofID": request.Proof.Proof.ID, "identifierID": request.IdentifierID, "expectedIdentifierVersion": request.ExpectedIdentifierVersion, "expectedVerificationVersion": request.ExpectedVerificationVersion, "username": request.Username})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, origin+"/v1/username/update", bytes.NewReader(body))
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "192.0.2.10:1234"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("Idempotency-Key", "canonical-native-rename")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: cookieAttributes.Name, Value: request.Session.Token()})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var out passwordhttp.UsernameRenameResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Changed || out.CommandID != expected.Binding.CommandID || out.IdentifierVersion != expected.Feature.AfterVersion || out.Recovery == nil || out.Recovery.RecordID != string(request.IdentifierID) {
			t.Fatal("native HTTP lost original committed rename after session invalidation", w.Code)
		}
		if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), request.Username) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("native rename recovery renewed or disclosed custody")
		}
	}
}
