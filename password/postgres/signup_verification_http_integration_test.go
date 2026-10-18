//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// The original token comes from the actual delivery worker's sender boundary.
// All identity, capability, command, risk and rate owners remain native.
func testRegistrationConfirmationHTTP(t *testing.T, ctx context.Context, service *SignupService, c SignupConfig, token, callback, expectedAddress string, caller authorization.DecisionContext, grant capability.Grant, command identity.CommandID, router *EmailVerificationRouter) {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := service.pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("confirmation rate migration failed", err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := service.pool.Raw().Exec(cleanup, migration.Down); err != nil {
				t.Error("confirmation rate cleanup failed", err)
			}
		}()
	}
	backend, err := ratepg.NewStrict(service.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "confirmation-native", Key: [32]byte{83}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 8192, MaximumDecodedBytes: 8192, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "auth.example.test", TenantID: identity.TenantID(grant.Payload().Tenant)}}}
	feature, err := emailhttp.NewFeature(emailhttp.FeatureConfig{ProfiledConfirmation: &emailhttp.ProfiledConfirmationConfig{Network: network, Service: router, Rate: rate, Origin: "https://auth.example.test", ActorID: identity.ActorID(caller.Request.Subject.ID), PolicyRevision: authorization.Revision(c.Coordinator.QueryPolicy.PolicyVersion), Now: time.Now, MaximumDuration: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: network, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Native confirmation", Version: "1"}}, ops, nil)
	if err != nil || len(document.Operations()) != 1 {
		t.Fatal("selected confirmation router unavailable", err)
	}
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil || document.Version() != "3.1.1" {
		t.Fatal("confirmation document unavailable", err)
	}
	invoke := func(origin, target string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]string{"token": token, "callback": target, "commandID": string(command)})
		if err != nil {
			t.Fatal("confirmation body unavailable")
		}
		defer clear(body)
		r := httptest.NewRequest(http.MethodPost, "/v1/email/verification-confirm", bytes.NewReader(body)).WithContext(ctx)
		r.Host = "auth.example.test"
		r.RemoteAddr, r.TLS = "[2001:db8::1]:1234", &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Authorization") != "" || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" || bytes.Contains(w.Body.Bytes(), []byte(token)) {
			t.Fatal("confirmation response escaped credential custody")
		}
		return w
	}
	assertCommands := func(want int) {
		t.Helper()
		var count int
		if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM rate_limit_atomic_commands`).Scan(&count); err != nil || count != want {
			t.Fatal("confirmation admission did not preserve original phases", err, count, want)
		}
	}
	if w := invoke("https://foreign.example.test", callback); w.Code != 403 {
		t.Fatal("foreign origin reached original confirmation", w.Code)
	}
	assertCommands(0)
	if w := invoke("https://auth.example.test", "https://foreign.example.test/finish"); w.Code != 403 {
		t.Fatal("foreign callback reached original confirmation", w.Code)
	}
	assertCommands(1)
	for index := 0; index < 2; index++ {
		w := invoke("https://auth.example.test", callback)
		var out emailhttp.ConfirmationResponse
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 200 || !out.Confirmed || out.CommitOutcome != "committed" || out.CommandID != command || out.Replayed != (index == 1) || out.Recovery == nil {
			t.Fatal("native selected confirmation failed", w.Code, out.CommitOutcome)
		}
		q := out.Recovery
		if q.TenantID != identity.TenantID(grant.Payload().Tenant) || q.UserID != identity.UserID(grant.Payload().Subject) || q.RecordID != grant.Payload().Resource || q.ActorID != identity.ActorID(caller.Request.Subject.ID) || q.ActorKind != authorization.SubjectServiceAccount {
			t.Fatal("confirmation recovery retargeted original scope")
		}
		if index == 0 {
			if out.Address == nil || expectedAddress == "" || out.Address.Email != expectedAddress || out.Address.UserID != q.UserID || out.Address.IdentifierID != identity.IdentifierID(q.RecordID) || out.Address.IdentifierVersion != 2 || out.Address.VerificationVersion != 2 {
				t.Fatal("fresh native confirmation withheld exact committed address")
			}
		} else if out.Address != nil {
			t.Fatal("native HTTP replay re-disclosed address")
		}
		schema := parsed.Raw()
		for _, key := range []string{"paths", "/v1/email/verification-confirm", "post", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
			var ok bool
			schema, ok = schema.Lookup(key)
			if !ok {
				t.Fatal("native confirmation response undocumented")
			}
		}
		instance, err := parse.JSON(ctx, bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
		if err != nil {
			t.Fatal("native confirmation response is not JSON")
		}
		report, err := validate.SchemaInstance(ctx, parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			t.Fatal("native confirmation violates its selected wire schema", err)
		}
		assertCommands(3 + index*2)
	}
}
