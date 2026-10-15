//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// The full graph supplies the database/rate history and real signup/session/
// sender path. This invokes the public change HTTP feature with the real native
// owner. It is not yet FeatureSet-owned email-management configuration.
func proveReferenceEmailChangeHTTPS(t *testing.T, ctx context.Context, f liveStores, service emailManagementConsumer, confirmation email.ChangeConfirmRequest, addressID identity.IdentifierID, token, origin string) {
	t.Helper()
	backend, err := ratepg.OpenStrict(ctx, f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal("reference-owned native HTTP rate history unavailable", err)
	}
	rate, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.ChallengeVerificationRateConfig{Shared: backend, Namespace: "reference-email-change", Key: [32]byte{215}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 8192, MaximumDecodedBytes: 8192, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "email-change.example.test", TenantID: confirmation.TenantID}}}
	feature, err := emailhttp.NewChangeConfirmationFeature(emailhttp.ChangeConfirmationConfig{Network: network, Service: service, Rate: rate, Origin: identityhttp.Origin(origin), ActorID: identity.ActorID(confirmation.Caller.Request.Subject.ID), PolicyRevision: confirmation.Caller.PolicyRevision, Now: time.Now, MaximumDuration: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(ctx, identityhttp.DocumentConfig{Title: "Email change", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || !bytes.Contains(doc.JSON(), []byte("/v1/email/change-confirm")) {
		t.Fatal("selected change route/wire is absent", err)
	}
	server := httptest.NewTLSServer(h)
	defer server.Close()
	client := server.Client()
	client.Timeout = 15 * time.Second
	defer client.CloseIdleConnections()
	for _, mode := range []string{"origin", "callback", "fresh", "replay"} {
		callback, requestOrigin, want := confirmation.Callback.String(), origin, 200
		if mode == "origin" {
			requestOrigin, want = "https://foreign.example", 403
		}
		if mode == "callback" {
			callback, want = origin+"/other", 403
		}
		wire, err := json.Marshal(map[string]string{"token": token, "callback": callback, "commandID": string(confirmation.CommandID)})
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/email/change-confirm", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Host = "email-change.example.test"
		r.Header.Set("Origin", requestOrigin)
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("public change HTTPS request failed", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		clear(wire)
		var out emailhttp.ConfirmationResponse
		if readErr != nil || closeErr != nil || len(body) > 16384 || json.Unmarshal(body, &out) != nil || response.StatusCode != want || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(body, []byte(token)) {
			t.Fatal("change HTTPS outcome/custody differs", mode, response.StatusCode, out.Error)
		}
		clear(body)
		if want != 200 {
			var pending bool
			if err := f.pool.Raw().QueryRow(ctx, `SELECT NOT verified AND NOT is_primary AND version=1 AND verification_version=1 FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(confirmation.TenantID), string(confirmation.Caller.Request.Resource.ID), string(addressID)).Scan(&pending); err != nil {
				t.Fatal("candidate cannot be independently observed", err)
			}
			if !pending || out.Confirmed || out.Address != nil {
				t.Fatal("denied HTTP request mutated/disclosed candidate")
			}
			continue
		}
		if !out.Confirmed || out.CommitOutcome != "committed" || out.CommandID != confirmation.CommandID || out.Recovery == nil || out.Replayed != (mode == "replay") || (out.Address == nil) != (mode == "replay") {
			t.Fatal("change HTTP lost original committed/replay identity")
		}
		if out.Address != nil {
			var actual int
			if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND canonical_value=$4 AND is_primary AND verified AND version=$5 AND verification_version=$6`, string(confirmation.TenantID), string(confirmation.Caller.Request.Resource.ID), string(addressID), out.Address.Email, out.Address.IdentifierVersion, out.Address.VerificationVersion).Scan(&actual); err != nil || actual != 1 || out.Address.IdentifierID != addressID || string(out.Address.UserID) != string(confirmation.Caller.Request.Resource.ID) || !out.Address.Primary || out.Address.IdentifierVersion != 2 || out.Address.VerificationVersion != 2 {
				t.Fatal("fresh HTTP projection disagrees with committed primary", err)
			}
		}
	}
}
