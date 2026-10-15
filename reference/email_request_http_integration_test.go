//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
)

func TestReferencePostgresEmailRequestsHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailAddressQueries: true, emailChangeCase: "request-http"})
}
func TestReferencePostgresEmailChangeRequestsHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailAddressQueries: true, emailChangeCase: "request-http"})
}

// Overrides only invocation transport; every store, proof, counter, issuer,
// delivery and lifecycle effect belongs to the actual running reference graph.
type httpEmailConsumer struct {
	emailManagementConsumer
	invoke func(passwordpg.EmailManagementRequest, bool, bool) (passwordpg.EmailManagementResult, error)
}

func (s httpEmailConsumer) VerificationSend(_ context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	return s.invoke(r, false, false)
}
func (s httpEmailConsumer) VerificationResend(_ context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	return s.invoke(r, true, false)
}
func (s httpEmailConsumer) ChangeRequest(_ context.Context, r passwordpg.EmailManagementRequest) (passwordpg.EmailManagementResult, error) {
	return s.invoke(r, false, true)
}

func invokeSelectedEmailRequest(t *testing.T, ctx context.Context, f liveStores, client *http.Client, base, origin string, r passwordpg.EmailManagementRequest, resend, change bool) (passwordpg.EmailManagementResult, error) {
	t.Helper()
	path := "/v1/email/verification-send"
	field := "address"
	if change {
		path = "/v1/email/change-request"
		field = "newAddress"
	}
	input := map[string]string{"proofID": string(r.Primary.Proof.Proof.ID), "callback": r.CallbackURL}
	if r.Address != "" {
		input[field] = string(r.Address)
	}
	if resend {
		input["addressID"] = string(r.Primary.AddressID)
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := r.Primary.CSRFToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := f.config.Session.Native.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	call := func() (*http.Response, emailhttp.RequestResponse) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", csrf)
		request.Header.Set("Idempotency-Key", string(r.Primary.CommandID))
		request.AddCookie(&http.Cookie{Name: cookie.Name, Value: r.Primary.Session.Token()})
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("selected email HTTPS request", err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		var out emailhttp.RequestResponse
		if readErr != nil || closeErr != nil || len(wire) > 16384 || json.Unmarshal(wire, &out) != nil || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(wire, []byte(r.Primary.Session.Token())) || bytes.Contains(wire, []byte(csrf)) || bytes.Contains(wire, []byte("@")) {
			t.Fatal("email request transport disclosed credentials or personal intent", response.StatusCode)
		}
		clear(wire)
		return response, out
	}
	response, out := call()
	result := passwordpg.EmailManagementResult{CommandID: out.CommandID}
	switch out.CommitOutcome {
	case "committed":
		result.Outcome = identity.CommitOutcomeCommitted
	case "not_committed":
		result.Outcome = identity.CommitOutcomeNotCommitted
	case "unknown":
		result.Outcome = identity.CommitOutcomeUnknown
	case "conflict":
		result.Outcome = identity.CommitOutcomeConflict
	case "in_progress":
		result.Outcome = identity.CommitOutcomeInProgress
	}
	if response.StatusCode != 202 {
		if out.Queued || out.DeliveryState != "" {
			t.Fatal("failed request claimed queued delivery")
		}
		return result, errors.New("selected request denied")
	}
	if !out.Queued || out.DeliveryState != "queued" || out.CommitOutcome != "committed" || out.CommandID == "" {
		t.Fatal("successful request has no original queued result")
	}
	// Independent native rows must already exist before any replay or native call.
	// A false HTTP acknowledgement cannot cause this oracle to build the feature.
	var version, verification uint64
	var address string
	err = f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,version,verification_version FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND (($3<>'' AND identifier_id=$3) OR ($3='' AND canonical_value=$4))`, string(r.Primary.TenantID), string(r.Primary.Caller.Request.Subject.ID), func() string {
		if resend {
			return string(r.Primary.AddressID)
		}
		return ""
	}(), string(r.Address)).Scan(&address, &version, &verification)
	if err != nil || version == 0 || verification == 0 {
		t.Fatal("HTTP acknowledged without native pending transition", err)
	}
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(out.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var grants, messages int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$2),(SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=$1 AND command_id=$3)`, string(r.Primary.TenantID), string(out.CommandID), command).Scan(&grants, &messages); err != nil || grants != 1 || messages != 1 {
		t.Fatal("HTTP response has no exactly-once native issuance/delivery", err)
	}
	replay, observed := call()
	if replay.StatusCode != 202 || observed != out {
		t.Fatal("original HTTP retry required live spent source or changed result", replay.StatusCode)
	}
	result.AddressID, result.IdentifierVersion, result.VerificationVersion = identity.IdentifierID(address), version, verification
	return result, nil
}

func proveSelectedEmailChangeConfirmation(t *testing.T, ctx context.Context, client *http.Client, base, origin string, r email.ChangeConfirmRequest, token string) {
	t.Helper()
	for _, mode := range []string{"callback", "fresh", "replay"} {
		callback := r.Callback.String()
		want := 200
		if mode == "callback" {
			callback = origin + "/wrong"
			want = 403
		}
		wire, err := json.Marshal(map[string]string{"token": token, "callback": callback, "commandID": string(r.CommandID)})
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/email/change-confirm", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		var out emailhttp.ConfirmationResponse
		if readErr != nil || closeErr != nil || len(body) > 16384 || json.Unmarshal(body, &out) != nil || response.StatusCode != want || len(response.Cookies()) != 0 || bytes.Contains(body, []byte(token)) {
			t.Fatal("selected change confirmation outcome", mode, response.StatusCode)
		}
		if mode == "fresh" && (!out.Confirmed || out.Address == nil) || mode == "replay" && (!out.Replayed || out.Address != nil) {
			t.Fatal("selected change confirmation lost fresh/replay disclosure")
		}
		clear(body)
		clear(wire)
	}
}
