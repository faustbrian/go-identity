//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresEmailManagementSharedHTTPS(t *testing.T) {
	_ = reference.HTTPRegistrationVerificationConfiguration{ManagedAddresses: true}
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementResend: true, emailAddressQueries: true, emailChangeCase: "shared-http"})
}

// This is the same running reference HTTPS server that already completed
// genuine signup verification/signin, now handling an actual managed successor.
// No test mounts another handler, supplies a fake store or performs confirmation.
func proveReferenceSharedEmailConfirmationHTTPS(t *testing.T, ctx context.Context, f liveStores, client *http.Client, base, origin string, r email.VerificationConfirmRequest, target identity.IdentifierID) {
	t.Helper()
	err := r.Token.Transfer(ctx, func(_ context.Context, token []byte) error {
		for _, mode := range []string{"origin", "callback", "signature", "fresh", "replay", "other-command"} {
			callback, requestOrigin, command, want := r.Callback.String(), origin, r.CommandID, 200
			proof := string(token)
			switch mode {
			case "origin":
				requestOrigin, want = "https://foreign.example", 403
			case "callback":
				callback, want = origin+"/confirm", 403
			case "signature":
				changed := bytes.Clone(token)
				if changed[len(changed)-8] == 'A' {
					changed[len(changed)-8] = 'B'
				} else {
					changed[len(changed)-8] = 'A'
				}
				proof, want = string(changed), 403
				clear(changed)
			case "other-command":
				command, _ = identity.NewCommandID()
				want = 403
			}
			wire, err := json.Marshal(map[string]string{"token": proof, "callback": callback, "commandID": string(command)})
			if err != nil {
				t.Fatal(err)
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/email/verification-confirm", bytes.NewReader(wire))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Origin", requestOrigin)
			request.Header.Set("Content-Type", "application/json")
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("shared native verification HTTPS", err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
			closeErr := response.Body.Close()
			clear(wire)
			var out emailhttp.ConfirmationResponse
			var decodeErr error
			if mode == "origin" {
				// The real outer CORS guard owns this documented plain-text
				// refusal; it runs before the email JSON handler.
				if string(body) != "identity.http.origin_denied\n" || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/plain") {
					t.Fatal("shared route lost outer origin-denial contract")
				}
			} else {
				decodeErr = json.Unmarshal(body, &out)
			}
			if readErr != nil || closeErr != nil || len(body) > 16384 || decodeErr != nil || response.StatusCode != want || len(response.Cookies()) != 0 || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(body, token) {
				t.Fatal("shared confirmation outcome/custody", mode, response.StatusCode, "decode", decodeErr, "bytes", len(body), "cookies", len(response.Cookies()), "cache", response.Header.Get("Cache-Control"), "redirect", response.Header.Get("Location") != "", "credential-echo", bytes.Contains(body, token))
			}
			clear(body)
			if want != 200 {
				if out.Confirmed || out.Address != nil {
					t.Fatal("denied shared route disclosed success")
				}
				continue
			}
			if !out.Confirmed || out.CommitOutcome != "committed" || out.CommandID != r.CommandID || out.Recovery == nil || out.Replayed != (mode == "replay") || (out.Address == nil) != (mode == "replay") {
				t.Fatal("shared route replaced original confirmation/replay")
			}
			if out.Address != nil {
				if out.Address.IdentifierID != target || out.Address.Primary || out.Address.IdentifierVersion != 3 || out.Address.VerificationVersion != 3 {
					t.Fatal("shared management route selected signup semantics")
				}
				var count int
				if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND verified AND NOT is_primary AND version=3 AND verification_version=3 AND canonical_value=$4`, string(r.TenantID), string(out.Address.UserID), string(out.Address.IdentifierID), out.Address.Email).Scan(&count); err != nil || count != 1 {
					t.Fatal("shared HTTP snapshot differs from native commit", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("shared route proof transport", err)
	}
}
