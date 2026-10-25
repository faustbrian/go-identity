package passkeyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	passkey "github.com/faustbrian/go-passkey"
)

// Only the borrowed native-result boundary is controlled here. Genuine
// assertion, persisted child and independent factor verification are exercised
// by the Reference PostgreSQL journey, not manufactured by this transport test.
type challengeSignin struct {
	*deniedSignin
	result passkey.SigninResult
	err    error
}

func (*challengeSignin) SigninRateSource(_ context.Context, r passkey.SigninCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	return passkey.CeremonyRateSource{Kind: passkey.RateSourceIdentifier, Identifier: r.Identifier, CeremonyID: r.CeremonyID, Lifetime: 5 * time.Minute}, nil
}
func (*challengeSignin) DiscoverableSigninRateSource(_ context.Context, r passkey.DiscoverableCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	return passkey.CeremonyRateSource{Kind: passkey.RateSourceAnonymousFlow, AnonymousFlowID: r.FlowID, CeremonyID: r.CeremonyID, Lifetime: 5 * time.Minute}, nil
}
func (o *challengeSignin) Signin(context.Context, passkey.SigninCompletion) (passkey.SigninResult, error) {
	return o.result, o.err
}
func (o *challengeSignin) DiscoverableSignin(context.Context, passkey.DiscoverableSigninCompletion) (passkey.SigninResult, error) {
	return o.result, o.err
}

func TestSigninMFAChallengeHasExplicitRevealOnceTransport(t *testing.T) {
	for _, mode := range []string{"fresh", "discoverable", "headers", "disabled", "replay", "expired", "extended", "same-id", "foreign-tenant", "foreign-actor", "foreign-schema", "foreign-version", "error", "mixed-token", "delayed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, base, flow, device := signinFixture(t)
			c.MFAContinuation = mode != "disabled"
			c.Discoverable = mode == "discoverable"
			now := c.Now()
			c.Now = func() time.Time { return now }
			signer, err := capability.NewHMACSHA256Signer("synthetic", []byte(strings.Repeat("x", 32)))
			if err != nil {
				t.Fatal(err)
			}
			wire, err := capability.Issue(t.Context(), capability.Payload{Version: 1, ID: "AgICAgICAgICAgICAgICAg", Issuer: "https://issuer.example", Tenant: "tenant-a", Subject: "user-a", Audiences: []string{c.Audience}, Resource: "identity.mfa/user-a", Operation: "identity.mfa.complete", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1}, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := capability.ParseProof(wire, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil }) })
			receipt := updateObservation(t, identity.CommitOutcomeCommitted).Receipt
			receipt.Binding.OperationID = "identity.passkey.signin-verify"
			receipt.Binding.SchemaID = "identity.passkey.signin-verify.native-v1"
			receipt.Binding.RecordID = string(receipt.Binding.CommandID)
			receipt.Binding.CorrelationID = string(receipt.Binding.CommandID)
			receipt.Feature.Operation.OperationID = receipt.Binding.OperationID
			receipt.Feature.Operation.SchemaID = receipt.Binding.SchemaID
			receipt.Feature.BeforeVersion, receipt.Feature.AfterVersion = 0, 1
			if receipt.Validate() != nil {
				t.Fatal("native observation fixture malformed")
			}
			owner := &challengeSignin{deniedSignin: base, result: passkey.SigninResult{Receipt: receipt, Challenge: &passkey.SigninMFAChallenge{ID: "AgICAgICAgICAgICAgICAg", Method: "totp", ExpiresAt: now.Add(time.Minute), Proof: proof}}}
			c.Service = owner
			switch mode {
			case "replay":
				owner.result.Replayed = true
			case "expired":
				owner.result.Challenge.ExpiresAt = now
			case "extended":
				owner.result.Challenge.ExpiresAt = now.Add(6 * time.Minute)
			case "same-id":
				owner.result.Challenge.ID = receipt.Binding.CommandID
			case "foreign-tenant":
				owner.result.Receipt.Binding.TenantID = "other-tenant"
			case "foreign-actor":
				owner.result.Receipt.Binding.ActorID = "other-actor"
			case "foreign-schema":
				owner.result.Receipt.Binding.SchemaID = "identity.passkey.update.native-v1"
			case "foreign-version":
				owner.result.Receipt.Feature.BeforeVersion, owner.result.Receipt.Feature.AfterVersion = 1, 2
			case "error":
				owner.err = errors.New("native unavailable")
			case "mixed-token":
				owner.result.Session.Token, _ = session.NewToken(32)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			middleware := []identityhttp.MiddlewareDescriptor{transportHook(identityhttp.MiddlewareBeforeHandler, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				next.ServeHTTP(w, r)
				switch mode {
				case "headers":
					w.Header().Set("X-MFA-Token", "injected")
					w.Header().Set("Set-Cookie", "injected")
					w.Header().Set("X-CSRF-Token", "injected")
				case "delayed":
					now = now.Add(2 * time.Minute)
				case "cancelled":
					cancel()
				}
			})}
			h, err := NewSigninVerifyHandlerWithMiddleware(c, middleware)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"mode":"identified","flowID":"AAAAAAAAAAAAAAAAAAAAAQ","identifier":"person@example.invalid","commandID":"AAAAAAAAAAAAAAAAAAAAAw","ceremonyID":"AAAAAAAAAAAAAAAAAAAAAg","response":{}}`
			// The original receipt command differs from the child. Keep the
			// client locator aligned with its immutable native observation.
			body = strings.Replace(body, `"commandID":"AAAAAAAAAAAAAAAAAAAAAw"`, `"commandID":"`+string(receipt.Binding.CommandID)+`"`, 1)
			if mode == "discoverable" {
				body = strings.Replace(body, `"mode":"identified"`, `"mode":"discoverable"`, 1)
				body = strings.Replace(body, `,"identifier":"person@example.invalid"`, "", 1)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, signinRequest("signin-verify", body, flow, device).WithContext(ctx))
			var out map[string]any
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), wire) || strings.Contains(w.Body.String(), "user-a") {
				t.Fatal("partial authentication escaped response custody")
			}
			if mode == "fresh" || mode == "discoverable" || mode == "headers" {
				if w.Code != 200 || w.Header().Get("X-MFA-Token") != wire || out["challengeRequired"] != true || out["signedIn"] != false || out["challengeID"] != "AgICAgICAgICAgICAgICAg" {
					t.Fatal("selected fresh challenge was not delivered without a session", w.Code)
				}
			} else if w.Code == 200 || w.Header().Get("X-MFA-Token") != "" || out["challengeRequired"] == true {
				t.Fatal("non-deliverable challenge escaped", mode, w.Code)
			}
			if err := proof.Transfer(t.Context(), func(context.Context, []byte) error { return nil }); err == nil {
				t.Fatal("returned native child retained reusable transport custody")
			}
		})
	}
}

func TestSigninMFAWireDeclaresOnlySelectedChallengeResponse(t *testing.T) {
	for _, selected := range []bool{false, true} {
		c, _, _, _ := signinFixture(t)
		c.MFAContinuation = selected
		feature, err := NewFeature(FeatureConfig{Signin: &c})
		if err != nil {
			t.Fatal(err)
		}
		_, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := openapi.ParseJSON(t.Context(), strings.NewReader(string(document.JSON())), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		response := parsed.Raw()
		for _, field := range []string{"paths", "/v1/passkey/signin-verify", "post", "responses", "200"} {
			var ok bool
			response, ok = response.Lookup(field)
			if !ok {
				t.Fatal("selected signin response missing")
			}
		}
		headers, _ := response.Lookup("headers")
		if _, present := headers.Lookup("X-MFA-Token"); present != selected {
			t.Fatal("challenge header advertised outside selection")
		}
		schema := response
		for _, field := range []string{"content", "application/json", "schema"} {
			var ok bool
			schema, ok = schema.Lookup(field)
			if !ok {
				t.Fatal("response schema missing")
			}
		}
		for _, sample := range []struct {
			wire  string
			valid bool
		}{
			{`{"signedIn":true,"commandID":"AAAAAAAAAAAAAAAAAAAAAw","commitOutcome":"committed","sessionID":"session-a","counterRisk":false}`, true},
			{`{"signedIn":false,"challengeRequired":true,"commandID":"AAAAAAAAAAAAAAAAAAAAAw","commitOutcome":"committed","challengeID":"AgICAgICAgICAgICAgICAg","challengeMethod":"totp","challengeExpiresAt":"2026-10-25T14:00:00Z"}`, selected},
			{`{"signedIn":false,"challengeRequired":true,"commandID":"AAAAAAAAAAAAAAAAAAAAAw","commitOutcome":"committed","challengeID":"AgICAgICAgICAgICAgICAg","challengeMethod":"totp","challengeExpiresAt":"2026-10-25T14:00:00Z","token":"forbidden"}`, false},
		} {
			instance, err := parse.JSON(t.Context(), strings.NewReader(sample.wire), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || report.Valid() != sample.valid {
				t.Fatal("closed selected MFA response contract diverged", err)
			}
		}
	}
}
