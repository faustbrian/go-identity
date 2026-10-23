package identityhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestPasskeyOptionsRateSharesOriginalIPAndIdentifierBudgets(t *testing.T) {
	now := func() time.Time { return time.Unix(1800000000, 0) }
	l, _ := authLimiter(t, now)
	facts := safeFacts(t, "198.51.100.1")
	for i := range 20 {
		operation := "identity.passkey.signin-options"
		if i%2 == 0 {
			operation = "identity.passkey.register-options"
		}
		if out, err := l.AdmitPasskeyOptionsIP(context.Background(), facts, operation); err != nil || !out.Allowed {
			t.Fatal("passkey options IP denied early", i, err)
		}
	}
	if out, err := l.AdmitOriginalFlow(context.Background(), facts); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != 30*time.Second {
		t.Fatal("passkey options escaped original auth IP budget", out, err)
	}
	identifiers, _ := authLimiter(t, now)
	for i := range 10 {
		originalFacts := safeFacts(t, fmt.Sprintf("198.51.100.%d", i+1))
		if out, err := identifiers.AdmitPasskeyOptionsIP(context.Background(), originalFacts, "identity.passkey.signin-options"); err != nil || !out.Allowed {
			t.Fatal("identified options IP denied early", i, err)
		}
		if out, err := identifiers.AdmitPasskeyOptionsIdentifier(context.Background(), originalFacts, identityhttp.AuthRateRequest{OperationID: "identity.passkey.signin-options", Identifier: "person@example.invalid"}); err != nil || !out.Allowed {
			t.Fatal("original identifier denied early", i, err)
		}
	}
	if out, err := identifiers.AdmitPasskeyOptionsIdentifier(context.Background(), facts, identityhttp.AuthRateRequest{OperationID: "identity.passkey.signin-options", Identifier: "person@example.invalid"}); !errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter != time.Minute {
		t.Fatal("passkey options identifier budget bypass", out, err)
	}
	for _, operation := range []string{"identity.password.signin", "identity.passkey.signin-verify", "unknown"} {
		if _, err := l.AdmitPasskeyOptionsIP(context.Background(), facts, operation); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("wrong operation used options IP profile", operation)
		}
	}
	for _, input := range []identityhttp.AuthRateRequest{
		{OperationID: "identity.passkey.register-options", Identifier: "person@example.invalid"},
		{OperationID: "identity.passkey.signin-options"},
		{OperationID: "identity.passkey.signin-options", Identifier: "person@example.invalid", UserID: "claimed"},
	} {
		if _, err := l.AdmitPasskeyOptionsIdentifier(context.Background(), facts, input); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("absent or invented options dimension accepted")
		}
	}
	if _, err := l.Admit(context.Background(), facts, identityhttp.AuthRateRequest{OperationID: "identity.passkey.signin-options", Identifier: "person@example.invalid"}); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("new selection silently changed generic signin rate policy")
	}
}

func TestPasskeyVerificationRatePreservesAnonymousAndIdentifierCustody(t *testing.T) {
	b := &secretShared{}
	l, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: b, Namespace: "verify-test", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	facts := safeFacts(t, "198.51.100.1")
	identified := identityhttp.PasskeyVerificationRateRequest{Identifier: "original@example.invalid", ChallengeID: "original-ceremony", ChallengeLifetime: 5 * time.Minute}
	if out, err := l.AdmitPasskey(context.Background(), facts, identified); err != nil || !out.Allowed || len(b.last.Requests) != 3 {
		t.Fatal("original identified verification denied", err)
	}
	first := b.last
	discovery := identified
	discovery.Identifier, discovery.AnonymousFlowID = "", "original-flow"
	if out, err := l.AdmitPasskey(context.Background(), facts, discovery); err != nil || !out.Allowed || len(b.last.Requests) != 3 {
		t.Fatal("original anonymous verification denied", err)
	}
	second := b.last
	if first.Requests[0].Key != second.Requests[0].Key || first.Requests[2].Key != second.Requests[2].Key || first.Requests[1].Key == second.Requests[1].Key {
		t.Fatal("anonymous rate source reset original IP/challenge or impersonated identifier")
	}
	for _, requests := range [][]string{{first.Requests[1].Key.String(), first.Requests[2].Key.String()}, {second.Requests[1].Key.String(), second.Requests[2].Key.String()}} {
		for _, key := range requests {
			if strings.Contains(key, "original") || strings.Contains(key, "example.invalid") {
				t.Fatal("rate key disclosed original input")
			}
		}
	}
	if second.Requests[1].Policy.Capacity() != 10 || second.Requests[1].Policy.Period() != 10*time.Minute || second.Requests[2].Policy.Capacity() != 10 || second.Requests[2].Policy.Period() != 5*time.Minute {
		t.Fatal("anonymous flow renewed or weakened original rate policy")
	}
	if out, err := l.AdmitIP(context.Background(), facts); err != nil || !out.Allowed || len(b.last.Requests) != 1 || b.last.Requests[0].Key != second.Requests[0].Key {
		t.Fatal("anonymous pre-source IP budget diverged", err)
	}
	if out, err := l.AdmitPasskeyChallenge(context.Background(), facts, discovery); err != nil || !out.Allowed || len(b.last.Requests) != 2 || b.last.Requests[0].Key != second.Requests[1].Key || b.last.Requests[1].Key != second.Requests[2].Key {
		t.Fatal("anonymous post-source admission reset dimensions or recounted IP", err)
	}
	for _, mutate := range []func(*identityhttp.PasskeyVerificationRateRequest){
		func(r *identityhttp.PasskeyVerificationRateRequest) { r.Identifier = "claimed@example.invalid" },
		func(r *identityhttp.PasskeyVerificationRateRequest) { r.ChallengeID = "" },
		func(r *identityhttp.PasskeyVerificationRateRequest) { r.AnonymousFlowID = "" },
		func(r *identityhttp.PasskeyVerificationRateRequest) { r.AnonymousFlowID = "space flow" },
		func(r *identityhttp.PasskeyVerificationRateRequest) {
			r.AnonymousFlowID = ""
			r.Identifier = "space identifier"
		},
		func(r *identityhttp.PasskeyVerificationRateRequest) { r.ChallengeLifetime = 0 },
	} {
		input := discovery
		mutate(&input)
		before := b.calls
		if out, err := l.AdmitPasskey(context.Background(), facts, input); !errors.Is(err, identityhttp.ErrInvalidInput) || out.Allowed || b.calls != before {
			t.Fatal("ambiguous or unowned source dispatched")
		}
	}
	for _, mode := range []int{1, 2, 3, 4, 5} {
		b.mode = mode
		before := b.calls
		if out, err := l.AdmitPasskey(context.Background(), facts, discovery); err == nil || out.Allowed || b.calls != before+1 {
			t.Fatal("anonymous backend failure retried or authenticated")
		}
	}
}

func TestPasskeyVerificationRateRequestRedactsOriginalCustody(t *testing.T) {
	r := identityhttp.PasskeyVerificationRateRequest{Identifier: "sensitive@example.invalid", AnonymousFlowID: "sensitive-flow", ChallengeID: "sensitive-ceremony", ChallengeLifetime: time.Minute}
	for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s", "%x"} {
		if got := fmt.Sprintf(verb, r); got != "identityhttp.PasskeyVerificationRateRequest(redacted)" {
			t.Fatal("passkey rate diagnostics disclosed original custody")
		}
	}
	if _, err := json.Marshal(r); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("passkey rate request implicitly serialized")
	}
	if wire, err := r.MarshalText(); len(wire) != 0 || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("passkey rate text exported")
	}
	if strings.Contains(r.LogValue().String(), "sensitive") {
		t.Fatal("passkey rate log disclosed original custody")
	}
}

func FuzzPasskeyVerificationRateSource(f *testing.F) {
	f.Add("person@example.invalid", "", "original-ceremony", int64(time.Minute))
	f.Add("", "original-flow", "original-ceremony", int64(time.Minute))
	f.Add("both@example.invalid", "original-flow", "original-ceremony", int64(time.Minute))
	f.Add("", "", "", int64(0))
	f.Fuzz(func(t *testing.T, identifier, flow, challenge string, lifetime int64) {
		b := &secretShared{}
		l, err := identityhttp.NewChallengeVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: b, Namespace: "verify-fuzz", Key: [32]byte{1}, Now: func() time.Time { return time.Unix(1800000000, 0) }, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		r := identityhttp.PasskeyVerificationRateRequest{Identifier: identifier, AnonymousFlowID: identity.PreAuthTransactionID(flow), ChallengeID: challenge, ChallengeLifetime: time.Duration(lifetime)}
		out, err := l.AdmitPasskey(t.Context(), safeFacts(t, "198.51.100.1"), r)
		if (identifier == "" && flow == "") || (identifier != "" && flow != "") || len(identifier) > 1024 || len(flow) > 128 || len(challenge) > 256 || challenge == "" || lifetime < int64(time.Second) || lifetime > int64(24*time.Hour) || lifetime%int64(time.Microsecond) != 0 {
			if !errors.Is(err, identityhttp.ErrInvalidInput) || out.Allowed || b.calls != 0 {
				t.Fatal("malformed source reached the atomic backend")
			}
		}
		if b.calls > 1 || (err != nil && out.Allowed) {
			t.Fatal("source failure retried or produced positive admission")
		}
	})
}
