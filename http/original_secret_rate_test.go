package identityhttp_test

import (
	"context"
	"errors"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"testing"
	"time"
)

func TestOriginalCommandSecretRatePreservesDebitAndSharedBudgets(t *testing.T) {
	l, b := secretLimiter(t)
	facts := safeFacts(t, "198.51.100.1")
	command, _ := identity.NewCommandID()
	r := identityhttp.OriginalCommandSecretRateRequest{OperationID: "identity.mfa.totp-uri", UserID: "user-secret", CommandID: command, ChallengeID: "original-enrollment", ChallengeLifetime: time.Minute}
	if out, err := l.AdmitOriginalCommand(t.Context(), facts, r); err != nil || !out.Allowed {
		t.Fatal("original reveal command not admitted", err)
	}
	first := b.last
	if len(first.Requests) != 3 || first.Requests[2].Policy.Capacity() != 5 || first.Requests[2].Policy.Period() != time.Minute {
		t.Fatal("original challenge quota missing")
	}
	if _, err := l.AdmitOriginalCommand(t.Context(), facts, r); err != nil || b.last.CommandID != first.CommandID {
		t.Fatal("retry changed debit command")
	}
	if _, err := l.Admit(t.Context(), facts, secretRequest(t)); err != nil || b.last.Requests[0].Key != first.Requests[0].Key || b.last.Requests[1].Key != first.Requests[1].Key || b.last.CommandID == first.CommandID {
		t.Fatal("original-command transport reset shared secret budgets")
	}
	before := b.calls
	for _, change := range []func(*identityhttp.OriginalCommandSecretRateRequest){func(r *identityhttp.OriginalCommandSecretRateRequest) { r.CommandID = "" }, func(r *identityhttp.OriginalCommandSecretRateRequest) { r.OperationID = "identity.password.change" }, func(r *identityhttp.OriginalCommandSecretRateRequest) { r.ChallengeLifetime = 0 }} {
		bad := r
		change(&bad)
		if _, err := l.AdmitOriginalCommand(t.Context(), facts, bad); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid original custody admitted")
		}
	}
	if b.calls != before {
		t.Fatal("invalid original input reached backend")
	}
	for _, mode := range []int{1, 2, 3, 4, 5} {
		b.mode = mode
		out, err := l.AdmitOriginalCommand(context.Background(), facts, r)
		if err == nil || out.Allowed {
			t.Fatal("failed atomic admission permitted reveal")
		}
	}
}

func TestRegenerationOriginalCommandRetainsRotationQuota(t *testing.T) {
	l, b := secretLimiter(t)
	facts := safeFacts(t, "198.51.100.1")
	command, _ := identity.NewCommandID()
	r := identityhttp.OriginalCommandSecretRateRequest{OperationID: "identity.mfa.recovery-regenerate", UserID: "original-user", CommandID: command, ChallengeID: "original-factor-proof", ChallengeLifetime: time.Minute}
	if out, err := l.AdmitOriginalCommand(t.Context(), facts, r); err != nil || !out.Allowed {
		t.Fatal("original replacement command cannot use shared quota", err)
	}
	first := b.last
	if len(first.Requests) != 3 || first.Requests[2].Policy.Capacity() != 5 || first.Requests[2].Policy.Period() != time.Minute {
		t.Fatal("original proof quota missing")
	}
	if _, err := l.AdmitOriginalCommand(t.Context(), facts, r); err != nil || b.last.CommandID != first.CommandID {
		t.Fatal("rotation retry changed original debit", err)
	}
}
