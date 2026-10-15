package mfapostgres

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func continuationFixture(t testing.TB) mfa.PartialAuthContinuation {
	t.Helper()
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 11, 18, 0, 0, 0, time.UTC)
	c, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: "AAAAAAAAAAAAAAAAAAAAAQ", PrimaryProofID: auth.ProofID("original-proof"), PrimaryProofDigest: [32]byte{1}, PrimaryProofExpiresAt: now.Add(3 * time.Minute), TenantID: "tenant", SubjectID: "user", SourcePreAuthID: "bbbbbbbbbbbbbbbbbbbbbg", Origin: "https://app.test", AllowedMethods: []string{"totp", "recovery-code"}, PolicyVersion: 3, FactorVersion: 7, RememberPolicy: remember, Purpose: "identity.mfa.complete", Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), MaxAttempts: 3, AttemptsRemaining: 3, State: mfa.Pending, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestContinuationStorageConservesOriginalScopeAndTerminalBudget(t *testing.T) {
	original := continuationFixture(t)
	before, _ := original.Bindings()
	digest, _ := original.ScopeDigest()
	wire, err := encodeContinuationScope(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []struct {
		state     mfa.ContinuationState
		version   uint64
		remaining uint32
	}{{mfa.Pending, 1, 3}, {mfa.Challenged, 2, 2}, {mfa.Revoked, 4, 0}, {mfa.Completed, 2, 2}} {
		got, err := decodeContinuationScope(wire, digest, state.state, state.version, state.remaining)
		if err != nil {
			t.Fatal(err)
		}
		scope, _ := got.Bindings()
		if scope.State != state.state || scope.Version != state.version || scope.AttemptsRemaining != state.remaining {
			t.Fatal("stored mutable state reset")
		}
		scope.State, scope.Version, scope.AttemptsRemaining = before.State, before.Version, before.AttemptsRemaining
		if !reflect.DeepEqual(scope, before) {
			t.Fatal("stored original scope changed")
		}
		actual, e := got.ScopeDigest()
		if e != nil || actual != digest {
			t.Fatal("attempt renewed immutable scope", e)
		}
	}
	foreign := digest
	foreign[0] ^= 1
	for _, data := range [][]byte{nil, []byte("{}"), append(append([]byte(nil), wire...), []byte(" {}")...), []byte(strings.Replace(string(wire), "https://app.test", "https://foreign.test", 1)), []byte(strings.Repeat("x", 8193))} {
		if c, err := decodeContinuationScope(data, digest, mfa.Pending, 1, 3); err == nil {
			t.Fatal("corrupt scope restored", c)
		}
	}
	if _, err := decodeContinuationScope(wire, foreign, mfa.Pending, 1, 3); err == nil {
		t.Fatal("foreign original digest restored")
	}
	if _, err := decodeContinuationScope(wire, digest, mfa.Pending, 1, 2); err == nil {
		t.Fatal("pending budget reset accepted")
	}
	if _, err := encodeContinuationScope(mfa.PartialAuthContinuation{}); err == nil {
		t.Fatal("zero scope stored")
	}
}

func TestContinuationPersistenceNeedsExactProtectedChallenge(t *testing.T) {
	for _, ctx := range []context.Context{nil, context.Background()} {
		if err := PersistMagicLinkContinuation(ctx, kernel.Work{}, nil, identity.Command{}, continuationFixture(t)); err == nil {
			t.Fatal("continuation persisted outside primary-consuming challenge")
		}
		if err := PersistPasswordContinuation(ctx, kernel.Work{}, nil, identity.Command{}, continuationFixture(t)); err == nil {
			t.Fatal("password continuation persisted without its comparison owner")
		}
	}
}
