package otp_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func csrfContinuation(t *testing.T, version uint32, digest byte) otp.Continuation {
	t.Helper()
	base := originalSessionSpec(t)
	record, err := session.NewSession(base)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		state, err := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: base.TenantID, SessionID: base.SessionID, SessionVersion: base.Version}, KeyVersion: version, Digest: [32]byte{digest}})
		if err != nil {
			t.Fatal(err)
		}
		record, err = session.NewSessionWithCSRF(base, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	flow, err := otp.NewBoundSessionAuthorization(record)
	if err != nil {
		t.Fatal(err)
	}
	scope := digestScopeSpec(t)
	scope.AuthorizationBinding = [32]byte{}
	scope.Purpose = otp.PurposeStepUp
	c, err := otp.NewContinuation(scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	retained, ok := flow.AuthenticatedSession()
	if !ok || retained != record {
		t.Fatal("original session replaced")
	}
	if version != 0 {
		want, _ := record.CSRFState().Bindings()
		got, err := retained.CSRFState().Bindings()
		if err != nil || got != want {
			t.Fatal("CSRF tuple changed")
		}
	} else if _, err := retained.CSRFState().Bindings(); err == nil {
		t.Fatal("legacy state fabricated")
	}
	return c
}

func TestBoundSessionCSRFChangesAuthorizationAndSubmission(t *testing.T) {
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{9})
	verifier, _ := otp.NewVerifier(7, map[uint32][32]byte{7: {9}})
	code, _ := auth.NewOneTimeCode("123456")
	binding, operation := commandAttemptScope()
	for _, mode := range []otp.AttemptMode{otp.AttemptModeCheck, otp.AttemptModeConsume} {
		seenBindings := map[[32]byte]bool{}
		seenDigests := map[otp.StoredCodeDigest]bool{}
		seenFingerprints := map[otp.AttemptFingerprint]bool{}
		for _, spec := range []struct {
			version uint32
			digest  byte
		}{{0, 0}, {7, 1}, {8, 1}, {7, 2}} {
			c := csrfContinuation(t, spec.version, spec.digest)
			b, _ := c.Bindings()
			if seenBindings[b.Scope.AuthorizationBinding] {
				t.Fatal("distinct CSRF state shared authorization binding")
			}
			seenBindings[b.Scope.AuthorizationBinding] = true
			scope, _ := c.DigestScope()
			digest, err := verifier.Digest(scope, code)
			if err != nil {
				t.Fatal(err)
			}
			if seenDigests[digest.Storage()] {
				t.Fatal("distinct CSRF state shared code digest")
			}
			seenDigests[digest.Storage()] = true
			a, err := issuer.PrepareForCommand(context.Background(), binding, operation, c, mode, 11, code)
			if err != nil {
				t.Fatal(err)
			}
			ab, _ := a.Bindings()
			if seenFingerprints[ab.Fingerprint] {
				t.Fatal("distinct CSRF state shared attempt fingerprint")
			}
			seenFingerprints[ab.Fingerprint] = true
		}
	}
}

func TestBoundSessionTokenlessHistoricalBinding(t *testing.T) {
	c := csrfContinuation(t, 0, 0)
	b, _ := c.Bindings()
	// Independent Ruby SHA-256 oracle over the literal historical v3 frame,
	// its seventeen strings, fixed integer fields and three absent optionals.
	const historical = "5f1bc820e27a7f61bf273fc587732e8641777ae19dccb3b8eaf7c5317bd081f8"
	if hex.EncodeToString(b.Scope.AuthorizationBinding[:]) != historical {
		t.Fatal("historical tokenless v3 binding changed")
	}
}

func TestBoundSessionCSRFSubstitutionRejectsSealedRecord(t *testing.T) {
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{9})
	code, _ := auth.NewOneTimeCode("123456")
	binding, operation := commandAttemptScope()
	c := csrfContinuation(t, 7, 1)
	a, err := issuer.PrepareForCommand(context.Background(), binding, operation, c, otp.AttemptModeConsume, 11, code)
	if err != nil {
		t.Fatal(err)
	}
	record, err := issuer.SealForCommand(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		version uint32
		digest  byte
	}{{0, 0}, {8, 1}, {7, 2}} {
		changed := record
		changed.Attempt.Continuation = csrfContinuation(t, spec.version, spec.digest)
		if err := issuer.VerifyCommandRecord(changed); err == nil {
			t.Fatal("CSRF substitution preserved original signature")
		}
		if _, err := issuer.RestoreForCommand(changed, code); err == nil {
			t.Fatal("CSRF substitution restored original submission")
		}
	}
	restored, err := issuer.RestoreForCommand(record, code)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := a.Recovery()
	got, _ := restored.Recovery()
	if got != want {
		t.Fatal("restoration regenerated recovery identity")
	}
	b, _ := restored.Bindings()
	retained, _ := b.Continuation.Bindings()
	original, _ := retained.Authorization.AuthenticatedSession()
	state, err := original.CSRFState().Bindings()
	if err != nil || state.KeyVersion != 7 || state.Digest != ([32]byte{1}) {
		t.Fatal("restored CSRF state changed")
	}
	for _, value := range []any{retained.Authorization, b.Continuation, b, record} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(format, value)
			if !strings.Contains(out, "redacted") || strings.Contains(out, "123456") || strings.Contains(out, "subject") {
				t.Fatal("private session custody disclosed")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private custody serialized")
		}
	}
}
