package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func TestAttemptCustodyPreservesCompleteOriginalPreAuthFlow(t *testing.T) {
	codec, err := NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	original, spec := mappedAttempt(t, otp.PurposeSignin, true)
	b, _ := original.Bindings()
	c, _ := b.Continuation.Bindings()
	c.Scope.AuthorizationBinding = [32]byte{}
	oldFlow, _ := c.Authorization.Bindings()
	now := time.Date(2026, 10, 7, 12, 0, 0, 123456789, time.UTC)
	projection := session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: oldFlow.PreAuthTransactionID, Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.otp.signin", Origin: "https://identity.test", CallbackURL: "https://app.test/return", Nonce: [32]byte{1}, Remember: c.RememberPolicy, PolicyID: "login", PolicyVersion: 11}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 3, Sum: [32]byte{1}}, Version: 1}
	record, err := session.NewPreAuthTransaction(projection)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewBoundPreAuthAuthorization(record)
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.AnonymousFlowID = string(projection.Binding.ID)
	continuation, err := otp.NewContinuation(c.Scope, flow, c.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := original.Code()
	attempt, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, b.ExpectedVersion, code)
	if err != nil {
		t.Fatal(err)
	}
	command, plan, err := codec.Map(context.Background(), attempt, 3, spec)
	if err != nil {
		t.Fatal(err)
	}
	foreign := spec.Binding
	foreign.AnonymousFlowID = "foreign"
	if _, err := issuer.PrepareForCommand(context.Background(), foreign, spec.Operation, continuation, otp.AttemptModeConsume, b.ExpectedVersion, code); err == nil {
		t.Fatal("bound original flow borrowed another anonymous namespace")
	}
	restarted, _ := NewAttemptCodec(codecConfig())
	restored, err := restarted.restoreAttempt(command, plan)
	if err != nil {
		t.Fatal("bound flow custody did not survive restart", err)
	}
	r, _ := restored.Bindings()
	retained, _ := r.Continuation.Bindings()
	full, ok := retained.Authorization.PreAuthTransaction()
	got, err := full.Bindings()
	if !ok || err != nil || got != projection || r.AttemptID != bAttemptID(t, attempt) {
		t.Fatal("complete original flow or attempt changed")
	}
	sealed, err := issuer.SealForCommand(attempt)
	if err != nil {
		t.Fatal(err)
	}
	changedProjection := projection
	changedProjection.Binding.Intent.Nonce[1] = 1
	changedRecord, _ := session.NewPreAuthTransaction(changedProjection)
	changedFlow, _ := otp.NewBoundPreAuthAuthorization(changedRecord)
	changedContinuation, err := otp.NewContinuation(c.Scope, changedFlow, c.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	changedCustody := sealed
	changedCustody.Attempt.Continuation = changedContinuation
	if issuer.VerifyCommandRecord(changedCustody) == nil {
		t.Fatal("changed original nonce retained server-attempt authentication")
	}
	plain := encodeAttemptRecord(sealed)
	legacy, err := issuer.SealForCommand(original)
	if err != nil {
		t.Fatal(err)
	}
	// A substring oracle is invalid: the original fractional timestamp can
	// legitimately contain the submitted digits. Pin the closed code-free frame
	// instead, and prove persisted custody cannot reconstruct a missing code.
	additional := 32 + 8 + 1 + 4*8 + 4 + 32 + 8
	i := projection.Binding.Intent
	for _, text := range []string{string(projection.Binding.ID), string(i.TenantID), i.Action, i.Origin, i.CallbackURL, i.PolicyID, projection.Binding.IssuedAt.Format(time.RFC3339Nano), projection.Binding.ExpiresAt.Format(time.RFC3339Nano)} {
		additional += 2 + len(text)
	}
	if len(plain) != len(encodeAttemptRecord(legacy))+additional {
		t.Fatal("closed code-free custody frame changed")
	}
	feature, _ := command.Feature()
	withoutCode, err := identity.NewFeatureCommand(feature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.restoreAttempt(withoutCode, plan); err == nil {
		t.Fatal("persisted custody reconstructed a missing submitted code")
	}
	for n := range len(plain) {
		if _, err := decodeAttemptRecord(plain[:n], spec.Binding, spec.Operation); err == nil {
			t.Fatal("truncated complete-flow custody admitted")
		}
	}
	if _, err := decodeAttemptRecord(append(bytes.Clone(plain), 0), spec.Binding, spec.Operation); err == nil {
		t.Fatal("trailing complete-flow custody admitted")
	}
}

func FuzzBoundPreAuthRecord(f *testing.F) {
	a, spec := mappedAttempt(f, otp.PurposeSignin, true)
	b, _ := a.Bindings()
	c, _ := b.Continuation.Bindings()
	c.Scope.AuthorizationBinding = [32]byte{}
	flowSpec, _ := c.Authorization.Bindings()
	now := time.Date(2026, 10, 7, 12, 0, 0, 123456789, time.UTC)
	p, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: session.PreAuthBinding{ID: flowSpec.PreAuthTransactionID, Intent: session.PreAuthIntent{TenantID: "tenant", Action: "identity.otp.signin", Origin: "https://identity.test", Nonce: [32]byte{1}, Remember: c.RememberPolicy, PolicyID: "login", PolicyVersion: 11}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}, Cookie: session.TokenDigest{KeyVersion: 3, Sum: [32]byte{1}}, Version: 1})
	if err != nil {
		f.Fatal(err)
	}
	flow, _ := otp.NewBoundPreAuthAuthorization(p)
	continuation, _ := otp.NewContinuation(c.Scope, flow, c.RememberPolicy)
	spec.Binding.AnonymousFlowID = string(flowSpec.PreAuthTransactionID)
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := a.Code()
	original, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, b.ExpectedVersion, code)
	if err != nil {
		f.Fatal(err)
	}
	r, _ := issuer.SealForCommand(original)
	f.Add(encodeAttemptRecord(r))
	f.Add([]byte(boundRecordPrefix))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8193 {
			return
		}
		decoded, err := decodeAttemptRecord(data, spec.Binding, spec.Operation)
		if err == nil && !bytes.Equal(encodeAttemptRecord(decoded), data) {
			t.Fatal("noncanonical accepted custody")
		}
	})
}

func bAttemptID(t *testing.T, a otp.AttemptCommand) otp.AttemptID {
	t.Helper()
	b, err := a.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return b.AttemptID
}
