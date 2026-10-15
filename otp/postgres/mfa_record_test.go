package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func mfaAttemptRecordFixture(t testing.TB) (otp.AttemptIssuer, otp.CommandAttemptRecord, session.PreAuthTransaction, otp.MFAFlowBinding) {
	t.Helper()
	initial, spec := mappedAttempt(t, otp.PurposeMFA, true)
	a, _ := initial.Bindings()
	c, _ := a.Continuation.Bindings()
	old, _ := c.Authorization.Bindings()
	now := time.Date(2026, 10, 13, 12, 0, 0, 123456789, time.UTC)
	original, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{
		Binding: session.PreAuthBinding{ID: old.PreAuthTransactionID,
			Intent: session.PreAuthIntent{TenantID: spec.Binding.TenantID, Action: "identity.password.signin",
				Origin: "https://identity.test", CallbackURL: "https://app.test/return", Nonce: [32]byte{1},
				Remember: c.RememberPolicy, PolicyID: "login", PolicyVersion: 11},
			IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)},
		Cookie: session.TokenDigest{KeyVersion: 3, Sum: [32]byte{1}}, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	mfa := otp.MFAFlowBinding{PrimaryCommandID: "AgICAgICAgICAgICAgICAg",
		ContinuationID: "AwMDAwMDAwMDAwMDAwMDAw", SubjectID: "mfa-user", ScopeDigest: [32]byte{8}}
	flow, err := otp.NewMFAFlowAuthorization(original, mfa)
	if err != nil {
		t.Fatal(err)
	}
	c.Scope.AuthorizationBinding = [32]byte{}
	c.Scope.Purpose, c.Scope.SubjectID, c.Scope.TargetID = otp.PurposeMFA, string(mfa.SubjectID), string(mfa.ContinuationID)
	continuation, err := otp.NewContinuation(c.Scope, flow, c.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	spec.Operation = identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify",
		SchemaID: "mfa-otp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted,
		SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	spec.Binding.UserID, spec.Binding.RecordID = "", ""
	spec.Binding.CommandID, spec.Binding.AnonymousFlowID = "BAQEBAQEBAQEBAQEBAQEBA", string(old.PreAuthTransactionID)
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := initial.Code()
	attempt, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, a.ExpectedVersion, code)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := issuer.SealForCommand(attempt)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, sealed, original, mfa
}

func TestMFAAttemptRecordPreservesConsumedPrimaryCustody(t *testing.T) {
	issuer, sealed, original, mfa := mfaAttemptRecordFixture(t)
	wire := encodeAttemptRecord(sealed)
	restored, err := decodeAttemptRecord(wire, sealed.Binding, sealed.Operation)
	if err != nil {
		t.Fatal("durable MFA attempt lost original custody", err)
	}
	if err := issuer.VerifyCommandRecord(restored); err != nil {
		t.Fatal("restored MFA attempt lost original MAC", err)
	}
	b, _ := restored.Attempt.Continuation.Bindings()
	got, retained, present := b.Authorization.MFAContinuation()
	gotSpec, gotErr := got.Bindings()
	originalSpec, _ := original.Bindings()
	if !present || gotErr != nil || gotSpec != originalSpec || retained != mfa || b.RememberPolicy != originalSpec.Binding.Intent.Remember {
		t.Fatal("MFA authority custody changed on persistence round trip")
	}
	if _, ok := b.Authorization.PreAuthTransaction(); ok {
		t.Fatal("durable MFA became ordinary pending preauth")
	}
	if _, ok := b.Authorization.AuthenticatedSession(); ok {
		t.Fatal("durable MFA became full session")
	}
	if !bytes.Equal(wire, encodeAttemptRecord(restored)) {
		t.Fatal("MFA custody bytes changed on reconstruction")
	}
	for n := range len(wire) {
		if _, err := decodeAttemptRecord(wire[:n], sealed.Binding, sealed.Operation); err == nil {
			t.Fatal("truncated MFA custody admitted")
		}
	}
	if _, err := decodeAttemptRecord(append(bytes.Clone(wire), 0), sealed.Binding, sealed.Operation); err == nil {
		t.Fatal("trailing MFA custody admitted")
	}
	// The native MAC binds every restored byte; the parser alone cannot make
	// an arbitrary complete-looking reference into consumed-primary authority.
	for n := range len(wire) {
		changed := bytes.Clone(wire)
		changed[n] ^= 1
		got, err := decodeAttemptRecord(changed, sealed.Binding, sealed.Operation)
		if err == nil && issuer.VerifyCommandRecord(got) == nil {
			t.Fatal("changed MFA custody kept authenticated attempt")
		}
	}
}

func TestMFANativeFlowKeepsConsumedPrimaryDisjoint(t *testing.T) {
	_, record, original, _ := mfaAttemptRecordFixture(t)
	flow, err := retainedNativeFlow(nativeCustody{record: record})
	if err != nil {
		t.Fatal("native OTP cannot restore original MFA browser custody", err)
	}
	if flow.preauth != (session.PreAuthTransaction{}) || flow.session != (session.Session{}) {
		t.Fatal("MFA custody became ordinary one-time preauth or full session")
	}
	spec, _ := original.Bindings()
	p := &Contributor{}
	if err := p.flowTime(flow, spec.Binding.IssuedAt); err != nil {
		t.Fatal("original MFA time admission changed", err)
	}
	if err := p.flowTime(flow, spec.Binding.ExpiresAt); err == nil {
		t.Fatal("MFA copy renewed absolute browser expiry")
	}
}

func TestMFANativeAttemptAuthenticatesOriginalCookieWithoutPendingFlow(t *testing.T) {
	issuer, record, original, correlation := mfaAttemptRecordFixture(t)
	p, _, _ := nativeContributorFixture(t)
	s, _ := original.Bindings()
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32)))
	token, _ := session.ParseToken(bearer.Token())
	s.Cookie, _ = token.PreAuthDigest(p.preauth.keys[3], s.Binding)
	original, err := session.NewPreAuthTransaction(s)
	if err != nil {
		t.Fatal(err)
	}
	authorization, _ := otp.NewMFAFlowAuthorization(original, correlation)
	continuation, _ := record.Attempt.Continuation.Bindings()
	continuation.Scope.AuthorizationBinding = [32]byte{}
	bound, err := otp.NewContinuation(continuation.Scope, authorization, continuation.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("123456")
	attempt, err := issuer.PrepareForCommand(t.Context(), record.Binding, record.Operation, bound, record.Attempt.Mode, record.Attempt.ExpectedVersion, code)
	if err != nil {
		t.Fatal(err)
	}
	spec := identity.FeatureCommandSpec{Binding: record.Binding, Operation: record.Operation}
	authority := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.global, TenantID: record.Binding.TenantID}, GlobalVersion: 2, TenantVersion: 3}}
	command, plan, err := p.codec.MapPreAuthWithAuthority(t.Context(), attempt, 3, spec, bearer, authority)
	if err != nil {
		t.Fatal("actual MFA cookie custody mapping unavailable", err)
	}
	metadata, _ := command.Feature()
	if _, err := p.codec.restoreCustody(metadata); err != nil {
		t.Fatal("mapped MFA custody lost authentication", err)
	}
	if _, err := p.codec.restoreAttempt(command, plan); err != nil {
		t.Fatal("mapped MFA submission lost its original plan/code binding", err)
	}
	if _, err := p.codec.authenticatePreAuth(t.Context(), p.preauth, command, plan); err != nil {
		t.Fatal("mapped MFA browser commitment denied", err)
	}
	if err := p.ValidateOTPAttemptCommand(command, plan); err != nil {
		t.Fatal("authenticated original MFA attempt denied", err)
	}
	flow, err := p.authenticateFlow(t.Context(), command, plan)
	actual, actualErr := flow.mfaOriginal.Bindings()
	if err != nil || actualErr != nil || actual != s || flow.mfa != correlation || flow.preauth != (session.PreAuthTransaction{}) {
		t.Fatal("actual cookie authentication changed consumed-primary custody", err)
	}
	wrong := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32)))
	substituted, _ := identity.NewFeatureOneTimeCodePreAuthCommand(metadata, code, wrong)
	if p.ValidateOTPAttemptCommand(substituted, plan) == nil {
		t.Fatal("foreign browser possession reached secondary OTP")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if flow, err := p.authenticateFlow(canceled, command, plan); err == nil || flow.mfaOriginal != (session.PreAuthTransaction{}) {
		t.Fatal("canceled MFA cookie admission retained authority")
	}
}

func FuzzMFAAttemptRecord(f *testing.F) {
	issuer, sealed, _, _ := mfaAttemptRecordFixture(f)
	seed := encodeAttemptRecord(sealed)
	if restored, err := decodeAttemptRecord(seed, sealed.Binding, sealed.Operation); err != nil || issuer.VerifyCommandRecord(restored) != nil {
		f.Fatal("MFA attempt fuzz seed does not exercise valid authenticated custody")
	}
	f.Add(seed)
	f.Add([]byte(mfaRecordPrefix))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		record, err := decodeAttemptRecord(data, sealed.Binding, sealed.Operation)
		if err == nil && !bytes.Equal(data, encodeAttemptRecord(record)) {
			t.Fatal("noncanonical attempt custody admitted")
		}
	})
}
