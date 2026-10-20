package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

func phoneRecoveryCommandFixture(t *testing.T) (*AttemptCodec, otp.AttemptCommand, identity.Command, AttemptAuthority, session.PreAuthTransaction) {
	t.Helper()
	codec, err := NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, spec := mappedAttempt(t, otp.PurposePasswordReset, false)
	spec.Operation = identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	spec.Binding.RecordID = "credential"
	flow, _ := phoneRecoveryPreAuthSeed(t).Bindings()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	token, _ := session.ParseToken(wire)
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	flow.Cookie, err = token.PreAuthDigest(key, flow.Binding)
	if err != nil {
		t.Fatal(err)
	}
	original, err := session.NewPreAuthTransaction(flow)
	if err != nil {
		t.Fatal(err)
	}
	authorization, _ := otp.NewBoundPreAuthAuthorization(original)
	destination, _ := otp.NewDestinationInput("+358401234567")
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: string(spec.Binding.TenantID), SubjectID: string(spec.Binding.UserID), Purpose: otp.PurposePasswordReset, Channel: otp.ChannelSMS, Destination: destination, ChallengeID: "challenge", TargetID: spec.Binding.RecordID, PolicyVersion: 11, Generation: 12}, authorization, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	attempt, err := issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, 13, sms)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := capability.NewHMACSHA256Signer("synthetic-phone-reset", bytes.Repeat([]byte{1}, 32))
	now := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	proofWire, err := capability.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "https://identity.test", Audiences: []string{"identity"}, Subject: "user", Resource: "identity.phone/credential", Operation: spec.Operation.OperationID, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), ID: "synthetic-phone-reset", Tenant: "tenant", MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(proofWire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := primitive.NewSecret([]byte("synthetic phone recovery password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(candidate.Destroy)
	input, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, candidate, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	input, err = identity.BindPhonePasswordResetPreAuth(input, auth.NewBearerCredential(wire))
	if err != nil {
		t.Fatal(err)
	}
	expected := AttemptAuthority{
		Directory:            kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3},
		Credential:           identity.CredentialRef{ID: "credential", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 1},
		UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6,
		UserAuthorization: kernel.UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, Version: 7},
	}
	return codec, attempt, input, expected, original
}

func TestPhoneRecoveryAttemptMappingRetainsJointInputAndOriginalFlow(t *testing.T) {
	codec, attempt, input, expected, original := phoneRecoveryCommandFixture(t)
	mapped, plan, err := codec.MapPhonePasswordResetWithAuthority(context.Background(), attempt, 3, input, expected)
	if err != nil {
		t.Fatal("joint attempt cannot enter native encrypted custody", err)
	}
	if _, ok := mapped.Feature(); ok {
		t.Fatal("mapping downgraded joint recovery to an ordinary feature")
	}
	if _, ok := mapped.OneTimeCode(); ok {
		t.Fatal("mapping dropped the independent factor")
	}
	spec, ok := mapped.PhonePasswordResetInputFeature()
	if !ok {
		t.Fatal("mapping changed the input variant")
	}
	gotAuthority, err := codec.restoreAuthority(spec)
	if err != nil || gotAuthority != expected {
		t.Fatal("mapping changed original authority", err)
	}
	_, wantProof, wantSMS, wantTOTP, _ := input.PhonePasswordResetInputCustody()
	password, proof, sms, totp, ok := mapped.PhonePasswordResetInputCustody()
	if !ok || password.Len() == 0 {
		t.Fatal("mapping lost original password custody")
	}
	wantDigest, _ := wantProof.CommandDigest([32]byte{1}, "test", 4096)
	gotDigest, err := proof.CommandDigest([32]byte{1}, "test", 4096)
	if err != nil || gotDigest != wantDigest {
		t.Fatal("mapping replaced original capability", err)
	}
	for _, pair := range [][2]auth.OneTimeCode{{wantSMS, sms}, {wantTOTP, totp}} {
		want, _ := pair[0].CommandDigest([32]byte{1}, "test")
		got, err := pair[1].CommandDigest([32]byte{1}, "test")
		if err != nil || got != want {
			t.Fatal("mapping changed or swapped original codes", err)
		}
	}
	restarted, _ := NewAttemptCodec(codecConfig())
	restored, err := restarted.restoreAttempt(mapped, plan)
	wantAttempt, _ := attempt.Bindings()
	gotAttempt, _ := restored.Bindings()
	if err != nil || gotAttempt.AttemptID != wantAttempt.AttemptID || gotAttempt.Fingerprint != wantAttempt.Fingerprint {
		t.Fatal("native restart lost original SMS attempt", err)
	}
	profile, _ := newPreAuthProfile(sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)})
	retained, err := restarted.authenticatePreAuth(context.Background(), profile, mapped, plan)
	wantFlow, _ := original.Bindings()
	gotFlow, _ := retained.Bindings()
	if err != nil || gotFlow != wantFlow {
		t.Fatal("native admission lost original sessionless browser flow", err)
	}
	if out, p, err := codec.MapPhonePasswordResetWithAuthority(context.Background(), attempt, 3, mapped, expected); err == nil || out != (identity.Command{}) || p != (kernel.OTPAttemptPlan{}) {
		t.Fatal("already mapped original submission was re-encrypted")
	}
}

func TestPhoneRecoveryAttemptMappingRejectsPartialOrChangedCustody(t *testing.T) {
	codec, attempt, input, expected, _ := phoneRecoveryCommandFixture(t)
	spec, _ := input.PhonePasswordResetInputFeature()
	password, proof, sms, totp, _ := input.PhonePasswordResetInputCustody()
	cookie, _ := input.PhonePasswordResetPreAuthCookie()
	unbound, _ := identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	wrong, _ := auth.NewOneTimeCode("999999")
	changed, _ := identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, wrong, totp)
	changed, _ = identity.BindPhonePasswordResetPreAuth(changed, cookie)
	generated, _ := identity.NewFeaturePhonePasswordResetCommand(spec, "synthetic-hash", proof, sms, totp)
	generated, _ = identity.BindPhonePasswordResetPreAuth(generated, cookie)
	plain, _ := identity.NewFeatureOneTimeCodePreAuthCommand(spec, sms, cookie)
	for _, command := range []identity.Command{{}, unbound, changed, generated, plain} {
		out, plan, err := codec.MapPhonePasswordResetWithAuthority(context.Background(), attempt, 3, command, expected)
		if err == nil || out != (identity.Command{}) || plan != (kernel.OTPAttemptPlan{}) {
			t.Fatal("partial, replaced or generated input entered preparation")
		}
	}
	for _, mutate := range []func(*AttemptAuthority){
		func(a *AttemptAuthority) { a.Credential = identity.CredentialRef{} },
		func(a *AttemptAuthority) { a.Credential.ID = "other" },
		func(a *AttemptAuthority) { a.Credential.Owner = "other" },
		func(a *AttemptAuthority) { a.UserAuthorityVersion = 0 },
		func(a *AttemptAuthority) { a.Directory.Query.TenantID = "other" },
	} {
		altered := expected
		mutate(&altered)
		out, plan, err := codec.MapPhonePasswordResetWithAuthority(context.Background(), attempt, 3, input, altered)
		if err == nil || out != (identity.Command{}) || plan != (kernel.OTPAttemptPlan{}) {
			t.Fatal("missing or changed original authority admitted")
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := codec.MapPhonePasswordResetWithAuthority(canceled, attempt, 3, input, expected); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation replaced or ignored", err)
	}
	if _, _, err := codec.MapPhonePasswordResetWithAuthority(nil, attempt, 3, input, expected); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("nil context admitted", err)
	}
	mapped, plan, err := codec.MapPhonePasswordResetWithAuthority(context.Background(), attempt, 3, input, expected)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := mapped.PhonePasswordResetInputFeature()
	changed, _ = identity.NewFeaturePhonePasswordResetInputCommand(metadata, password, proof, wrong, totp)
	changed, _ = identity.BindPhonePasswordResetPreAuth(changed, cookie)
	if _, err := codec.restoreAttempt(changed, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("restart accepted changed original SMS", err)
	}
	wrongCookie := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32)))
	changed, _ = identity.NewFeaturePhonePasswordResetInputCommand(metadata, password, proof, sms, totp)
	changed, _ = identity.BindPhonePasswordResetPreAuth(changed, wrongCookie)
	profile, _ := newPreAuthProfile(sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)})
	if _, err := codec.authenticatePreAuth(context.Background(), profile, changed, plan); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("restart admitted changed original browser cookie", err)
	}
}
