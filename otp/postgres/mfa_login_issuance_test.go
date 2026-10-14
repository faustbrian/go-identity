package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// This is the native generation/custody boundary, not child verification or
// current factor admission. The real MFA owner supplies those in protected Work.
func TestMFALoginIssuerRetainsOriginalConsumedBrowserAndDelivery(t *testing.T) {
	native, _, _ := nativeContributorFixture(t)
	_, record, original, correlation := mfaAttemptRecordFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	projection, _ := original.Bindings()
	projection.Binding.IssuedAt, projection.Binding.ExpiresAt = now, now.Add(5*time.Minute)
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32)))
	token, _ := session.ParseToken(bearer.Token())
	projection.Cookie, _ = token.PreAuthDigest(native.preauth.keys[3], projection.Binding)
	original, _ = session.NewPreAuthTransaction(projection)
	flow, _ := otp.NewMFAFlowAuthorization(original, correlation)
	b, _ := record.Attempt.Continuation.Bindings()
	b.Scope.AuthorizationBinding = [32]byte{}
	b.Scope.ChallengeID = string(record.Binding.CommandID)
	continuation, err := otp.NewContinuation(b.Scope, flow, b.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	spec := identity.FeatureCommandSpec{Binding: record.Binding, Operation: op, Fields: []identity.FeatureField{{Name: "factor.parent-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(correlation.PrimaryCommandID)}}}}
	spec.Binding.OperationID, spec.Binding.SchemaID = op.OperationID, op.SchemaID
	spec.Binding.RecordID = "BQUFBQUFBQUFBQUFBQUFBQ"
	root, err := identity.NewFeaturePreAuthCommand(spec, bearer)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeMFA, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	policy, _ := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	config := MFALoginIssuerConfig{Store: ContributorConfig{Schema: native.schema, Codec: native.codec, GlobalAuthorityID: native.global, UserPolicyNamespace: native.namespace, LockoutKey: [32]byte{0x61}, PreAuth: native.preauth.config, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}},
		Delivery: issuanceDeliveryOwner(t), Policy: policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: preparedSendTemplates("{{.code}}")}
	issuer, err := NewMFALoginIssuer(config)
	if err != nil {
		t.Fatal("native partial-login issuer unavailable", err)
	}
	changedConfig := config
	changedProfile, _ := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeMFA, Alphabet: "0123456789", Length: 6, TTL: 4 * time.Minute, ResendInterval: time.Minute, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	changedConfig.Policy, _ = otp.NewAttemptPolicy(changedProfile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	other, err := NewMFALoginIssuer(changedConfig)
	configurationIdentity, identityErr := issuer.Configuration()
	otherIdentity, otherErr := other.Configuration()
	if err != nil || identityErr != nil || otherErr != nil || configurationIdentity == otherIdentity {
		t.Fatal("changed OTP policy reused original login configuration identity")
	}
	recipient := kernel.RecipientRecord{Query: kernel.RecipientQuery{TenantID: spec.Binding.TenantID, UserID: correlation.SubjectID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: correlation.SubjectID, TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
		Identifier:           identity.Identifier{ID: "email", UserID: correlation.SubjectID, Kind: identity.IdentifierEmail, CanonicalValue: b.Scope.Destination.Value(), Verified: true, Version: 9},
		Verification:         identity.Verification{IdentifierID: "email", State: identity.VerificationVerified, VerifiedAt: now, Version: 3},
		UserAuthorityVersion: 11, IdentifierAuthorityVersion: 12, CredentialAuthorityVersion: 13, ObservedAt: now}
	input := MFALoginSendInput{Continuation: continuation, Authority: AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: native.global, TenantID: spec.Binding.TenantID}, GlobalVersion: 2, TenantVersion: 3}}, Recipient: recipient, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	longChild := input
	longChild.ExpiresAt = now.Add(5 * time.Minute)
	boundedWire, err := other.PrepareLoginSend(t.Context(), root, longChild)
	if err != nil {
		t.Fatal("shorter OTP lifetime cannot be selected under a longer original child", err)
	}
	defer clear(boundedWire)
	bounded, err := other.ReadLoginSend(t.Context(), root, boundedWire)
	if err != nil || !bounded.ExpiresAt.Equal(now.Add(4*time.Minute)) || !bounded.IssuedAt.Equal(now) {
		t.Fatal("OTP lifetime did not retain original issuance or cap to its own policy", err)
	}
	retained, err := issuer.PrepareLoginSend(t.Context(), root, input)
	if err != nil || len(retained) == 0 || bytes.Contains(retained, []byte(bearer.Token())) {
		t.Fatal("original input cannot enter code/bearer-free request custody", err)
	}
	defer clear(retained)
	restarted, err := NewMFALoginIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := restarted.ReadLoginSend(t.Context(), root, retained)
	if err != nil || !decoded.IssuedAt.Equal(input.IssuedAt) || !decoded.ExpiresAt.Equal(input.ExpiresAt) || decoded.Recipient.Identifier != input.Recipient.Identifier {
		t.Fatal("restart selected a new recipient or renewed original time", err)
	}
	if _, err := other.ReadLoginSend(t.Context(), root, retained); err == nil {
		t.Fatal("changed native configuration adopted original input")
	}
	if _, err := restarted.ReadLoginSend(t.Context(), root, append(bytes.Clone(retained), 0)); err == nil {
		t.Fatal("trailing input adopted original request")
	}
	for _, size := range []int{0, 1, len(retained) - 1} {
		if _, err := restarted.ReadLoginSend(t.Context(), root, retained[:size]); err == nil {
			t.Fatal("truncated input adopted original request")
		}
	}
	wire, err := issuer.GenerateLoginSend(t.Context(), root, retained, 1)
	if err != nil || len(wire) == 0 || bytes.Contains(wire, []byte(bearer.Token())) {
		t.Fatal("native login send generation failed or retained bearer", err)
	}
	prepared, err := restarted.RestoreLoginSend(t.Context(), root, retained, 1, wire)
	if err != nil {
		t.Fatal("original login send cannot restore", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Intents) != 1 || plan.Intents[0].SubjectID != spec.Binding.AnonymousFlowID || !plan.Intents[0].ExpiresAt.Equal(input.ExpiresAt) {
		t.Fatal("original login delivery lost browser namespace or bounded lifetime", err)
	}
	completion, err := restarted.RestoreLoginCompletion(t.Context(), root, retained, 1, wire)
	if err != nil || completion.Contributor() == nil {
		t.Fatal("actual original login send cannot supply its consuming owner", err)
	}
	verify := identity.FeatureCommandSpec{Binding: spec.Binding, Operation: mfaLoginCompletionOperation()}
	verify.Binding.CommandID = "BgYGBgYGBgYGBgYGBgYGBg"
	verify.Binding.OperationID, verify.Binding.SchemaID, verify.Binding.RecordID = verify.Operation.OperationID, verify.Operation.SchemaID, ""
	verificationRoot, err := identity.NewFeaturePreAuthCommand(verify, bearer)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := auth.NewOneTimeCode("012345")
	consuming, consumingPlan, err := completion.prepare(t.Context(), verificationRoot, code, 1, 7)
	if err != nil || consumingPlan.Mode != kernel.OTPConsume || consumingPlan.ChallengeID != string(spec.Binding.CommandID) {
		t.Fatal("login completion did not retain actual challenge and consuming purpose", err)
	}
	stored, _ := consuming.Feature()
	restored, restoredPlan, err := completion.RestorePrepared(t.Context(), verificationRoot, code, stored)
	if err != nil || restoredPlan != consumingPlan || restarted.store.ValidateOTPAttemptCommand(restored, restoredPlan) != nil {
		t.Fatal("login consuming preparation cannot restart unchanged", err)
	}
	wrongRoot := verify
	wrongRoot.Binding.AnonymousFlowID = "AQEBAQEBAQEBAQEBAQEBAQ"
	foreignAttempt, _ := identity.NewFeaturePreAuthCommand(wrongRoot, bearer)
	if _, _, err := completion.RestorePrepared(t.Context(), foreignAttempt, code, stored); err == nil {
		t.Fatal("another browser adopted the original consuming login attempt")
	}
	otherCode, _ := auth.NewOneTimeCode("987654")
	if _, _, err := completion.RestorePrepared(t.Context(), verificationRoot, otherCode, stored); err == nil {
		t.Fatal("retained consuming metadata adopted a different submitted code")
	}
	otherCookie, _ := session.NewToken(32)
	otherBearer, _ := otherCookie.Reveal()
	foreignAttempt, _ = identity.NewFeaturePreAuthCommand(verify, auth.NewBearerCredential(otherBearer))
	if _, _, err := completion.RestorePrepared(t.Context(), foreignAttempt, code, stored); err == nil {
		t.Fatal("retained consuming metadata adopted another cookie")
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, _, err := completion.RestorePrepared(canceled, verificationRoot, code, stored); !errors.Is(err, context.Canceled) {
		t.Fatal("consuming restoration lost cancellation", err)
	}
	if (MFALoginCompletion{}).Contributor() != nil {
		t.Fatal("zero completion supplied an OTP owner")
	}
	if _, _, err := (MFALoginCompletion{}).RestorePrepared(t.Context(), verificationRoot, code, stored); err == nil {
		t.Fatal("zero completion adopted original consuming metadata")
	}
	for _, mutate := range []func(*MFALoginSendInput){
		func(i *MFALoginSendInput) { i.ExpiresAt = i.ExpiresAt.Add(time.Second) },
		func(i *MFALoginSendInput) { i.Recipient.Identifier.Version++ },
		func(i *MFALoginSendInput) { i.Authority.Directory.TenantVersion++ },
	} {
		changed := input
		mutate(&changed)
		if _, err := issuer.Restore(t.Context(), root, changed, 1, wire); err == nil {
			t.Fatal("changed original login input adopted retained delivery")
		}
	}
	if _, err := issuer.Restore(t.Context(), root, input, 2, wire); err == nil {
		t.Fatal("login output adopted another generation")
	}
	wrong := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32)))
	foreign, _ := identity.NewFeaturePreAuthCommand(spec, wrong)
	if _, err := issuer.Restore(t.Context(), foreign, input, 1, wire); err == nil {
		t.Fatal("another browser obtained original login delivery")
	}
	changedParent := spec
	changedParent.Fields = []identity.FeatureField{{Name: "factor.parent-command", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "BgYGBgYGBgYGBgYGBgYGBg"}}}
	foreign, _ = identity.NewFeaturePreAuthCommand(changedParent, bearer)
	if _, err := issuer.Generate(t.Context(), foreign, input, 1); err == nil {
		t.Fatal("login issuer accepted a different consumed primary")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := issuer.Generate(canceled, root, input, 1); err == nil {
		t.Fatal("canceled login issuance generated output")
	}
}
