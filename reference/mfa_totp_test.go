package reference

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestNativeTOTPProtectedAdmissionPreparesExactCountersWithoutCharging(t *testing.T) {
	r := nativeTOTPRequest(t)
	now := time.Now().UTC().Truncate(time.Second)
	policy, counterKeys := routerPolicy(t)
	coordinator, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: counterKeys, Clock: time.Now, Timeout: time.Second, Store: routedCounterStore(func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
		t.Fatal("MFA provider preparation dispatched nontransactional counters")
		return risk.CounterResult{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: time.Second, Counters: &coordinator})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{71}, 32), bytes.Repeat([]byte{72}, 32))
	cfg := risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "mfa-risk-v1", Keys: []risk.EvidenceKey{key}}
	custody, err := risk.NewProtectedProviderAdmissionCustody(cfg)
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(riskpg.Config{Schema: "risk", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{key}, EnvelopeKeys: map[string][]byte{"test": bytes.Repeat([]byte{73}, 32)}, CurrentEnvelopeKey: "test", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: counterKeys}})
	if err != nil {
		t.Fatal(err)
	}
	state := &magicLinkTOTPState{config: MagicLinkTOTPCompletionConfig{ConfigurationID: "native-totp-v1", PolicyID: "magic-login", ComparisonKeyVersion: 1, Risk: cfg, Coordinator: kernel.CoordinatorConfig{AdmissionPolicy: &kernel.CommandQueryPolicy{PolicyVersion: 9}}}, custody: custody, counters: counters}
	command, err := state.originalCommand(r, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	remember, _ := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	continuation, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: mfa.ContinuationID(r.ChallengeID), PrimaryProofID: "primary", PrimaryProofDigest: [32]byte{1}, PrimaryProofExpiresAt: now.Add(time.Minute), TenantID: r.TenantID, SubjectID: "subject", SourcePreAuthID: r.PreAuthID, Origin: r.Origin, AllowedMethods: []string{"totp"}, PolicyVersion: 9, FactorVersion: 7, RememberPolicy: remember, Purpose: "identity.mfa.complete", Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(time.Minute), MaxAttempts: 3, AttemptsRemaining: 3, State: mfa.Pending, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := continuation.Bindings()
	p := &magicTOTPPhase{state: state, input: &magicTOTPInput{request: r, command: command, continuation: continuation, scope: scope, recipient: kernel.RecipientRecord{User: identity.User{ID: "subject"}}, child: kernel.CapabilityPlan{CapabilityID: string(r.ChallengeID), Purpose: "identity.mfa.complete", MaxUses: 1}}}
	if err := p.admitRisk(t.Context()); err != nil {
		t.Fatal("native protected provider admission unavailable", err)
	}
	if p.counterCommand == (identity.Command{}) || p.counterPlan.PolicyVersion != 3 || p.counterPlan.Fingerprint == ([32]byte{}) || p.input.command != command || p.admission.Check(t.Context()) != nil {
		t.Fatal("original intent/counter/protected custody not composed")
	}
	if err := counters.ValidateCommandCounters(p.counterCommand, p.counterPlan); err != nil {
		t.Fatal("unvalidated native counters", err)
	}
}

func TestNativeTOTPCompletionRejectsMissingOwnedComposition(t *testing.T) {
	if service, err := newMagicLinkTOTPService(nil, nil, MagicLinkTOTPCompletionConfig{}, nil); err == nil || service != nil {
		t.Fatal("missing durable owners admitted native MFA completion")
	}
	var service *magicLinkTOTPService
	if input, err := service.readInput(context.Background(), mfa.TotpVerifyRequest{}); err == nil || input != nil {
		t.Fatal("missing native service returned authentication input")
	}
	if user, challenge, lifetime, err := service.TotpVerificationRateSource(t.Context(), mfa.TotpVerifyRequest{}); err == nil || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("zero native owner disclosed rate source")
	}
	if result, err := service.TotpVerify(t.Context(), mfa.TotpVerifyRequest{}); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("missing completion service returned an outcome")
	}
	if result, err := service.RecoverTotpVerify(t.Context(), identity.RecoveryQuery{}, authorization.DecisionContext{}); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
		t.Fatal("missing completion service recovered an outcome")
	}
	if _, err := json.Marshal(MagicLinkTOTPCompletionConfig{}); err == nil {
		t.Fatal("MFA signing/comparison/session configuration serialized")
	}
	if fmt.Sprintf("%#v", MagicLinkTOTPCompletionConfig{}) != "reference.MagicLinkTOTPCompletionConfig(redacted)" {
		t.Fatal("MFA key custody exposed by configuration formatting")
	}
}

func TestLoginTOTPRejectsActiveStepUpBeforeComposition(t *testing.T) {
	r := nativeTOTPRequest(t)
	r.ChallengeID, r.PreAuthID = "", ""
	r.Proof, r.Cookie = capability.Proof{}, auth.BearerCredential{}
	r.Callback, r.Device = "", ""
	csrf, err := session.ParseCSRFToken(strings.Repeat("A", 43))
	if err != nil {
		t.Fatal(err)
	}
	r.StepUp = &mfa.TOTPAuthenticatedStepUp{Session: auth.NewBearerCredential(strings.Repeat("A", 43)), CSRFToken: csrf, Purpose: "identity.mfa.recovery-regenerate"}
	r.Caller = authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(r.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "user-a"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.user", ID: "user-a"}}}
	if r.Validate() != nil {
		t.Fatal("active-session fixture is not structurally valid")
	}
	calls := 0
	s := &magicLinkTOTPService{state: func() *magicLinkTOTPState {
		calls++
		return &magicLinkTOTPState{config: MagicLinkTOTPCompletionConfig{MaximumDuration: time.Second}}
	}}
	if out, err := s.TotpVerify(t.Context(), r); err == nil || out.Outcome != identity.CommitOutcomeInvalid || calls != 0 {
		t.Fatal("unselected active-session profile reached login composition")
	}
	if user, challenge, ttl, err := s.TotpVerificationRateSource(t.Context(), r); err == nil || user != "" || challenge != "" || ttl != 0 || calls != 0 {
		t.Fatal("unselected active-session profile reached login rate source")
	}
}

func TestMagicLinkTOTPFeatureCannotBypassGraphLifetime(t *testing.T) {
	var empty FeatureSet
	if owner, err := empty.MagicLinkTOTP(); err == nil || owner != nil {
		t.Fatal("zero graph exposed TOTP completion")
	}
	c, d, graph := serverFixture(t)
	_ = c
	_ = d
	graph.state.features.magicTOTP = &magicLinkTOTPService{}
	owner, err := graph.MagicLinkTOTP()
	if err != nil || owner == nil {
		t.Fatal("selected native TOTP unavailable", err)
	}
	// Even a retained handle cannot use uninitialized or closed primary owners.
	if result, err := owner.TotpVerify(t.Context(), nativeTOTPRequest(t)); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("uninitialized graph authenticated")
	}
	graph.state.mu.Lock()
	graph.state.closed = true
	graph.state.mu.Unlock()
	if next, err := graph.MagicLinkTOTP(); err == nil || next != nil {
		t.Fatal("closed graph exposed native TOTP")
	}
	if result, err := owner.TotpVerify(t.Context(), nativeTOTPRequest(t)); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("retained TOTP handle bypassed shutdown")
	}
	source := owner.(interface {
		TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error)
	})
	if user, challenge, lifetime, err := source.TotpVerificationRateSource(t.Context(), nativeTOTPRequest(t)); err == nil || user != "" || challenge != "" || lifetime != 0 {
		t.Fatal("retained rate source bypassed shutdown")
	}
}

func TestPasswordTOTPSelectionNeverFallsBackAndRetainedHandleDeniesShutdown(t *testing.T) {
	var empty FeatureSet
	if owner, err := empty.PasswordTOTP(); err == nil || owner != nil {
		t.Fatal("zero graph exposed password TOTP")
	}
	_, _, graph := serverFixture(t)
	graph.state.features.magicTOTP = &magicLinkTOTPService{}
	if owner, err := graph.PasswordTOTP(); err == nil || owner != nil {
		t.Fatal("magic-link selection silently enabled password TOTP")
	}
	graph.state.features.passwordTOTP = &magicLinkTOTPService{}
	owner, err := graph.PasswordTOTP()
	if err != nil || owner == nil {
		t.Fatal("selected password completion unavailable", err)
	}
	graph.state.mu.Lock()
	graph.state.closed = true
	graph.state.mu.Unlock()
	if next, err := graph.PasswordTOTP(); err == nil || next != nil {
		t.Fatal("closed graph exposed password completion")
	}
	if result, err := owner.TotpVerify(t.Context(), nativeTOTPRequest(t)); err == nil || result.Session.Token != (session.Token{}) {
		t.Fatal("retained password completion bypassed shutdown")
	}
	source := owner.(interface {
		TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error)
	})
	if user, challenge, life, err := source.TotpVerificationRateSource(t.Context(), nativeTOTPRequest(t)); err == nil || user != "" || challenge != "" || life != 0 {
		t.Fatal("retained password rate source bypassed shutdown")
	}
}

func nativeTOTPRequest(t *testing.T) mfa.TotpVerifyRequest {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{Choice: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := mfa.NewPartialAuthContinuation(mfa.ContinuationSpec{ID: "AAAAAAAAAAAAAAAAAAAAAQ", PrimaryProofID: "primary-proof", PrimaryProofDigest: [32]byte{1}, PrimaryProofExpiresAt: now.Add(3 * time.Minute), TenantID: "tenant", SubjectID: "subject", SourcePreAuthID: "bbbbbbbbbbbbbbbbbbbbbg", Origin: "https://app.test", AllowedMethods: []string{"totp"}, PolicyVersion: 9, FactorVersion: 7, RememberPolicy: remember, Purpose: "identity.mfa.complete", Audience: "identity", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), MaxAttempts: 3, AttemptsRemaining: 3, State: mfa.Pending, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := continuation.CapabilityPayload("https://issuer.test")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("fixture-v1", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := capability.Issue(t.Context(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := capability.ParseProof(wire, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	r := mfa.TotpVerifyRequest{TenantID: "tenant", CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", ChallengeID: "AAAAAAAAAAAAAAAAAAAAAQ", FactorID: "AgICAgICAgICAgICAgICAg", Proof: proof, Code: code, PreAuthID: "bbbbbbbbbbbbbbbbbbbbbg", Cookie: auth.NewBearerCredential(strings.Repeat("A", 43)), Origin: "https://app.test", Callback: "https://app.test/login", Network: "127.0.0.1", Caller: authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "transport"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: "AAAAAAAAAAAAAAAAAAAAAQ"}}}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestNativeTOTPOriginalIntentIsStableAndBindsTransportAndFactor(t *testing.T) {
	r := nativeTOTPRequest(t)
	state := &magicLinkTOTPState{config: MagicLinkTOTPCompletionConfig{ConfigurationID: "native-totp-v1", PolicyID: "magic-login", ComparisonKeyVersion: 1, Coordinator: kernel.CoordinatorConfig{AdmissionPolicy: &kernel.CommandQueryPolicy{PolicyVersion: 9}}}}
	original, err := state.originalCommand(r, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.Feature()
	again, err := state.originalCommand(r, [32]byte{1})
	got, _ := again.Feature()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("same input changed original intent", err)
	}
	for _, change := range []func(*mfa.TotpVerifyRequest){func(r *mfa.TotpVerifyRequest) { r.Device = "other-device" }, func(r *mfa.TotpVerifyRequest) { r.Network = "127.0.0.2" }, func(r *mfa.TotpVerifyRequest) { r.Callback = "https://app.test/other" }, func(r *mfa.TotpVerifyRequest) { r.FactorID = "AwMDAwMDAwMDAwMDAwMDAw" }, func(r *mfa.TotpVerifyRequest) { r.TrustDevice = true }} {
		changed := r
		change(&changed)
		command, err := state.originalCommand(changed, [32]byte{1})
		projection, _ := command.Feature()
		if err != nil || reflect.DeepEqual(projection.Fields, want.Fields) {
			t.Fatal("changed intent adopted same fingerprint fields", err)
		}
	}
	if _, err := state.originalCommand(r, [32]byte{}); err == nil {
		t.Fatal("missing verified envelope identity accepted")
	}
}

func TestNativeTOTPTransactionRejectsZeroCustody(t *testing.T) {
	phase := &magicTOTPPhase{}
	if _, err := phase.RecordMFATOTPAttemptDenial(t.Context(), kernel.MFATOTPAttemptWork{}); err == nil {
		t.Fatal("missing factor owners admitted a counted attempt")
	}
	if _, err := phase.ApplyFeature(t.Context(), kernel.Work{}, identity.Command{}); err == nil {
		t.Fatal("missing native owners admitted completion")
	}
}
