package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// This fixture proves native mapping/custody, not the composed public login.
func signinMappingFixture(t *testing.T) (*AttemptCodec, otp.AttemptCommand, identity.FeatureCommandSpec, auth.BearerCredential, issuanceCustody, session.Session) {
	t.Helper()
	c, challenge, spec, cookie, authority := issuanceCustodyFixture(t, false)
	draft, _ := challenge.Bindings()
	continuation, _ := draft.Continuation.Bindings()
	continuation.Scope.ChallengeID = "AgICAgICAgICAgICAgICAg"
	continuation.Scope.AuthorizationBinding = [32]byte{}
	var err error
	draft.Continuation, err = otp.NewContinuation(continuation.Scope, continuation.Authorization, continuation.RememberPolicy)
	if err != nil {
		t.Fatal(err)
	}
	spec.Operation = signinOperation(spec.Operation.SubjectRequirement)
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.RecordID = spec.Operation.OperationID, spec.Operation.SchemaID, ""
	spec.Fields = nil
	code, _ := auth.NewOneTimeCode("123456")
	scope, _ := draft.Continuation.DigestScope()
	verifier, err := otp.NewVerifier(3, codecConfig().CodeKeys)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := verifier.Digest(scope, code)
	if err != nil {
		t.Fatal(err)
	}
	draft.Digest = digest.Storage()
	challenge, err = otp.NewChallenge(draft)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.issuers[7].PrepareForCommand(context.Background(), spec.Binding, spec.Operation, draft.Continuation, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := a.Bindings()
	id := identity.IdentifierID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	r := kernel.RecipientRecord{
		Query:                kernel.RecipientQuery{TenantID: spec.Binding.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: continuation.Scope.Destination.Value(), Eligibility: kernel.RecipientVerified},
		User:                 identity.User{ID: "recipient", TenantID: spec.Binding.TenantID, Status: identity.StatusActive, Version: 7},
		Identifier:           identity.Identifier{ID: id, UserID: "recipient", Kind: identity.IdentifierEmail, CanonicalValue: continuation.Scope.Destination.Value(), Verified: true, Primary: true, Version: 9},
		Verification:         identity.Verification{IdentifierID: id, State: identity.VerificationVerified, VerifiedAt: draft.IssuedAt, Version: 3},
		UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6, ObservedAt: draft.IssuedAt,
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	keys, _ := kernel.KernelAuthorityKeys(authority.Directory.Query, r.User.ID)
	sk, _ := sessionpg.SessionAuthorityKeys(spec.Binding.TenantID, r.User.ID, "family", "session")
	binding := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	vector, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding(keys.Global, 2), Tenant: binding(keys.Tenant, 3), User: binding(keys.User, 4), Identifier: binding(keys.Identifier, 5), Credential: binding(keys.Credential, 6), SessionFamily: binding(sk.Family, 1), Session: binding(sk.Session, 1), Authorization: binding("authorization:user", 9)})
	if err != nil {
		t.Fatal(err)
	}
	preauth, _ := continuation.Authorization.PreAuthTransaction()
	flow, _ := preauth.Bindings()
	until := draft.ExpiresAt
	if flow.Binding.ExpiresAt.Before(until) {
		until = flow.Binding.ExpiresAt
	}
	metadata, err := session.NewOTPAuthentication(session.OTPAuthenticationSpec{CommandID: spec.Binding.CommandID, SendCommandID: identity.CommandID(continuation.Scope.ChallengeID), ChallengeID: continuation.Scope.ChallengeID, AttemptID: string(ab.AttemptID), IdentifierID: id, IdentifierKind: identity.IdentifierEmail, IdentifierVersion: 9, VerificationVersion: 3, AuthenticatedAt: draft.IssuedAt, ValidUntil: until})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithOTP(session.SessionSpec{SessionID: "session", FamilyID: "family", TenantID: spec.Binding.TenantID, UserID: r.User.ID, Audience: "service-a", Version: 1, FamilyVersion: 1, Remember: continuation.RememberPolicy, Authority: vector, Lookup: session.TokenDigest{KeyVersion: 1, Sum: [32]byte{1}}, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationOTP}, IssuedAt: draft.IssuedAt, LastActivityAt: draft.IssuedAt}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	return c, a, spec, cookie, issuanceCustody{challenge: challenge, authority: authority, recipient: &r}, record
}

func TestSigninMappingRetainsOriginalRecipientAndCompleteSession(t *testing.T) {
	c, attempt, spec, cookie, original, record := signinMappingFixture(t)
	command, plan, err := c.mapSigninCommand(context.Background(), attempt, 3, spec, cookie, original, record)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewAttemptCodec(codecConfig())
	if err != nil {
		t.Fatal(err)
	}
	restored, selected, err := restarted.restoreSignin(command, plan)
	if err != nil || !reflect.DeepEqual(selected, *original.recipient) {
		t.Fatal("original recipient lost", err)
	}
	want, _ := sessionpg.OTPSigninSessionFields(record)
	got, _ := sessionpg.OTPSigninSessionFields(restored)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("complete session changed")
	}
	f, _ := command.Feature()
	if f.Binding != spec.Binding || f.Binding.UserID != "" || f.Binding.RecordID != "" || plan.Mode != kernel.OTPConsume {
		t.Fatal("anonymous or consuming scope changed")
	}
	if _, ok := command.PreAuthCookie(); !ok {
		t.Fatal("original pre-auth custody lost")
	}
	if _, ok := command.SessionToken(); ok {
		t.Fatal("login gained authenticated-session authority")
	}
	// The ciphertext commits the full session, not merely its user or ID.
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(f *identity.FeatureCommandSpec) { f.Binding.CorrelationID += "changed" },
		func(f *identity.FeatureCommandSpec) {
			f.Fields = append(f.Fields, identity.FeatureField{Name: "foreign.field", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
		},
		func(f *identity.FeatureCommandSpec) {
			for i := range f.Fields {
				if f.Fields[i].Name == "signin.custody" {
					f.Fields[i].Value.Bytes[0] ^= 1
				}
			}
		},
		func(f *identity.FeatureCommandSpec) {
			for i := range f.Fields {
				if f.Fields[i].Value.Kind == identity.FeatureText && f.Fields[i].Value.Text == "service-a" {
					f.Fields[i].Value.Text = "different-audience"
				}
			}
		},
		func(f *identity.FeatureCommandSpec) {
			for i := range f.Fields {
				if f.Fields[i].Name == "signin.custody" {
					f.Fields = append(f.Fields[:i], f.Fields[i+1:]...)
					break
				}
			}
		},
	} {
		changed, _ := command.Feature()
		mutate(&changed)
		code, _ := command.OneTimeCode()
		altered, err := identity.NewFeatureOneTimeCodePreAuthCommand(changed, code, cookie)
		if err != nil {
			t.Fatal("mutation did not reach native boundary", err)
		}
		if _, _, err := restarted.restoreSignin(altered, plan); err == nil {
			t.Fatal("changed original consuming intent accepted")
		}
	}
	changed := plan
	changed.ExpectedVersion++
	if _, _, err := restarted.restoreSignin(command, changed); err == nil {
		t.Fatal("changed attempt plan accepted")
	}
}

func TestSigninMappingRejectsSubstitutedOriginalInputs(t *testing.T) {
	c, attempt, spec, cookie, original, record := signinMappingFixture(t)
	for _, mutate := range []func(*issuanceCustody){
		func(c *issuanceCustody) { c.recipient = nil },
		func(c *issuanceCustody) { r := *c.recipient; r.Suppressed = true; c.recipient = &r },
		func(c *issuanceCustody) { r := *c.recipient; r.User.ID = "different"; c.recipient = &r },
		func(c *issuanceCustody) { c.challenge = otp.Challenge{} },
		func(c *issuanceCustody) { c.authority.Directory.GlobalVersion++ },
	} {
		copy := original
		mutate(&copy)
		if _, _, err := c.mapSigninCommand(context.Background(), attempt, 3, spec, cookie, copy, record); err == nil {
			t.Fatal("substituted original accepted")
		}
	}
	s, _ := record.Bindings()
	remember, _ := s.Remember.Bindings()
	remember.AbsoluteTTL += time.Hour
	s.Remember, _ = session.NewRememberPolicy(remember)
	changed, err := session.NewSessionWithOTP(s, record.OTPAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.mapSigninCommand(context.Background(), attempt, 3, spec, cookie, original, changed); err == nil {
		t.Fatal("signin extended original remember policy")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.mapSigninCommand(ctx, attempt, 3, spec, cookie, original, record); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func TestNativeSigninFeatureRequiresCompleteConsumingIntent(t *testing.T) {
	c, attempt, spec, cookie, original, record := signinMappingFixture(t)
	command, otpPlan, err := c.mapSigninCommand(context.Background(), attempt, 3, spec, cookie, original, record)
	if err != nil {
		t.Fatal(err)
	}
	base, _, _ := nativeContributorFixture(t)
	p, err := newSigninContributor(base, sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, sessionpg.OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"})
	if err != nil {
		t.Fatal(err)
	}
	// Mapping must bind the selected authorization namespace even for anonymous
	// commands; the session effect cannot adopt caller-selected authority keys.
	if err := p.ValidateFeatureCommand(command, kernel.CommandPlan{}); err == nil {
		t.Fatal("absent protected plan accepted")
	}
	if _, err := p.ApplyFeature(context.Background(), kernel.Work{}, command); err == nil {
		t.Fatal("unowned work created session")
	}
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: spec.Operation}, SubjectType: "otp_signin", OTP: &otpPlan, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.signed-in.v1"}, Audits: []kernel.AuditPlan{{EventType: "otp.signin"}}}
	if err := p.ValidateFeatureCommand(command, plan); err == nil {
		t.Fatal("foreign selected-user authorization namespace accepted")
	}
	// Rebuild original prospective custody with the owner's real policy key.
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	scope := authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "recipient"}
	a.Authorization.ScopeKey, _ = scope.Key()
	s.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	record, err = session.NewSessionWithOTP(s, record.OTPAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	command, otpPlan, err = c.mapSigninCommand(context.Background(), attempt, 3, spec, cookie, original, record)
	if err != nil {
		t.Fatal(err)
	}
	plan.OTP = &otpPlan
	if err := p.ValidateFeatureCommand(command, plan); err != nil {
		t.Fatal("complete original intent denied", err)
	}
	if err := base.ValidateFeatureCommand(command, plan); err == nil {
		t.Fatal("ordinary contributor gained signin profile")
	}
	for _, change := range []func(*kernel.CommandPlan){
		func(p *kernel.CommandPlan) { p.SubjectType = "otp_check" },
		func(p *kernel.CommandPlan) {
			p.Lifecycle = &kernel.LifecyclePlan{EventType: "otp.signed-in.v1", AfterVersion: 1}
		},
		func(p *kernel.CommandPlan) { p.OTP = nil },
		func(p *kernel.CommandPlan) { p.Delivery = &kernel.DeliveryPlan{} },
		func(p *kernel.CommandPlan) { p.CaptchaReplayReservation = true },
	} {
		candidate := plan
		change(&candidate)
		if err := p.ValidateFeatureCommand(command, candidate); err == nil {
			t.Fatal("unrelated protected effects admitted")
		}
	}
}
