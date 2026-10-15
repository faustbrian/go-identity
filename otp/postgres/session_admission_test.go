package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type nativeSessionConfig struct {
	ContributorConfig
	Session *SessionAdmissionConfig
}

func nativeSessionFixture(t *testing.T, age ...time.Duration) (nativeSessionConfig, identity.Command, kernel.OTPAttemptPlan, session.Session) {
	t.Helper()
	a, spec, record := sessionCustodyFixture(t)
	s, _ := record.Bindings()
	vector, _ := s.Authority.Bindings()
	vector.ActiveOrganizationID = ""
	vector.Organization, vector.Factor, vector.Passkey = session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}
	keys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: s.TenantID}, s.UserID)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	policy := authority.AuthorityScope{TenantID: "tenant", SubjectID: "user", PolicyNamespace: "users"}
	pk, _ := policy.Key()
	vector.Global.ScopeKey, vector.Tenant.ScopeKey, vector.User.ScopeKey = keys.Global, keys.Tenant, keys.User
	vector.Identifier.ScopeKey, vector.Credential.ScopeKey = keys.Identifier, keys.Credential
	vector.Session.ScopeKey, vector.SessionFamily.ScopeKey, vector.Authorization.ScopeKey = sk.Session, sk.Family, pk
	s.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	s.Authentication.Proof.Assurance = auth.AssuranceSingleFactor
	s.IssuedAt = time.Now().UTC()
	if len(age) != 0 {
		s.IssuedAt = s.IssuedAt.Add(-age[0])
	}
	s.LastActivityAt = s.IssuedAt
	s.Authentication.Proof.IssuedAt = s.IssuedAt.Add(-time.Minute)
	s.Authentication.Proof.ExpiresAt = s.IssuedAt.Add(time.Minute)
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	token, _ := session.ParseToken(wire)
	s.Lookup, _ = token.Digest(key, string(s.TenantID))
	record, err = session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := a.Bindings()
	cb, _ := b.Continuation.Bindings()
	cb.Scope.AuthorizationBinding = [32]byte{}
	flow, _ := otp.NewBoundSessionAuthorization(record)
	continuation, err := otp.NewContinuation(cb.Scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.ActorID, spec.Binding.ActorKind = "user", "user"
	spec.Operation.Owner, spec.Operation.OperationID, spec.Operation.SchemaID = "identity/email", "identity.email.verify", "identity-email-verify"
	spec.Operation.SubjectRequirement = identity.FeatureSubjectUser
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	code, _ := a.Code()
	a, err = issuer.PrepareForCommand(context.Background(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, 1, code)
	if err != nil {
		t.Fatal(err)
	}
	codec, _ := NewAttemptCodec(codecConfig())
	original := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3},
		UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6,
		Credential:        identity.CredentialRef{ID: "credential", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: 14},
		UserAuthorization: kernel.UserAuthorizationAdmission{Scope: policy, Version: 9}}
	command, plan, err := codec.MapSessionWithAuthority(context.Background(), a, 3, spec, auth.NewBearerCredential(wire), original)
	if err != nil {
		t.Fatal(err)
	}
	config := nativeSessionConfig{ContributorConfig: ContributorConfig{Schema: "otp_store", Codec: codec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}},
		Session: &SessionAdmissionConfig{Store: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second},
			Profile:           sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "identity", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"},
			RetainedTokenKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}, FreshnessLimit: 10 * time.Minute}}
	return config, command, plan, record
}

func TestNativeSessionProfileLimitsAndFreshness(t *testing.T) {
	config, _, _, original := nativeSessionFixture(t)
	for _, change := range []func(*SessionAdmissionConfig){
		func(c *SessionAdmissionConfig) { c.Store.Schema = "public" },
		func(c *SessionAdmissionConfig) { c.Store.MaximumDuration = 0 },
		func(c *SessionAdmissionConfig) { c.Profile.Audience = "" },
		func(c *SessionAdmissionConfig) { c.Profile.GlobalAuthorityID = "other" },
		func(c *SessionAdmissionConfig) { c.Profile.PolicyNamespace = "other" },
		func(c *SessionAdmissionConfig) { c.Profile.CredentialKind = identity.CredentialPasskey },
		func(c *SessionAdmissionConfig) { c.FreshnessLimit = 0 },
		func(c *SessionAdmissionConfig) { c.FreshnessLimit = 24*time.Hour + time.Nanosecond },
		func(c *SessionAdmissionConfig) { c.RetainedTokenKeys = nil },
		func(c *SessionAdmissionConfig) { c.RetainedTokenKeys = map[uint32][]byte{3: make([]byte, 32)} },
	} {
		candidate := *config.Session
		change(&candidate)
		c := config
		c.Session = &candidate
		if p, err := NewContributorWithSession(c.ContributorConfig, *c.Session); p != nil || !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatal("invalid session profile admitted", err)
		}
	}
	p, err := NewContributorWithSession(config.ContributorConfig, *config.Session)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := original.Bindings()
	deadline := s.Authentication.Proof.IssuedAt.Add(config.Session.FreshnessLimit)
	if p.sessionTime(original, deadline.Add(-time.Nanosecond)) != nil || p.sessionTime(original, deadline) == nil {
		t.Fatal("freshness equality renewed")
	}
	if p.sessionTime(original, s.IssuedAt.Add(-time.Nanosecond)) == nil || p.sessionTime(session.Session{}, s.IssuedAt) == nil {
		t.Fatal("future/zero original accepted")
	}
	if !strings.Contains(fmt.Sprintf("%#v", *config.Session), "redacted") {
		t.Fatal("session keys disclosed")
	}
	if _, err := json.Marshal(*config.Session); !errors.Is(err, otp.ErrSensitiveSerialization) {
		t.Fatal("session configuration export", err)
	}
}

func TestNativeSessionContributorRequiresOriginalAndToken(t *testing.T) {
	config, command, plan, _ := nativeSessionFixture(t)
	p, err := NewContributorWithSession(config.ContributorConfig, *config.Session)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateOTPAttemptCommand(command, plan); err != nil {
		t.Fatal("complete session submission denied", err)
	}
	spec, _ := command.Feature()
	code, _ := command.OneTimeCode()
	wrongWire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x59}, 32))
	wrong, _ := identity.NewFeatureOneTimeCodeSessionCommand(spec, code, auth.NewBearerCredential(wrongWire))
	if p.ValidateOTPAttemptCommand(wrong, plan) == nil {
		t.Fatal("wrong token admitted")
	}
	legacy, _, _ := nativeContributorFixture(t)
	if legacy.ValidateOTPAttemptCommand(command, plan) == nil {
		t.Fatal("session implicitly enabled")
	}
	config.Session.RetainedTokenKeys[3][0]++
	delete(config.Session.RetainedTokenKeys, 3)
	if p.ValidateOTPAttemptCommand(command, plan) != nil {
		t.Fatal("caller replaced retained keys")
	}
}
