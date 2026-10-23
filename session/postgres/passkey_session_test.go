package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func passkeySessionFixture(t *testing.T) (session.Session, identity.CommandBinding, PasskeyAdmissionConfig) {
	t.Helper()
	original, command, profile := identifierSessionFixture(t)
	spec, _ := original.Bindings()
	spec.Version, spec.FamilyVersion = 1, 1
	spec.Authentication.CredentialID = "passkey-a"
	spec.Authentication.Proof.Method = "passkey"
	spec.Authentication.Proof.Assurance = auth.AssurancePhishingResistant
	spec.LastActivityAt = spec.IssuedAt
	v, _ := spec.Authority.Bindings()
	v.Session.Version, v.SessionFamily.Version = 1, 1
	factor, err := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	v.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: factor, Version: 2}}
	v.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:rp-a:user-a", Version: 3}}
	spec.Authority, _ = session.NewAuthoritySnapshot(v)
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	b := command.Binding
	b.CommandID, b.OperationID, b.SchemaID, b.SchemaVersion, b.RecordID = "AQEBAQEBAQEBAQEBAQEBAQ", "identity.passkey.signin-verify", "identity.passkey.signin-verify.native-v1", 1, spec.SessionID
	b.PolicyID, b.PolicyVersion, b.CorrelationID = "policy-a", 1, "correlation-a"
	return record, b, PasskeyAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience, RPNamespace: "rp-a"}
}

func TestPasskeySessionRetainsExactNativeAndOwnerDimensions(t *testing.T) {
	record, b, profile := passkeySessionFixture(t)
	spec, _ := record.Bindings()
	directory, credential, policy, err := passkeySessionAdmission(profile, record, b)
	if err != nil || directory.GlobalVersion != 1 || directory.TenantVersion != 2 || credential.Credential.Kind != identity.CredentialPasskey || credential.Credential.Owner != "passkey" || credential.Credential.ID != "passkey-a" || credential.Credential.Version != spec.Authentication.CredentialVersion || policy.Version != 8 {
		t.Fatal("passkey credential/native authority projection changed", err)
	}
	fields, err := PasskeySigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: passkeySessionOperation(), Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := PasskeySigninSession(command)
	want, _, wantErr := encodeRecord(record)
	got, _, gotErr := encodeRecord(restored)
	if err != nil || wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
		t.Fatal("complete passkey session projection not retained", err)
	}
	// A legacy password profile must not erase either optional owner dimension.
	legacy := IdentifierAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	if _, _, _, err := sessionAdmissionBindings(legacy, record, b, spec.SessionID, spec.Version); err == nil {
		t.Fatal("passkey record admitted as password")
	}
	for _, field := range []identity.FeatureField{
		{Name: "session.result.unknown", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "extra"}},
		{Name: "session.result.proof.method", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "password"}},
	} {
		frozen, _ := command.Feature()
		found := false
		for i := range frozen.Fields {
			if frozen.Fields[i].Name == field.Name {
				frozen.Fields[i], found = field, true
			}
		}
		if !found {
			frozen.Fields = append(frozen.Fields, field)
		}
		changed, err := identity.NewFeatureCommand(frozen)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PasskeySigninSession(changed); err == nil {
			t.Fatal("foreign or extra session mapping admitted")
		}
	}
}

func TestPasskeySessionAuthorityLeaseCannotRenew(t *testing.T) {
	now := time.Date(2026, 10, 23, 14, 0, 0, 0, time.UTC)
	start := now.Add(-3 * time.Second)
	valid := PasskeySessionAuthorityObservation{PasskeyVersion: 3, FactorVersion: 2, ReadStartedAt: now.Add(-5 * time.Second), ValidUntil: now.Add(10 * time.Second)}
	earliest, until, err := passkeyObservationBounds(valid, start, now)
	if err != nil || earliest != valid.ReadStartedAt || until != valid.ValidUntil {
		t.Fatal("earliest owner lease changed", err)
	}
	for _, change := range []func(*PasskeySessionAuthorityObservation){
		func(o *PasskeySessionAuthorityObservation) { o.PasskeyVersion = 0 },
		func(o *PasskeySessionAuthorityObservation) { o.FactorVersion = 0 },
		func(o *PasskeySessionAuthorityObservation) { o.ReadStartedAt = time.Time{} },
		func(o *PasskeySessionAuthorityObservation) { o.ReadStartedAt = now.Add(time.Second) },
		func(o *PasskeySessionAuthorityObservation) { o.ValidUntil = now },
		func(o *PasskeySessionAuthorityObservation) {
			o.ValidUntil = o.ReadStartedAt.Add(20*time.Second + time.Nanosecond)
		},
	} {
		candidate := valid
		change(&candidate)
		if _, _, err := passkeyObservationBounds(candidate, start, now); err == nil {
			t.Fatal("invalid owner evidence lease admitted")
		}
	}
	if service, err := NewPasskeySessionService(nil, PasskeySessionServiceConfig{}); err == nil || service != nil {
		t.Fatal("missing native owners admitted")
	}
	if _, err := (&primarySessionReader{}).ObserveSession(context.Background(), session.SessionLookup{}); err == nil {
		t.Fatal("zero native reader admitted")
	}
}

func TestPasskeySessionMappingBindsActualLifecycleSubject(t *testing.T) {
	record, b, _ := passkeySessionFixture(t)
	fields, err := PasskeySigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	b.RecordID = "foreign-session"
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: passkeySessionOperation(), Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PasskeySigninSession(command); err == nil {
		t.Fatal("session creation attributed to another record")
	}
}

type passkeyTestAuthority struct{}

func (*passkeyTestAuthority) ObservePasskeySession(context.Context, string, session.Session) (PasskeySessionAuthorityObservation, error) {
	return PasskeySessionAuthorityObservation{}, identity.ForbiddenError{}
}
func (*passkeyTestAuthority) RequirePasskeySession(context.Context, kernel.Work, kernel.FeatureExecutionContributor, string, session.Session) error {
	return identity.ForbiddenError{}
}

func TestPasskeySessionEffectRejectsUnownedWork(t *testing.T) {
	_, _, profile := passkeySessionFixture(t)
	effect, err := NewPasskeySigninEffect(Config{Schema: "session_store", MaximumDuration: time.Second}, profile, &passkeyTestAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []*PasskeySigninEffect{nil, {}, effect} {
		if _, err := candidate.Apply(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned passkey session write admitted")
		}
		if err := candidate.Check(context.Background(), kernel.Work{}, nil, identity.Command{}); err == nil {
			t.Fatal("unowned final check admitted")
		}
		if _, err := candidate.Recover(context.Background(), kernel.RecoveryWork{}, nil); err == nil {
			t.Fatal("unowned recovery admitted")
		}
	}
}

func TestPasskeySessionRevocationRequiresExplicitMatchingOwner(t *testing.T) {
	record, b, profile := passkeySessionFixture(t)
	r := &Repository{}
	if _, err := r.revokeRecordAdmission(record, b); err == nil {
		t.Fatal("unselected passkey revocation admitted")
	}
	r.revokePasskey = &passkeySessionSelection{profile: profile, authority: &passkeyTestAuthority{}}
	admission, err := r.revokeRecordAdmission(record, b)
	if err != nil || !admission.passkey || admission.credential == nil || admission.credential.Credential.Kind != identity.CredentialPasskey || admission.factor != nil {
		t.Fatal("passkey revocation lost or relabeled owner dimensions", err)
	}
	foreign := b
	foreign.ActorID = "foreign-user"
	if _, err := r.revokeRecordAdmission(record, foreign); err == nil {
		t.Fatal("foreign passkey revocation admitted")
	}
	for _, value := range []any{profile, PasskeySessionServiceConfig{}, PasskeySessionAdmission{}, &PasskeySigninEffect{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("passkey configuration serialized")
		}
		if !bytes.Contains([]byte(fmt.Sprintf("%#v", value)), []byte("redacted")) {
			t.Fatal("passkey configuration formatting disclosed scope")
		}
	}
}
