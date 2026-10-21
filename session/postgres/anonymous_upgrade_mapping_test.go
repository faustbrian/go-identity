package postgres

import (
	"strings"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func anonymousUpgradeSessionFixture(t *testing.T) (identity.FeatureCommandSpec, session.Session, session.Session) {
	t.Helper()
	_, guest := anonymousSessionMappingFixture(t)
	g, _ := guest.Bindings()
	g.UserID = "guest-source"
	guest, err := session.NewSession(g)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := testSession(t).Bindings()
	p.Version, p.FamilyVersion = 1, 1
	p.SessionID, p.FamilyID = "permanent-successor", "permanent-successor-family"
	p.Authentication.Proof.Method, p.Authentication.CredentialID = "password", "password-target"
	a, _ := p.Authority.Bindings()
	a.ActiveOrganizationID, a.Organization, a.Factor, a.Passkey = "", session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}
	a.Session.Version, a.SessionFamily.Version = 1, 1
	p.Authority, err = session.NewAuthoritySnapshot(a)
	if err != nil {
		t.Fatal(err)
	}
	p.Remember = g.Remember
	permanent, err := session.NewSession(p)
	if err != nil {
		t.Fatal(err)
	}
	b := revokeBinding()
	b.TenantID, b.UserID, b.ActorID, b.ActorKind, b.RecordID = p.TenantID, p.UserID, identity.ActorID(p.UserID), authorization.SubjectUser, string(g.UserID)
	b.OperationID, b.SchemaID = "identity.anonymous.upgrade", "identity.anonymous.upgrade.native-v1"
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	return identity.FeatureCommandSpec{Binding: b, Operation: op}, guest, permanent
}

func TestAnonymousUpgradeSessionIntentBindsCompleteRecordsWithinCommandLimit(t *testing.T) {
	f, guest, permanent := anonymousUpgradeSessionFixture(t)
	// ActionPrimarySource keeps its full permanent source-session vocabulary.
	// Three flattened complete records do not fit the shared 128-field bound.
	targetFields, _ := OriginalSessionFields(permanent)
	guestFields, _ := AnonymousSourceSessionFields(guest)
	resultFields, _ := OriginalSessionFields(permanent)
	for n := range resultFields {
		resultFields[n].Name = "session.upgrade-result." + strings.TrimPrefix(resultFields[n].Name, "source-session.")
	}
	legacy := f
	legacy.Fields = append(append(append([]identity.FeatureField(nil), targetFields...), guestFields...), resultFields...)
	if len(legacy.Fields) <= 128 {
		t.Fatal("fixture did not reach actual three-record field limit", len(legacy.Fields))
	}
	if _, err := identity.NewFeatureCommand(legacy); err == nil {
		t.Fatal("shared field limit unexpectedly widened")
	}
	fields, err := AnonymousUpgradeSessionFields(guest, permanent)
	if err != nil {
		t.Fatal(err)
	}
	f.Fields = append(targetFields, fields...)
	command, err := identity.NewFeatureCommand(f)
	if err != nil {
		t.Fatal("complete commitment did not fit bounded command", err)
	}
	if err := ValidateAnonymousUpgradeSessionIntent(command, guest, permanent); err != nil {
		t.Fatal("original session intent denied", err)
	}
	for _, change := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.SessionID = "other-successor" },
		func(s *session.SessionSpec) { s.FamilyID = "other-family" },
		func(s *session.SessionSpec) { s.Lookup.Sum[0]++ },
		func(s *session.SessionSpec) { s.Authentication.CredentialVersion-- },
	} {
		s, _ := permanent.Bindings()
		change(&s)
		other, err := session.NewSession(s)
		if err != nil {
			t.Fatal(err)
		}
		if ValidateAnonymousUpgradeSessionIntent(command, guest, other) == nil {
			t.Fatal("substituted complete target record accepted")
		}
	}
	g, _ := guest.Bindings()
	g.Lookup.Sum[0]++
	changedGuest, _ := session.NewSession(g)
	if ValidateAnonymousUpgradeSessionIntent(command, changedGuest, permanent) == nil {
		t.Fatal("substituted original guest accepted")
	}
	// Returned field custody does not alias the immutable source records.
	fields[0].Value.Bytes[0]++
	if ValidateAnonymousUpgradeSessionIntent(command, guest, permanent) != nil {
		t.Fatal("caller field mutation changed retained command or session")
	}
}

func TestAnonymousUpgradeSessionIntentRejectsMissingForeignAndChangedRemember(t *testing.T) {
	f, guest, permanent := anonymousUpgradeSessionFixture(t)
	fields, err := AnonymousUpgradeSessionFields(guest, permanent)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing", "digest", "extra", "schema", "target", "guest", "tenant"} {
		t.Run(mode, func(t *testing.T) {
			other := f
			other.Fields = append([]identity.FeatureField(nil), fields...)
			switch mode {
			case "missing":
				other.Fields = other.Fields[1:]
			case "digest":
				other.Fields[0].Value.Bytes = append([]byte(nil), other.Fields[0].Value.Bytes...)
				other.Fields[0].Value.Bytes[0]++
			case "extra":
				other.Fields = append(other.Fields, identity.FeatureField{Name: fields[0].Name + ".extra", Value: fields[0].Value})
			case "schema":
				other.Binding.SchemaVersion++
				other.Operation.SchemaVersion++
			case "target":
				other.Binding.UserID, other.Binding.ActorID = "other-target", "other-target"
			case "guest":
				other.Binding.RecordID = "other-guest"
			case "tenant":
				other.Binding.TenantID = "other-tenant"
			}
			command, err := identity.NewFeatureCommand(other)
			if err != nil {
				t.Fatal(err)
			}
			if ValidateAnonymousUpgradeSessionIntent(command, guest, permanent) == nil {
				t.Fatal("foreign/partial session intent accepted")
			}
		})
	}
	s, _ := permanent.Bindings()
	r, _ := s.Remember.Bindings()
	r.AbsoluteTTL--
	s.Remember, err = session.NewRememberPolicy(r)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AnonymousUpgradeSessionFields(guest, changed); err == nil {
		t.Fatal("guest remember policy changed")
	}
}

func TestAnonymousUpgradeSessionIntentRejectsOtherPasswordProfiles(t *testing.T) {
	_, guest, permanent := anonymousUpgradeSessionFixture(t)
	for _, change := range []func(*session.SessionSpec){
		func(s *session.SessionSpec) { s.Authentication.Proof.Assurance = authentication.AssuranceMultiFactor },
		func(s *session.SessionSpec) { s.Authentication.Proof.Purpose = "password-reset" },
	} {
		s, _ := permanent.Bindings()
		change(&s)
		other, err := session.NewSession(s)
		if err != nil {
			t.Fatal("control must remain a valid generic session", err)
		}
		if _, err := AnonymousUpgradeSessionFields(guest, other); err == nil {
			t.Fatal("unsupported password profile admitted as upgrade result")
		}
	}
}
