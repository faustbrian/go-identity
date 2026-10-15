package email_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
)

func managedVerificationFixture(t testing.TB) (email.RegistrationVerificationConfig, email.ManagedVerificationSpec) {
	t.Helper()
	c, signup := registrationVerificationFixture(t)
	b := signup.Binding
	b.AnonymousFlowID = ""
	b.UserID = identity.UserID(signup.Payload.SubjectID)
	b.ActorID = identity.ActorID(b.UserID)
	b.ActorKind = authorization.SubjectUser
	b.RecordID = string(signup.IdentifierID)
	b.OperationID = "identity.email.verification-send"
	b.SchemaID = b.OperationID + ".native-v1"
	return c, email.ManagedVerificationSpec{Binding: b, IdentifierID: signup.IdentifierID, IdentifierVersion: 1, VerificationVersion: 1, Payload: signup.Payload, IssuedAt: signup.IssuedAt, ExpiresAt: signup.ExpiresAt, SessionID: "original-session", SessionVersion: 3}
}

func TestManagedVerificationSelectedSupersessionBindsStableMailboxFamily(t *testing.T) {
	c, s := managedVerificationFixture(t)
	policy, err := email.NewManagedVerificationPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	owner, supported := any(policy).(interface {
		PayloadWithSupersession(email.ManagedVerificationSpec) (capability.Payload, error)
	})
	if !supported {
		t.Fatal("managed policy cannot select resend supersession")
	}
	payload, err := owner.PayloadWithSupersession(s)
	if err != nil || len(payload.Caveats) != 5 || len(payload.Caveats["email.supersession"]) != 64 {
		t.Fatal("selected family absent from signed intent", err)
	}
	grant := registrationGrant(t, payload)
	if policy.Authorize(grant, s, s.IssuedAt) != nil {
		t.Fatal("original selected family denied")
	}
	changed := s
	changed.Binding.CommandID, _ = identity.NewCommandID()
	changed.Binding.SchemaID = "identity.email.verification-send.resend-v1"
	changed.SessionID, changed.SessionVersion = "fresh-session", s.SessionVersion+1
	changed.Payload.Version++
	changed.IssuedAt, changed.ExpiresAt = s.IssuedAt.Add(time.Minute), s.ExpiresAt.Add(time.Minute)
	resend, err := owner.PayloadWithSupersession(changed)
	if err != nil || resend.Caveats["email.supersession"] != payload.Caveats["email.supersession"] || resend.Caveats["email.intent"] == payload.Caveats["email.intent"] || policy.Authorize(grant, changed, changed.IssuedAt) == nil {
		t.Fatal("new request escaped family or borrowed predecessor intent", err)
	}
	for _, value := range []string{strings.Repeat("f", 64), strings.ToUpper(payload.Caveats["email.supersession"])} {
		forged := payload
		forged.Caveats = make(map[string]string, len(payload.Caveats))
		for key, original := range payload.Caveats {
			forged.Caveats[key] = original
		}
		forged.Caveats["email.supersession"] = value
		if policy.Authorize(registrationGrant(t, forged), s, s.IssuedAt) == nil {
			t.Fatal("cryptographically signed forged family admitted")
		}
	}
	legacy, err := policy.Payload(s)
	if err != nil || len(legacy.Caveats) != 4 || policy.Authorize(registrationGrant(t, legacy), s, s.IssuedAt) != nil {
		t.Fatal("unselected legacy management shape changed", err)
	}
}

func TestManagedVerificationAuthenticatesOriginalManagementIntent(t *testing.T) {
	c, s := managedVerificationFixture(t)
	policy, err := email.NewManagedVerificationPolicy(c)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := policy.Payload(s)
	if err != nil || payload.Subject != string(s.Binding.UserID) || payload.Resource != string(s.IdentifierID) || payload.ID != "" || payload.MaxUses != 1 || payload.Bearer || payload.Caveats["email.profile"] != "management-v1" || payload.Caveats["email.confirm_operation"] != "identity.email.verification-confirm" {
		t.Fatal("managed link was absent or retargeted", err)
	}
	if strings.Contains(fmt.Sprint(payload.Caveats), s.Payload.CanonicalAddress.Record().Value) {
		t.Fatal("link published raw address")
	}
	grant := registrationGrant(t, payload)
	if policy.Authorize(grant, s, s.IssuedAt) != nil || policy.Authorize(grant, s, s.ExpiresAt.Add(-time.Nanosecond)) != nil || policy.Authorize(grant, s, s.ExpiresAt) == nil {
		t.Fatal("original signed intent or exclusive expiry changed")
	}
	for _, mutate := range []func(*email.ManagedVerificationSpec){
		func(s *email.ManagedVerificationSpec) { s.SessionID = "another-session" },
		func(s *email.ManagedVerificationSpec) { s.SessionVersion++ },
		func(s *email.ManagedVerificationSpec) { s.Binding.CommandID, _ = identity.NewCommandID() },
		func(s *email.ManagedVerificationSpec) {
			s.IdentifierID = "another-address"
			s.Binding.RecordID = string(s.IdentifierID)
		},
		func(s *email.ManagedVerificationSpec) { s.IdentifierVersion++ },
		func(s *email.ManagedVerificationSpec) { s.VerificationVersion++ },
		func(s *email.ManagedVerificationSpec) { s.Payload.Version++ },
		func(s *email.ManagedVerificationSpec) { s.Binding.PolicyVersion++ },
		func(s *email.ManagedVerificationSpec) { s.Payload.Redirect.RawQuery = "state=other" },
		func(s *email.ManagedVerificationSpec) {
			s.Binding.OperationID = "identity.email.change-request"
			s.Binding.SchemaID = s.Binding.OperationID + ".native-v1"
		},
		func(s *email.ManagedVerificationSpec) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
	} {
		changed := s
		mutate(&changed)
		if policy.Authorize(grant, changed, s.IssuedAt) == nil {
			t.Fatal("management intent substitution accepted")
		}
	}
	changed := s
	changed.Binding.OperationID = "identity.email.change-request"
	changed.Binding.SchemaID = changed.Binding.OperationID + ".native-v1"
	changed.ChangeProfile = email.ChangeProfile{CurrentAddress: email.PrimaryOrSoleVerifiedAddress, Sessions: email.InvalidateIdentifierSessions}
	changed.Previous = email.PreviousAddress{ID: "old-address", CanonicalAddress: "old@example.test", IdentifierVersion: 7, VerificationVersion: 6, Primary: true}
	changePayload, err := policy.Payload(changed)
	if err != nil || changePayload.Caveats["email.confirm_operation"] != "identity.email.change-confirm" {
		t.Fatal("change link became ordinary verification", err)
	}
	changeGrant := registrationGrant(t, changePayload)
	for _, mutate := range []func(*email.ManagedVerificationSpec){
		func(s *email.ManagedVerificationSpec) { s.Previous.ID = "other-old" },
		func(s *email.ManagedVerificationSpec) { s.Previous.CanonicalAddress = "other@example.test" },
		func(s *email.ManagedVerificationSpec) { s.Previous.IdentifierVersion++ },
		func(s *email.ManagedVerificationSpec) { s.Previous.VerificationVersion++ },
		func(s *email.ManagedVerificationSpec) { s.Previous.Primary = false },
		func(s *email.ManagedVerificationSpec) { s.ChangeProfile.CurrentAddress = email.RequirePrimaryAddress },
	} {
		other := changed
		mutate(&other)
		if policy.Authorize(changeGrant, other, s.IssuedAt) == nil {
			t.Fatal("change borrowed a different original address or policy")
		}
	}
	changed.Previous = email.PreviousAddress{}
	if _, err := policy.Payload(changed); err == nil {
		t.Fatal("change without an original address admitted")
	}
	_, signup := registrationVerificationFixture(t)
	registration, _ := email.NewRegistrationVerificationPolicy(c)
	registrationPayload, _ := registration.Payload(signup)
	registrationGrantValue := registrationGrant(t, registrationPayload)
	if policy.Authorize(registrationGrantValue, s, s.IssuedAt) == nil || registration.Authorize(grant, signup, signup.IssuedAt) == nil {
		t.Fatal("registration and authenticated management profiles confused")
	}
	if _, err := s.MarshalJSON(); err == nil {
		t.Fatal("private management intent serialized")
	}
	if diagnostic := fmt.Sprintf("%#v", s); strings.Contains(diagnostic, string(s.Binding.UserID)) || !strings.Contains(diagnostic, "redacted") {
		t.Fatal("private management intent disclosed")
	}
}

func TestManagedVerificationRejectsMalformedScopeAndConservesRetainedKeys(t *testing.T) {
	c, s := managedVerificationFixture(t)
	policy, _ := email.NewManagedVerificationPolicy(c)
	unsigned, _ := policy.Payload(s)
	grant := registrationGrant(t, unsigned)
	c.CurrentBindingKeyVersion = 2
	c.RetainedBindingKeys[2] = [32]byte{43}
	rotated, err := email.NewManagedVerificationPolicy(c)
	if err != nil || rotated.Authorize(grant, s, s.IssuedAt) != nil || rotated.Authorize(grant, s, s.ExpiresAt) == nil {
		t.Fatal("key rotation renewed or lost original validity", err)
	}
	delete(c.RetainedBindingKeys, 1)
	withoutOld, _ := email.NewManagedVerificationPolicy(c)
	if withoutOld.Authorize(grant, s, s.IssuedAt) == nil {
		t.Fatal("missing original binding key accepted")
	}
	if rotated.Authorize(grant, s, s.IssuedAt) != nil {
		t.Fatal("caller changed retained key custody")
	}
	for _, mutate := range []func(*email.ManagedVerificationSpec){
		func(s *email.ManagedVerificationSpec) { s.Binding.ActorID = "another-user" },
		func(s *email.ManagedVerificationSpec) { s.Binding.ActorKind = authorization.SubjectServiceAccount },
		func(s *email.ManagedVerificationSpec) { s.Binding.UserID = "another-user" },
		func(s *email.ManagedVerificationSpec) { s.Binding.TenantID = "another-tenant" },
		func(s *email.ManagedVerificationSpec) { s.Binding.AnonymousFlowID = "AgICAgICAgICAgICAgICAg" },
		func(s *email.ManagedVerificationSpec) { s.Binding.RecordID = "another-address" },
		func(s *email.ManagedVerificationSpec) { s.Binding.OperationID = "identity.password.signup" },
		func(s *email.ManagedVerificationSpec) { s.Binding.SchemaID = "unsupported" },
		func(s *email.ManagedVerificationSpec) { s.SessionID = "" },
		func(s *email.ManagedVerificationSpec) { s.SessionVersion = 0 },
		func(s *email.ManagedVerificationSpec) { s.SessionVersion = ^uint64(0) },
		func(s *email.ManagedVerificationSpec) { s.IdentifierVersion = 0 },
		func(s *email.ManagedVerificationSpec) { s.VerificationVersion = 0 },
		func(s *email.ManagedVerificationSpec) { s.Payload.Version = 0 },
		func(s *email.ManagedVerificationSpec) { s.Payload.Purpose = "identity.password.reset" },
		func(s *email.ManagedVerificationSpec) { s.IssuedAt = time.Time{} },
		func(s *email.ManagedVerificationSpec) { s.ExpiresAt = s.IssuedAt },
		func(s *email.ManagedVerificationSpec) { s.ExpiresAt = s.IssuedAt.Add(25 * time.Hour) },
		func(s *email.ManagedVerificationSpec) { s.IssuedAt = s.IssuedAt.Add(time.Nanosecond) },
		func(s *email.ManagedVerificationSpec) { s.Payload.Redirect.RawPath = strings.Repeat("x", 2049) },
	} {
		changed := s
		mutate(&changed)
		if _, err := policy.Payload(changed); err == nil {
			t.Fatal("malformed managed link issued")
		}
	}
	var absent *email.ManagedVerificationPolicy
	if _, err := absent.Payload(s); err == nil {
		t.Fatal("nil policy issued link")
	}
	if absent.Authorize(grant, s, s.IssuedAt) == nil {
		t.Fatal("nil policy authorized link")
	}
	if _, err := email.NewManagedVerificationPolicy(email.RegistrationVerificationConfig{}); err == nil {
		t.Fatal("zero config enabled management")
	}
}

func FuzzManagedVerificationOriginalIntent(f *testing.F) {
	c, s := managedVerificationFixture(f)
	policy, _ := email.NewManagedVerificationPolicy(c)
	unsigned, _ := policy.Payload(s)
	grant := registrationGrant(f, unsigned)
	selected, err := policy.PayloadWithSupersession(s)
	if err != nil {
		f.Fatal(err)
	}
	selectedGrant := registrationGrant(f, selected)
	f.Add(s.SessionID, s.SessionVersion, s.Payload.Redirect.RawQuery)
	f.Add("", uint64(0), "")
	f.Add("other-session", uint64(3), "state=other")
	f.Add(strings.Repeat("x", 129), ^uint64(0), strings.Repeat("x", 2049))
	f.Fuzz(func(t *testing.T, sessionID string, version uint64, query string) {
		changed := s
		changed.SessionID = sessionID
		changed.SessionVersion = version
		changed.Payload.Redirect.RawQuery = query
		exact := sessionID == s.SessionID && version == s.SessionVersion && query == s.Payload.Redirect.RawQuery
		for _, original := range []capability.Grant{grant, selectedGrant} {
			if err := policy.Authorize(original, changed, s.IssuedAt); (err == nil) != exact {
				t.Fatal("original intent authorization changed")
			}
		}
	})
}
