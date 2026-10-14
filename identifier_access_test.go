package identity

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIdentifierAccessPreservesHumanLoginPaths(t *testing.T) {
	state, change, now := identifierFixture()
	change = IdentifierChange{TenantID: state.User.TenantID, UserID: state.User.ID, Action: IdentifierRemove, ID: "a", ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2}
	password := LoginMethod{Credential: CredentialRef{ID: "password", TenantID: state.User.TenantID, UserID: state.User.ID, Kind: CredentialPassword, Owner: "identity/password", Version: 1}, Usable: true}
	bound := IdentifierLoginMethod{Method: password, IdentifierID: "a", IdentifierVersion: 3, VerificationVersion: 2, RequiresVerified: true}
	independent := IdentifierLoginMethod{Method: LoginMethod{Credential: CredentialRef{ID: "passkey", TenantID: state.User.TenantID, UserID: state.User.ID, Kind: CredentialPasskey, Owner: "passkey", Version: 1}, Usable: true}}
	for _, tc := range []struct {
		name    string
		methods []IdentifierLoginMethod
		allowed bool
	}{
		{"last dependent path", []IdentifierLoginMethod{bound}, false},
		{"independent passkey", []IdentifierLoginMethod{bound, independent}, true},
		{"disabled passkey", []IdentifierLoginMethod{bound, {Method: LoginMethod{Credential: independent.Method.Credential}}}, false},
		{"expired passkey", []IdentifierLoginMethod{bound, {Method: LoginMethod{Credential: independent.Method.Credential, Usable: true, ExpiresAt: now}}}, false},
		{"API key is not human access", []IdentifierLoginMethod{bound, {Method: LoginMethod{Credential: CredentialRef{ID: "key", TenantID: state.User.TenantID, UserID: state.User.ID, Kind: CredentialAPIKey, Owner: "identity/apikey", Version: 1}, Usable: true}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := IdentifierAccessSnapshot{State: state, Methods: tc.methods}
			before := append([]IdentifierLoginMethod(nil), tc.methods...)
			plan, err := CheckIdentifierAccess(snapshot, change, now)
			if tc.allowed {
				if err != nil || plan.RemainingUsablePaths != 1 || len(plan.Mutation.State.Identifiers) != 0 {
					t.Fatal("independent human access lost", err)
				}
			} else {
				var final FinalAccessError
				if !errors.As(err, &final) || !reflect.DeepEqual(plan, IdentifierAccessPlan{}) {
					t.Fatal("orphaned access admitted", err)
				}
			}
			if !reflect.DeepEqual(before, tc.methods) || state.Identifiers[0].ID != "a" {
				t.Fatal("decision mutated caller state")
			}
		})
	}
	change.Action, change.Kind, change.CanonicalValue = IdentifierReplace, IdentifierEmail, "new@example.test"
	if _, err := CheckIdentifierAccess(IdentifierAccessSnapshot{State: state, Methods: []IdentifierLoginMethod{bound}}, change, now); err == nil {
		t.Fatal("replacement inherited old login binding")
	}
}

func TestIdentifierAccessAlternativePathsAndPrimarySelection(t *testing.T) {
	state, _, now := identifierFixture()
	state.Identifiers = append(state.Identifiers, Identifier{ID: "b", UserID: state.User.ID, Kind: IdentifierEmail, CanonicalValue: "two@example.test", Verified: true, Version: 1})
	state.Verifications = append(state.Verifications, Verification{IdentifierID: "b", State: VerificationVerified, VerifiedAt: now.Add(-time.Hour), Version: 1})
	method := LoginMethod{Credential: CredentialRef{ID: "password", TenantID: state.User.TenantID, UserID: state.User.ID, Kind: CredentialPassword, Owner: "identity/password", Version: 1}, Usable: true}
	a := IdentifierLoginMethod{Method: method, IdentifierID: "a", IdentifierVersion: 3, VerificationVersion: 2, RequiresVerified: true}
	b := IdentifierLoginMethod{Method: method, IdentifierID: "b", IdentifierVersion: 1, VerificationVersion: 1, RequiresVerified: true}
	change := IdentifierChange{TenantID: state.User.TenantID, UserID: state.User.ID, Action: IdentifierRemove, ID: "a", ExpectedUserVersion: 4, ExpectedAuthorityVersion: 2, ExpectedIdentifierVersion: 3, ExpectedVerificationVersion: 2}
	plan, err := CheckIdentifierAccess(IdentifierAccessSnapshot{State: state, Methods: []IdentifierLoginMethod{a, b}}, change, now)
	if err != nil || plan.RemainingUsablePaths != 1 {
		t.Fatal("same credential's alternative login path lost", err)
	}
	a.RequiresPrimary = true
	change.Action, change.ID, change.ExpectedIdentifierVersion, change.ExpectedVerificationVersion = IdentifierMakePrimary, "b", 1, 1
	if _, err := CheckIdentifierAccess(IdentifierAccessSnapshot{State: state, Methods: []IdentifierLoginMethod{a}}, change, now); err == nil {
		t.Fatal("demoted primary retained primary-only login access")
	}
	plan, err = CheckIdentifierAccess(IdentifierAccessSnapshot{State: state, Methods: []IdentifierLoginMethod{a, b}}, change, now)
	if err != nil || plan.RemainingUsablePaths != 1 || !plan.Mutation.State.Identifiers[1].Primary {
		t.Fatal("primary transition failed to preserve alternate access", err)
	}
	if !state.Identifiers[0].Primary || state.Identifiers[1].Primary {
		t.Fatal("caller-owned primary selection mutated")
	}
	// The credential is shared, but current policy/expiry eligibility belongs
	// to each login path and need not agree across email/username alternatives.
	a.Method.Usable = false
	b.Method.ExpiresAt = now.Add(time.Hour)
	plan, err = CheckIdentifierAccess(IdentifierAccessSnapshot{State: state, Methods: []IdentifierLoginMethod{a, b}}, change, now)
	if err != nil || plan.RemainingUsablePaths != 1 {
		t.Fatal("path-specific eligibility confused with credential identity", err)
	}
}

func TestIdentifierAccessBoundsProviderAndDiagnostics(t *testing.T) {
	state, change, now := identifierFixture()
	account := Account{ID: "provider-link", TenantID: state.User.TenantID, UserID: state.User.ID, Provider: "provider", Issuer: "https://provider.example.test", Subject: "subject", Version: 1}
	path := IdentifierLoginMethod{Method: LoginMethod{Credential: CredentialRef{ID: "provider", TenantID: state.User.TenantID, UserID: state.User.ID, Kind: CredentialProvider, Owner: "identity/oauth", Version: 1}, AccountID: account.ID, Usable: true}}
	snapshot := IdentifierAccessSnapshot{State: state, Accounts: []Account{account}, Methods: []IdentifierLoginMethod{path}}
	plan, err := CheckIdentifierAccess(snapshot, change, now)
	if err != nil || plan.RemainingUsablePaths != 1 {
		t.Fatal("independent linked provider denied", err)
	}
	for _, value := range []any{snapshot, path, plan} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(verb, value), "example.test") || strings.Contains(fmt.Sprintf(verb, value), "provider-link") {
				t.Fatal("diagnostics leaked login linkage")
			}
		}
	}
	for _, alter := range []func(*IdentifierAccessSnapshot){
		func(s *IdentifierAccessSnapshot) { s.Accounts = nil },
		func(s *IdentifierAccessSnapshot) { s.Methods = make([]IdentifierLoginMethod, 129) },
		func(s *IdentifierAccessSnapshot) { s.Methods[0].Method.ExpiresAt = now.Add(time.Nanosecond) },
		func(s *IdentifierAccessSnapshot) { s.Methods[0].RequiresPrimary = true },
		func(s *IdentifierAccessSnapshot) { s.Methods[0].Method.Credential.Owner = "foreign-owner" },
		func(s *IdentifierAccessSnapshot) {
			s.Methods = append(s.Methods, s.Methods[0])
			s.Methods[1].Method.Usable = false
		},
	} {
		copy := snapshot
		copy.Methods = append([]IdentifierLoginMethod(nil), snapshot.Methods...)
		alter(&copy)
		if result, err := CheckIdentifierAccess(copy, change, now); err == nil || !reflect.DeepEqual(result, IdentifierAccessPlan{}) {
			t.Fatal("malformed/unbounded provider snapshot admitted")
		}
	}
	if _, err := CheckIdentifierAccess(snapshot, change, time.Time{}); err == nil {
		t.Fatal("zero trusted time admitted")
	}
}

func TestIdentifierAccessRejectsUnboundEligibility(t *testing.T) {
	state, change, now := identifierFixture()
	method := IdentifierLoginMethod{Method: LoginMethod{Credential: CredentialRef{ID: "password", TenantID: state.User.TenantID, UserID: state.User.ID, Kind: CredentialPassword, Owner: "identity/password", Version: 1}, Usable: true}, IdentifierID: "a", IdentifierVersion: 3, VerificationVersion: 2, RequiresVerified: true}
	for _, alter := range []func(*IdentifierLoginMethod){
		func(m *IdentifierLoginMethod) { m.IdentifierVersion++ },
		func(m *IdentifierLoginMethod) { m.VerificationVersion++ },
		func(m *IdentifierLoginMethod) { m.IdentifierID = "missing" },
		func(m *IdentifierLoginMethod) { m.Method.Credential.TenantID = "foreign" },
		func(m *IdentifierLoginMethod) { m.Method.AccountID = "fake" },
		func(m *IdentifierLoginMethod) { m.IdentifierID = "" },
	} {
		m := method
		alter(&m)
		if plan, err := CheckIdentifierAccess(IdentifierAccessSnapshot{State: state, Methods: []IdentifierLoginMethod{m}}, change, now); err == nil || !reflect.DeepEqual(plan, IdentifierAccessPlan{}) {
			t.Fatal("malformed/stale path admitted")
		}
	}
	if _, err := CheckIdentifierAccess(IdentifierAccessSnapshot{State: state, Methods: []IdentifierLoginMethod{method, method}}, change, now); err == nil {
		t.Fatal("duplicate path admitted")
	}
}
