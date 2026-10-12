package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	policy "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestMFASessionServiceRequiresNativeOwners(t *testing.T) {
	if s, err := NewMFAMagicLinkSessionService(nil, MFAMagicLinkSessionServiceConfig{}); err == nil || s != nil {
		t.Fatal("missing MFA owners accepted")
	}
	if _, err := mfapg.NewTOTPSessionFactorReader(nil, time.Second); err == nil {
		t.Fatal("missing factor primary accepted")
	}
	for _, r := range []*mfapg.TOTPSessionFactorReader{nil, {}} {
		if _, err := r.Read(context.Background(), "tenant", "user", "AQEBAQEBAQEBAQEBAQEBAQ"); err == nil {
			t.Fatal("unowned factor state became authority")
		}
	}
	if got := fmt.Sprintf("%#v", MFAMagicLinkSessionServiceConfig{}); got != "postgres.MFAMagicLinkSessionServiceConfig(redacted)" {
		t.Fatal("MFA session configuration disclosed")
	}
	if _, err := json.Marshal(MFAMagicLinkSessionServiceConfig{}); err == nil {
		t.Fatal("MFA session configuration exported")
	}
}

func TestMFASessionAdmissionKeepsExactFactorOwner(t *testing.T) {
	_, record := mfaCompletionMappingFixture(t, false)
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	profile := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: s.Audience}
	keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: s.TenantID}, s.UserID)
	sessionKeys, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	policyKey, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(s.UserID)}).Key()
	factorKey, _ := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
	a.Global.ScopeKey, a.Tenant.ScopeKey, a.User.ScopeKey, a.Identifier.ScopeKey, a.Credential.ScopeKey = keys.Global, keys.Tenant, keys.User, keys.Identifier, keys.Credential
	a.SessionFamily.ScopeKey, a.Session.ScopeKey, a.Authorization.ScopeKey, a.Factor.Binding.ScopeKey = sessionKeys.Family, sessionKeys.Session, policyKey, factorKey
	for _, test := range []struct{ foreign, recovery bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		foreign := test.foreign
		current := a
		if foreign {
			current.Factor.Binding.ScopeKey = "foreign-factor"
		}
		s.Authority, _ = session.NewAuthoritySnapshot(current)
		factor := record.MFAAuthentication()
		if test.recovery {
			metadata, _ := factor.Bindings()
			metadata.Method, metadata.RecoverySetID, metadata.RecoverySetVersion = "recovery-code", "BwcHBwcHBwcHBwcHBwcHBw", 2
			var err error
			factor, err = session.NewMFAAuthentication(metadata)
			if err != nil {
				t.Fatal(err)
			}
		}
		expected, err := session.NewSessionWithMagicLinkMFA(s, record.MagicLinkAuthentication(), factor)
		if err != nil {
			t.Fatal(err)
		}
		q, scope, err := mfaMagicLinkSessionAdmission(profile, expected)
		if foreign {
			if err == nil {
				t.Fatal("foreign factor key admitted")
			}
			continue
		}
		if err != nil || q.TenantID != s.TenantID || scope.SubjectID != authorization.SubjectID(s.UserID) {
			t.Fatal("exact native factor scope rejected", err)
		}
		if _, _, err := magicLinkSessionAdmission(profile, expected); err == nil {
			t.Fatal("MFA record downgraded to single-factor")
		}
		b := identity.CommandBinding{TenantID: s.TenantID, UserID: s.UserID, ActorID: identity.ActorID(s.UserID), ActorKind: authorization.SubjectUser}
		r := &Repository{revokeAdmission: &SingleFactorSessionAdmissionConfig{MagicLink: &profile}, revokeMFAMagicLink: &profile}
		if admission, err := r.revokeRecordAdmission(expected, b); err != nil || admission.factor == nil {
			t.Fatal("selected MFA revoke lost original factor", err)
		}
		r.revokeMFAMagicLink = nil
		if _, err := r.revokeRecordAdmission(expected, b); err == nil {
			t.Fatal("unselected MFA revocation downgraded")
		}
	}
	for _, invalid := range []session.Session{{}, magicLinkRecordFixture(t, false), otpRecordFixture(t, false)} {
		if _, _, err := mfaMagicLinkSessionAdmission(profile, invalid); err == nil {
			t.Fatal("unconfirmed factor profile accepted")
		}
	}
}
