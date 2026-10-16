package postgres

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestPasswordMFASessionAdmissionRetainsCredentialAndFactor(t *testing.T) {
	original, command, profile := identifierSessionFixture(t)
	s, _ := original.Bindings()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	s.Authentication.Proof.ID = "AAAAAAAAAAAAAAAAAAAAAQ"
	s.Authentication.Proof.Purpose = session.PasswordMFAPrimaryPurpose
	key, err := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Authority.Bindings()
	a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: key, Version: 7}}
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	remember, _ := s.Remember.Bindings()
	factor, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: id, PrimaryCommandID: "AAAAAAAAAAAAAAAAAAAAAQ", ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 1, FactorAuthorityVersion: 7, ContinuationVersion: 1, Remember: remember, VerifiedAt: s.IssuedAt, ValidUntil: s.Authentication.Proof.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithPasswordMFA(s, factor)
	if err != nil {
		t.Fatal(err)
	}
	recoveryMetadata, _ := factor.Bindings()
	recoveryMetadata.Method, recoveryMetadata.RecoverySetID, recoveryMetadata.RecoverySetVersion = "recovery-code", "BwcHBwcHBwcHBwcHBwcHBw", 2
	recoveryFactor, err := session.NewMFAAuthentication(recoveryMetadata)
	if err != nil {
		t.Fatal(err)
	}
	recoveryRecord, err := session.NewSessionWithPasswordMFA(s, recoveryFactor)
	if err != nil {
		t.Fatal(err)
	}
	_, recoveryCredential, _, err := passwordMFASessionAdmissionMethod(profile, recoveryRecord, command.Binding, s.SessionID, s.Version, "recovery-code")
	if err != nil || recoveryCredential.Credential.ID != identity.CredentialID(s.Authentication.CredentialID) || recoveryCredential.Credential.Version != s.Authentication.CredentialVersion {
		t.Fatal("recovery issuance lost original credential", err)
	}
	if _, _, _, err := passwordMFASessionAdmissionMethod(profile, record, command.Binding, s.SessionID, s.Version, "recovery-code"); err == nil {
		t.Fatal("recovery issuance accepted TOTP metadata")
	}
	if _, _, _, err := passwordMFASessionAdmission(profile, recoveryRecord, command.Binding, s.SessionID, s.Version); err != nil {
		t.Fatal("selected MFA reader rejected complete recovery provenance", err)
	}
	if _, _, _, err := sessionAdmissionBindings(profile, recoveryRecord, command.Binding, s.SessionID, s.Version); err == nil {
		t.Fatal("recovery MFA entered single-factor reader")
	}
	_, credential, _, err := passwordMFASessionAdmission(profile, record, command.Binding, s.SessionID, s.Version)
	if err != nil || credential.Credential.ID != identity.CredentialID(s.Authentication.CredentialID) || credential.Credential.Version != s.Authentication.CredentialVersion {
		t.Fatal("original credential lost", err)
	}
	if _, _, _, err := sessionAdmissionBindings(profile, record, command.Binding, s.SessionID, s.Version); err == nil {
		t.Fatal("MFA downgraded into ordinary password reader")
	}
	if _, _, _, err := passwordMFASessionAdmission(profile, original, command.Binding, s.SessionID, s.Version); err == nil {
		t.Fatal("single-factor upgraded through MFA reader")
	}
	r := &Repository{revokeMFAPassword: &profile}
	guard, err := NewPasswordMFAActionSessionGuard(Config{Schema: "session_store", MaximumDuration: time.Second}, profile)
	if err != nil {
		t.Fatal(err)
	}
	action := command.Binding
	action.OperationID, action.SchemaID, action.SchemaVersion = "identity.mfa.totp-verify", "mfa-totp-step-up", 1
	for _, candidate := range []session.Session{record, recoveryRecord} {
		directory, primary, policy, err := OriginalMFAPasswordSessionAdmission(profile, candidate, command.Binding)
		if err != nil || primary != credential || directory.GlobalVersion != 1 || directory.TenantVersion != 2 || policy.Version != 8 {
			t.Fatal("explicit original MFA profile lost primary owner expectations", err)
		}
		if _, _, _, err := OriginalSessionAdmission(profile, candidate, command.Binding); err == nil {
			t.Fatal("original single-factor profile admitted MFA")
		}
		got, err := guard.admission(candidate, action)
		if err != nil || got.credential == nil || got.factor == nil || got.credential.Credential != credential.Credential || got.factor.FactorAuthorityVersion != 7 {
			t.Fatal("authenticated factor action lost original credential or factor", err)
		}
	}
	if _, _, _, err := OriginalMFAPasswordSessionAdmission(profile, original, command.Binding); err == nil {
		t.Fatal("original MFA profile upgraded a single-factor record")
	}
	for _, mutation := range []string{"actor", "schema", "operation", "tenant"} {
		bad := action
		switch mutation {
		case "actor":
			bad.ActorID = "other-user"
		case "schema":
			bad.SchemaID = "mfa-totp-verify"
		case "operation":
			bad.OperationID = "identity.session.revoke-one"
		case "tenant":
			bad.TenantID = "foreign"
		}
		if _, err := guard.admission(record, bad); err == nil {
			t.Fatal("foreign or anonymous factor action admitted", mutation)
		}
	}
	admission, err := r.revokeRecordAdmission(record, command.Binding)
	if err != nil || admission.factor == nil || admission.credential == nil || admission.credential.Credential != credential.Credential || admission.factor.FactorID != "BgYGBgYGBgYGBgYGBgYGBg" {
		t.Fatal("native password revocation lost credential or factor", err)
	}
	r.revokeMFAPassword = nil
	if _, err := r.revokeRecordAdmission(record, command.Binding); err == nil {
		t.Fatal("unselected MFA revocation fell back")
	}
	a.Factor.Binding.ScopeKey = "foreign-factor"
	s.Authority, _ = session.NewAuthoritySnapshot(a)
	foreign, err := session.NewSessionWithPasswordMFA(s, factor)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := passwordMFASessionAdmission(profile, foreign, command.Binding, s.SessionID, s.Version); err == nil {
		t.Fatal("foreign factor admitted")
	}
	if _, _, _, err := OriginalMFAPasswordSessionAdmission(profile, foreign, command.Binding); err == nil {
		t.Fatal("original MFA profile erased a foreign factor scope")
	}
}

func TestPasswordMFAServiceRequiresExplicitNativeOwners(t *testing.T) {
	if service, err := NewMFAPasswordSessionService(nil, SessionServiceConfig{}); err == nil || service != nil {
		t.Fatal("missing primary accepted")
	}
}
