package postgres

import (
	"bytes"
	"testing"

	authorization "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func TestPossessionRevokeAdmissionRequiresSelectedExactOwners(t *testing.T) {
	for _, record := range []session.Session{otpRecordFixture(t, false), magicLinkRecordFixture(t, true)} {
		s, _ := record.Bindings()
		a, _ := s.Authority.Bindings()
		query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: s.TenantID}
		keys, _ := kernel.KernelAuthorityKeys(query, s.UserID)
		sk, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
		pk, _ := (authorization.AuthorityScope{TenantID: "tenant-a", PolicyNamespace: "users", SubjectID: "user-a"}).Key()
		a.Global.ScopeKey, a.Tenant.ScopeKey, a.User.ScopeKey, a.Identifier.ScopeKey, a.Credential.ScopeKey = keys.Global, keys.Tenant, keys.User, keys.Identifier, keys.Credential
		a.Session.ScopeKey, a.SessionFamily.ScopeKey, a.Authorization.ScopeKey = sk.Session, sk.Family, pk
		s.Authority, _ = session.NewAuthoritySnapshot(a)
		if s.Authentication.Kind == session.AuthenticationOTP {
			record, _ = session.NewSessionWithOTP(s, record.OTPAuthentication())
		} else {
			record, _ = session.NewSessionWithMagicLinkAndCSRF(s, record.MagicLinkAuthentication(), record.CSRFState())
		}
		otp := OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: s.Audience}
		magic := MagicLinkAdmissionConfig(otp)
		r := &Repository{revokeAdmission: &SingleFactorSessionAdmissionConfig{OTP: &otp, MagicLink: &magic}}
		b := revokeBinding()
		admission, err := r.revokeRecordAdmission(record, b)
		if err != nil || admission.credential != nil || admission.identifier == nil || admission.identifier.User.CredentialAuthorityVersion != a.Credential.Version {
			t.Fatal("possession requires original identifier, not fabricated credential", err)
		}
		for _, mode := range []string{"unselected", "tenant", "actor", "global", "namespace", "audience"} {
			bad := *r
			selection := *r.revokeAdmission
			bad.revokeAdmission = &selection
			x := b
			switch mode {
			case "unselected":
				bad.revokeAdmission = nil
			case "tenant":
				x.TenantID = "foreign"
			case "actor":
				x.ActorID = "other-user"
			default:
				p, m := otp, magic
				switch mode {
				case "global":
					p.GlobalAuthorityID, m.GlobalAuthorityID = "foreign", "foreign"
				case "namespace":
					p.PolicyNamespace, m.PolicyNamespace = "foreign", "foreign"
				case "audience":
					p.Audience, m.Audience = "foreign", "foreign"
				}
				selection.OTP, selection.MagicLink = &p, &m
			}
			if _, err := bad.revokeRecordAdmission(record, x); err == nil {
				t.Fatal("foreign/unselected revocation accepted", mode)
			}
		}
	}
}

func TestPossessionSessionRevokeMappingPreservesHistoricalAuthentication(t *testing.T) {
	for _, record := range []session.Session{otpRecordFixture(t, false), otpRecordFixture(t, true), magicLinkRecordFixture(t, false), magicLinkRecordFixture(t, true)} {
		s, _ := record.Bindings()
		s.Version = 7
		authority, _ := s.Authority.Bindings()
		authority.Session.Version = s.Version
		s.Authority, _ = session.NewAuthoritySnapshot(authority)
		var state session.CSRFState
		if p, err := record.CSRFState().Bindings(); err == nil {
			p.Binding.SessionVersion = s.Version
			state, _ = session.NewCSRFState(p)
		}
		var err error
		if s.Authentication.Kind == session.AuthenticationOTP {
			if state != (session.CSRFState{}) {
				record, err = session.NewSessionWithOTPAndCSRF(s, record.OTPAuthentication(), state)
			} else {
				record, err = session.NewSessionWithOTP(s, record.OTPAuthentication())
			}
		} else {
			if state != (session.CSRFState{}) {
				record, err = session.NewSessionWithMagicLinkAndCSRF(s, record.MagicLinkAuthentication(), state)
			} else {
				record, err = session.NewSessionWithMagicLink(s, record.MagicLinkAuthentication())
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		b := revokeBinding()
		op := session.RevokeOneOperation()
		b.CommandID = "BAQEBAQEBAQEBAQEBAQEBA"
		b.RecordID, b.OperationID, b.SchemaID = s.SessionID, op.OperationID, op.SchemaID
		one, err := session.NewRevokeOneCommand(b, record)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := MapCommand(one)
		if err != nil {
			t.Fatal("possession session cannot map self-revocation", err)
		}
		restored, err := nativeRevokeOne(mapped)
		if err != nil {
			t.Fatal("cannot restore original revocation", err)
		}
		got, _ := restored.RevokeOne()
		a, _, _ := encodeRecord(record)
		z, _, _ := encodeRecord(got.Session)
		if got.Binding != b || !bytes.Equal(a, z) {
			t.Fatal("original session provenance changed")
		}
		projection, _ := mapped.Feature()
		for i := range projection.Fields {
			bad := projection
			bad.Fields = append([]identity.FeatureField(nil), projection.Fields[:i]...)
			bad.Fields = append(bad.Fields, projection.Fields[i+1:]...)
			command, err := identity.NewFeatureCommand(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := nativeRevokeOne(command); err == nil {
				t.Fatal("incomplete original revocation accepted", projection.Fields[i].Name)
			}
		}
		// A different method's historical fields must not be tolerated as inactive
		// union payload, even when the declared kind and principal remain valid.
		projection.Fields = append(projection.Fields, identity.FeatureField{Name: "proof.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "substituted"}})
		mixed, err := identity.NewFeatureCommand(projection)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nativeRevokeOne(mixed); err == nil {
			t.Fatal("mixed method projection admitted")
		}
	}
}
