package postgres

import (
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const passwordSessionPrefix = "session.result."

// PasswordSigninSessionFields freezes the complete prospective password session
// into the closed session.result vocabulary before command fingerprinting. The
// selected tenant/user are explicit even when the command remains anonymous.
// Returned fields and bytes are caller-owned; no password, cookie or bearer is
// included. Only initial single-factor password issuance without organization,
// factor, passkey or credential-continuation authority is supported. Zero and
// unsupported records return ErrInvalidSessionCommand. This pure mapping does
// not authenticate, compare current owners, consume pre-auth or permit issuance.
func PasswordSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	if !passwordSigninRecord(record) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	for i := range fields {
		fields[i].Name = passwordSessionPrefix + strings.TrimPrefix(fields[i].Name, originalSessionPrefix)
	}
	s, _ := record.Bindings()
	fields = append(fields,
		identity.FeatureField{Name: passwordSessionPrefix + "tenant.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(s.TenantID)}},
		identity.FeatureField{Name: passwordSessionPrefix + "user.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(s.UserID)}},
	)
	return fields, nil
}

// PasswordSigninSession restores only the exact session-owned projection from
// the closed paired password-signin v1 command. Missing, extra, malformed or
// cross-scope fields, ordinary/OTP variants and destroyed password owners deny
// with ErrInvalidSessionCommand. Other fields remain the password owner's
// responsibility. Anonymous command scope is never rewritten to the selected
// session user. Inputs must remain immutable during this synchronous bounded
// call. No comparison, provenance, freshness renewal or recovery authority is
// established: native execution must check the selected user and all owners in
// the original Work before staging this record. Do not log correlated fields.
func PasswordSigninSession(command identity.Command) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	p, ok := command.PasswordSigninFeature()
	secret, _, custody := command.PasswordSigninCustody()
	if !ok || !custody || secret.Len() == 0 || p.Operation != passwordSessionOperation(p.Binding) {
		return deny()
	}
	return passwordSessionFromFeature(p)
}

// Both closed password profiles retain the same prospective record vocabulary;
// their custody and exact operation checks remain separate at entry.
func passwordSessionFromFeature(p identity.FeatureCommandSpec) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	var tenant identity.TenantID
	var user identity.UserID
	fields := make([]identity.FeatureField, 0, 64)
	for _, f := range p.Fields {
		name, owned := strings.CutPrefix(f.Name, passwordSessionPrefix)
		if !owned {
			continue
		}
		switch name {
		case "tenant.id", "user.id":
			if f.Value.Kind != identity.FeatureText || f.Value.Uint64 != 0 || f.Value.Int64 != 0 || f.Value.Bool || f.Value.Time != (time.Time{}) || f.Value.Bytes != nil {
				return deny()
			}
			if name == "tenant.id" {
				tenant = identity.TenantID(f.Value.Text)
			} else {
				user = identity.UserID(f.Value.Text)
			}
		default:
			f.Name = originalSessionPrefix + name
			fields = append(fields, f)
		}
	}
	if tenant != p.Binding.TenantID || user == "" || p.Binding.UserID != "" && user != p.Binding.UserID {
		return deny()
	}
	record, err := OriginalSessionFromFields(tenant, user, fields)
	if err != nil || !passwordSigninRecord(record) {
		return deny()
	}
	return record, nil
}

func passwordSessionOperation(b identity.CommandBinding) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if b.AnonymousFlowID != "" {
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return op
}

func passwordSigninRecord(record session.Session) bool {
	s, err := record.Bindings()
	if err != nil {
		return false
	}
	a, err := s.Authority.Bindings()
	if err != nil || s.Version != 1 || !s.IssuedAt.Equal(s.LastActivityAt) || a.Organization.Present || a.Factor.Present || a.Passkey.Present || s.Authentication.Kind != session.AuthenticationVerified || s.Authentication.Proof.Method != "password" || s.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || s.IssuedAt.Before(s.Authentication.Proof.IssuedAt) {
		return false
	}
	if _, continued := record.CredentialContinuation(); continued {
		return false
	}
	return s.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(s.TenantID), Subject: string(s.UserID), Purpose: "session-issue", Audience: s.Audience, Now: s.IssuedAt}) == nil
}
