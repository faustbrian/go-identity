package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	authorizationpg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type revokeRecordAuthority struct {
	directory  kernel.DirectoryAuthorityAdmission
	credential *kernel.CredentialAdmission
	identifier *kernel.VerifiedIdentifierAdmission
	policy     kernel.UserAuthorizationAdmission
	factor     *session.MFAAuthenticationSpec
}

func copySingleFactorAdmission(c SingleFactorSessionAdmissionConfig) SingleFactorSessionAdmissionConfig {
	if p := c.Verified; p != nil {
		copied := *p
		c.Verified = &copied
	}
	if p := c.OTP; p != nil {
		copied := *p
		c.OTP = &copied
	}
	if p := c.MagicLink; p != nil {
		copied := *p
		c.MagicLink = &copied
	}
	return c
}

// Method choice comes from immutable stored provenance, not an authentication
// fallback. Structural mapping still grants no permission; final owner checks
// run in the original Work and retain every original security epoch.
func (r *Repository) revokeRecordAdmission(record session.Session, b identity.CommandBinding) (revokeRecordAuthority, error) {
	deny := func() (revokeRecordAuthority, error) { return revokeRecordAuthority{}, identity.ForbiddenError{} }
	s, err := record.Bindings()
	if r == nil || err != nil || s.TenantID != b.TenantID || s.UserID != b.UserID || string(b.ActorID) != string(s.UserID) || b.ActorKind != authorization.SubjectUser {
		return deny()
	}
	if s.Authentication.Kind == session.AuthenticationVerified {
		if record.MFAAuthentication() != (session.MFAAuthentication{}) {
			if r.revokeMFAPassword == nil {
				return deny()
			}
			directory, credential, policy, err := passwordMFASessionAdmission(*r.revokeMFAPassword, record, b, s.SessionID, s.Version)
			factor, factorErr := record.MFAAuthentication().Bindings()
			if err != nil || factorErr != nil {
				return deny()
			}
			return revokeRecordAuthority{directory: directory, credential: &credential, policy: policy, factor: &factor}, nil
		}
		var profile *IdentifierAdmissionConfig
		if r.revokeAdmission != nil {
			profile = r.revokeAdmission.Verified
		} else if r.issueAdmission != nil {
			p := IdentifierAdmissionConfig(*r.issueAdmission)
			profile = &p
		}
		if profile == nil {
			return deny()
		}
		directory, credential, policy, err := sessionAdmissionBindings(*profile, record, b, s.SessionID, s.Version)
		if err != nil {
			return deny()
		}
		return revokeRecordAuthority{directory: directory, credential: &credential, policy: policy}, nil
	}
	if r.revokeAdmission == nil {
		return deny()
	}
	var query kernel.DirectoryAuthorityQuery
	var policy kernel.UserAuthorizationAdmission
	var original verifiedIdentifierProvenance
	var factor *session.MFAAuthenticationSpec
	a, _ := s.Authority.Bindings()
	switch s.Authentication.Kind {
	case session.AuthenticationOTP:
		if r.revokeAdmission.OTP == nil {
			return deny()
		}
		q, scope, e := otpSessionAdmission(*r.revokeAdmission.OTP, record)
		if e != nil {
			return deny()
		}
		p, _ := record.OTPAuthentication().Bindings()
		query, policy, original = q, kernel.UserAuthorizationAdmission{Scope: scope, Version: a.Authorization.Version}, verifiedIdentifierProvenance{p.IdentifierID, p.IdentifierKind, p.IdentifierVersion, p.VerificationVersion}
	case session.AuthenticationMagicLink:
		var q kernel.DirectoryAuthorityQuery
		var scope authorizationpg.AuthorityScope
		var e error
		if record.MFAAuthentication() != (session.MFAAuthentication{}) {
			if r.revokeMFAMagicLink == nil {
				return deny()
			}
			q, scope, e = mfaMagicLinkSessionAdmission(*r.revokeMFAMagicLink, record)
			m, me := record.MFAAuthentication().Bindings()
			if me != nil {
				return deny()
			}
			factor = &m
		} else {
			if r.revokeAdmission.MagicLink == nil {
				return deny()
			}
			q, scope, e = magicLinkSessionAdmission(*r.revokeAdmission.MagicLink, record)
		}
		if e != nil {
			return deny()
		}
		p, _ := record.MagicLinkAuthentication().Bindings()
		query, policy, original = q, kernel.UserAuthorizationAdmission{Scope: scope, Version: a.Authorization.Version}, verifiedIdentifierProvenance{p.IdentifierID, identity.IdentifierEmail, p.IdentifierVersion, p.VerificationVersion}
	default:
		return deny()
	}
	identifier := kernel.VerifiedIdentifierAdmission{IdentifierID: original.id, Kind: original.kind, IdentifierVersion: original.version, VerificationVersion: original.verification, User: kernel.UserAuthorityAdmission{UserAuthorityVersion: a.User.Version, IdentifierAuthorityVersion: a.Identifier.Version, CredentialAuthorityVersion: a.Credential.Version}}
	return revokeRecordAuthority{directory: kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}, identifier: &identifier, policy: policy, factor: factor}, nil
}

func (r *Repository) requireRevokeRecordAuthority(ctx context.Context, w kernel.Work, record session.Session, b identity.CommandBinding) error {
	return r.requireRevokeRecordAuthorityFor(ctx, w, r, record, b)
}

func (r *Repository) requireRevokeRecordAuthorityFor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session, b identity.CommandBinding) error {
	a, err := r.revokeRecordAdmission(record, b)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, a.directory); err != nil {
		return err
	}
	if a.credential != nil {
		if _, err := w.RequireActiveCredential(ctx, owner, *a.credential); err != nil {
			return err
		}
	} else if a.identifier != nil {
		if err := w.RequireVerifiedIdentifier(ctx, owner, *a.identifier); err != nil {
			return err
		}
	} else {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveUserAuthorization(ctx, owner, a.policy); err != nil {
		return err
	}
	if a.factor != nil {
		return mfapg.RequireTOTPSessionFactor(ctx, w, owner, b.UserID, a.factor.FactorID, mfapg.TOTPSessionFactorState{EnrollmentVersion: a.factor.EnrollmentVersion, AuthorityVersion: a.factor.FactorAuthorityVersion})
	}
	return nil
}
