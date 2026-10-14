package postgres

import (
	"context"
	"fmt"
	authentication "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"strings"
	"time"
)

// IssueAdmissionConfig freezes the single-factor self-service issuance profile.
// Fields have IdentifierAdmissionConfig's trusted owner/scope semantics. This
// profile cannot omit organization, factor or passkey checks: those variants
// deny until their native owners are composed. No callback, verifier or pool
// transaction is supplied. Zero is invalid; configuration grants no policy Allow.
type IssueAdmissionConfig IdentifierAdmissionConfig

// Format redacts correlated deployment configuration.
func (IssueAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.IssueAdmissionConfig(redacted)"))
}

// MarshalJSON rejects implicit correlated configuration export.
func (IssueAdmissionConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRecord }

// NewRepositoryWithIssueAdmission freezes the trusted issuance owner profile
// without IO. Config/pool ownership retain NewRepository's semantics. The same
// instance must be registered as the protected native feature contributor;
// requests cannot select another current-authority source or policy namespace.
func NewRepositoryWithIssueAdmission(pool *database.Pool, config Config, profile IssueAdmissionConfig) (*Repository, error) {
	if !IdentifierAdmissionConfig(profile).valid() {
		return nil, identity.InvalidInputError{Field: "session_issue_configuration"}
	}
	r, err := NewRepository(pool, config)
	if err != nil {
		return nil, err
	}
	profile.GlobalAuthorityID = strings.Clone(profile.GlobalAuthorityID)
	profile.PolicyNamespace = strings.Clone(profile.PolicyNamespace)
	profile.Audience = strings.Clone(profile.Audience)
	profile.AuthenticationMethod = strings.Clone(profile.AuthenticationMethod)
	profile.CredentialOwner = strings.Clone(profile.CredentialOwner)
	r.issueAdmission = &profile
	return r, nil
}

var _ kernel.AuthenticatedFeatureContributor = (*Repository)(nil)

// ValidateAuthenticatedFeature compares every original credential/proof field
// with the exhaustively mapped native record. It is pure and grants no current
// eligibility or one-time use. The coordinator validates opaque provenance.
func (r *Repository) ValidateAuthenticatedFeature(command identity.Command, original authentication.AuthenticatedProofSpec) error {
	native, err := nativeIssue(command)
	if err != nil || r == nil || r.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	issue, _ := native.Issue()
	spec, _ := issue.Session.Bindings()
	a, p := spec.Authentication, original.Proof
	expected := a.Proof
	expected.IssuedAt, expected.ExpiresAt = expected.IssuedAt.UTC(), expected.ExpiresAt.UTC()
	p.IssuedAt, p.ExpiresAt = p.IssuedAt.UTC(), p.ExpiresAt.UTC()
	if a.Kind != session.AuthenticationVerified || a.ProofVersion != original.ProofVersion || a.CredentialID != original.CredentialID || a.CredentialVersion != original.CredentialVersion || expected != p {
		return session.ErrInvalidSessionCommand
	}
	_, _, _, err = sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), issue.Session, issue.Binding, spec.SessionID, 1)
	return err
}

// CheckAuthenticatedFeature compares the original current owner vector under
// primary share locks before mutation and again before terminalization. It
// uses no independent transaction, network IO, snapshot refresh or proof mint.
// New sessions require a new family at version1 or an exact active existing
// family; final checks additionally compare the complete persisted session.
// Every applicable original dimension must agree; optional uncomposed profiles
// deny. The coordinator owns proof expiry/consumption and poisons failed Work.
func (r *Repository) CheckAuthenticatedFeature(ctx context.Context, w kernel.Work, command identity.Command, proof authentication.AuthenticatedProofSpec, final bool) error {
	if ctx == nil || r == nil || r.issueAdmission == nil || r.maximumDuration <= 0 {
		return session.ErrInvalidSessionCommand
	}
	if err := r.ValidateAuthenticatedFeature(command, proof); err != nil {
		return err
	}
	native, _ := nativeIssue(command)
	issue, _ := native.Issue()
	spec, _ := issue.Session.Bindings()
	binding, feature, transition, err := w.FeatureScope(r)
	if err != nil || binding != issue.Binding || feature.Operation != session.IssueOperation() || transition.BeforeVersion != 0 || transition.AfterVersion != 1 {
		return session.ErrInvalidSessionCommand
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), issue.Session, binding, spec.SessionID, 1)
	if err != nil {
		return err
	}
	if err = w.RequireActiveDirectoryAuthority(bounded, r, directory); err != nil {
		return err
	}
	if _, err = w.RequireActiveCredential(bounded, r, credential); err != nil {
		return err
	}
	if err = w.RequireActiveUserAuthorization(bounded, r, policy); err != nil {
		return err
	}
	if err = r.requireIssueFamily(bounded, w, spec, final); err != nil {
		return err
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if err = native.ValidateIssueAt(now); err != nil {
		return identity.ForbiddenError{}
	}
	if final {
		return RequireSession(bounded, w, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, issue.Session)
	}
	return nil
}

func (r *Repository) requireIssueFamily(ctx context.Context, w kernel.Work, s session.SessionSpec, required bool) error {
	rows, err := w.Query(ctx, `SELECT user_id,version::text,state,issued_at FROM `+r.schema+`.families WHERE tenant_id=$1 AND family_id=$2 FOR SHARE`, string(s.TenantID), s.FamilyID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err = rows.Err(); err != nil {
			return err
		}
		if !required && s.FamilyVersion == 1 {
			return nil
		}
		return identity.ForbiddenError{}
	}
	var user, version, state, issued string
	if err = rows.Scan(&user, &version, &state, &issued); err != nil {
		return err
	}
	if rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	familyIssued, err := time.Parse(storedTimeLayout, issued)
	if err != nil || familyIssued.UTC().Format(storedTimeLayout) != issued {
		return identity.UnavailableError{}
	}
	// A family retains its original creation time across independently issued
	// siblings. Requiring equality would reject every later session in it.
	if user != string(s.UserID) || state != "active" || version != fmt.Sprint(s.FamilyVersion) || familyIssued.After(s.IssuedAt) {
		return identity.ForbiddenError{}
	}
	return nil
}
