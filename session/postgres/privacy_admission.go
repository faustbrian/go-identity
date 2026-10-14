package postgres

import (
	"context"
	"fmt"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

var _ kernel.PrivacyExportAdmissionContributor = (*Repository)(nil)

// PrivacyExportAdmissionConfig opts into native read-only privacy eligibility.
// Trusted deployment/profile fields have IdentifierAdmissionConfig's semantics.
// It supports single-factor self-service sessions; organization, factor and
// passkey applicability deny until their native owner checks are composed.
// Zero is invalid. Configuration is neither authentication nor access policy.
type PrivacyExportAdmissionConfig struct {
	GlobalAuthorityID, PolicyNamespace, Audience, AuthenticationMethod string
	CredentialKind                                                     identity.CredentialKind
	CredentialOwner                                                    string
}

// Format hides deployment and authentication correlations.
func (PrivacyExportAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PrivacyExportAdmissionConfig(redacted)"))
}

// MarshalJSON rejects accidental correlated configuration export.
func (PrivacyExportAdmissionConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRecord }

// NewRepositoryWithPrivacyExportAdmission freezes explicit privacy eligibility
// without IO. Pool lifetime, schema and read budgets retain Config's semantics.
// Existing constructors remain opted out of privacy. Register this same store
// instance as the coordinator's native read-only participant. No coordinator,
// Work, callback or consumer-written domain store is accepted.
func NewRepositoryWithPrivacyExportAdmission(pool *database.Pool, c Config, profile PrivacyExportAdmissionConfig) (*Repository, error) {
	if !IdentifierAdmissionConfig(profile).valid() {
		return nil, identity.InvalidInputError{Field: "session_privacy_configuration"}
	}
	r, err := NewRepository(pool, c)
	if err != nil {
		return nil, err
	}
	profile.GlobalAuthorityID = strings.Clone(profile.GlobalAuthorityID)
	profile.PolicyNamespace = strings.Clone(profile.PolicyNamespace)
	profile.Audience = strings.Clone(profile.Audience)
	profile.AuthenticationMethod = strings.Clone(profile.AuthenticationMethod)
	profile.CredentialOwner = strings.Clone(profile.CredentialOwner)
	r.privacyAdmission = &profile
	return r, nil
}

// CheckPrivacyExport uses only the selected live original Work: exact session
// projection, owner-derived scope keys, global/tenant, user/credential and
// authorization authority followed by session/family share locks and primary
// expiry. Initial and final checks retain the same original versions and proof
// metadata; privacy epoch allocation never renews session validity. Reads are
// serial and bounded by the earlier caller/Work deadline and Config budget.
// All locks remain until the original transaction closes. No pool IO, write,
// independent transaction, retained handle or network callback is used.
// Errors deny and the coordinator poisons/aborts Work. Success is not policy
// Allow, fresh reauthentication, proof consumption or runnable export admission.
func (r *Repository) CheckPrivacyExport(ctx context.Context, h kernel.PrivacyExportAdmissionWork) error {
	command, _, err := h.Command(r)
	if err != nil {
		return err
	}
	if ctx == nil || r == nil || r.privacyAdmission == nil || r.maximumDuration <= 0 {
		return identity.InvalidInputError{Field: "session_privacy_configuration"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	config := Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}
	record, err := readPrivacySession(bounded, h, config, command)
	if err != nil {
		return err
	}
	directory, credential, policy, err := privacySessionBindings(*r.privacyAdmission, record, command)
	if err != nil {
		return err
	}
	if err := h.RequireActiveDirectoryAuthority(bounded, r, directory); err != nil {
		return err
	}
	if _, err := h.RequireActiveCredential(bounded, r, credential); err != nil {
		return err
	}
	if err := h.RequireActiveUserAuthorization(bounded, r, policy); err != nil {
		return err
	}
	return RequireSession(bounded, h, config, record)
}

func readPrivacySession[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, command identity.PrivacyExportRequestCommand) (session.Session, error) {
	return readBoundSession(ctx, q, c, command.Binding, command.SessionID, command.SessionVersion)
}

func privacySessionBindings(c PrivacyExportAdmissionConfig, record session.Session, command identity.PrivacyExportRequestCommand) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(c), record, command.Binding, command.SessionID, command.SessionVersion)
	if err != nil || command.ExpectedAuthorityVersion == 0 || credential.UserAuthorityVersion != command.ExpectedAuthorityVersion {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	return directory, credential, policy, nil
}
