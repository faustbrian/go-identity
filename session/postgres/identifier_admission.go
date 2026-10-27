package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

var _ kernel.IdentifierAdmissionContributor = (*Repository)(nil)

// IdentifierAdmissionConfig opts the native session repository into protected
// identifier eligibility checks. All values come from trusted composition, not
// requests. The configured method/kind/owner pairing must describe the exact
// supported authentication profile; it never converts method metadata into a
// verified proof. Organization, factor and passkey profiles currently deny,
// rather than omit their required owner checks. Zero is invalid. This is not
// an access policy, credential verifier or session issuance configuration.
type IdentifierAdmissionConfig struct {
	GlobalAuthorityID, PolicyNamespace, Audience, AuthenticationMethod string
	CredentialKind                                                     identity.CredentialKind
	CredentialOwner                                                    string
}

// Format hides correlated deployment/profile configuration.
func (IdentifierAdmissionConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.IdentifierAdmissionConfig(redacted)"))
}

// MarshalJSON rejects accidental correlated configuration export.
func (IdentifierAdmissionConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalidRecord }

func (c IdentifierAdmissionConfig) valid() bool {
	ref := identity.CredentialRef{ID: "credential", TenantID: "tenant", UserID: "user", Kind: c.CredentialKind, Owner: c.CredentialOwner, Version: 1}
	return (kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: "tenant"}).Validate() == nil &&
		(authority.AuthorityScope{TenantID: "tenant", PolicyNamespace: c.PolicyNamespace, SubjectID: "user"}).Validate() == nil &&
		scopeID(c.AuthenticationMethod) && len(c.Audience) <= 256 && visibleAdmissionText(c.Audience) && ref.Validate("tenant", "user") == nil
}
func visibleAdmissionText(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}

// NewRepositoryWithIdentifierAdmission validates and freezes an explicit native
// eligibility profile without IO. Existing NewRepository remains opted out.
// Pool ownership, schema and maximum duration retain Config's semantics. No
// coordinator, Work, registry, callback or caller-written store is accepted.
// The caller must apply the real kernel/session/authorization migrations and
// register this same Repository as the plan's read-only admission participant.
func NewRepositoryWithIdentifierAdmission(pool *database.Pool, c Config, profile IdentifierAdmissionConfig) (*Repository, error) {
	if !profile.valid() {
		return nil, identity.InvalidInputError{Field: "session_identifier_configuration"}
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
	r.identifierAdmission = &profile
	return r, nil
}

// CheckIdentifier performs the registered read-only eligibility invocation on
// the original coordinator transaction. It reads the command's original active
// session, derives every applicable owner key, checks global/tenant, exact
// credential and user epochs, existing authorization authority, then locks and
// checks the session/family and authoritative expiry. Initial/final comparison
// uses the original snapshot; only the Work-owned identifier successor changes
// the final expected epoch. No snapshot, metadata or freshness is rewritten.
//
// Reads are serial under the earlier caller/Work deadline and Config's finite
// budget. Primary owner locks remain until the coordinator closes Work. No
// pool access, independent transaction, write, retained handle or callback is
// used here. Errors deny the invocation and are redacted; the coordinator must
// poison/abort it. Success is not authentication, fresh reauthentication, policy
// Allow, proof consumption, issuance or complete protected workflow authority.
func (r *Repository) CheckIdentifier(ctx context.Context, h kernel.IdentifierAdmissionWork) error {
	command, final, err := h.Command(r)
	if err != nil {
		return err
	}
	if ctx == nil || r == nil || r.identifierAdmission == nil || r.maximumDuration <= 0 {
		return identity.InvalidInputError{Field: "session_identifier_configuration"}
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	epoch, err := h.IdentifierAuthorityVersion(r)
	if err != nil {
		return err
	}
	record, err := readIdentifierSession(bounded, h, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, command)
	if err != nil {
		return err
	}
	directory, credential, policy, err := identifierSessionBindings(*r.identifierAdmission, record, command, epoch, final)
	if err != nil {
		return err
	}
	// Read the session projection without locks first, then acquire owner locks
	// in directory/user/credential/authorization/session order. RequireSession
	// compares the complete original projection after locking, denying races.
	if err = h.RequireActiveDirectoryAuthority(bounded, r, directory); err != nil {
		return err
	}
	if _, err = h.RequireActiveCredential(bounded, r, credential); err != nil {
		return err
	}
	if err = h.RequireActiveUserAuthorization(bounded, r, policy); err != nil {
		return err
	}
	return RequireSession(bounded, h, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, record)
}

func readIdentifierSession[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, command identity.IdentifierCommand) (session.Session, error) {
	return readBoundSession(ctx, q, c, command.Binding, command.SessionID, command.SessionVersion)
}

func readBoundSession[R SessionRows](ctx context.Context, q SessionQueryer[R], c Config, binding identity.CommandBinding, sessionID string, version uint64) (session.Session, error) {
	if ctx == nil || nilSessionHandle(q) || !validSchema(c.Schema) || !scopeID(string(binding.TenantID)) || !scopeID(string(binding.UserID)) || !scopeID(sessionID) || version == 0 {
		return session.Session{}, identity.InvalidInputError{Field: "session_identifier"}
	}
	// Config comes from the already bounded native invocation. No pool fallback.
	rows, err := q.Query(ctx, `SELECT record::text FROM `+pgx.Identifier{c.Schema}.Sanitize()+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='active'`, string(binding.TenantID), string(binding.UserID), sessionID, strconv.FormatUint(version, 10))
	if err != nil {
		return session.Session{}, readError(ctx, err)
	}
	if nilSessionHandle(rows) {
		return session.Session{}, identity.UnavailableError{}
	}
	var payload []byte
	err = readSessionAdmission(rows, &payload)
	rows.Close()
	if err != nil {
		return session.Session{}, admissionError(ctx, err)
	}
	record, err := decodeRecord(payload)
	if err != nil {
		return session.Session{}, identity.UnavailableError{}
	}
	s, err := record.Bindings()
	if err != nil || s.TenantID != binding.TenantID || s.UserID != binding.UserID || s.SessionID != sessionID || s.Version != version {
		return session.Session{}, identity.ForbiddenError{}
	}
	return record, nil
}

func identifierSessionBindings(c IdentifierAdmissionConfig, record session.Session, command identity.IdentifierCommand, epoch uint64, final bool) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	directory, credential, policy, err := sessionAdmissionBindings(c, record, command.Binding, command.SessionID, command.SessionVersion)
	if err != nil || credential.IdentifierAuthorityVersion != command.Change.ExpectedAuthorityVersion {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	expected := command.Change.ExpectedAuthorityVersion
	if final {
		if expected == ^uint64(0) {
			return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
		}
		expected++
	}
	if epoch == 0 || epoch != expected {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	credential.IdentifierAuthorityVersion = epoch
	return directory, credential, policy, nil
}

// Both workflows derive owner keys from the same original session projection.
// Workflow-specific version transitions are validated by their owning wrappers.
func sessionAdmissionBindings(c IdentifierAdmissionConfig, record session.Session, binding identity.CommandBinding, sessionID string, version uint64) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	return passwordSessionAdmissionBindings(c, record, binding, sessionID, version, session.OptionalAuthorityBinding{})
}

func passwordSessionAdmissionBindings(c IdentifierAdmissionConfig, record session.Session, binding identity.CommandBinding, sessionID string, version uint64, factor session.OptionalAuthorityBinding) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	if c.CredentialKind == identity.CredentialPasskey {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	return credentialSessionAdmissionBindings(c, record, binding, sessionID, version, factor, session.OptionalAuthorityBinding{}, authentication.AssuranceSingleFactor)
}

// Shared kernel/session key derivation does not select an authentication
// method. The closed password and passkey wrappers supply exact dimensions and
// assurance; their respective native owners must fence those dimensions.
func credentialSessionAdmissionBindings(c IdentifierAdmissionConfig, record session.Session, binding identity.CommandBinding, sessionID string, version uint64, factor, passkey session.OptionalAuthorityBinding, assurance authentication.Assurance) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	return credentialSessionAdmissionBindingsWithOrganization(c, record, binding, sessionID, version, factor, passkey, session.OptionalAuthorityBinding{}, assurance)
}

func credentialSessionAdmissionBindingsWithOrganization(c IdentifierAdmissionConfig, record session.Session, binding identity.CommandBinding, sessionID string, version uint64, factor, passkey, organization session.OptionalAuthorityBinding, assurance authentication.Assurance) (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
	deny := func() (kernel.DirectoryAuthorityAdmission, kernel.CredentialAdmission, kernel.UserAuthorizationAdmission, error) {
		return kernel.DirectoryAuthorityAdmission{}, kernel.CredentialAdmission{}, kernel.UserAuthorizationAdmission{}, identity.ForbiddenError{}
	}
	s, err := record.Bindings()
	if err != nil || !c.valid() {
		return deny()
	}
	a, err := s.Authority.Bindings()
	if err != nil {
		return deny()
	}
	if s.TenantID != binding.TenantID || s.UserID != binding.UserID || string(binding.ActorID) != string(s.UserID) || binding.ActorKind != authorization.SubjectUser || s.SessionID != sessionID || s.Version != version || s.Audience != c.Audience || s.Authentication.Kind != session.AuthenticationVerified || s.Authentication.Proof.Method != c.AuthenticationMethod || s.Authentication.Proof.Assurance != assurance || a.Organization != organization || a.Factor != factor || a.Passkey != passkey {
		return deny()
	}
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: s.TenantID}
	keys, err := kernel.KernelAuthorityKeys(query, s.UserID)
	if err != nil {
		return deny()
	}
	sessionKeys, err := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		return deny()
	}
	scope := authority.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: c.PolicyNamespace, SubjectID: authorization.SubjectID(s.UserID)}
	policyKey, err := scope.Key()
	if err != nil {
		return deny()
	}
	if a.Global.ScopeKey != keys.Global || a.Tenant.ScopeKey != keys.Tenant || a.User.ScopeKey != keys.User || a.Identifier.ScopeKey != keys.Identifier || a.Credential.ScopeKey != keys.Credential || a.SessionFamily.ScopeKey != sessionKeys.Family || a.Session.ScopeKey != sessionKeys.Session || a.Authorization.ScopeKey != policyKey {
		return deny()
	}
	ref := identity.CredentialRef{ID: identity.CredentialID(s.Authentication.CredentialID), TenantID: s.TenantID, UserID: s.UserID, Kind: c.CredentialKind, Owner: c.CredentialOwner, Version: record.EffectiveCredentialVersion()}
	if ref.Validate(s.TenantID, s.UserID) != nil {
		return deny()
	}
	return kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}, kernel.CredentialAdmission{Credential: ref, UserAuthorityVersion: a.User.Version, IdentifierAuthorityVersion: a.Identifier.Version, CredentialAuthorityVersion: a.Credential.Version}, kernel.UserAuthorizationAdmission{Scope: scope, Version: a.Authorization.Version}, nil
}
