package postgres

import (
	"bytes"
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// SSOOIDCJITDomainConfig selects the identifier owner's comparison policy and
// retained retirement keys. These are the same keys used for identifier removal,
// not provider secrets. Construction copies the key map.
type SSOOIDCJITDomainConfig struct {
	ComparisonProfile           string
	CurrentIdentifierKeyVersion uint32
	RetainedIdentifierKeys      map[uint32][32]byte
}

func (SSOOIDCJITDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOIDCJITDomainConfig(redacted)"))
}

func (SSOOIDCJITDomainConfig) MarshalJSON() ([]byte, error) { return nil, invalidSSOOIDCJIT() }

// SSOOIDCJITDomain owns the new directory rows of an enterprise OIDC callback.
// It borrows the enlisted repository and original Work and does not own a
// transaction, policy decision, external request, or session issuer.
type SSOOIDCJITDomain struct {
	repository *Repository
	comparison string
	reuse      identifierMutationPolicy
}

func (SSOOIDCJITDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOIDCJITDomain(redacted)"))
}

func (SSOOIDCJITDomain) MarshalJSON() ([]byte, error) { return nil, invalidSSOOIDCJIT() }

type ssoOIDCJITCreation struct {
	user       identity.User
	validUntil time.Time
}

// NewSSOOIDCJITDomain validates the repository and copies retained identifier
// policy without I/O. Install account, credential, identifier normalization and
// retirement history and SSOOIDCSubjectAvailabilityMigrationSource before use.
func NewSSOOIDCJITDomain(r *Repository, c SSOOIDCJITDomainConfig) (*SSOOIDCJITDomain, error) {
	shared, err := NewPasswordRegistrationDomain(r, PasswordRegistrationDomainConfig(c))
	if err != nil {
		return nil, invalidSSOOIDCJIT()
	}
	return &SSOOIDCJITDomain{repository: r, comparison: shared.comparison, reuse: shared.reuse}, nil
}

// Apply creates the exact prospective user, verified email and provider
// account inside the native callback that already consumed its original state.
// The SSO owner must first prove current opt-in policy, verified claims and
// domain routing. Identity rechecks durable subject and mailbox occupancy
// under the coordinator's tenant lock. This never links an existing user or
// reactivates a retired account. Any denial poisons Work; success is provisional.
func (d *SSOOIDCJITDomain) Apply(ctx context.Context, w Work, owner FeatureExecutionContributor, command identity.Command, intent SSOOIDCJITIntent) (identity.User, error) {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(ctx, err) }
	if d == nil || d.repository == nil || w.state.ssoOIDCJITCreation != nil || intent.ComparisonProfile != d.comparison {
		return fail(invalidSSOOIDCJIT())
	}
	consumed, err := w.SSOOIDCSigninConsumption(owner)
	if err != nil {
		return fail(err)
	}
	_, feature, lifecycle, err := w.FeatureScope(owner)
	profile, _ := providerSigninProfile(ssoOIDCSigninOperation())
	if err != nil || feature.Contributor != profile.Contrib || lifecycle != profile.Lifecycle {
		return fail(invalidSSOOIDCJIT())
	}
	if err := validateSSOOIDCJITCommand(command, intent); err != nil {
		return fail(err)
	}
	if !d.enlisted(w.state.execution.reservation.plan) || intent.ValidUntil.After(consumed.Plan.ExpiresAt) {
		return fail(invalidSSOOIDCJIT())
	}

	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.User{}, err
	}
	if !now.Before(intent.ValidUntil) || intent.ValidUntil.Sub(now) > 20*time.Second {
		return fail(identity.ForbiddenError{})
	}
	if err := requireUnoccupiedSSOOIDCSubject(ctx, w, intent.Account.Account); err != nil {
		return identity.User{}, err
	}
	mail := intent.Email
	change := identity.IdentifierChange{Action: identity.IdentifierAttach, TenantID: consumed.Command.TenantID, UserID: mail.UserID,
		ID: mail.ID, Kind: mail.Kind, CanonicalValue: mail.CanonicalValue}
	occupied, err := classifyIdentifierReuse(ctx, w, change, d.reuse, now, false)
	if err != nil {
		return identity.User{}, err
	}
	if occupied {
		return fail(identity.ConflictError{})
	}

	user, err := insertInitialUser(ctx, w, change.TenantID, change.UserID)
	if err != nil {
		return identity.User{}, err
	}
	if err := insertSSOOIDCJITIdentity(ctx, w, intent, now); err != nil {
		return identity.User{}, err
	}
	w.state.ssoOIDCJITCreation = &ssoOIDCJITCreation{user: user, validUntil: intent.ValidUntil}
	return w.SSOOIDCJITUser(ctx, owner, command)
}

func (d *SSOOIDCJITDomain) enlisted(plan *admittedKernelPlan) bool {
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == d.repository {
			return true
		}
	}
	return false
}

func validateSSOOIDCJITCommand(command identity.Command, intent SSOOIDCJITIntent) error {
	account, err := SSOOIDCSigninAccount(command)
	if err != nil || account != intent.Account {
		return invalidSSOOIDCJIT()
	}
	wanted, err := SSOOIDCJITIntentField(intent)
	if err != nil {
		return err
	}
	spec, _ := command.Feature()
	for _, actual := range spec.Fields {
		if actual.Name == wanted.Name && actual.Value.Kind == wanted.Value.Kind && bytes.Equal(actual.Value.Bytes, wanted.Value.Bytes) {
			return nil
		}
	}
	return invalidSSOOIDCJIT()
}

func requireUnoccupiedSSOOIDCSubject(ctx context.Context, w Work, a identity.Account) error {
	rows, err := w.Query(ctx, ssoOIDCSubjectAvailableSQL, string(a.TenantID), a.Provider, a.Issuer, a.Subject)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return w.fail(ctx, identity.UnavailableError{})
	}
	var available bool
	if err := rows.Scan(&available); err != nil {
		return err
	}
	if rows.Next() {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !available {
		return w.fail(ctx, identity.ConflictError{})
	}
	return nil
}

func insertSSOOIDCJITIdentity(ctx context.Context, w Work, intent SSOOIDCJITIntent, now time.Time) error {
	insert := func(sql string, args ...any) error {
		n, err := w.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		if n != 1 {
			return w.fail(ctx, identity.ConflictError{})
		}
		return nil
	}
	a, mail, credential := intent.Account.Account, intent.Email, intent.Account.Credential.Credential
	tenant, user := string(a.TenantID), string(a.UserID)
	if err := insert(`INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version,verified_at,normalization_profile,normalization_version)
 VALUES($1,$2,$3,'email',$4,$5,true,false,1,2,1,$6,$7,$8::numeric) ON CONFLICT DO NOTHING`, tenant, user, string(mail.ID), mail.CanonicalValue,
		mail.DisplayValue, now, mail.NormalizationProfile, mail.NormalizationVersion); err != nil {
		return err
	}
	if err := insert(`INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
 VALUES($1,$2,$3,$4,$5,$6,sha256(convert_to(octet_length($4::text)::text||':'||$4::text||octet_length($5::text)::text||':'||$5::text||octet_length($6::text)::text||':'||$6::text,'UTF8')),1,1,true)
 ON CONFLICT DO NOTHING`, tenant, user, string(a.ID), a.Provider, a.Issuer, a.Subject); err != nil {
		return err
	}
	if err := insert(`INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled)
 VALUES($1,$2,$3,$4,'sso',1,true) ON CONFLICT DO NOTHING`, tenant, user, string(credential.ID), int16(identity.CredentialProvider)); err != nil {
		return err
	}
	return insert(`INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id)
 VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, tenant, user, string(credential.ID), string(a.ID))
}

// SSOOIDCJITUser returns only the user this callback just created, for its
// borrowed membership and factor owners. It is not a lookup, authentication
// grant or lease. It denies on a reconstructed command, another invocation or
// originally expired evidence, even if the caller ignores the error.
func (w Work) SSOOIDCJITUser(ctx context.Context, owner FeatureExecutionContributor, command identity.Command) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(w.state.ctx, err) }
	if ctx == nil {
		return fail(invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	binding, feature, _, err := w.FeatureScope(owner)
	creation := w.state.ssoOIDCJITCreation
	if err != nil || feature.Operation != ssoOIDCSigninOperation() || creation == nil || creation.user.TenantID != binding.TenantID {
		return fail(invalidWork())
	}
	if w.state.featureApplying {
		if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
			return identity.User{}, err
		}
	} else if w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return fail(invalidWork())
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.User{}, err
	}
	if !now.Before(creation.validUntil) {
		return fail(identity.ForbiddenError{})
	}
	return creation.user, nil
}
