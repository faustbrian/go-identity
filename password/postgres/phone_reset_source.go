package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// Source selection is private request preparation, not an authentication proof
// or permission to send. The sole request Work must fence every observation
// before generation and again when committing the SMS/capability/risk effects.
type phonePasswordRecoverySource struct {
	pool                      *database.Pool
	directory                 *kernel.Repository
	passwords                 *Repository
	authorization             *authoritypg.AuthorityStore
	factors                   *mfapg.TOTPFactorReader
	numbers                   phone.NumberPolicy
	session                   sessionpg.Config
	flowKeys                  []session.DigestKey
	identifierKey             []byte
	global, namespace, policy string
	policyVersion             uint64
	origins, callbacks        []string
	maximum                   time.Duration
}

type phonePasswordRecoverySelection struct {
	flow       session.PreAuthTransaction
	recipient  kernel.RecipientRecord
	credential kernel.CredentialAdmission
	directory  kernel.DirectoryAuthorityAdmission
	policy     kernel.UserAuthorizationAdmission
	factor     mfapg.TOTPFactorSnapshot
	observedAt time.Time
	// The SMS owner's narrower known-user query is read once during original
	// keyed preparation. Its timestamp participates in the actual SMS AAD.
	smsObservedAt time.Time
}

// Only the existing native primary profile is borrowed. No signin, password
// comparison, session issuance, remote provider or key generation is invoked.
func newPhonePasswordRecoverySource(pool *database.Pool, c SigninConfig, numbers *phone.NumberPolicy) (*phonePasswordRecoverySource, error) {
	if pool == nil || pool.Raw() == nil || numbers == nil || numbers.Profile() != phone.CurrentNumberProfile() || c.Repository.MaximumDuration <= 0 || c.Repository.MaximumDuration > 5*time.Second || c.Profile.Validate() != nil || c.Profile.CredentialKind != identity.CredentialPassword || c.Profile.CredentialOwner != "identity/password" || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.AdmissionPolicy.PolicyVersion == 0 || len(c.FlowKeys) < 1 || len(c.FlowKeys) > 16 || len(c.IdentifierKey) < 32 || len(c.IdentifierKey) > 64 || !signinURLs(c.Origins, true) || !signinURLs(c.CallbackURLs, false) || !reauthenticationText(c.PolicyID, 128) {
		return nil, password.ErrPasswordWork
	}
	probe, _ := session.ParseToken("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	versions := make(map[uint32]bool, len(c.FlowKeys))
	for _, key := range c.FlowKeys {
		digest, err := probe.Digest(key, "phone-reset-configuration")
		if err != nil || versions[digest.KeyVersion] {
			return nil, password.ErrPasswordWork
		}
		versions[digest.KeyVersion] = true
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: c.Repository.MaximumDuration})
	if err != nil {
		return nil, err
	}
	material, err := NewRepository(pool, c.Repository)
	if err != nil {
		return nil, err
	}
	policy, err := authoritypg.NewAuthorityStore(pool.Raw(), c.Repository.MaximumDuration)
	if err != nil {
		return nil, err
	}
	factors, err := mfapg.NewTOTPFactorReader(pool, c.Repository.MaximumDuration)
	if err != nil {
		return nil, err
	}
	return &phonePasswordRecoverySource{pool: pool, directory: directory, passwords: material, authorization: policy, factors: factors, numbers: *numbers, session: c.Session, flowKeys: slices.Clone(c.FlowKeys), identifierKey: slices.Clone(c.IdentifierKey), global: c.Profile.GlobalAuthorityID, namespace: c.Profile.PolicyNamespace, policy: c.PolicyID, policyVersion: c.Coordinator.AdmissionPolicy.PolicyVersion, origins: slices.Clone(c.Origins), callbacks: slices.Clone(c.CallbackURLs), maximum: c.Repository.MaximumDuration}, nil
}

type phoneResetPrimaryRows struct{ pool *database.Pool }

func (q phoneResetPrimaryRows) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return q.pool.Raw().Query(ctx, sql, args...)
}

func (s *phonePasswordRecoverySource) prepare(ctx context.Context, r phone.PasswordResetRequestRequestSpec) (out phonePasswordRecoverySelection, err error) {
	if r.Validate() != nil {
		return out, password.ErrPasswordWork
	}
	return s.prepareOriginal(ctx, phoneResetRiskInput(r))
}

func phoneResetRiskInput(r phone.PasswordResetRequestRequestSpec) phone.PasswordResetInitiationRiskRequestSpec {
	return phone.PasswordResetInitiationRiskRequestSpec{TenantID: r.TenantID, CommandID: r.CommandID, IssuanceCommandID: r.RiskIssuanceCommandID, Number: r.Number, Flow: r.Flow, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
}

func (s *phonePasswordRecoverySource) prepareOriginal(ctx context.Context, r phone.PasswordResetInitiationRiskRequestSpec) (out phonePasswordRecoverySelection, err error) {
	if ctx == nil || s == nil || r.Validate() != nil {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.maximum)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = phonePasswordRecoverySelection{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			out, err = phonePasswordRecoverySelection{}, ctx.Err()
		}
	}()
	if !slices.Contains(s.origins, r.Origin) || r.Caller.PolicyRevision != authorization.Revision(s.policyVersion) {
		return out, identity.ForbiddenError{}
	}
	number, err := r.Number.Record()
	if err != nil {
		return out, password.ErrPasswordWork
	}
	if _, err = s.numbers.Restore(ctx, number); err != nil {
		return out, err
	}
	kind, flowID, cookie, err := r.Flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationPreAuthTransaction {
		return out, identity.ForbiddenError{}
	}
	if err = s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&out.observedAt); err != nil {
		return phonePasswordRecoverySelection{}, readerFailure(ctx)
	}
	out.observedAt = out.observedAt.UTC().Truncate(time.Microsecond)
	out.flow, err = sessionpg.ReadPreAuth(ctx, phoneResetPrimaryRows{s.pool}, s.session, r.TenantID, identity.PreAuthTransactionID(flowID))
	if err != nil {
		return phonePasswordRecoverySelection{}, err
	}
	f, err := out.flow.Bindings()
	if err != nil || f.Binding.Intent.Purpose != session.PreAuthPhonePasswordRecovery || f.Binding.Intent.Action != "identity.phone.password-reset-request" || f.Binding.Intent.Origin != r.Origin || f.Binding.Intent.PolicyID != s.policy || f.Binding.Intent.PolicyVersion != s.policyVersion || !slices.Contains(s.callbacks, f.Binding.Intent.CallbackURL) || f.Binding.Intent.Remember != (session.RememberPolicy{}) {
		return phonePasswordRecoverySelection{}, identity.ForbiddenError{}
	}
	target, err := phone.PasswordResetIdentifierBinding(r.Number, r.TenantID, s.identifierKey)
	if err != nil || !hmac.Equal(target[:], f.Binding.Intent.IdentifierBinding[:]) {
		return phonePasswordRecoverySelection{}, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return phonePasswordRecoverySelection{}, identity.ForbiddenError{}
	}
	matched := false
	for _, key := range s.flowKeys {
		actual, e := token.PreAuthDigest(key, f.Binding)
		if e == nil && actual.KeyVersion == f.Cookie.KeyVersion && hmac.Equal(actual.Sum[:], f.Cookie.Sum[:]) {
			matched = true
		}
	}
	if !matched || out.flow.Check(out.observedAt, f.Binding, f.Cookie) != nil {
		return phonePasswordRecoverySelection{}, identity.ForbiddenError{}
	}
	out.recipient, err = s.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierPhone, CanonicalValue: number.E164, NormalizationProfile: number.Profile.ID, NormalizationVersion: number.Profile.Version, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return phonePasswordRecoverySelection{}, err
	}
	if out.recipient.Suppressed {
		return phonePasswordRecoverySelection{}, identity.ForbiddenError{}
	}
	material, err := s.passwords.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: r.TenantID, SubjectID: out.recipient.User.ID})
	if err != nil {
		return phonePasswordRecoverySelection{}, readerFailure(ctx)
	}
	a := material.Authority()
	if a.User.ID != out.recipient.User.ID || a.User.Status != identity.StatusActive || !a.Enabled || !a.ExpiresAt.IsZero() && !out.observedAt.Before(a.ExpiresAt) || a.AuthorityVersion != out.recipient.CredentialAuthorityVersion {
		return phonePasswordRecoverySelection{}, identity.ForbiddenError{}
	}
	out.credential = kernel.CredentialAdmission{Credential: a.Credential, UserAuthorityVersion: out.recipient.UserAuthorityVersion, IdentifierAuthorityVersion: out.recipient.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.AuthorityVersion}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.global, TenantID: r.TenantID})
	if err != nil {
		return phonePasswordRecoverySelection{}, err
	}
	if !directory.Enabled {
		return phonePasswordRecoverySelection{}, identity.ForbiddenError{}
	}
	out.directory = kernel.DirectoryAuthorityAdmission{Query: directory.Query, GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion}
	policy, err := s.authorization.Get(ctx, authoritypg.AuthorityScope{TenantID: authorization.TenantID(r.TenantID), SubjectID: authorization.SubjectID(out.recipient.User.ID), PolicyNamespace: s.namespace})
	if err != nil {
		return phonePasswordRecoverySelection{}, readerFailure(ctx)
	}
	out.policy = kernel.UserAuthorizationAdmission{Scope: policy.Scope, Version: policy.Version}
	out.factor, err = s.factors.SelectForPhoneRecovery(ctx, r.TenantID, out.recipient.User.ID)
	if err != nil {
		return phonePasswordRecoverySelection{}, err
	}
	return out, nil
}
