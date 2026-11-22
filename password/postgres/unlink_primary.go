package passwordpostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

const accountUnlinkPrimaryAction = "identity.account.unlink"

// AccountUnlinkPrimaryConfig selects the original password-proof audience and
// source session transport. MaximumAge is positive and at most fifteen minutes.
// Cookie use requires retained CSRF keys; bearer use rejects those keys.
type AccountUnlinkPrimaryConfig struct {
	Audience   string
	MaximumAge time.Duration
	Transport  session.CredentialKind
	CSRFKeys   []session.CSRFKey
}

// AccountUnlinkPrimarySource borrows the actual configured password, session
// and signed-record owners for typed self-unlink. It owns no persistence,
// goroutines or transaction. The borrowed pool must outlive concurrent calls.
type AccountUnlinkPrimarySource struct{ primary *EmailPrimarySource }

// AccountUnlinkPrimaryAdmission is opaque original password/session custody,
// not permission or a renewed freshness lease. Zero denies.
type AccountUnlinkPrimaryAdmission struct {
	primary  EmailPrimaryAdmission
	original identity.Command
}

// NewAccountUnlinkPrimarySource validates the exact configured single-factor
// password issuance target before use. No I/O, proof issuance or feature-command
// profile is enabled at construction.
func NewAccountUnlinkPrimarySource(service *ReauthenticationService, config AccountUnlinkPrimaryConfig) (*AccountUnlinkPrimarySource, error) {
	primary, err := newSelectedPrimarySource(service, nil, EmailPrimaryConfig{
		Action: accountUnlinkPrimaryAction, Audience: config.Audience, MaximumAge: config.MaximumAge,
		Transport: config.Transport, CSRFKeys: config.CSRFKeys,
	}, false, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	return &AccountUnlinkPrimarySource{primary: primary}, nil
}

// MatchesAccountUnlinkSource checks that the OAuth owner and password owner
// borrow the same primary pool and identify the same session/policy profile.
func (s *AccountUnlinkPrimarySource) MatchesAccountUnlinkSource(pool *database.Pool, c sessionpg.SessionServiceConfig, revision uint64) bool {
	return s != nil && s.primary != nil && pool != nil && s.primary.source.pool == pool &&
		s.primary.source.c.Session.Schema == c.Repository.Schema && s.primary.source.c.Profile == c.Profile &&
		s.primary.source.c.Coordinator.AdmissionPolicy.PolicyVersion == revision
}

// Prepare authenticates the typed original session and signed proof for the
// exact self-user. Caller and CSRF must come from the original request. It
// neither consumes the proof nor grants unlink permission; the native owner
// still fences current authority and independent usable login methods in Work.
// Wrong operation, subject, session, proof or selected transport fails closed.
func (s *AccountUnlinkPrimarySource) Prepare(ctx context.Context, original identity.Command, caller authorization.DecisionContext, csrf session.CSRFToken) (AccountUnlinkPrimaryAdmission, error) {
	if s == nil || s.primary == nil {
		return AccountUnlinkPrimaryAdmission{}, password.ErrPasswordWork
	}
	spec, bearer, ok := original.AccountUnlinkPreparationInput()
	if !ok || spec.Binding.PolicyVersion != s.primary.source.c.Coordinator.AdmissionPolicy.PolicyVersion {
		return AccountUnlinkPrimaryAdmission{}, identity.ForbiddenError{}
	}
	admission, err := s.primary.prepare(ctx, EmailPrimaryRequest{
		TenantID: spec.Binding.TenantID, CommandID: spec.Binding.CommandID, AddressID: identity.IdentifierID(spec.Change.AccountID),
		Session: bearer, Proof: spec.Primary, Caller: caller, CSRFToken: csrf,
	}, spec.Binding.UserID)
	if err != nil {
		return AccountUnlinkPrimaryAdmission{}, err
	}
	return AccountUnlinkPrimaryAdmission{primary: admission, original: original}, nil
}

// AdmitPreparation checks current original password/session authority in the
// coordinator's preparation transaction, before acknowledged generation.
// This grants no consumption, capability issuance or unlink permission.
func (a AccountUnlinkPrimaryAdmission) AdmitPreparation(ctx context.Context, w kernel.AccountUnlinkPreparationWork, owner kernel.AccountUnlinkPreparationContributor) error {
	expected, _, ok := a.original.AccountUnlinkPreparationInput()
	if ctx == nil || !ok || a.primary.custody == nil {
		return identity.ForbiddenError{}
	}
	spec, err := w.Command(owner)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(spec, expected) {
		return identity.ForbiddenError{}
	}
	return a.requireCurrent(ctx, w, expected.Binding, expected.Change.ExpectedCredentialVersion, expected.Change.ExpectedCredentialVersion, unlinkPrimaryFences{
		directory: func(e kernel.DirectoryAuthorityAdmission) error {
			return w.RequireActiveDirectoryAuthority(ctx, owner, e)
		},
		credential: func(e kernel.CredentialAdmission) error {
			_, err := w.RequireActiveCredential(ctx, owner, e)
			return err
		},
		policy: func(e kernel.UserAuthorizationAdmission) error {
			return w.RequireActiveUserAuthorization(ctx, owner, e)
		},
	})
}

// RequireCurrent checks the same original admission inside protected execution.
// Only the exact successor epoch persisted by this Work may replace the
// expected epoch during final checks. Original session, CSRF and proof
// deadlines never change. The unlink workflow separately fences MFA and scope.
func (a AccountUnlinkPrimaryAdmission) RequireCurrent(ctx context.Context, w kernel.AccountUnlinkWork, owner kernel.AccountUnlinkPreparationContributor) error {
	expected, expectedBearer, ok := a.original.AccountUnlinkPreparationInput()
	if ctx == nil || !ok || a.primary.custody == nil {
		return identity.ForbiddenError{}
	}
	original, wire, _, err := w.Preparation(owner)
	defer clear(wire)
	if err != nil {
		return err
	}
	spec, bearer, same := original.AccountUnlinkPreparationInput()
	if !same || !reflect.DeepEqual(spec, expected) || bearer.Token() != expectedBearer.Token() {
		return identity.ForbiddenError{}
	}
	epoch, err := w.CredentialAuthorityVersion(owner)
	if err != nil {
		return err
	}
	return a.requireCurrent(ctx, w, expected.Binding, expected.Change.ExpectedCredentialVersion, epoch, unlinkPrimaryFences{
		directory: func(e kernel.DirectoryAuthorityAdmission) error {
			return w.RequireActiveDirectoryAuthority(ctx, owner, e)
		},
		credential: func(e kernel.CredentialAdmission) error {
			_, err := w.RequireActiveCredential(ctx, owner, e)
			return err
		},
		policy: func(e kernel.UserAuthorizationAdmission) error {
			return w.RequireActiveUserAuthorization(ctx, owner, e)
		},
	})
}

type unlinkPrimaryReadWork interface {
	Query(context.Context, string, ...any) (*kernel.WorkRows, error)
	DatabaseTime(context.Context) (time.Time, error)
}

type unlinkPrimaryFences struct {
	directory  func(kernel.DirectoryAuthorityAdmission) error
	credential func(kernel.CredentialAdmission) error
	policy     func(kernel.UserAuthorizationAdmission) error
}

func (a AccountUnlinkPrimaryAdmission) requireCurrent(ctx context.Context, w unlinkPrimaryReadWork, binding identity.CommandBinding, originalEpoch, workEpoch uint64, fences unlinkPrimaryFences) error {
	state := a.primary.custody()
	source := state.source.source
	directory, credential, policy, err := sessionpg.OriginalSessionAdmission(source.c.Profile, state.original, binding)
	if err != nil || credential.CredentialAuthorityVersion != originalEpoch {
		return identity.ForbiddenError{}
	}
	credential.CredentialAuthorityVersion = workEpoch
	if err := fences.directory(directory); err != nil {
		return err
	}
	if err := fences.credential(credential); err != nil {
		return err
	}
	if err := fences.policy(policy); err != nil {
		return err
	}
	if err := sessionpg.RequireSession(ctx, w, source.c.Session, state.original); err != nil {
		return err
	}
	if state.source.config.Transport == session.CredentialCookie {
		if err := sessionpg.RequireCSRF(ctx, w, source.c.Session, state.original, state.request.CSRFToken, state.csrfKey); err != nil {
			return err
		}
	}
	if err := requireUnlinkPasswordMaterial(ctx, w, credential.Credential, source.repository.limits); err != nil {
		return err
	}
	return unlinkPrimaryTime(ctx, w, state)
}

const lockReauthenticationPasswordSQL = `SELECT version::text,CASE WHEN octet_length(encoded_hash)<=$4 THEN encoded_hash ELSE '' END
FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3 FOR SHARE`

// The kernel reference fence protects authority, not the actual password
// material. Lock and validate the exact password record before it can count as
// remaining access; missing or malformed material must not strand the user.
func requireUnlinkPasswordMaterial(ctx context.Context, w unlinkPrimaryReadWork, ref identity.CredentialRef, limits primitive.Limits) error {
	rows, err := w.Query(ctx, lockReauthenticationPasswordSQL, string(ref.TenantID), string(ref.UserID), string(ref.ID), limits.EncodedHashBytes)
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return identity.ForbiddenError{}
	}
	var version, encoded string
	if rows.Scan(&version, &encoded) != nil || rows.Next() || rows.Err() != nil {
		return password.ErrPasswordWork
	}
	v, err := canonicalVersion(version)
	if err != nil || v != ref.Version {
		return identity.ForbiddenError{}
	}
	if _, err := primitive.ParseEncodedHash(encoded, limits); err != nil {
		return identity.ForbiddenError{}
	}
	return nil
}

// RemainingPassword reads the same verified password credential and actual
// material for the optimistic last-access decision. It exposes only the
// reference. The protected unlink repeats the material/reference checks under
// locks and separately validates the original native MFA generation.
func (a AccountUnlinkPrimaryAdmission) RemainingPassword(ctx context.Context) (identity.CredentialRef, error) {
	if a.primary.custody == nil || ctx == nil {
		return identity.CredentialRef{}, identity.ForbiddenError{}
	}
	state := a.primary.custody()
	spec, _, ok := a.original.AccountUnlinkPreparationInput()
	if !ok {
		return identity.CredentialRef{}, identity.ForbiddenError{}
	}
	source := state.source.source
	_, want, _, err := sessionpg.OriginalSessionAdmission(source.c.Profile, state.original, spec.Binding)
	if err != nil || want.CredentialAuthorityVersion != spec.Change.ExpectedCredentialVersion {
		return identity.CredentialRef{}, identity.ForbiddenError{}
	}
	current, err := source.repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: spec.Binding.TenantID, SubjectID: spec.Binding.UserID})
	if err != nil {
		if errors.Is(err, password.ErrCredentialAbsent) {
			return identity.CredentialRef{}, identity.ForbiddenError{}
		}
		return identity.CredentialRef{}, err
	}
	now := source.c.Verifier.Now()
	if err := state.checkTime(now); err != nil {
		return identity.CredentialRef{}, err
	}
	if identity.CheckCredentialAuthority(current.Authority(), want.Credential, want.CredentialAuthorityVersion, now) != nil {
		return identity.CredentialRef{}, identity.ForbiddenError{}
	}
	return want.Credential, nil
}

func unlinkPrimaryTime(ctx context.Context, w unlinkPrimaryReadWork, state emailPrimaryCustody) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return state.checkTime(now)
}

// Consume takes the existing one-use password record's exclusive lock only in
// the owning unlink persistence callback. It rechecks original age after the
// lock wait. Errors must abort the same Work as the account and token effects.
func (a AccountUnlinkPrimaryAdmission) Consume(ctx context.Context, w kernel.AccountUnlinkWork, owner kernel.AccountUnlinkPreparationContributor) error {
	spec, err := w.PersistenceIntent(owner)
	if err != nil {
		return err
	}
	if spec.Binding.OperationID != accountUnlinkPrimaryAction {
		return identity.ForbiddenError{}
	}
	if err := a.RequireCurrent(ctx, w, owner); err != nil {
		return err
	}
	state := a.primary.custody()
	return consumeReauthenticationWith(ctx, w, spec.Binding, state.record, func(ctx context.Context) error {
		return unlinkPrimaryTime(ctx, w, state)
	}, lockUnlinkReauthentication, consumeUnlinkReauthentication)
}

const lockUnlinkReauthentication = `SELECT CASE WHEN octet_length(p.record)<=$4 THEN p.record ELSE ''::bytea END,
p.consumed_command_id IS NULL AND p.unlink_consumed_command_id IS NULL
FROM identity_password.reauthentication_records p JOIN identity.commands c USING(tenant_id,purpose,command_id)
WHERE p.proof_id=$1 AND p.tenant_id=$2 AND p.user_id=$3 AND c.state='committed' FOR UPDATE OF p`
const consumeUnlinkReauthentication = `UPDATE identity_password.reauthentication_records
SET unlink_consumed_command_id=$4,unlink_consumed_purpose=$5,unlink_consumed_at=$6
WHERE proof_id=$1 AND tenant_id=$2 AND user_id=$3 AND consumed_command_id IS NULL AND unlink_consumed_command_id IS NULL`

// AccountUnlinkPasswordNotConsumed tests retained negative evidence for the
// exact unlink command. It is callable only through the enlisted contributor's
// recovery Work. Absence cannot prove rollback on its own and cannot restore
// the expired proof or permit another attempt.
func AccountUnlinkPasswordNotConsumed(ctx context.Context, w kernel.RecoveryWork, owner kernel.AccountUnlinkContributor) (bool, error) {
	b, _, err := w.AccountUnlinkScope(owner)
	if err != nil || ctx == nil {
		return false, password.ErrPasswordWork
	}
	consumed, err := accountUnlinkPasswordConsumed(ctx, w.Query, b)
	return !consumed && err == nil, err
}

// RequireConsumed checks the exact unlink command's one-use effect before
// final commit. The command's proof is already locked by Consume.
func (a AccountUnlinkPrimaryAdmission) RequireConsumed(ctx context.Context, w kernel.AccountUnlinkWork, owner kernel.AccountUnlinkContributor) error {
	spec, final, err := w.Command(owner)
	wanted, _, ok := a.original.AccountUnlinkPreparationInput()
	if err != nil || ctx == nil || !final || !ok || spec.Binding != wanted.Binding {
		return identity.ForbiddenError{}
	}
	consumed, err := accountUnlinkPasswordConsumed(ctx, w.Query, spec.Binding)
	if err != nil {
		return err
	}
	if !consumed {
		return identity.ForbiddenError{}
	}
	return nil
}

func accountUnlinkPasswordConsumed(ctx context.Context, query func(context.Context, string, ...any) (*kernel.WorkRows, error), b identity.CommandBinding) (bool, error) {
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return false, password.ErrPasswordWork
	}
	rows, err := query(ctx, `SELECT EXISTS(SELECT 1 FROM identity_password.reauthentication_records
WHERE tenant_id=$1 AND unlink_consumed_purpose=$2 AND unlink_consumed_command_id=$3)`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var consumed bool
	if !rows.Next() || rows.Scan(&consumed) != nil || rows.Next() || rows.Err() != nil {
		return false, password.ErrPasswordWork
	}
	return consumed, nil
}

// Original returns immutable original session provenance, not current authority.
func (a AccountUnlinkPrimaryAdmission) Original() (session.Session, error) {
	return a.primary.Original()
}

// Deadline is the original earliest proof age/expiry and session lifetime.
func (a AccountUnlinkPrimaryAdmission) Deadline() (time.Time, error) {
	return a.primary.Deadline()
}

// Format redacts original authentication and request custody.
func (AccountUnlinkPrimaryAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.AccountUnlinkPrimaryAdmission(redacted)"))
}

// MarshalJSON rejects implicit serialization of password/session custody.
func (AccountUnlinkPrimaryAdmission) MarshalJSON() ([]byte, error) {
	return nil, password.ErrPasswordWork
}

// MarshalText rejects implicit serialization of password/session custody.
func (AccountUnlinkPrimaryAdmission) MarshalText() ([]byte, error) {
	return nil, password.ErrPasswordWork
}
