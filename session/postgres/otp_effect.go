package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// OTPSigninEffect owns session writes within the OTP feature's original checked
// consuming Work. It owns no pool, coordinator, OTP participant, callbacks or
// goroutines. Configuration is immutable and concurrent calls use independent
// serial Work handles. Zero is invalid. This is a native adapter seam, not a
// public login endpoint, authentication proof or permission to reveal a bearer.
type OTPSigninEffect struct {
	native  Repository
	config  Config
	profile OTPAdmissionConfig
}

// Format redacts deployment and stored-owner configuration for every verb.
func (*OTPSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPSigninEffect(redacted)"))
}

// MarshalJSON rejects implicit deployment configuration export.
func (*OTPSigninEffect) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit export and map-key disclosure.
func (*OTPSigninEffect) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewOTPSigninEffect validates and freezes trusted deployment configuration
// without IO. Install kernel/authorization/session and OTPIssueMigrationSource
// histories before use. The registered OTP feature alone lends the sole primary
// transaction during its synchronous callback; no application store is accepted.
func NewOTPSigninEffect(c Config, p OTPAdmissionConfig) (*OTPSigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	return &OTPSigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

// Apply stages the complete original command-mapped session, family and retained
// effect identity under the exact active feature invocation. The OTP owner must
// exhaustively validate original Send/pre-auth possession, recipient and remember
// custody before admission, and finalize OTP/pre-auth in this same coordinator
// transaction. This helper checks the checked consuming phase, exact recipient,
// every applicable current owner and original expiry after downstream waits.
// It creates no proof, bearer or validity lease and never closes/retains Work.
// Every error must be propagated from ApplyFeature so the coordinator aborts;
// provisional success cannot authorize credential delivery before commit.
func (e *OTPSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, recipient kernel.RecipientRecord) (identity.FeatureReceipt, error) {
	fail := func() (identity.FeatureReceipt, error) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return fail()
	}
	record, err := OTPSigninSession(command)
	if err != nil {
		return fail()
	}
	f, _ := command.Feature()
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || b != f.Binding || feature.Operation != f.Operation || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return fail()
	}
	consumption, err := w.OTPConsumption(owner)
	p, _ := record.OTPAuthentication().Bindings()
	if err != nil || consumption.Command != b || consumption.Plan.AttemptID != p.AttemptID || consumption.Plan.ChallengeID != p.ChallengeID || consumption.Plan.Mode != kernel.OTPConsume {
		return fail()
	}
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	query, policy, err := otpSessionAdmission(e.profile, record)
	if err != nil || s.Version != 1 || !s.IssuedAt.Equal(s.LastActivityAt) || recipient.Validate() != nil || recipient.Suppressed || recipient.Query.TenantID != b.TenantID || recipient.Query.UserID != b.UserID || recipient.Query.Eligibility != kernel.RecipientVerified || recipient.User.ID != s.UserID || recipient.Identifier.ID != p.IdentifierID || recipient.Identifier.Kind != p.IdentifierKind || recipient.Identifier.Version != p.IdentifierVersion || recipient.Verification.Version != p.VerificationVersion || recipient.Verification.State != identity.VerificationVerified || recipient.UserAuthorityVersion != a.User.Version || recipient.IdentifierAuthorityVersion != a.Identifier.Version || recipient.CredentialAuthorityVersion != a.Credential.Version {
		return fail()
	}
	bounded, cancel := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer cancel()
	if err := w.RequireActiveDirectoryAuthority(bounded, owner, kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.RequireRecipient(bounded, owner, recipient); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := authority.RequireAuthority(bounded, w, policy, a.Authorization.Version, e.config.MaximumDuration); err != nil {
		if errors.Is(err, authority.ErrAuthorityDenied) {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
		return identity.FeatureReceipt{}, readError(bounded, err)
	}
	if err := e.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireOTPIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, record, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireOTPIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: feature.Operation}, nil
}

func requireOTPIssueTime(ctx context.Context, w kernel.Work, record session.Session) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	s, _ := record.Bindings()
	p, _ := record.OTPAuthentication().Bindings()
	life, err := record.Lifetime(now)
	if err != nil || now.Before(s.IssuedAt) || now.Before(p.AuthenticatedAt) || !now.Before(p.ValidUntil) || !life.Fresh {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover supplies only retained session-owned evidence during the original
// coordinator's recovery invocation. It does not disclose a session/bearer,
// authenticate current access, compare a code or infer rollback from expiry.
// The coordinator must reconcile all participants and enforce current disclosure
// policy. Session payload deletion does not erase this retained commitment.
func (e *OTPSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != otpSessionOperation(b) || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, cancel := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer cancel()
	return recoverOTPIssuance(bounded, w, e.native.schema, b, transition)
}

// The public entry point supplies only invocation-fenced RecoveryWork. Keeping
// decoding separate does not introduce another authority or recovery journal.
func recoverOTPIssuance[R SessionRows](ctx context.Context, q SessionQueryer[R], schema string, b identity.CommandBinding, transition kernel.LifecyclePlan) (kernel.RecoveryStatus, error) {
	_, status, err := readOTPIssuanceIdentity(ctx, q, schema, b, transition)
	return status, err
}

// One retained decoder serves both sealed recovery and trusted primary
// inspection; neither path depends on a live payload or reconstructs a session.
func readOTPIssuanceIdentity[R SessionRows](ctx context.Context, q SessionQueryer[R], schema string, b identity.CommandBinding, transition kernel.LifecyclePlan) (OTPSigninIdentity, kernel.RecoveryStatus, error) {
	return readNativeIssuanceIdentity(ctx, q, schema, b, transition, otpIssuanceDigest)
}

// Only closed native wrappers select the retained digest domain. Existing OTP
// bytes remain unchanged; password signin cannot borrow an OTP commitment.
func readNativeIssuanceIdentity[R SessionRows](ctx context.Context, q SessionQueryer[R], schema string, b identity.CommandBinding, transition kernel.LifecyclePlan, digestFor func([32]byte, string, string, string, []byte) [32]byte) (OTPSigninIdentity, kernel.RecoveryStatus, error) {
	id, bindingDigest := revocationEvidence(b, transition)
	rows, err := q.Query(ctx, `SELECT purpose,user_id,session_id,family_id,binding_digest,record_digest FROM `+schema+`.session_issuances WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return OTPSigninIdentity{}, kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return OTPSigninIdentity{}, kernel.RecoveryUnknown, err
		}
		return OTPSigninIdentity{}, kernel.RecoveryNotCommitted, nil
	}
	var purpose, user, idSession, family string
	var stored, record []byte
	if err := rows.Scan(&purpose, &user, &idSession, &family, &stored, &record); err != nil {
		return OTPSigninIdentity{}, kernel.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return OTPSigninIdentity{}, kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	digest := digestFor(bindingDigest, user, idSession, family, record)
	if purpose != b.OperationID || !scopeID(user) || (b.UserID != "" && user != string(b.UserID)) || !scopeID(idSession) || !scopeID(family) || subtle.ConstantTimeCompare(stored, digest[:]) != 1 || len(record) != sha256.Size || subtle.ConstantTimeCompare(record, make([]byte, sha256.Size)) == 1 {
		return OTPSigninIdentity{}, kernel.RecoveryUnknown, nil
	}
	return OTPSigninIdentity{UserID: identity.UserID(user), SessionID: idSession, FamilyID: family}, kernel.RecoveryCommitted, nil
}

// Record-free anonymous commands cannot identify the selected session in their
// binding. Commit the actual tuple and complete original record hash as well,
// so retained recovery cannot silently substitute either after payload cleanup.
// This complements the coordinator's keyed intent; it is not authentication.
func otpIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-otp-issuance-v1\x00", binding, user, id, family, record)
}

func passwordIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-password-issuance-v1\x00", binding, user, id, family, record)
}

func nativeIssuanceDigest(domain string, binding [32]byte, user, id, family string, record []byte) [32]byte {
	// Closed scalar fields cannot fail JSON encoding; framing is unambiguous.
	payload, _ := json.Marshal(struct {
		Binding               [32]byte
		User, Session, Family string
		Record                []byte
	}{binding, user, id, family, record})
	return sha256.Sum256(append([]byte(domain), payload...))
}
