package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

const oidcEndSessionUntil = "oidc.end-session.valid-until"

func oidcEndSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "oauth-server/oidc", OperationID: "identity.oauth-server.end-session", SchemaID: "identity.oauth-server.end-session.native-rp-logout-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func oidcEndSessionOwner() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
}

// OIDCEndSessionFields freezes the exact original session and exclusive
// observation deadline in the protocol owner's command. It contains no bearer
// and grants no authentication, hint verification or permission to terminate.
// The native OAuth owner must preserve its original read-start budget (at most
// 20 seconds), independently authenticate the source, and validate its issued
// hint, current client/key and origin before this effect can be used.
// Until must be microsecond-exact for the shared command codec. If a native
// clock has finer precision, floor the original deadline before calling;
// rounding up would extend its authority window.
func OIDCEndSessionFields(source session.Session, until time.Time) ([]identity.FeatureField, error) {
	s, err := source.Bindings()
	if err != nil || !sessionReadTime(until) || until.Nanosecond()%1000 != 0 || !until.After(s.LastActivityAt) {
		return nil, session.ErrInvalidSessionCommand
	}
	life, err := source.Lifetime(s.LastActivityAt)
	if err != nil || until.After(life.ExpiresAt) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(source)
	if err != nil {
		return nil, err
	}
	return append(fields, identity.FeatureField{Name: oidcEndSessionUntil, Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: until.UTC()}}), nil
}

func oidcEndSessionIntent(c identity.Command) (session.Session, time.Time, error) {
	f, ok := c.Feature()
	deny := func() (session.Session, time.Time, error) {
		return session.Session{}, time.Time{}, session.ErrInvalidSessionCommand
	}
	if !ok || f.Operation != oidcEndSessionOperation() || f.Binding.ActorKind != authorization.SubjectUser || string(f.Binding.ActorID) != string(f.Binding.UserID) {
		return deny()
	}
	var fields []identity.FeatureField
	var until time.Time
	for _, field := range f.Fields {
		switch {
		case strings.HasPrefix(field.Name, originalSessionPrefix):
			fields = append(fields, field)
		case field.Name == oidcEndSessionUntil:
			if !until.IsZero() || field.Value.Kind != identity.FeatureTime {
				return deny()
			}
			until = field.Value.Time
		case strings.HasPrefix(field.Name, "oidc.end-session."):
			return deny()
		}
	}
	source, err := OriginalSessionFromFields(f.Binding.TenantID, f.Binding.UserID, fields)
	if err != nil {
		return deny()
	}
	s, _ := source.Bindings()
	if f.Binding.RecordID != s.SessionID || s.Version == ^uint64(0) {
		return deny()
	}
	if _, err := OIDCEndSessionFields(source, until); err != nil {
		return deny()
	}
	return source, until, nil
}

// OIDCEndSessionEffect owns exact single-session invalidation inside the native
// OAuth participant's existing Work. It borrows no transaction or pool and
// starts no goroutines. It does not verify an ID token, authenticate a bearer,
// clear cookies or decide redirects. The OAuth owner must atomically require
// its protected end-session audit and session.revoked.v1 lifecycle effect.
// Immutable configuration supports independent concurrent calls.
type OIDCEndSessionEffect struct {
	native Repository
	config Config
}

// NewOIDCEndSessionEffect freezes the selected password/single-factor profile
// without IO. Unsupported factor, organization and passkey authority denies,
// never falls back. Install OIDCEndSessionMigrationSource after the existing
// single-session revocation history. This enables no endpoint by itself.
func NewOIDCEndSessionEffect(c Config, p IdentifierAdmissionConfig) (*OIDCEndSessionEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() || p.AuthenticationMethod != "password" || p.CredentialKind != identity.CredentialPassword || p.CredentialOwner != "identity/password" {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.AuthenticationMethod, p.CredentialOwner = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience), strings.Clone(p.AuthenticationMethod), strings.Clone(p.CredentialOwner)
	profile := IssueAdmissionConfig(p)
	return &OIDCEndSessionEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration, issueAdmission: &profile}, config: c}, nil
}

func oidcEndSessionScope(b identity.CommandBinding, f kernel.FeatureRegistration, l kernel.LifecyclePlan, source session.Session) bool {
	s, err := source.Bindings()
	return err == nil && b.ValidateFor(oidcEndSessionOperation()) == nil && f.Contributor == oidcEndSessionOwner() && f.Operation == oidcEndSessionOperation() && b.ActorKind == authorization.SubjectUser && string(b.ActorID) == string(b.UserID) && b.TenantID == s.TenantID && b.UserID == s.UserID && b.RecordID == s.SessionID && l.EventType == "session.revoked.v1" && l.BeforeVersion == s.Version && s.Version < ^uint64(0) && l.AfterVersion == s.Version+1
}

func (e *OIDCEndSessionEffect) intent(w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) (identity.CommandBinding, kernel.FeatureRegistration, kernel.LifecyclePlan, session.Session, time.Time, error) {
	b, f, l, err := w.FeatureScope(owner)
	source, until, se := oidcEndSessionIntent(c)
	spec, ok := c.Feature()
	if err != nil || se != nil || !ok || spec.Binding != b || owner.Descriptor() != oidcEndSessionOwner() || !oidcEndSessionScope(b, f, l, source) {
		return identity.CommandBinding{}, kernel.FeatureRegistration{}, kernel.LifecyclePlan{}, session.Session{}, time.Time{}, session.ErrInvalidSessionCommand
	}
	return b, f, l, source, until, nil
}

func oidcEndSessionWindow(ctx context.Context, w kernel.Work, source session.Session, until time.Time) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if _, err := source.Lifetime(now); err != nil || !now.Before(until) || until.After(now.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Apply rechecks original authority, locks the exact original active record and
// revokes only it through the existing session mutation/journal. No family or
// sibling version advances. Every error must abort the complete OAuth command;
// the receipt is provisional until required events and final checks commit.
func (e *OIDCEndSessionEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.native.issueAdmission == nil {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, f, l, source, until, err := e.intent(w, owner, c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := oidcEndSessionWindow(bounded, w, source, until); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return e.native.applySingleSessionRevocation(bounded, w, owner, b, f, l, source)
}

// Check repeats current directory/credential/policy, exact terminal session,
// unchanged active family, retained original journal and original deadline in
// the sole commit fence. The revoked credential is not re-authenticated.
func (e *OIDCEndSessionEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	if ctx == nil || e == nil || e.native.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	b, _, l, source, until, err := e.intent(w, owner, c)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.native.requireRevokeRecordAuthorityFor(bounded, w, owner, source, b); err != nil {
		return err
	}
	s, _ := source.Bindings()
	payload, _, err := encodeRecord(source)
	if err != nil {
		return err
	}
	rows, err := w.Query(bounded, `SELECT session_id FROM `+e.native.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND version=$4::numeric AND state='revoked' AND record=$5::jsonb FOR SHARE`, string(b.TenantID), string(b.UserID), s.SessionID, strconv.FormatUint(s.Version, 10), string(payload))
	if err != nil {
		return err
	}
	var id string
	err = readSessionAdmission(rows, &id)
	rows.Close()
	if err != nil || id != s.SessionID {
		return identity.ForbiddenError{}
	}
	if err := e.native.requireIssueFamily(bounded, w, s, true); err != nil {
		return err
	}
	commandID, _ := revocationEvidence(b, l)
	rows, err = w.Query(bounded, oidcEndSessionEvidenceSQL(e.native.schema), string(b.TenantID), commandID)
	if err != nil {
		return err
	}
	status, err := readOIDCEndSessionEvidence(rows, b, l, source)
	rows.Close()
	if err != nil || status != kernel.RecoveryCommitted {
		return identity.ForbiddenError{}
	}
	return oidcEndSessionWindow(bounded, w, source, until)
}

func oidcEndSessionEvidenceSQL(schema string) string {
	return `SELECT purpose,user_id,session_id,before_version::text,after_version::text,binding_digest,record_digest FROM ` + schema + `.session_revocations WHERE tenant_id=$1 AND command_id=$2`
}

func readOIDCEndSessionEvidence(rows subjectEvidenceRows, b identity.CommandBinding, l kernel.LifecyclePlan, source session.Session) (kernel.RecoveryStatus, error) {
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var purpose, user, id, before, after string
	var binding, record []byte
	if err := rows.Scan(&purpose, &user, &id, &before, &after, &binding, &record); err != nil {
		return kernel.RecoveryUnknown, err
	}
	wire, _, err := encodeRecord(source)
	_, wantBinding := revocationEvidence(b, l)
	wantRecord := sha256.Sum256(wire)
	if err != nil || rows.Next() || rows.Err() != nil || purpose != b.OperationID || user != string(b.UserID) || id != b.RecordID || before != strconv.FormatUint(l.BeforeVersion, 10) || after != strconv.FormatUint(l.AfterVersion, 10) || subtle.ConstantTimeCompare(binding, wantBinding[:]) != 1 || subtle.ConstantTimeCompare(record, wantRecord[:]) != 1 {
		return kernel.RecoveryUnknown, session.ErrUnavailable
	}
	return kernel.RecoveryCommitted, nil
}

type subjectEvidenceRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

// Recover votes from the retained original single-session tombstone and exact
// original record digest. No live session, bearer, key publication or fresh
// authentication is required. It neither re-executes nor decides the whole
// command outcome; the existing coordinator reconciles all participant votes.
func (e *OIDCEndSessionEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor, source session.Session) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.native.issueAdmission == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || owner.Descriptor() != oidcEndSessionOwner() || !oidcEndSessionScope(b, f, l, source) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	id, _ := revocationEvidence(b, l)
	rows, err := w.Query(bounded, oidcEndSessionEvidenceSQL(e.native.schema), string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	return readOIDCEndSessionEvidence(rows, b, l, source)
}

// RequireNotRevoked fences this exact original source's RP-logout disposition
// in the existing OAuth token Work. Ordinary browser signout is intentionally
// not this disposition. The OAuth owner must supply its actual grant-associated
// source and current authority; this check alone authenticates nothing. The
// coordinator's tenant mutex serializes absence with every revocation writer.
func (e *OIDCEndSessionEffect) RequireNotRevoked(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, source session.Session) error {
	if ctx == nil || e == nil || e.native.issueAdmission == nil {
		return session.ErrInvalidSessionCommand
	}
	b, f, _, err := w.FeatureScope(owner)
	s, se := source.Bindings()
	if err != nil || se != nil || owner.Descriptor() != oidcEndSessionOwner() || f.Contributor != oidcEndSessionOwner() || f.Operation != (identity.FeatureOperation{Owner: "oauth-server", OperationID: "identity.oauth-server.token", SchemaID: "identity.oauth-server.token.public-password-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) || b.TenantID != s.TenantID || b.UserID != s.UserID {
		return session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	rows, err := w.Query(bounded, `SELECT session_id FROM `+e.native.schema+`.session_revocations WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND purpose='identity.oauth-server.end-session' FOR SHARE`, string(s.TenantID), string(s.UserID), s.SessionID)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		return identity.ForbiddenError{}
	}
	return rows.Err()
}

// OIDCEndSessionRevoked reads only the exact source's retained RP-logout
// disposition from the primary, including after payload pruning. False means
// only absence of this tombstone, not active authentication or usable grant
// authority. Callers preserve their original authoritative read-start deadline;
// this method supplies no lease, cache renewal or stale fallback. Ordinary
// signout tombstones are deliberately distinct. Missing history fails closed.
func (r *Repository) OIDCEndSessionRevoked(ctx context.Context, tenant identity.TenantID, user identity.UserID, id string) (bool, error) {
	if ctx == nil || r == nil || r.pool == nil || r.pool.Raw() == nil || r.maximumDuration <= 0 || !scopeID(string(tenant)) || !scopeID(string(user)) || !scopeID(id) {
		return false, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	var revoked bool
	err := r.pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM `+r.schema+`.session_revocations WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3 AND purpose='identity.oauth-server.end-session')`, string(tenant), string(user), id).Scan(&revoked)
	if err != nil || bounded.Err() != nil {
		return false, admissionError(bounded, err)
	}
	return revoked, nil
}

func (*OIDCEndSessionEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OIDCEndSessionEffect(redacted)"))
}
func (*OIDCEndSessionEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (*OIDCEndSessionEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
