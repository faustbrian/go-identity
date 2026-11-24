package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// SSOSAMLIDPLogoutEffect owns revocation of the exact local sessions selected
// by the verified IdP request. The SSO owner verifies the signed request and
// pins the complete provider-owned selection in the same coordinator Work.
type SSOSAMLIDPLogoutEffect struct {
	schema          string
	maximumDuration time.Duration
}

// NewSSOSAMLIDPLogoutEffect selects the protected session mutation without IO.
// Install SP and IdP session issuance history and SSOSAMLIDPLogoutMigrationSource
// before opting in. This effect exposes no route, signature check or bearer.
func NewSSOSAMLIDPLogoutEffect(c Config) (*SSOSAMLIDPLogoutEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute {
		return nil, session.ErrInvalidSessionCommand
	}
	return &SSOSAMLIDPLogoutEffect{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, nil
}

// Apply locks every expected predecessor before writing. It leaves the family
// and unrelated sessions alone, including other sessions of the same user.
// Errors must abort the caller's Work. The receipt is provisional until commit.
func (e *SSOSAMLIDPLogoutEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, intent kernel.SSOSAMLIDPLogoutIntent) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.schema == "" {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.RequireSSOSAMLIDPLogoutRequest(ctx, owner, c, intent); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, feature, l, err := w.FeatureScope(owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, e.maximumDuration)
	defer cancel()
	if err := requireSAMLIDPLogoutWindow(bounded, w, intent.ValidUntil); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.requireTargets(bounded, w, b, intent, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requireSAMLIDPLogoutWindow(bounded, w, intent.ValidUntil); err != nil {
		return identity.FeatureReceipt{}, err
	}
	id, binding := revocationEvidence(b, l)
	digest, err := samlIDPLogoutIntentDigest(intent)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	ids := make([]string, 0, len(intent.Targets))
	for _, target := range intent.Targets {
		ids = append(ids, target.SessionID)
	}
	// Only identifiers are encoded. Their exact versions are already locked and
	// checked; a revocation does not rewrite the immutable predecessor record.
	encoded, _ := json.Marshal(ids)
	n, err := w.Exec(bounded, e.updateTargetsSQL(), string(b.TenantID), string(b.UserID), string(encoded))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != int64(len(ids)) {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	n, err = w.Exec(bounded, e.insertEvidenceSQL(), string(b.TenantID), id, b.OperationID, string(b.UserID), binding[:], digest[:], len(ids))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: l.BeforeVersion, AfterVersion: l.AfterVersion}, nil
}

// Check requires the original invocation and exact retained receipt and
// confirms every target is now revoked, before the original cutoff expires.
func (e *SSOSAMLIDPLogoutEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, intent kernel.SSOSAMLIDPLogoutIntent) error {
	if ctx == nil || e == nil || e.schema == "" {
		return session.ErrInvalidSessionCommand
	}
	if err := w.RequireSSOSAMLIDPLogoutRequest(ctx, owner, c, intent); err != nil {
		return err
	}
	b, _, l, err := w.FeatureScope(owner)
	if err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, e.maximumDuration)
	defer cancel()
	status, err := e.readEvidence(bounded, w, b, l, intent)
	if err != nil {
		return err
	}
	if status != kernel.RecoveryCommitted {
		return identity.ConflictError{}
	}
	if err := e.requireTargets(bounded, w, b, intent, true); err != nil {
		return err
	}
	return requireSAMLIDPLogoutWindow(bounded, w, intent.ValidUntil)
}

// Recover votes only from the retained receipt and original frozen intent
// supplied by the native owner. It never replaces that intent with a new
// lookup, reopens a time window, or repeats the revocation.
func (e *SSOSAMLIDPLogoutEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor, intent kernel.SSOSAMLIDPLogoutIntent) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.schema == "" {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	op := kernel.SSOSAMLIDPLogoutOperation()
	if err != nil || f.Operation != op || f.Contributor != kernel.SSOSAMLIDPLogoutDescriptor() || l != kernel.SSOSAMLIDPLogoutLifecycle() ||
		b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectServiceAccount || b.RecordID != string(b.CommandID) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, cancel := context.WithTimeout(ctx, e.maximumDuration)
	defer cancel()
	return e.readEvidence(bounded, w, b, l, intent)
}

func requireSAMLIDPLogoutWindow(ctx context.Context, w kernel.Work, until time.Time) error {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(until) {
		return identity.ForbiddenError{}
	}
	return nil
}

func samlIDPLogoutIntentDigest(intent kernel.SSOSAMLIDPLogoutIntent) ([32]byte, error) {
	fields, err := kernel.SSOSAMLIDPLogoutFields(intent)
	if err != nil {
		return [32]byte{}, err
	}
	// Freeze the receipt codec apart from the upstream FeatureField struct.
	// The fields already contain the canonical target-set digest and no raw
	// SAML subject, bearer or caller-supplied codec.
	type digestField struct {
		Name  string
		Text  string
		Bytes []byte
		Time  string
	}
	frozen := make([]digestField, 0, len(fields))
	for _, field := range fields {
		value := field.Value
		frozen = append(frozen, digestField{field.Name, value.Text, value.Bytes, value.Time.UTC().Format(time.RFC3339Nano)})
	}
	encoded, err := json.Marshal(frozen)
	if err != nil {
		return [32]byte{}, identity.UnavailableError{}
	}
	return sha256.Sum256(append([]byte("identity-session-saml-idp-logout-v1\x00"), encoded...)), nil
}

type samlIDPLogoutEvidenceReader interface {
	Query(context.Context, string, ...any) (*kernel.WorkRows, error)
}

func (e *SSOSAMLIDPLogoutEffect) readEvidence(ctx context.Context, w samlIDPLogoutEvidenceReader, b identity.CommandBinding, l kernel.LifecyclePlan, intent kernel.SSOSAMLIDPLogoutIntent) (kernel.RecoveryStatus, error) {
	id, binding := revocationEvidence(b, l)
	digest, err := samlIDPLogoutIntentDigest(intent)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, e.evidenceSQL(), string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var purpose, user string
	var storedBinding, storedDigest []byte
	var count int64
	if err := rows.Scan(&purpose, &user, &storedBinding, &storedDigest, &count); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if rows.Next() {
		return kernel.RecoveryUnknown, nil
	}
	if err := rows.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	if purpose != b.OperationID || user != string(b.UserID) || count != int64(len(intent.Targets)) ||
		subtle.ConstantTimeCompare(storedBinding, binding[:]) != 1 || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

func (e *SSOSAMLIDPLogoutEffect) evidenceSQL() string {
	return `SELECT purpose,user_id,binding_digest,intent_digest,target_count::bigint FROM ` + e.schema + `.saml_idp_logout_revocations WHERE tenant_id=$1 AND command_id=$2`
}

func (e *SSOSAMLIDPLogoutEffect) insertEvidenceSQL() string {
	return `INSERT INTO ` + e.schema + `.saml_idp_logout_revocations(tenant_id,command_id,purpose,user_id,binding_digest,intent_digest,target_count) VALUES($1,$2,$3,$4,$5,$6,$7)`
}

func (e *SSOSAMLIDPLogoutEffect) updateTargetsSQL() string {
	return `UPDATE ` + e.schema + `.sessions s SET state='revoked' FROM jsonb_array_elements_text($3::jsonb) AS requested(session_id)
WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.session_id=requested.session_id COLLATE "C" AND s.state='active'`
}

func (e *SSOSAMLIDPLogoutEffect) targetRowsSQL(lock bool) string {
	q := `SELECT s.record::text,s.state,f.state,f.version::text,s.expires_at,s.tenant_id,s.session_id,s.user_id,s.family_id,s.version::text,s.family_version::text,s.digest_version,s.digest
FROM jsonb_to_recordset($3::jsonb) AS requested(session_id text,issuance_hex text)
JOIN ` + e.schema + `.sessions s ON s.tenant_id=$1 AND s.user_id=$2 AND s.session_id=requested.session_id COLLATE "C"
JOIN ` + e.schema + `.families f USING(tenant_id,family_id,user_id)
JOIN ` + e.schema + `.session_issuances i ON i.tenant_id=s.tenant_id AND i.user_id=s.user_id AND i.session_id=s.session_id AND i.family_id=s.family_id
 AND i.command_id=decode(requested.issuance_hex,'hex') AND i.purpose IN ($4,$5)
ORDER BY s.session_id`
	if lock {
		q += ` FOR UPDATE OF s`
	}
	return q
}

func (e *SSOSAMLIDPLogoutEffect) requireTargets(ctx context.Context, w kernel.Work, b identity.CommandBinding, intent kernel.SSOSAMLIDPLogoutIntent, revoked bool) error {
	// The shared Work cursor has a 1 MiB result budget; even the maximum-size
	// session record fits in pages of 16. The frozen order is checked again as
	// rows arrive and supplies a consistent acquisition order for session locks.
	const pageSize = 16
	for start := 0; start < len(intent.Targets); start += pageSize {
		page := intent.Targets[start:min(start+pageSize, len(intent.Targets))]
		if err := e.requireTargetPage(ctx, w, b, intent.OrganizationID, page, revoked); err != nil {
			return err
		}
	}
	return nil
}

func (e *SSOSAMLIDPLogoutEffect) requireTargetPage(ctx context.Context, w kernel.Work, b identity.CommandBinding, organization string, page []kernel.SSOSAMLIDPLogoutTarget, revoked bool) error {
	type targetKey struct {
		Session  string `json:"session_id"`
		Issuance string `json:"issuance_hex"`
	}
	keys := make([]targetKey, 0, len(page))
	for _, target := range page {
		// The exact work fence validated the issuance ID before reaching SQL.
		id, _ := base64.RawURLEncoding.DecodeString(string(target.IssuanceCommandID))
		keys = append(keys, targetKey{Session: target.SessionID, Issuance: hex.EncodeToString(id)})
	}
	encoded, _ := json.Marshal(keys)
	rows, err := w.Query(ctx, e.targetRowsSQL(!revoked), string(b.TenantID), string(b.UserID), string(encoded), kernel.SSOSAMLSigninOperation().OperationID, kernel.SSOSAMLIDPConfirmationOperation().OperationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for _, target := range page {
		if !rows.Next() {
			if err := rows.Err(); err != nil {
				return err
			}
			return identity.ConflictError{}
		}
		var row primaryStoredRow
		if err := row.scan(rows); err != nil {
			return err
		}
		stored, err := row.decode(b.TenantID, target.SessionID, nil)
		if err != nil || stored.Revoked != revoked || !samlIDPLogoutTargetMatches(stored.Session, b.UserID, organization, target) {
			return identity.ConflictError{}
		}
	}
	if rows.Next() {
		return identity.ConflictError{}
	}
	return rows.Err()
}

func samlIDPLogoutTargetMatches(s session.Session, user identity.UserID, organization string, target kernel.SSOSAMLIDPLogoutTarget) bool {
	spec, err := s.Bindings()
	if err != nil || spec.UserID != user || spec.FamilyID != target.FamilyID || spec.Version != target.Version || spec.Authentication.Kind != session.AuthenticationVerified {
		return false
	}
	proof := spec.Authentication.Proof
	authority, err := spec.Authority.Bindings()
	// This validates stored provenance, not bearer freshness, factor policy or
	// current membership. Stale authentication never prevents a pure revocation.
	return err == nil && authority.ActiveOrganizationID == organization && proof.Method == "sso-saml" &&
		proof.Purpose == "session-issue" && identity.CommandID(proof.ID) == target.IssuanceCommandID
}
