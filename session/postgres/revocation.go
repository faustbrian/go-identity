package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

var _ identitypostgres.FeatureExecutionContributor = (*Repository)(nil)

// Descriptor returns the stable native session store identity. It performs no
// IO and supplies no Work, transaction, registry or execution authority.
func (*Repository) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
}

// FeatureOperations declares native revocation and explicitly configured
// protected issuance and source-bound rotation. Issue registration cannot
// turn structural metadata into opaque proof admission or ordinary execution.
func (r *Repository) FeatureOperations() []identity.FeatureOperation {
	ops := []identity.FeatureOperation{session.RevokeFamilyOperation()}
	if r != nil && r.cleanupBatch > 0 {
		ops = append(ops, cleanupOperation())
	}
	if r != nil && r.issueAdmission != nil {
		ops = append(ops, session.IssueOperation(), session.RevokeOneOperation(), session.RevokeOtherOperation(), session.RevokeAllOperation(), session.RotateOperation())
	}
	return ops
}

// MapCommand exhaustively maps closed native issuance or family revocation to identity's
// shared immutable intent vocabulary. It performs no IO or authorization. All
// behavior-affecting input is bound; no arbitrary JSON, bearer or callback is
// admitted. Mapping is structural only: issuance cannot execute until its
// native admission/effect profile is registered, and must use the protected
// proof-bearing coordinator reservation rather than ordinary ReserveCommand.
func MapCommand(c session.SessionCommand) (identity.Command, error) {
	if s, ok := c.Issue(); ok {
		return mapIssue(s)
	}
	if s, ok := c.RevokeOne(); ok {
		return mapSessionRecord(s.Binding, session.RevokeOneOperation(), s.Session)
	}
	s, ok := c.RevokeFamily()
	if !ok {
		return identity.Command{}, session.ErrInvalidSessionCommand
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: s.Binding, Operation: session.RevokeFamilyOperation(), Fields: []identity.FeatureField{{Name: "expected.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: s.ExpectedVersion}}}})
}

func nativeRevocation(c identity.Command) (session.SessionCommand, error) {
	s, ok := c.Feature()
	if ok && s.Operation == session.RevokeFamilyOperation() && len(s.Fields) == 6 {
		proof, err := nativeReplayEvidence(c)
		if err != nil {
			return session.SessionCommand{}, err
		}
		return session.NewRevokeFamilyCommand(s.Binding, proof.version)
	}
	if !ok || s.Operation != session.RevokeFamilyOperation() || len(s.Fields) != 1 || s.Fields[0].Name != "expected.version" || s.Fields[0].Value.Kind != identity.FeatureUint64 {
		return session.SessionCommand{}, session.ErrInvalidSessionCommand
	}
	return session.NewRevokeFamilyCommand(s.Binding, s.Fields[0].Value.Uint64)
}

// ValidateFeatureCommand checks the complete native schema and exact mandatory
// security/lifecycle declarations before reservation. The coordinator separately
// checks registered contributors, budgets, binding digests and keyed intent.
// Standard or protected retention must be selected by the trusted operation
// policy; privileged callers require protected retention. This pure method
// neither authorizes a caller nor reads current family state.
func (r *Repository) ValidateFeatureCommand(c identity.Command, p identitypostgres.CommandPlan) error {
	if s, ok := c.Feature(); ok && s.Operation == cleanupOperation() {
		return r.validateCleanupPlan(c, p)
	}
	if s, ok := c.Feature(); ok && s.Operation == session.RotateOperation() {
		return r.validateRotationPlan(c, p)
	}
	if s, ok := c.Feature(); ok && (s.Operation == session.RevokeOtherOperation() || s.Operation == session.RevokeAllOperation()) {
		return r.validateRevokeSetPlan(c, p)
	}
	if s, ok := c.Feature(); ok && s.Operation == session.RevokeOneOperation() {
		return r.validateRevokeOnePlan(c, p)
	}
	if s, ok := c.Feature(); ok && s.Operation == session.IssueOperation() {
		return r.validateIssuePlan(c, p)
	}
	native, err := nativeRevocation(c)
	if err != nil || r == nil {
		return session.ErrInvalidSessionCommand
	}
	s, _ := native.RevokeFamily()
	if p.Feature == nil || p.Feature.Contributor != r.Descriptor() || p.Feature.Operation != session.RevokeFamilyOperation() || p.SubjectType != "session_family" || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session_family.revoked.v1" || p.Lifecycle.BeforeVersion != s.ExpectedVersion || p.Lifecycle.AfterVersion != s.ExpectedVersion+1 || len(p.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := p.Audits[0]
	if s.Binding.ActorKind == authorization.SubjectServiceAccount && lenFeatureFields(c) == 6 && a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	if a.EventType != "identity.session.revoke" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "standard" && a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

// ApplyFeature is invoked only by the sole coordinator. It reconstructs the
// closed native command, then delegates to Apply. No audit/lifecycle is staged
// here: the coordinator owns their exact required phases and terminal receipt.
func (r *Repository) ApplyFeature(ctx context.Context, w identitypostgres.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if s, ok := c.Feature(); ok && s.Operation == cleanupOperation() {
		return r.applyCleanup(ctx, w, c)
	}
	if s, ok := c.Feature(); ok && s.Operation == session.RotateOperation() {
		native, until, _, err := nativeRotationIntent(c)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		intent, err := rotationIntentDigest(c)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return r.applyRotation(ctx, w, native, until, intent)
	}
	if s, ok := c.Feature(); ok && (s.Operation == session.RevokeOtherOperation() || s.Operation == session.RevokeAllOperation()) {
		native, until, err := nativeRevokeSet(c)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		set, _ := native.RevokeSet()
		return r.applyRevokeSet(ctx, w, set, until)
	}
	if s, ok := c.Feature(); ok && s.Operation == session.RevokeOneOperation() {
		native, source, err := nativeRevokeIntent(c)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if source != nil {
			one, _ := native.RevokeOne()
			if r == nil || r.issueAdmission == nil {
				return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
			}
			if err := r.requireRevokeSource(ctx, w, one.Binding, one.Session, source); err != nil {
				return identity.FeatureReceipt{}, err
			}
		}
		return r.Apply(ctx, w, native)
	}
	if s, ok := c.Feature(); ok && s.Operation == session.IssueOperation() {
		native, err := nativeIssue(c)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		return r.Apply(ctx, w, native)
	}
	native, err := nativeRevocation(c)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if lenFeatureFields(c) == 6 {
		if err = r.requireReplayEvidence(ctx, w, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return r.Apply(ctx, w, native)
}

func lenFeatureFields(c identity.Command) int {
	s, _ := c.Feature()
	return len(s.Fields)
}

// Apply requires this exact repository's active coordinator feature invocation.
// Configured authenticated issuance stages the complete session/family record
// and retained evidence after protected initial admission; the coordinator owns
// original opaque proof consumption and the required final eligibility check.
// Revocation stages one active-to-revoked family transition and a retained command
// binding through that Work, with a full-width checked successor. Every sibling
// is invalidated by the current family tombstone/version without rewriting its
// original session snapshot. Missing, foreign-owner, stale or revoked targets
// return redacted errors, never evidence of another user's existence.
// The caller must already be authorized by the owning service; no opaque proof or
// bearer is accepted, minted or revealed. The returned receipt is provisional.
// This method never begins/closes/retains a transaction or performs network IO;
// any error requires coordinator Abort. Calls on independent Work are safe.
func (r *Repository) Apply(ctx context.Context, w identitypostgres.Work, c session.SessionCommand) (identity.FeatureReceipt, error) {
	if ctx == nil || r == nil || r.schema == "" {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if issue, ok := c.Issue(); ok {
		return r.applyIssue(ctx, w, issue)
	}
	if one, ok := c.RevokeOne(); ok {
		return r.applyRevokeOne(ctx, w, one)
	}
	s, ok := c.RevokeFamily()
	if !ok {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || b != s.Binding || feature.Operation != session.RevokeFamilyOperation() || transition.BeforeVersion != s.ExpectedVersion || transition.AfterVersion != s.ExpectedVersion+1 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	n, err := w.Exec(ctx, `UPDATE `+r.schema+`.families SET state='revoked',version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND family_id=$3 AND state='active' AND version=$4::numeric`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(s.ExpectedVersion, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	id, digest := revocationEvidence(b, transition)
	n, err = w.Exec(ctx, `INSERT INTO `+r.schema+`.family_revocations(tenant_id,command_id,purpose,user_id,family_id,before_version,after_version,binding_digest) VALUES($1,$2,$3,$4,$5,$6::numeric,$7::numeric,$8)`, string(b.TenantID), id, b.OperationID, string(b.UserID), b.RecordID, strconv.FormatUint(transition.BeforeVersion, 10), strconv.FormatUint(transition.AfterVersion, 10), digest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: transition.BeforeVersion, AfterVersion: transition.AfterVersion}, nil
}

// RecoverParticipant reads this invocation's exact retained mutation binding
// on the locked primary. Absence proves native noncommit only because these
// bindings are never pruned with session payloads and all writes share the sole
// coordinator transaction. Exact presence proves this participant committed,
// not the complete command receipt. Conflicting/corrupt/missing infrastructure
// stays Unknown; current family state is never used to reconstruct success.
func (r *Repository) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if ctx == nil || r == nil || r.schema == "" {
		return identitypostgres.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	if _, feature, _, err := w.FeatureScope(r); err == nil && feature.Operation == cleanupOperation() {
		return r.recoverCleanup(ctx, w)
	}
	if _, feature, _, err := w.FeatureScope(r); err == nil && feature.Operation == session.RotateOperation() {
		return r.recoverRotation(ctx, w)
	}
	if _, feature, _, err := w.FeatureScope(r); err == nil && (feature.Operation == session.RevokeOtherOperation() || feature.Operation == session.RevokeAllOperation()) {
		return r.recoverRevokeSet(ctx, w)
	}
	if _, feature, _, err := w.FeatureScope(r); err == nil && feature.Operation == session.IssueOperation() {
		return r.recoverIssue(ctx, w)
	}
	if _, feature, _, err := w.FeatureScope(r); err == nil && feature.Operation == session.RevokeOneOperation() {
		return r.recoverRevokeOne(ctx, w)
	}
	b, feature, transition, err := w.FeatureScope(r)
	if err != nil || feature.Operation != session.RevokeFamilyOperation() || transition.BeforeVersion == 0 || transition.BeforeVersion == ^uint64(0) || transition.AfterVersion != transition.BeforeVersion+1 {
		return identitypostgres.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	id, digest := revocationEvidence(b, transition)
	rows, err := w.Query(ctx, `SELECT user_id,family_id,purpose,before_version::text,after_version::text,binding_digest FROM `+r.schema+`.family_revocations WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id)
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return identitypostgres.RecoveryUnknown, err
		}
		return identitypostgres.RecoveryNotCommitted, nil
	}
	var user, family, purpose, before, after string
	var stored []byte
	if err := rows.Scan(&user, &family, &purpose, &before, &after, &stored); err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	if rows.Next() || rows.Err() != nil {
		return identitypostgres.RecoveryUnknown, identity.UnavailableError{}
	}
	if user != string(b.UserID) || family != b.RecordID || purpose != b.OperationID || before != strconv.FormatUint(transition.BeforeVersion, 10) || after != strconv.FormatUint(transition.AfterVersion, 10) || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return identitypostgres.RecoveryUnknown, nil
	}
	return identitypostgres.RecoveryCommitted, nil
}

// This portable non-secret binding complements (never replaces) the sole
// coordinator's keyed intent/receipt. Scope includes actor, policy and schema;
// transition includes the exact expected successor. JSON preserves uint64 and
// is used only for the closed scalar digest input, not as a command codec.
func revocationEvidence(b identity.CommandBinding, l identitypostgres.LifecyclePlan) ([]byte, [32]byte) {
	id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	bytes, _ := json.Marshal(struct {
		Binding       identity.CommandBinding
		Before, After uint64
	}{b, l.BeforeVersion, l.AfterVersion})
	return id, sha256.Sum256(append([]byte("identity-session-family-revocation-v1\x00"), bytes...))
}
