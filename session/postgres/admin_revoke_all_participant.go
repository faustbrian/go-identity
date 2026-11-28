package postgres

import (
	"context"
	"crypto/subtle"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type adminRevokeAllParticipant struct {
	*Repository
	config  AdminRevokeExecutorConfig
	request session.AdminSessionRevocation
}

var _ kernel.FeatureCommitContributor = (*adminRevokeAllParticipant)(nil)

func (*adminRevokeAllParticipant) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{session.AdminSessionRevokeAllOperation()}
}

func mapAdminRevokeAllCommand(b identity.CommandBinding, before uint64) (identity.Command, error) {
	if b.ActorKind != authorization.SubjectUser || b.RecordID != string(b.UserID) || before == ^uint64(0) {
		return identity.Command{}, session.ErrInvalidSessionCommand
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: session.AdminSessionRevokeAllOperation(), Fields: []identity.FeatureField{
		{Name: "subject.version-before", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: before}},
	}})
}

func adminRevokeAllCommand(c identity.Command) (identity.FeatureCommandSpec, uint64, error) {
	s, ok := c.Feature()
	if !ok || s.Operation != session.AdminSessionRevokeAllOperation() || s.Binding.ActorKind != authorization.SubjectUser || s.Binding.RecordID != string(s.Binding.UserID) || len(s.Fields) != 1 {
		return s, 0, session.ErrInvalidSessionCommand
	}
	v := s.Fields[0]
	if v.Name != "subject.version-before" || v.Value.Kind != identity.FeatureUint64 || v.Value.Uint64 == ^uint64(0) {
		return s, 0, session.ErrInvalidSessionCommand
	}
	return s, v.Value.Uint64, nil
}

func adminRevokeAllTransition(before uint64) kernel.LifecyclePlan {
	return kernel.LifecyclePlan{EventType: "session.set-revoked.v1", BeforeVersion: before, AfterVersion: before + 1}
}

func (p *adminRevokeAllParticipant) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	s, before, err := adminRevokeAllCommand(c)
	if p == nil || p.Repository == nil || err != nil || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != s.Operation || plan.SubjectType != "session_set" || plan.Capability != nil || plan.Lifecycle == nil || *plan.Lifecycle != adminRevokeAllTransition(before) || len(plan.Audits) != 1 {
		return session.ErrInvalidSessionCommand
	}
	a := plan.Audits[0]
	if a.EventType != s.Operation.OperationID || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return session.ErrInvalidSessionCommand
	}
	return nil
}

func (p *adminRevokeAllParticipant) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	var out identity.FeatureReceipt
	if p == nil || p.Repository == nil || ctx == nil {
		return out, session.ErrInvalidSessionCommand
	}
	s, before, err := adminRevokeAllCommand(c)
	if err != nil {
		return out, err
	}
	b, feature, transition, err := w.FeatureScope(p)
	prepared, present := p.request.Binding()
	if err != nil || !present || b != s.Binding || b != prepared || feature.Operation != s.Operation || transition != adminRevokeAllTransition(before) {
		return out, session.ErrInvalidSessionCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.maximumDuration)
	defer stop()
	if _, err = requireAdminRevocationActor(ctx, w, p, p.config.Actor, b, p.request.Caller()); err != nil {
		return out, err
	}
	if err := requireAdminRevokeAllTarget(ctx, w, b); err != nil {
		return out, err
	}
	// Coordinator Work holds the tenant mutation fence even for an empty set.
	// Recheck under that fence the generation frozen before reservation; all
	// issuance and rotation using this coordinator are ordered around the set.
	current, err := readAdminRevokeAllVersion(ctx, w, p.schema, b.TenantID, b.UserID)
	if err != nil {
		return out, err
	}
	if current != before {
		return out, identity.ConflictError{}
	}
	count, err := lockAdminRevokeAllRows(ctx, w, p.schema, b)
	if err != nil {
		return out, err
	}
	if err = p.Repository.requireAdminRevocationSession(ctx, w, p.config.Sessions, p.request, p.config.CSRFKey); err != nil {
		return out, err
	}
	if count != 0 {
		n, err := w.Exec(ctx, adminRevokeAllUpdateSQL(p.schema), string(b.TenantID), string(b.UserID))
		if err != nil {
			return out, err
		}
		if n != int64(count) {
			return out, identity.ConflictError{}
		}
	}
	id, binding := revocationEvidence(b, transition)
	digest := setResultDigest(b, before, transition.AfterVersion, transition.AfterVersion, count, true)
	n, err := w.Exec(ctx, adminRevokeAllInsertSQL(p.schema), string(b.TenantID), id, b.OperationID, string(b.UserID), strconv.FormatUint(before, 10), strconv.FormatUint(transition.AfterVersion, 10), int64(count), binding[:], digest[:])
	if err != nil {
		return out, err
	}
	if n != 1 {
		return out, identity.ConflictError{}
	}
	return identity.FeatureReceipt{Operation: feature.Operation, BeforeVersion: before, AfterVersion: transition.AfterVersion}, nil
}

func (p *adminRevokeAllParticipant) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	return checkAdminRevocationCommit(ctx, w, p, c, p.request, p.config.Sessions, session.AdminSessionRevokeAllOperation())
}

func (p *adminRevokeAllParticipant) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p == nil || p.Repository == nil || ctx == nil {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, transition, err := w.FeatureScope(p)
	if err != nil || f.Operation != session.AdminSessionRevokeAllOperation() || transition.BeforeVersion == ^uint64(0) || transition != adminRevokeAllTransition(transition.BeforeVersion) || b.RecordID != string(b.UserID) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	_, present, err := readAdminRevokeAllReceipt(ctx, w, p.schema, b, transition)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	if !present {
		return kernel.RecoveryNotCommitted, nil
	}
	return kernel.RecoveryCommitted, nil
}

func requireAdminRevokeAllTarget(ctx context.Context, w kernel.Work, b identity.CommandBinding) error {
	rows, err := w.Query(ctx, adminRevokeAllTargetSQL, string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var got string
	if err := readSessionAdmission(rows, &got); err != nil {
		return admissionError(ctx, err)
	}
	if got != string(b.UserID) {
		return identity.ForbiddenError{}
	}
	return nil
}

const adminRevokeAllTargetSQL = `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`

func lockAdminRevokeAllRows(ctx context.Context, w kernel.Work, schema string, b identity.CommandBinding) (uint32, error) {
	var count uint32
	cursor := ""
	const pageSize = 128
	for {
		rows, err := w.Query(ctx, adminRevokeAllLockSQL(schema), string(b.TenantID), string(b.UserID), cursor, int64(pageSize))
		if err != nil {
			return 0, err
		}
		page := 0
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				break
			}
			page++
			count++
			if id <= cursor || page > pageSize || count > session.MaxAdminSessionRevokeCount {
				err = identity.ConflictError{}
				break
			}
			cursor = id
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return 0, err
		}
		if page < pageSize {
			return count, nil
		}
	}
}

func readAdminRevokeAllVersion[R SessionRows](ctx context.Context, q SessionQueryer[R], schema string, tenant identity.TenantID, user identity.UserID) (uint64, error) {
	rows, err := q.Query(ctx, adminRevokeAllVersionSQL(schema), string(tenant), string(user))
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	if !rows.Next() {
		return 0, rows.Err()
	}
	var raw string
	if rows.Scan(&raw) != nil || rows.Next() || rows.Err() != nil {
		return 0, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || v == 0 {
		return 0, identity.UnavailableError{}
	}
	return v, nil
}

func readAdminRevokeAllReceipt[R SessionRows](ctx context.Context, q SessionQueryer[R], schema string, b identity.CommandBinding, transition kernel.LifecyclePlan) (session.AdminSessionRevokeAllResult, bool, error) {
	var out session.AdminSessionRevokeAllResult
	id, binding := revocationEvidence(b, transition)
	rows, err := q.Query(ctx, adminRevokeAllReceiptSQL(schema), string(b.TenantID), id)
	if err != nil {
		return out, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return out, false, rows.Err()
	}
	var purpose, user, before, after string
	var count int64
	var gotBinding, gotResult []byte
	if rows.Scan(&purpose, &user, &before, &after, &count, &gotBinding, &gotResult) != nil || rows.Next() || rows.Err() != nil || count < 0 || count > int64(session.MaxAdminSessionRevokeCount) {
		return out, false, identity.UnavailableError{}
	}
	digest := setResultDigest(b, transition.BeforeVersion, transition.AfterVersion, transition.AfterVersion, uint32(count), true)
	if purpose != b.OperationID || user != string(b.UserID) || before != strconv.FormatUint(transition.BeforeVersion, 10) || after != strconv.FormatUint(transition.AfterVersion, 10) || subtle.ConstantTimeCompare(gotBinding, binding[:]) != 1 || subtle.ConstantTimeCompare(gotResult, digest[:]) != 1 {
		return out, false, identity.UnavailableError{}
	}
	return session.AdminSessionRevokeAllResult{RevokedCount: uint32(count), SubjectVersion: transition.AfterVersion}, true, nil
}

func adminRevokeAllLockSQL(schema string) string {
	return `SELECT session_id FROM ` + schema + `.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active' AND session_id>$3 ORDER BY session_id LIMIT $4 FOR UPDATE`
}

func adminRevokeAllUpdateSQL(schema string) string {
	return `UPDATE ` + schema + `.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2 AND state='active'`
}

func adminRevokeAllVersionSQL(schema string) string {
	// Qualify the source column so ORDER BY uses the numeric version, not
	// the identically named text projection consumed by pgx.
	return `SELECT e.subject_version::text FROM ` + schema + `.admin_set_revocations AS e WHERE e.tenant_id=$1 AND e.user_id=$2 ORDER BY e.subject_version DESC LIMIT 1`
}

func adminRevokeAllInsertSQL(schema string) string {
	return `INSERT INTO ` + schema + `.admin_set_revocations(tenant_id,command_id,purpose,user_id,before_version,subject_version,revoked_count,binding_digest,result_digest) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9)`
}

func adminRevokeAllReceiptSQL(schema string) string {
	return `SELECT purpose,user_id,before_version::text,subject_version::text,revoked_count,binding_digest,result_digest FROM ` + schema + `.admin_set_revocations WHERE tenant_id=$1 AND command_id=$2`
}
