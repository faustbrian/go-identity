package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// Protective revocation grants no positive authority: a blocked owner or stale
// credential cannot prevent denial of a compromised family. Exact retired
// bearer lineage and current configured service policy own this narrow action.
func (r *Repository) requireReplayEvidence(ctx context.Context, w kernel.Work, command identity.Command) error {
	proof, err := nativeReplayEvidence(command)
	if err != nil {
		return err
	}
	b, feature, transition, err := w.FeatureScope(r)
	spec, _ := command.Feature()
	if err != nil || b != spec.Binding || feature.Operation != session.RevokeFamilyOperation() || transition.BeforeVersion != proof.version || transition.AfterVersion != proof.version+1 {
		return session.ErrInvalidSessionCommand
	}
	rows, err := w.Query(ctx, `SELECT version::text FROM `+r.schema+`.families WHERE tenant_id=$1 AND user_id=$2 AND family_id=$3 AND state='active' AND version=$4::numeric FOR UPDATE`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(proof.version, 10))
	if err != nil {
		return err
	}
	var version string
	err = readSessionAdmission(rows, &version)
	rows.Close()
	if err != nil || version != strconv.FormatUint(proof.version, 10) {
		return identity.ConflictError{}
	}
	rows, err = w.Query(ctx, r.replayEvidenceSQL(true), string(b.TenantID), int64(proof.lookup.KeyVersion), proof.lookup.Sum[:])
	if err != nil {
		return err
	}
	if !rows.Next() {
		rows.Close()
		return session.ErrUnavailable
	}
	current, err := scanReplayEvidence(rows, b.TenantID, proof.lookup)
	extra := rows.Next() || rows.Err() != nil
	rows.Close()
	if err != nil || extra || current != proof {
		return session.ErrUnavailable
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(proof.expires) {
		return identity.ForbiddenError{}
	}
	return nil
}
