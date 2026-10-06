package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

var _ identitypostgres.CaptchaExecutionContributor = (*Repository)(nil)

// CheckCaptchaEvidence authenticates admitted native custody and current
// selected policy, locks the exact reserved primary row and checks its original
// facts and exclusive expiry after exclusion. It grants no independent domain
// authority. The invocation and rows are not retained; no provider, callback or
// private transaction runs. Concurrent invocations use independent handles.
func (r *Repository) CheckCaptchaEvidence(ctx context.Context, w identitypostgres.CaptchaApplyWork) error {
	_, _, err := r.checkCaptchaUse(ctx, w)
	return err
}

// FinalizeCaptchaEvidence repeats current-use validation and terminally CASes
// the exact reserved generation in the protected domain transaction. Original
// issuance, expiry and reservation time never change. Failure requires the
// coordinator to roll back all provisional effects; it is not release proof.
func (r *Repository) FinalizeCaptchaEvidence(ctx context.Context, w identitypostgres.CaptchaFinalizeWork) error {
	b, args, err := r.checkCaptchaUse(ctx, w)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE `+r.schema+`.captcha_issued_evidence e SET state='finalized',terminal_at=clock_timestamp()
 WHERE `+reservedCaptchaUsePredicate+` AND expires_at>clock_timestamp() AND reserved_at<=clock_timestamp()`, args...)
	if err != nil {
		return err
	}
	if n != 1 || b.PreviousGeneration != 0 {
		return identity.ConflictError{}
	}
	return nil
}

// ReleaseCaptchaEvidence records terminal release only through the exact
// coordinator-owned rollback or unanimous primary noncommit invocation. Current
// verifier removal and historical expiry do not obstruct cleanup and never
// grant proof or reusability. Exact predecessor custody is CASed to the supplied
// generation without renewing the original interval. Handles are serial-use,
// bounded and not retained; no private transaction or callbacks run.
func (r *Repository) ReleaseCaptchaEvidence(ctx context.Context, w identitypostgres.CaptchaReleaseWork) error {
	if ctx == nil || r == nil || r.schema == "" {
		return risk.ErrInvalidEvidenceExecution
	}
	b, err := w.Binding(r)
	if err != nil {
		return err
	}
	args, err := reservedCaptchaUseArgs(b, b.PreviousGeneration)
	if err != nil {
		return err
	}
	args = append(args, strconv.FormatUint(b.Generation, 10))
	n, err := w.Exec(ctx, `UPDATE `+r.schema+`.captcha_issued_evidence e SET state='released',consumer_generation=$15::numeric,terminal_at=clock_timestamp()
 WHERE `+reservedCaptchaUsePredicate+` AND reserved_at<=clock_timestamp()`, args...)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// These two current-use phases deliberately share exactly the same check. The
// interface remains private: only the sealed coordinator handles can supply it.
type captchaCurrentWork interface {
	Binding(identitypostgres.CaptchaUseReservationContributor) (identitypostgres.CaptchaUseReservationBinding, error)
	NativeCommand(identitypostgres.CaptchaUseReservationContributor) (identity.Command, error)
	Query(context.Context, string, ...any) (*identitypostgres.WorkRows, error)
	DatabaseTime(context.Context) (time.Time, error)
}

func (r *Repository) checkCaptchaUse(ctx context.Context, w captchaCurrentWork) (identitypostgres.CaptchaUseReservationBinding, []any, error) {
	bad := func() (identitypostgres.CaptchaUseReservationBinding, []any, error) {
		return identitypostgres.CaptchaUseReservationBinding{}, nil, identity.ConflictError{}
	}
	if ctx == nil || r == nil || r.schema == "" {
		return identitypostgres.CaptchaUseReservationBinding{}, nil, risk.ErrInvalidEvidenceExecution
	}
	b, err := w.Binding(r)
	if err != nil {
		return identitypostgres.CaptchaUseReservationBinding{}, nil, err
	}
	command, err := w.NativeCommand(r)
	if err != nil {
		return identitypostgres.CaptchaUseReservationBinding{}, nil, err
	}
	s, ok := command.Feature()
	if !ok || s.Binding != b.Command || b.PreviousGeneration != 0 || r.ValidateCaptchaUseCommand(command, b.Plan) != nil {
		return bad()
	}
	claim, err := restoreCaptchaUseCommand(command, r.keys, r.policy)
	if err != nil {
		return bad()
	}
	p := claim.Prepared()
	args, err := reservedCaptchaUseArgs(b, b.Generation)
	if err != nil {
		return bad()
	}
	rows, err := w.Query(ctx, `SELECT e.intent_digest,e.proof_digest,e.hostname,e.reserved_at FROM `+r.schema+`.captcha_issued_evidence e WHERE `+reservedCaptchaUsePredicate+` FOR UPDATE OF e`, args...)
	if err != nil {
		return identitypostgres.CaptchaUseReservationBinding{}, nil, err
	}
	var intent, proof []byte
	var hostname string
	var reservedAt time.Time
	matched := rows.Next() && rows.Scan(&intent, &proof, &hostname, &reservedAt) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched {
		return bad()
	}
	original, err := r.restoreCaptchaOriginal(p.Original)
	if err != nil {
		return bad()
	}
	record, err := original.Materialize(p.IssuedAt)
	if err != nil || !bytes.Equal(intent, record.IntentDigest[:]) || !bytes.Equal(proof, record.ProofDigest[:]) || hostname != record.Hostname || record.EvidenceDigest != p.EvidenceDigest {
		return bad()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identitypostgres.CaptchaUseReservationBinding{}, nil, err
	}
	if now.Before(reservedAt) {
		return bad()
	}
	for _, custody := range r.captcha {
		if _, err := custody.RecheckUse(p.Original, p, now); err == nil {
			return b, args, nil
		}
	}
	return bad()
}

// Only an exact still-reserved predecessor is negative finalization evidence.
// Missing, terminal or divergent rows are unknown; the coordinator must obtain
// every other participant's evidence before invoking release. No expiry or
// current configuration check may reinterpret historical ownership.
func (r *Repository) recoverCaptchaUse(ctx context.Context, w identitypostgres.RecoveryWork, b identitypostgres.CaptchaUseReservationBinding) (identitypostgres.RecoveryStatus, error) {
	args, err := reservedCaptchaUseArgs(b, b.PreviousGeneration)
	if err != nil {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM `+r.schema+`.captcha_issued_evidence e WHERE `+reservedCaptchaUsePredicate+`)`, args...)
	if err != nil {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	defer rows.Close()
	var exact bool
	if !rows.Next() || rows.Scan(&exact) != nil || rows.Next() || rows.Err() != nil || !exact {
		return identitypostgres.RecoveryUnknown, risk.ErrEvidenceUnavailable
	}
	return identitypostgres.RecoveryNotCommitted, nil
}

const reservedCaptchaUsePredicate = `e.tenant_id=$1 AND e.key_version=$2 AND e.evidence_digest=$3 AND e.command_id=$4
 AND e.user_id=$5 AND e.anonymous_flow_id=$6 AND e.issued_at=$7 AND e.expires_at=$8 AND e.state='reserved'
 AND e.consumer_command_id=$9 AND e.consumer_purpose=$10 AND e.consumer_fingerprint=$11
 AND e.consumer_generation=$12::numeric AND e.consumer_binding_digest=$13 AND e.consumer_signature=$14
 AND e.reserved_at IS NOT NULL AND e.terminal_at IS NULL
 AND EXISTS(SELECT 1 FROM identity.commands c WHERE c.command_id=e.command_id AND c.tenant_id=e.tenant_id AND c.purpose=e.command_purpose AND c.state='committed' AND c.terminal_class='committed')`

func reservedCaptchaUseArgs(b identitypostgres.CaptchaUseReservationBinding, generation uint64) ([]any, error) {
	p := b.Plan
	original, err := base64.RawURLEncoding.Strict().DecodeString(p.IssuanceCommandID)
	if err != nil || len(original) != 16 {
		return nil, identity.ConflictError{}
	}
	consumer, err := base64.RawURLEncoding.Strict().DecodeString(string(b.Command.CommandID))
	if err != nil || len(consumer) != 16 || bytes.Equal(original, consumer) || generation == 0 || b.Generation == 0 || b.Fingerprint == ([32]byte{}) || p.Signature == ([32]byte{}) {
		return nil, identity.ConflictError{}
	}
	link := bindingDigest(b.Command)
	return []any{string(b.Command.TenantID), int64(p.KeyVersion), p.EvidenceDigest[:], original, string(b.Command.UserID), b.Command.AnonymousFlowID, p.IssuedAt, p.ExpiresAt, consumer, b.Command.OperationID, b.Fingerprint[:], strconv.FormatUint(generation, 10), link[:], p.Signature[:]}, nil
}
