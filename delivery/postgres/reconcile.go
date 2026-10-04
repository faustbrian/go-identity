package postgres

import (
	"context"
	"crypto/hmac"
	"errors"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
)

// reconcileIn applies already authenticated provider evidence in a borrowed
// transaction. Before/after are purpose-scoped keyed cursor commitments; zero
// before starts a query sequence, zero after ends it, not the effect. ExpectedStep
// fences exact prior progress so later polling may restart an unresolved effect
// without permitting stale initial requests to reopen a completed sequence.
// The caller owns
// cursor custody, current policy, original kernel command/audit/lifecycle and
// query outside transactions. This phase never queries a provider, grants retry
// permission, closes a transaction or supplies a second reservation authority.
func (s *receiptStore) reconcileIn(ctx context.Context, sql cancellationSQL, q delivery.ReceiptRecordRequest, subject string, expectedStep int64, before, after [32]byte) (delivery.ReceiptRecordResult, error) {
	if s == nil || q.Validate() != nil {
		return delivery.ReceiptRecordResult{}, delivery.ErrInvalidInput
	}
	event, evidence := s.digests(q)
	return s.reconcileEvidenceIn(ctx, sql, q, subject, expectedStep, before, after, event, evidence)
}

// Protected commands carry original keyed evidence, never raw provider events.
// Do not rehash the redacted placeholder produced by the command decoder.
func (s *receiptStore) reconcileEvidenceIn(ctx context.Context, sql cancellationSQL, q delivery.ReceiptRecordRequest, subject string, expectedStep int64, before, after, event, evidence [32]byte) (delivery.ReceiptRecordResult, error) {
	if ctx == nil || s == nil || !safeID(s.deployment, false) || s.namespaceKey == ([32]byte{}) || sql.scan == nil || sql.exec == nil || q.Validate() != nil || !safeID(subject, false) || expectedStep < 0 || expectedStep == 9223372036854775807 {
		return delivery.ReceiptRecordResult{}, delivery.ErrInvalidInput
	}
	if event == ([32]byte{}) || evidence == ([32]byte{}) {
		return delivery.ReceiptRecordResult{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	var state, provider string
	err := sql.scan(ctx, `SELECT state,provider FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND subject_id=$4 FOR UPDATE`, []any{s.deployment, string(q.TenantID), string(q.IntentID), subject}, &state, &provider)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, delivery.ErrNotFound
	}
	if err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	if provider != q.Provider {
		return delivery.ReceiptRecordResult{}, delivery.ErrForbidden
	}
	var priorBefore, priorAfter []byte
	var priorEffect string
	var priorGeneration, priorStep int64
	err = sql.scan(ctx, `SELECT effect_id,generation,step,before_digest,after_digest FROM identity.delivery_reconciliation_checkpoints WHERE deployment=$1 AND tenant_id=$2 AND provider=$3 AND event_digest=$4`, []any{s.deployment, string(q.TenantID), provider, event[:]}, &priorEffect, &priorGeneration, &priorStep, &priorBefore, &priorAfter)
	if err == nil {
		if priorEffect != string(q.IntentID) || priorGeneration != int64(q.Generation) || priorStep != expectedStep+1 || !hmac.Equal(priorBefore, before[:]) || !hmac.Equal(priorAfter, after[:]) {
			return delivery.ReceiptRecordResult{}, delivery.ErrConflict
		}
		// Existing receipt evidence owns immutable result and changed-input denial.
		return s.recordEvidenceIn(ctx, sql, q, subject, event, evidence)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	var generation int64
	var live bool
	err = sql.scan(ctx, `SELECT generation,lease_owner IS NOT NULL AND lease_until>clock_timestamp() FROM identity.delivery_processing WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 FOR UPDATE`, []any{s.deployment, string(q.TenantID), string(q.IntentID)}, &generation, &live)
	if errors.Is(err, pgx.ErrNoRows) {
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	}
	if err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	if generation != int64(q.Generation) || live || state != "outcome-unknown" && state != "submitted" {
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	}
	var step int64
	var latest []byte
	err = sql.scan(ctx, `SELECT step,after_digest FROM identity.delivery_reconciliation_checkpoints WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3 AND generation=$4 ORDER BY step DESC LIMIT 1`, []any{s.deployment, string(q.TenantID), string(q.IntentID), generation}, &step, &latest)
	if errors.Is(err, pgx.ErrNoRows) {
		if before != ([32]byte{}) || expectedStep != 0 {
			return delivery.ReceiptRecordResult{}, delivery.ErrConflict
		}
	} else if err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	} else if step < 1 || step != expectedStep || len(latest) != 32 || !hmac.Equal(latest, before[:]) {
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	}
	out, err := s.recordEvidenceIn(ctx, sql, q, subject, event, evidence)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	// An event already admitted through a different path cannot acquire a new
	// query checkpoint or reverse a later generation's progress.
	if out.Deduplicated {
		return delivery.ReceiptRecordResult{}, delivery.ErrConflict
	}
	if err := sql.exec(ctx, `INSERT INTO identity.delivery_reconciliation_checkpoints(deployment,tenant_id,effect_id,generation,step,provider,event_digest,before_digest,after_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, s.deployment, string(q.TenantID), string(q.IntentID), generation, step+1, provider, event[:], before[:], after[:]); err != nil {
		return delivery.ReceiptRecordResult{}, attemptFailure(ctx, err)
	}
	return out, nil
}
