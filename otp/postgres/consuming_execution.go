package postgres

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/jackc/pgx/v5"
)

var _ kernel.OTPExecutionContributor = (*Contributor)(nil)

// CheckOTP admits only the exact reserved original command under the
// coordinator's protected transaction. It authenticates the separately borrowed
// context-specific bearer and original authority, rechecks validity after downstream
// waits, and never borrows, compares, charges or persists the submitted code.
func (p *Contributor) CheckOTP(ctx context.Context, w kernel.OTPApplyWork) error {
	if ctx == nil || p == nil {
		return ErrInvalidCommand
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	spec, err := w.CommandSpec(p)
	if err != nil {
		return err
	}
	cookie, err := w.PreAuthCookie(p)
	if err != nil {
		cookie, err = w.SessionToken(p)
	}
	if err != nil {
		return err
	}
	_, _, _, err = p.checkConsuming(ctx, w, b, spec, cookie)
	return err
}

// FinalizeOTP rechecks current authority and finalizes OTP and any pre-auth flow
// in the same transaction as the protected domain, audits, outbox and receipt.
// Any prefix is provisional; coordinator failure rolls it back atomically.
func (p *Contributor) FinalizeOTP(ctx context.Context, w kernel.OTPFinalizeWork) error {
	if ctx == nil || p == nil {
		return ErrInvalidCommand
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	spec, err := w.CommandSpec(p)
	if err != nil {
		return err
	}
	cookie, err := w.PreAuthCookie(p)
	if err != nil {
		cookie, err = w.SessionToken(p)
	}
	if err != nil {
		return err
	}
	row, flow, now, err := p.checkConsuming(ctx, w, b, spec, cookie)
	if err != nil {
		return err
	}
	if flow.preauth != (session.PreAuthTransaction{}) {
		if err = sessionpg.FinalizePreAuth(ctx, w, p.preauth.config, flow.preauth, sessionpg.PreAuthUse{Command: b.Command, Fingerprint: b.Fingerprint, Generation: b.Generation}); err != nil {
			return err
		}
	}
	return terminalReservation(ctx, w.Exec, row, b, reservationFinalized, now)
}

func (p *Contributor) checkConsuming(ctx context.Context, w consumingWork, b kernel.OTPReservationBinding, spec identity.FeatureCommandSpec, cookie auth.BearerCredential) (lockedReservation, nativeFlow, time.Time, error) {
	bad := func(err error) (lockedReservation, nativeFlow, time.Time, error) {
		return lockedReservation{}, nativeFlow{}, time.Time{}, err
	}
	if b.PreviousGeneration != 0 || !validOwnership(b) || spec.Binding != b.Command {
		return bad(ErrInvalidCommand)
	}
	c, err := p.codec.restoreCustody(spec)
	if err != nil || c.authority == nil || c.authority.Directory.Query.GlobalAuthorityID != p.global || b.Command.UserID != "" && c.authority.UserAuthorization.Scope.PolicyNamespace != p.namespace {
		return bad(ErrInvalidCommand)
	}
	flow, err := p.authenticateFlowSpec(ctx, spec, b.Plan, cookie)
	if err != nil {
		return bad(err)
	}
	if err = p.requireConsumingAuthority(ctx, w, b, *c.authority); err != nil {
		return bad(err)
	}
	if err = requireNativeFlow(ctx, w, p, flow, &sessionpg.PreAuthUse{Command: b.Command, Fingerprint: b.Fingerprint, Generation: b.Generation}); err != nil {
		return bad(err)
	}
	continuation, _ := c.record.Attempt.Continuation.Bindings()
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	if _, _, err = p.lockout.loadLockouts(ctx, query, p.schema, continuation.Scope); err != nil {
		return bad(err)
	}
	row, err := loadReservation(ctx, query, p.schema, b, b.Generation, continuation.Scope.SubjectID)
	if err != nil {
		return bad(err)
	}
	retained, _, err := p.retainedOriginal(ctx, query, b)
	if err != nil {
		return bad(err)
	}
	wire, err := originalEnvelope(spec, b)
	if err != nil || !bytes.Equal(wire, retained) {
		return bad(ErrInvalidCommand)
	}
	now, err := p.consumingTime(ctx, w, *c.authority, flow)
	if err != nil {
		return bad(err)
	}
	if now.Before(row.reservedAt) || !now.Before(row.expiresAt) {
		return bad(ErrInvalidCommand)
	}
	return row, flow, now, nil
}

// ReleaseOTP requires the live coordinator-proven noncommit phase. It restores
// original code/bearer-free custody from the existing participant and terminally
// releases exact OTP and, when applicable, pre-auth reservations. Authenticated
// sessions are never reserved or released. Expiry, revoked live authority
// or lease loss cannot authorize this method and do not strand proven rollback.
// Missing/divergent custody aborts release; no independently exposed proof API,
// pool, journal, retry or transaction owner is created. Install the session
// PreAuthReleaseMigrationSource before enabling consuming execution.
func (p *Contributor) ReleaseOTP(ctx context.Context, w kernel.OTPReleaseWork) error {
	if ctx == nil || p == nil {
		return ErrInvalidCommand
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	_, c, err := p.retainedOriginal(ctx, query, b)
	if err != nil {
		return err
	}
	flow, err := retainedNativeFlow(c)
	if err != nil {
		return err
	}
	// Keep the original flow-before-challenge exclusion order. Release receives
	// sealed noncommit authority, never an expired original bearer submission.
	if flow.preauth != (session.PreAuthTransaction{}) {
		if p.preauth == nil {
			return ErrInvalidCommand
		}
		if err = sessionpg.ReleasePreAuth(ctx, w, p, p.preauth.config, flow.preauth); err != nil {
			return err
		}
	} else if flow.session != (session.Session{}) && p.sessionAuthority(flow.session, b.Command, *c.authority) != nil {
		return ErrInvalidCommand
	}
	// MFA's already-consumed primary is neither an OTP-owned preauth reservation
	// nor a session. Sealed noncommit custody releases only this exact OTP row.
	scope, _ := c.record.Attempt.Continuation.Bindings()
	row, err := loadReservation(ctx, query, p.schema, b, b.PreviousGeneration, scope.Scope.SubjectID)
	if err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return terminalReservation(ctx, w.Exec, row, b, reservationReleased, now)
}

func (p *Contributor) recoverConsuming(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, err := w.OTPBinding(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	_, c, err := p.retainedOriginal(ctx, query, b)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	flow, err := retainedNativeFlow(c)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	scope, _ := c.record.Attempt.Continuation.Bindings()
	if flow.session != (session.Session{}) || flow.mfaOriginal != (session.PreAuthTransaction{}) {
		if flow.session != (session.Session{}) && p.sessionAuthority(flow.session, b.Command, *c.authority) != nil {
			return kernel.RecoveryUnknown, ErrInvalidCommand
		}
		_, err := loadReservation(ctx, query, p.schema, b, b.PreviousGeneration, scope.Scope.SubjectID)
		if err != nil {
			if errors.Is(err, ErrInvalidCommand) {
				return kernel.RecoveryUnknown, nil
			}
			return kernel.RecoveryUnknown, err
		}
		// Neither a session nor an already-consumed MFA primary belongs to
		// this reservation. Exact OTP reserved custody, not upstream expiry
		// or revocation, supplies this owner's noncommit evidence.
		return kernel.RecoveryNotCommitted, nil
	}
	if p.preauth == nil {
		return kernel.RecoveryUnknown, ErrInvalidCommand
	}
	original, err := flow.preauth.Bindings()
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	current, err := sessionpg.ReadPreAuth(ctx, w, p.preauth.config, original.Binding.Intent.TenantID, original.Binding.ID)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	observed, err := current.Bindings()
	if err != nil || observed != original {
		return kernel.RecoveryUnknown, nil
	}
	// The retained original is independent evidence. Reading current primary
	// state only tests equality; it cannot refresh intent, epochs or validity.
	id, _ := ownershipID(string(b.Command.CommandID))
	rows, err := w.Query(ctx, `SELECT flow_id FROM `+pgx.Identifier{p.preauth.config.Schema}.Sanitize()+`.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2 AND state='reserved' AND version=$3::numeric AND issued_version=$4::numeric AND command_id=$5 AND fingerprint=$6 AND generation=$7::numeric FOR SHARE`, string(b.Command.TenantID), string(original.Binding.ID), strconv.FormatUint(original.Version+1, 10), strconv.FormatUint(original.Version, 10), id, b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	var flowID string
	ok := rows.Next() && rows.Scan(&flowID) == nil && flowID == string(original.Binding.ID)
	if rows.Next() || rows.Err() != nil {
		ok = false
	}
	rows.Close()
	if !ok {
		return kernel.RecoveryUnknown, nil
	}
	_, err = loadReservation(ctx, query, p.schema, b, b.PreviousGeneration, scope.Scope.SubjectID)
	if err != nil {
		if errors.Is(err, ErrInvalidCommand) {
			return kernel.RecoveryUnknown, nil
		}
		return kernel.RecoveryUnknown, err
	}
	// Exact retained reserved predecessors under primary exclusion prove this
	// participant never finalized. Only unanimity across every owner may release.
	return kernel.RecoveryNotCommitted, nil
}
