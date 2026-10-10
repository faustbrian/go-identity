package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type emailVerificationProgress struct {
	intent             EmailVerificationIntent
	mutation           identity.IdentifierMutation
	at                 time.Time
	applied, finalized bool
}

func prepareEmailVerification(ctx context.Context, w Work, command identity.Command) error {
	plan := w.state.execution.reservation.plan
	var native EmailVerificationContributor
	var repo *Repository
	for _, e := range plan.contributors {
		if e.descriptor == plan.feature.Contributor {
			native, _ = e.contributor.(EmailVerificationContributor)
		}
		if e.descriptor.Owner == "identity/postgres" {
			repo, _ = e.contributor.(*Repository)
		}
	}
	if repo == nil || repo.read == nil || native == nil || w.state.emailVerification != nil {
		return w.fail(ctx, invalidEmailVerification())
	}
	intent, err := emailVerificationCommand(native, command, plan.snapshot())
	if err != nil {
		return w.fail(ctx, err)
	}
	state, now, err := lockIdentifierPartition(ctx, w, intent.Change)
	if err != nil {
		return err
	}
	matched := false
	for _, i := range state.Identifiers {
		if i.ID == intent.Change.ID {
			matched = i.Kind == identity.IdentifierEmail && i.CanonicalValue == intent.CanonicalAddress && !i.Primary && !i.Verified
		}
	}
	if !matched {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	origin, err := base64.RawURLEncoding.DecodeString(string(intent.RegistrationCommandID))
	if err != nil {
		return w.fail(ctx, invalidEmailVerification())
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.registration_bindings r JOIN identity.commands c USING(tenant_id,purpose,command_id) WHERE r.tenant_id=$1 AND r.purpose='identity.password.signup' AND r.command_id=$2 AND r.user_id=$3 AND r.identifier_id=$4 AND c.state='committed')`, string(intent.Change.TenantID), origin, string(intent.Change.UserID), string(intent.Change.ID))
	if err != nil {
		return err
	}
	var exists bool
	valid := rows.Next() && rows.Scan(&exists) == nil
	if rows.Next() || rows.Err() != nil {
		valid = false
	}
	rows.Close()
	if !valid {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if !exists {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	mutation, err := identity.ApplyIdentifierChange(state, intent.Change, now)
	if err != nil {
		return w.fail(ctx, err)
	}
	w.state.emailVerification = &emailVerificationProgress{intent: intent, mutation: mutation, at: now}
	return nil
}

func applyEmailVerification(ctx context.Context, w Work) error {
	p := w.state.emailVerification
	if p == nil || p.applied {
		return w.fail(ctx, invalidEmailVerification())
	}
	c := p.intent.Change
	if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.identifiers SET verified=true,version=version+1,verification_state=2,verification_version=verification_version+1,verified_at=$6 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND kind='email' AND canonical_value=$4 AND version=$5::numeric AND verification_version=1 AND verification_state=1 AND NOT verified AND NOT is_primary`, string(c.TenantID), string(c.UserID), string(c.ID), p.intent.CanonicalAddress, strconv.FormatUint(c.ExpectedIdentifierVersion, 10), p.at)
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	n, err = w.Exec(ctx, `UPDATE identity.users SET version=version+1,identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active' AND version=$3::numeric AND identifier_version=$4::numeric`, string(c.TenantID), string(c.UserID), strconv.FormatUint(c.ExpectedUserVersion, 10), strconv.FormatUint(c.ExpectedAuthorityVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	key, err := base64.RawURLEncoding.DecodeString(string(w.state.binding.CommandID))
	if err != nil {
		return w.fail(ctx, invalidEmailVerification())
	}
	origin, err := base64.RawURLEncoding.DecodeString(string(p.intent.RegistrationCommandID))
	if err != nil {
		return w.fail(ctx, invalidEmailVerification())
	}
	n, err = w.Exec(ctx, `INSERT INTO identity.email_verifications(tenant_id,user_id,identifier_id,command_id,command_key,registration_command_key,before_user_version,after_user_version,before_authority_version,after_authority_version,verified_at) VALUES($1,$2,$3,$4,$5,$6,$7::numeric,$8::numeric,$9::numeric,$10::numeric,$11)`, string(c.TenantID), string(c.UserID), string(c.ID), string(w.state.binding.CommandID), key, origin, strconv.FormatUint(c.ExpectedUserVersion, 10), strconv.FormatUint(c.ExpectedUserVersion+1, 10), strconv.FormatUint(c.ExpectedAuthorityVersion, 10), strconv.FormatUint(c.ExpectedAuthorityVersion+1, 10), p.at)
	if err != nil {
		return err
	}
	if n != 1 {
		return w.fail(ctx, identity.ConflictError{})
	}
	p.applied = true
	return nil
}

func (c *Coordinator) finalizeEmailVerification(w Work) error {
	p := w.state.emailVerification
	if p == nil {
		return nil
	}
	if !p.applied || p.finalized || w.state.featureReceipt == nil {
		return w.fail(w.state.ctx, invalidEmailVerification())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	p.finalized = true
	return nil
}

func recoverEmailVerification(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.email_verifications WHERE command_id=$1 AND tenant_id=$2 AND user_id=$3 AND identifier_id=$4)`, string(b.CommandID), string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}
