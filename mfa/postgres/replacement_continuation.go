package mfapostgres

import (
	"context"
	"encoding/base64"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The committed factor-update envelope is a distinct original source. Keep it
// intact rather than constructing an enable input or password verification.
func (p *totpURIPhase) restoreReplacementParent(ctx context.Context, k kernel.RequestKeyPreparationBinding, plain, secret []byte, version uint64) error {
	selected := p.state.config.Replacement
	if selected == nil || selected.Management == nil {
		return identity.ForbiddenError{}
	}
	var in factorUpdateInput
	if decodeEnrollmentJSON(plain, &in) != nil {
		clear(in.Primary)
		clear(in.Record.Original.Signature)
		return invalidAuthority()
	}
	accepted := false
	defer func() {
		if !accepted {
			clear(in.Primary)
			clear(in.Record.Original.Signature)
		}
	}()
	s, b, r := selected.Management.state(), in.Binding, p.request
	validation := &factorUpdatePhase{state: s, request: mfa.FactorUpdateRequest{Action: mfa.Replace, Origin: r.Origin, Network: r.Network}}
	if in.Schema != 1 || b.ValidateFor(factorUpdateOperation()) != nil || b.CommandID != k.Admission.CommandID || b.TenantID != r.TenantID || b.UserID != identity.UserID(r.Caller.Request.Subject.ID) || b.ActorID != k.Scope.ActorID || b.ActorKind != authorization.SubjectUser || b.RecordID != string(b.UserID) || b.PolicyID != s.shared.config.PolicyID || b.PolicyVersion != s.shared.config.Coordinator.AdmissionPolicy.PolicyVersion || b.CorrelationID != string(b.CommandID) || in.Before.Version == 0 || in.Before.Version == math.MaxUint64 || in.Before.State != mfa.FactorActive || in.Before.Method != "totp" || !validation.validReplacementInput(&in) || in.Replacement.FactorID != string(r.EnrollmentID) || in.Replacement.AuthorityVersion == 0 || in.Replacement.AuthorityVersion == math.MaxUint64 || in.CreatedAt.IsZero() || in.CreatedAt.Nanosecond()%1000 != 0 || !in.CreatedAt.Before(in.Until) || len(in.Primary) < 1 || len(in.Primary) > 32768 {
		return identity.ForbiddenError{}
	}
	if _, err := encodeFactorVerificationRecord(in.Record); err != nil {
		return err
	}
	if (mfa.ListResult{Factors: []mfa.FactorProjection{in.Before}}).ValidateAt(in.CreatedAt) != nil {
		return invalidAuthority()
	}
	var primary TOTPReplacementPrimary
	var err error
	if p.confirmation == nil {
		primary, err = selected.Primary.RestoreReplacementForURI(ctx, r, in.Primary, *in.ReplacementUntil)
	} else {
		primary, err = selected.Primary.RestoreReplacementForConfirmation(ctx, p.confirmRequest, in.Primary, *in.ReplacementUntil)
	}
	if err != nil {
		return err
	}
	original, err := primary.Original()
	if err != nil {
		return err
	}
	bound, err := original.Bindings()
	if err != nil || bound.TenantID != b.TenantID || bound.UserID != b.UserID || in.Record.Original.Proof.SessionID != bound.SessionID || in.Record.Original.Proof.SessionVersion != bound.Version || in.Record.Original.Proof.Action != b.OperationID || in.Record.Original.Issuer != s.stepup.config.Issuer || in.Record.Original.Environment != s.stepup.config.Environment {
		return identity.ForbiddenError{}
	}
	until, err := primary.OriginalDeadline()
	if err != nil {
		return err
	}
	for _, candidate := range []time.Time{in.Record.Original.Proof.Proof.ExpiresAt, in.Record.Original.Proof.Proof.IssuedAt.Add(s.config.MaximumAge), bound.Authentication.Proof.IssuedAt.Add(s.config.PrimaryMaximumAge)} {
		if candidate.Before(until) {
			until = candidate
		}
	}
	if !until.Equal(in.Until) {
		return identity.ForbiddenError{}
	}
	ceiling := in.Replacement.ExpiresAt
	for _, candidate := range []time.Time{in.Record.Original.Proof.Proof.ExpiresAt, in.Record.Original.Proof.Proof.IssuedAt.Add(s.config.MaximumAge), bound.Authentication.Proof.IssuedAt.Add(s.config.PrimaryMaximumAge)} {
		if candidate.Before(ceiling) {
			ceiling = candidate
		}
	}
	if !ceiling.Equal(*in.ReplacementUntil) {
		return identity.ForbiddenError{}
	}
	p.pending = &totpURIPending{Replacement: &in, Wire: slices.Clone(secret), RowVersion: version}
	p.primary = primary
	accepted = true
	return nil
}

func (p *totpURIPhase) deadline() (time.Time, error) {
	until, err := p.primary.Deadline()
	if err == nil && p.pending != nil && p.pending.Replacement != nil && p.pending.Replacement.ReplacementUntil.Before(until) {
		until = *p.pending.Replacement.ReplacementUntil
	}
	return until, err
}

func (p *totpURIPhase) refreshPrimary(ctx context.Context) error {
	if p.pending == nil || p.pending.Replacement == nil {
		return nil
	}
	primary, ok := p.primary.(TOTPReplacementPrimary)
	if !ok {
		return identity.ForbiddenError{}
	}
	return primary.ReadCurrent(ctx)
}

// These checks run in the original continuation Work, before generation and
// again at the final fence. Parent outcome alone cannot authorize a successor
// after predecessor replacement, metadata change, proof substitution or expiry.
func (p *totpURIPhase) checkReplacementPredecessor(ctx context.Context, w kernel.Work) error {
	in := p.pending.Replacement
	if in == nil {
		return nil
	}
	b, m := in.Binding, *in.Replacement
	parent, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT t.row_version::text,t.label,a.version::text,a.active_factors
FROM identity_mfa.totp_factors t
JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id)
JOIN identity_mfa.totp_factors n ON n.tenant_id=t.tenant_id AND n.user_id=t.user_id AND n.replaces_factor_id=t.factor_id AND n.replaces_version=$6::numeric+1 AND t.row_version>=n.replaces_version
JOIN identity_mfa.factor_update_effects e ON e.tenant_id=n.tenant_id AND e.user_id=n.user_id AND e.command_id=n.created_command_id AND e.replacement_factor_id=n.factor_id AND e.factor_id=t.factor_id
JOIN identity_mfa.factor_verifications v ON v.tenant_id=e.tenant_id AND v.user_id=e.user_id AND v.proof_id=e.proof_id AND v.used_command_id=e.command_id AND v.used_purpose=e.purpose
WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3 AND t.state=2 AND t.confirmed_at IS NOT NULL AND t.encrypted_secret IS NOT NULL AND t.last_step IS NOT NULL
AND n.factor_id=$4 AND n.state=1 AND n.created_command_id=$5 AND n.created_purpose='identity.mfa.factor-update'
AND e.purpose=n.created_purpose AND e.action=3 AND e.before_version=$6::numeric AND e.after_version=n.replaces_version AND e.before_authority=$7::numeric AND e.after_authority=e.before_authority AND v.proof_id=$8 AND t.enrollment_version=$9::numeric
FOR SHARE OF t,a,e,v`, string(b.TenantID), string(b.UserID), string(in.Before.ID), m.FactorID, parent, strconv.FormatUint(in.Before.Version, 10), strconv.FormatUint(m.AuthorityVersion, 10), string(in.Record.Original.Proof.Proof.ID), strconv.FormatUint(in.Record.Original.CredentialVersion, 10))
	if err != nil {
		return err
	}
	var version, label, authority string
	var count int32
	if !rows.Next() || rows.Scan(&version, &label, &authority, &count) != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	currentVersion, versionErr := strconv.ParseUint(version, 10, 64)
	if extra || rowErr != nil || versionErr != nil || version != strconv.FormatUint(currentVersion, 10) || currentVersion < in.Before.Version+1 || currentVersion == math.MaxUint64 || label != in.Before.Label || authority != strconv.FormatUint(m.AuthorityVersion, 10) || count != 1 {
		return identity.ForbiddenError{}
	}
	// Last-step replay updates advance this row without changing management
	// authority. The original receipt/lineage stays fixed; only this locked
	// invocation's retirement CAS follows that benign advancement.
	p.predecessorRowVersion = currentVersion
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(in.CreatedAt) || !now.Before(*in.ReplacementUntil) || !now.Before(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *totpURIPhase) checkActivatedReplacement(ctx context.Context, w kernel.Work) error {
	in := p.pending.Replacement
	if in == nil || in.Replacement == nil || !p.activated || p.confirmation == nil || p.predecessorRowVersion == 0 || p.predecessorRowVersion == math.MaxUint64 {
		return invalidAuthority()
	}
	b, m := in.Binding, *in.Replacement
	activation, _ := base64.RawURLEncoding.Strict().DecodeString(string(p.request.CommandID))
	parent, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT p.row_version::text,p.state=3 AND p.encrypted_secret IS NULL AND p.last_step IS NULL,
n.row_version::text,n.activation_before_version::text,n.activation_authority_before::text,a.version::text,a.active_factors,
NOT EXISTS(SELECT 1 FROM identity_mfa.recovery_sets q WHERE q.tenant_id=p.tenant_id AND q.user_id=p.user_id AND q.factor_id=p.factor_id AND q.state<>3)
FROM identity_mfa.totp_factors p JOIN identity_mfa.totp_factors n ON n.tenant_id=p.tenant_id AND n.user_id=p.user_id AND n.replaces_factor_id=p.factor_id
JOIN identity_mfa.factor_authorities a ON a.tenant_id=n.tenant_id AND a.user_id=n.user_id
JOIN identity_mfa.recovery_sets s ON s.tenant_id=n.tenant_id AND s.user_id=n.user_id AND s.factor_id=n.factor_id AND s.set_id=n.factor_id
WHERE p.tenant_id=$1 AND p.user_id=$2 AND p.factor_id=$3 AND n.factor_id=$4 AND n.state=2 AND n.confirmed_at IS NOT NULL AND n.last_step IS NOT NULL
AND n.activation_command_id=$5 AND n.created_command_id=$6 AND n.created_purpose='identity.mfa.factor-update' AND n.replaces_version=$7::numeric
AND s.state=2 AND s.row_version=2 AND s.created_command_id=n.created_command_id AND s.created_purpose=n.created_purpose`, string(b.TenantID), string(b.UserID), string(in.Before.ID), m.FactorID, activation, parent, strconv.FormatUint(in.Before.Version+1, 10))
	if err != nil {
		return err
	}
	var oldVersion, newVersion, before, beforeAuthority, currentAuthority string
	var retired, oldCodesRetired bool
	var count int32
	if !rows.Next() || rows.Scan(&oldVersion, &retired, &newVersion, &before, &beforeAuthority, &currentAuthority, &count, &oldCodesRetired) != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	extra, rowErr := rows.Next(), rows.Err()
	rows.Close()
	if extra || rowErr != nil || !retired || !oldCodesRetired || oldVersion != strconv.FormatUint(p.predecessorRowVersion+1, 10) || newVersion != strconv.FormatUint(p.pending.RowVersion+1, 10) || before != strconv.FormatUint(p.pending.RowVersion, 10) || beforeAuthority != strconv.FormatUint(m.AuthorityVersion, 10) || currentAuthority != strconv.FormatUint(m.AuthorityVersion+1, 10) || count != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
