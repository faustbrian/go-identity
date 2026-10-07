package postgres

import (
	"bytes"
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

var _ kernel.OTPReservationContributor = (*Contributor)(nil)

// Extract only encrypted bounded original custody; never code or cookie.
// The phase authenticates this projection before it may reach storage.
func originalEnvelope(s identity.FeatureCommandSpec, b kernel.OTPReservationBinding) ([]byte, error) {
	if s.Binding != b.Command || s.Binding.ValidateFor(s.Operation) != nil {
		return nil, ErrInvalidCommand
	}
	var wire []byte
	var version uint64
	for _, f := range s.Fields {
		if !otpField(f.Name) {
			continue
		}
		switch f.Name {
		case "otp.attempt-custody":
			if wire != nil || f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) == 0 || len(f.Value.Bytes) > 8192 {
				return nil, ErrInvalidCommand
			}
			wire = f.Value.Bytes
		case "otp.digest-key-version":
			if version != 0 || f.Value.Kind != identity.FeatureUint64 {
				return nil, ErrInvalidCommand
			}
			version = f.Value.Uint64
		default:
			return nil, ErrInvalidCommand
		}
	}
	if wire == nil || version != uint64(b.Plan.DigestKeyVersion) {
		return nil, ErrInvalidCommand
	}
	return wire, nil
}

// Only live native consuming handles satisfy this private policy bridge. It
// retains no handle or authority and uses the established owner operations.
type consumingWork interface {
	Query(context.Context, string, ...any) (*kernel.WorkRows, error)
	DatabaseTime(context.Context) (time.Time, error)
	RequireActiveDirectoryAuthority(context.Context, kernel.OTPReservationContributor, kernel.DirectoryAuthorityAdmission) error
	RequireActiveUserAuthority(context.Context, kernel.OTPReservationContributor, kernel.UserAuthorityAdmission) error
	RequireActiveCredential(context.Context, kernel.OTPReservationContributor, kernel.CredentialAdmission) (time.Time, error)
	RequireActiveUserAuthorization(context.Context, kernel.OTPReservationContributor, kernel.UserAuthorizationAdmission) error
}

func (p *Contributor) requireConsumingAuthority(ctx context.Context, w consumingWork, b kernel.OTPReservationBinding, a AttemptAuthority) error {
	if err := w.RequireActiveDirectoryAuthority(ctx, p, a.Directory); err != nil {
		return err
	}
	if b.Command.UserID == "" {
		return nil
	}
	u := kernel.UserAuthorityAdmission{UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion}
	if err := w.RequireActiveUserAuthority(ctx, p, u); err != nil {
		return err
	}
	if a.Credential != (identity.CredentialRef{}) {
		if _, err := w.RequireActiveCredential(ctx, p, credentialAdmission(a)); err != nil {
			return err
		}
	}
	return w.RequireActiveUserAuthorization(ctx, p, a.UserAuthorization)
}

func credentialAdmission(a AttemptAuthority) kernel.CredentialAdmission {
	return kernel.CredentialAdmission{Credential: a.Credential, UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion}
}

func (p *Contributor) consumingTime(ctx context.Context, w consumingWork, a AttemptAuthority, flow nativeFlow) (time.Time, error) {
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if a.Credential != (identity.CredentialRef{}) {
		now, err = w.RequireActiveCredential(ctx, p, credentialAdmission(a))
		if err != nil {
			return time.Time{}, err
		}
	}
	if p.flowTime(flow, now) != nil {
		return time.Time{}, ErrInvalidCommand
	}
	return now, nil
}

// ReserveOTP compares once after current original authority, original flow,
// ordered lockouts and challenge exclusion. OTP, original code-free custody
// and pre-auth reservation commit only in the coordinator's single transaction.
// Wrong submissions roll back here; counted denials use the separate protocol.
func (p *Contributor) ReserveOTP(ctx context.Context, w kernel.OTPReservationWork) error {
	if ctx == nil || p == nil {
		return ErrInvalidCommand
	}
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration != 0 {
		return ErrInvalidCommand
	}
	command, err := w.NativeCommand(p)
	if err != nil {
		return err
	}
	attempt, a, err := p.original(command, b.Plan)
	if err != nil {
		return err
	}
	if err = p.requireConsumingAuthority(ctx, w, b, a); err != nil {
		return err
	}
	flow, err := p.authenticateFlow(ctx, command, b.Plan)
	if err != nil {
		return err
	}
	// Lock original flow before downstream exclusions. Pre-auth acquires its
	// update lock directly to avoid share-lock upgrades between submissions;
	// authenticated sessions are checked read-only and are never reserved.
	if err = reserveNativeFlow(ctx, w, p, flow, b); err != nil {
		return err
	}
	ab, _ := attempt.Bindings()
	c, _ := ab.Continuation.Bindings()
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	if _, _, err = p.lockout.loadLockouts(ctx, query, p.schema, c.Scope); err != nil {
		return err
	}
	row, err := p.codec.loadChallenge(ctx, query, p.schema, attempt, b.Plan.DigestKeyVersion)
	if err != nil {
		return err
	}
	now, err := p.consumingTime(ctx, w, a, flow)
	if err != nil {
		return err
	}
	d, err := p.codec.verifier.EvaluateAttempt(row.challenge, attempt, now)
	if err != nil || d.Outcome != otp.AttemptReserved {
		return ErrInvalidCommand
	}
	spec, _ := command.Feature()
	return persistOriginalReservation(ctx, w.Exec, row, d, b, now, &spec)
}

// RebindOTP transfers both exact predecessor reservations atomically without
// comparing the code, charging again or replacing original authority/times.
// Callback errors abort the coordinator's complete all-participant takeover.
func (p *Contributor) RebindOTP(ctx context.Context, w kernel.OTPReservationWork) error {
	if ctx == nil || p == nil {
		return ErrInvalidCommand
	}
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration == 0 {
		return ErrInvalidCommand
	}
	command, err := w.NativeCommand(p)
	if err != nil {
		return err
	}
	_, a, err := p.original(command, b.Plan)
	if err != nil {
		return err
	}
	if err = p.requireConsumingAuthority(ctx, w, b, a); err != nil {
		return err
	}
	flow, err := p.authenticateFlow(ctx, command, b.Plan)
	if err != nil {
		return err
	}
	if err = reserveNativeFlow(ctx, w, p, flow, b); err != nil {
		return err
	}
	query := func(ctx context.Context, sql string, args ...any) (challengeRows, error) {
		return w.Query(ctx, sql, args...)
	}
	spec, _ := command.Feature()
	r, err := p.codec.restoreRecord(spec)
	if err != nil {
		return err
	}
	c, _ := r.Attempt.Continuation.Bindings()
	if _, _, err = p.lockout.loadLockouts(ctx, query, p.schema, c.Scope); err != nil {
		return err
	}
	row, err := loadReservation(ctx, query, p.schema, b, b.PreviousGeneration)
	if err != nil {
		return err
	}
	retained, _, err := p.retainedOriginal(ctx, query, b)
	if err != nil {
		return err
	}
	wire, err := originalEnvelope(spec, b)
	if err != nil || !bytes.Equal(wire, retained) {
		return ErrInvalidCommand
	}
	now, err := p.consumingTime(ctx, w, a, flow)
	if err != nil {
		return err
	}
	return rebindReservation(ctx, w.Exec, row, b, now)
}

// Caller holds exact reservation exclusion. Recovery/release authenticate this
// retained projection, never substitute a fresh original from mutable storage.
func (p *Contributor) retainedOriginal(ctx context.Context, query challengeQuery, b kernel.OTPReservationBinding) ([]byte, nativeCustody, error) {
	rows, err := query(ctx, `SELECT consumer_envelope,consumer_owner,consumer_record_requirement,consumer_subject_requirement FROM `+pgx.Identifier{p.schema}.Sanitize()+`.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(b.Command.TenantID), b.Plan.ChallengeID)
	if err != nil {
		return nil, nativeCustody{}, challengeFailure(ctx)
	}
	if rows == nil {
		return nil, nativeCustody{}, ErrUnavailable
	}
	defer rows.Close()
	var wire []byte
	var owner string
	var record, subject int16
	if !rows.Next() || rows.Scan(&wire, &owner, &record, &subject) != nil || rows.Next() || rows.Err() != nil {
		return nil, nativeCustody{}, ErrInvalidCommand
	}
	op := identity.FeatureOperation{Owner: owner, OperationID: b.Command.OperationID, SchemaID: b.Command.SchemaID, SchemaVersion: b.Command.SchemaVersion, RecordRequirement: identity.FeatureRecordRequirement(record), SubjectRequirement: identity.FeatureSubjectRequirement(subject)}
	spec := identity.FeatureCommandSpec{Binding: b.Command, Operation: op, Fields: []identity.FeatureField{{Name: "otp.attempt-custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: wire}}, {Name: "otp.digest-key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(b.Plan.DigestKeyVersion)}}}}
	c, err := p.codec.restoreCustody(spec)
	if err != nil || c.authority == nil {
		return nil, nativeCustody{}, ErrInvalidCommand
	}
	plan, err := p.codec.recordPlan(c.record, b.Plan.DigestKeyVersion)
	if err != nil || plan != b.Plan || c.authority.Directory.Query.GlobalAuthorityID != p.global || b.Command.UserID != "" && c.authority.UserAuthorization.Scope.PolicyNamespace != p.namespace {
		return nil, nativeCustody{}, ErrInvalidCommand
	}
	return wire, c, nil
}
