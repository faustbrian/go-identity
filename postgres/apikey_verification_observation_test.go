package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

type lostPreparationSnapshotReader struct{}

func (lostPreparationSnapshotReader) QueryRow(context.Context, string, ...any) pgx.Row {
	return lostPreparationSnapshotRow{}
}

type lostPreparationSnapshotRow struct{}

func (lostPreparationSnapshotRow) Scan(...any) error { return pgx.ErrNoRows }

func TestAPIKeyPreparationSnapshotRaceNeverReportsAbsent(t *testing.T) {
	c, command, _, _ := apiKeyVerificationRuntimeFixture(t, false)
	spec, _ := command.Feature()
	query, caller := queryInputs(spec.Binding)
	c.admissionPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	})}
	claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
	now, state := time.Now().UTC().Truncate(time.Microsecond), "pending"
	until := now.Add(time.Minute)
	// The first primary read found this immutable claim. The database seam
	// models losing only the second, snapshot-qualified preparation read to
	// concurrent attachment/lease change; it must never become global absence.
	c.commandRead = func(ctx context.Context, _ identity.CommandID) (commandObservation, error) {
		observed := commandObservation{tenant: string(query.TenantID), purpose: query.OperationID, scope: claim.safeFields, state: &state, until: &until, now: now, fingerprint: fp[:], fingerprintKeyVersion: int64(c.keys.current)}
		return observed, readObservedCounterPreparation(ctx, lostPreparationSnapshotReader{}, nil, &observed)
	}
	var unavailable identity.UnavailableError
	if out, fp, err := c.ObserveAPIKeyVerificationCommand(t.Context(), command, caller); !errors.As(err, &unavailable) || out != (CommandAdmission{}) || fp != ([32]byte{}) {
		t.Fatal("API-key snapshot loss became false absence", err)
	}
	if out, err := c.ObserveCommandAdmission(t.Context(), query, caller); !errors.As(err, &unavailable) || out != (CommandAdmission{}) {
		t.Fatal("generic snapshot loss became false absence", err)
	}
}

func TestAPIKeyPreparedRecoveryPreservesExpiredUngatedAndGatedUncertainty(t *testing.T) {
	for _, profile := range []int16{1, 2} {
		c, command, _, native := apiKeyVerificationRuntimeFixture(t, false)
		spec, _ := command.Feature()
		query, caller := queryInputs(spec.Binding)
		policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		c.admissionPolicy, c.queryPolicy = policy, policy
		claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
		if err != nil {
			t.Fatal(err)
		}
		fp := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
		now, state := time.Now().UTC().Truncate(time.Microsecond), "pending"
		until := now.Add(-time.Minute)
		observed := commandObservation{tenant: string(query.TenantID), purpose: query.OperationID, scope: claim.safeFields, state: &state, until: &until, now: now, fingerprint: fp[:], fingerprintKeyVersion: int64(c.keys.current), preparationProfile: &profile}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
		// No pool is available: attempting takeover, terminalization or any
		// participant invocation cannot masquerade as a successful observation.
		for range 2 {
			admission, gotFP, err := c.ObserveAPIKeyVerificationCommand(t.Context(), command, caller)
			if err != nil || admission.Record.Outcome != identity.CommitOutcomeInProgress || gotFP != fp {
				t.Fatal("expired preparation lost original pending observation", profile, err)
			}
			result, err := c.RecoverAPIKeyVerificationCommand(t.Context(), query, fp, caller)
			if err != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Binding != spec.Binding || state != "pending" || native.verificationCalls != 0 || native.genericCalls != 0 {
				t.Fatal("expired preparation generated/compared or fabricated rollback", profile, result.Outcome, err)
			}
		}
	}
}

func TestAPIKeyVerificationPreparationCannotReplaceOriginalKeyVersion(t *testing.T) {
	b, original := apiKeyVerificationPlanFixture(t, false)
	if !preparationFinalDeclaration(b, original, original) {
		t.Fatal("unchanged API-key preparation rejected")
	}
	for _, changed := range []*APIKeyVerificationPlan{nil, {KeyVersion: original.APIKeyVerification.KeyVersion + 1}} {
		final := original
		final.APIKeyVerification = changed
		if preparationFinalDeclaration(b, original, final) {
			t.Fatal("restoration replaced the original API-key version fence")
		}
	}
}

func TestAPIKeyVerificationSubmissionBindsDeclarationVersion(t *testing.T) {
	_, command, plan, _ := apiKeyVerificationRuntimeFixture(t, false)
	spec, _ := command.Feature()
	spec.Fields = []identity.FeatureField{{Name: "apikey.verify.key-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: plan.APIKeyVerification.KeyVersion}}}
	command, err := identity.NewFeatureCommand(spec)
	if err != nil || !apiKeyVerificationDeclarationMatches(command, plan) {
		t.Fatal("original version declaration rejected", err)
	}
	plan.APIKeyVerification.KeyVersion++
	if apiKeyVerificationDeclarationMatches(command, plan) {
		t.Fatal("new invocation substituted a version outside original intent")
	}
}

// N1/K5: the public native adapter needs the original claim commitment even
// before a domain effect exists. Neither scope equality nor its own second
// fingerprint authority is an acceptable substitute for the coordinator.
func TestAPIKeyVerificationObservationPreservesOriginalCommitment(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		c, command, plan, _ := apiKeyVerificationRuntimeFixture(t, anonymous)
		spec, _ := command.Feature()
		q, caller := queryInputs(spec.Binding)
		policy := CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		c.admissionPolicy, c.queryPolicy = &policy, &policy
		claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
			return commandObservation{}, pgx.ErrNoRows
		}
		admission, got, err := c.ObserveAPIKeyVerificationCommand(t.Context(), command, caller)
		if err != nil || !admission.Absent || got != fingerprint {
			t.Fatal("authorized absence lost the exact prospective coordinator commitment", err)
		}
		wire, err := encodeFeaturePlan(spec.Binding, fingerprint, plan)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		until, state := now.Add(time.Minute), "pending"
		observed := commandObservation{tenant: string(q.TenantID), purpose: q.OperationID, scope: claim.safeFields, state: &state, until: &until, now: now, plan: wire, fingerprint: bytes.Clone(fingerprint[:]), fingerprintKeyVersion: int64(c.keys.current)}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
		// Issuance rotation must not assign a new identity to the pending claim.
		c.keys.current = 2
		c.keys.retained[2] = [32]byte{28}
		admission, got, err = c.ObserveAPIKeyVerificationCommand(t.Context(), command, caller)
		if err != nil || admission.Absent || admission.Record.Outcome != identity.CommitOutcomeInProgress || got != fingerprint {
			t.Fatal("retained-key pending observation rekeyed the original attempt", err)
		}
		changed := spec
		changed.Fields = []identity.FeatureField{{Name: "apikey.verify.intent", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte("different canonical request")}}}
		other, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		var conflict identity.ConflictError
		if out, fp, err := c.ObserveAPIKeyVerificationCommand(t.Context(), other, caller); !errors.As(err, &conflict) || out != (CommandAdmission{}) || fp != ([32]byte{}) {
			t.Fatal("same scope accepted a different original request", err)
		}
		// No pool is supplied: a mismatch must fail before recovery can open a
		// transaction, invoke a participant or terminalize an expired command.
		until = now.Add(-time.Second)
		bad := fingerprint
		bad[0] ^= 1
		if out, err := c.RecoverAPIKeyVerificationCommand(t.Context(), q, bad, caller); !errors.As(err, &conflict) || out != (identity.CommandResult{}) {
			t.Fatal("wrong fingerprint reached pending recovery", err)
		}
	}
}

func TestAPIKeyVerificationObservationDeniesWithoutDisclosingCommitment(t *testing.T) {
	for _, mode := range []string{"deny", "foreign-caller", "cancel-read", "failed-read", "failed-policy", "foreign-operation", "human-actor", "no-admission"} {
		t.Run(mode, func(t *testing.T) {
			c, command, _, _ := apiKeyVerificationRuntimeFixture(t, false)
			spec, _ := command.Feature()
			_, caller := queryInputs(spec.Binding)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			reads := 0
			c.admissionPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				if mode == "failed-policy" {
					return authorization.Decision{}, errors.New("private diagnostic")
				}
				outcome := authorization.Allow
				if mode == "deny" {
					outcome = authorization.Deny
				}
				return authorization.Decision{Outcome: outcome, Revision: 9}, nil
			})}
			c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) {
				reads++
				if mode == "cancel-read" {
					cancel()
				}
				if mode == "failed-read" {
					return commandObservation{}, errors.New("private primary diagnostic")
				}
				return commandObservation{}, pgx.ErrNoRows
			}
			switch mode {
			case "foreign-caller":
				caller.Request.Subject.ID = "other-key"
			case "no-admission":
				c.admissionPolicy = nil
			case "foreign-operation":
				spec.Operation.Owner = "identity/foreign"
			case "human-actor":
				spec.Binding.ActorKind = authorization.SubjectUser
			}
			if mode == "foreign-operation" || mode == "human-actor" {
				var err error
				command, err = identity.NewFeatureCommand(spec)
				if err != nil {
					t.Fatal(err)
				}
			}
			out, fingerprint, err := c.ObserveAPIKeyVerificationCommand(ctx, command, caller)
			if err == nil || out != (CommandAdmission{}) || fingerprint != ([32]byte{}) {
				t.Fatal("denied or unproven read disclosed commitment", err)
			}
			wantReads := 1
			if mode == "foreign-operation" || mode == "human-actor" || mode == "no-admission" {
				wantReads = 0
			}
			if reads != wantReads {
				t.Fatal("changed policy-denial read shape", reads)
			}
		})
	}
}

func TestAPIKeyVerificationRecoveryMatchesTerminalFingerprint(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		c, command, plan, _ := apiKeyVerificationRuntimeFixture(t, anonymous)
		spec, _ := command.Feature()
		q, caller := queryInputs(spec.Binding)
		c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		})}
		claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := claimFingerprint(c.keys.retained[c.keys.current], claim.canonical)
		wire, err := encodeFeaturePlan(spec.Binding, fingerprint, plan)
		if err != nil {
			t.Fatal(err)
		}
		receipt := featureOutcome(spec.Binding, &spec.Operation, identity.CommitOutcomeCommitted, 0)
		receipt.AuditEventID = "authentication-audit"
		body, err := encodeJournalResult(claim, receipt)
		if err != nil {
			t.Fatal(err)
		}
		now, state, class, version := time.Now().UTC().Truncate(time.Microsecond), "committed", "committed", int32(1)
		observed := commandObservation{tenant: string(q.TenantID), purpose: q.OperationID, scope: claim.safeFields, state: &state, until: &now, now: now, plan: wire, fingerprint: bytes.Clone(fingerprint[:]), fingerprintKeyVersion: int64(c.keys.current), result: body, class: &class, resultVersion: &version}
		c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return observed, nil }
		for range 2 {
			got, err := c.RecoverAPIKeyVerificationCommand(t.Context(), q, fingerprint, caller)
			if err != nil || got.Binding != receipt.Binding || got.Outcome != identity.CommitOutcomeCommitted || got.AuditEventID != receipt.AuditEventID || got.Feature == nil || *got.Feature != *receipt.Feature {
				t.Fatal("exact original committed recovery changed history", err)
			}
		}
		bad := fingerprint
		bad[31] ^= 1
		var conflict identity.ConflictError
		if got, err := c.RecoverAPIKeyVerificationCommand(t.Context(), q, bad, caller); !errors.As(err, &conflict) || got != (identity.CommandResult{}) {
			t.Fatal("terminal fingerprint mismatch disclosed history", err)
		}
		if got, err := c.RecoverAPIKeyVerificationCommand(t.Context(), q, [32]byte{}, caller); err == nil || got != (identity.CommandResult{}) {
			t.Fatal("missing original fingerprint selected recovery")
		}
	}
}
