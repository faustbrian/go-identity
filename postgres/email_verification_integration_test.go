//go:build integration

package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This native fixture owns no kernel SQL. The real original signup supplies
// the account and pending identifier. Proof crypto/public email composition
// remain a separate consumer test; here the SQL participant is deliberate.
type emailVerificationNativePhase struct {
	intent   EmailVerificationIntent
	expected identity.Command
	fail     bool
}

type emailVerificationCounterPhase struct {
	commandCounterProbe
	deny bool
}

func (p *emailVerificationCounterPhase) ReserveCommandCounters(ctx context.Context, w CommandCounterWork) (CommandCounterDisposition, error) {
	if _, err := w.Binding(p); err != nil {
		return 0, err
	}
	if p.deny {
		return CommandCounterDenied, nil
	}
	return CommandCounterAllowed, nil
}

func (p *emailVerificationCounterPhase) CheckCommandCounters(ctx context.Context, w CommandCounterAdmissionWork) error {
	_, err := w.Binding(p)
	return err
}

type emailVerificationCapabilityPhase struct {
	recoveryCapabilityPhase
	failFinalize bool
}

func (p *emailVerificationCapabilityPhase) ReleaseCapability(ctx context.Context, w CapabilityReleaseWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_recovery_fixture SET state='released',generation=$7::numeric WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), strconv.FormatUint(b.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *emailVerificationCapabilityPhase) ReserveCapability(ctx context.Context, w CapabilityReservationWork) error {
	return reserveAbortCapability(ctx, w, p)
}
func (p *emailVerificationCapabilityPhase) RebindCapability(ctx context.Context, w CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_recovery_fixture SET generation=$7::numeric WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$8 AND expiry>clock_timestamp()`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.PreviousGeneration, 10), strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *emailVerificationCapabilityPhase) ApplyCapability(ctx context.Context, w CapabilityApplyWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_recovery_fixture SET state='consuming' WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='reserved' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$7 AND expiry>clock_timestamp()`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func (p *emailVerificationCapabilityPhase) FinalizeCapability(ctx context.Context, w CapabilityFinalizeWork) error {
	if p.failFinalize {
		return identity.UnavailableError{}
	}
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity.capability_recovery_fixture SET state='finalized' WHERE tenant_id=$1 AND purpose=$2 AND capability_id=$3 AND state='consuming' AND command_id=$4 AND fingerprint=$5 AND generation=$6::numeric AND expiry=$7 AND expiry>clock_timestamp()`, string(b.Command.TenantID), string(b.Plan.Purpose), b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (*emailVerificationNativePhase) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
}
func (*emailVerificationNativePhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{registrationEmailVerificationOperation()}
}
func (p *emailVerificationNativePhase) EmailVerification(identity.Command) (EmailVerificationIntent, error) {
	return p.intent, nil
}
func (p *emailVerificationNativePhase) ValidateFeatureCommand(c identity.Command, _ CommandPlan) error {
	if c != p.expected {
		return invalidPlan()
	}
	return nil
}
func (p *emailVerificationNativePhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.fail {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: registrationEmailVerificationOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}
func (*emailVerificationNativePhase) CheckFeatureCommit(ctx context.Context, _ Work, _ identity.Command) error {
	return ctx.Err()
}
func (*emailVerificationNativePhase) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func testRegistrationEmailVerification(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository, original identity.CommandBinding, identifier identity.Identifier) {
	for _, mode := range []string{"counter-denied", "foreign-origin", "foreign-address", "stale-user", "native-failure", "finalize-failure", "commit"} {
		t.Run(mode, func(t *testing.T) {
			testRegistrationEmailVerificationMode(t, ctx, pool, repo, original, identifier, mode)
		})
	}
}

func testRegistrationEmailVerificationMode(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository, original identity.CommandBinding, identifier identity.Identifier, mode string) {
	// Bounded risk plan: real signup provenance and pending target; verify and
	// capability/effects in one Work; replay; stale/cross-origin denial; rollback
	// and finalization failure. No session or authenticated-session proof exists.
	native := &emailVerificationNativePhase{intent: EmailVerificationIntent{
		Change:           identity.IdentifierChange{TenantID: original.TenantID, UserID: identifier.UserID, ID: identifier.ID, Action: identity.IdentifierVerify, ExpectedUserVersion: 1, ExpectedAuthorityVersion: 1, ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1},
		CanonicalAddress: identifier.CanonicalValue, ComparisonProfile: "email-v1", RegistrationCommandID: original.CommandID,
	}}
	native.fail = mode == "native-failure"
	cap := &emailVerificationCapabilityPhase{failFinalize: mode == "finalize-failure"}
	counters := &emailVerificationCounterPhase{deny: mode == "counter-denied"}
	registry, err := NewContributorRegistry([]Contributor{repo, &recoveryAuditPhase{}, &recoveryLifecyclePhase{}, native, counters, cap})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	b, plan := emailVerificationPlanFixture(t)
	plan.Capability.CapabilityID = "email-proof-" + mode
	b.TenantID, b.UserID, b.RecordID = original.TenantID, identifier.UserID, string(identifier.ID)
	b.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	if mode == "foreign-origin" {
		native.intent.RegistrationCommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
	}
	if mode == "foreign-address" {
		native.intent.CanonicalAddress = "other@example.test"
	}
	if mode == "stale-user" {
		native.intent.Change.ExpectedUserVersion = 2
	}
	// Literal metadata is independent of the new production field mapper.
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "email-verification." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "email-verification." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	fields := []identity.FeatureField{text("tenant", string(b.TenantID)), text("user", string(b.UserID)), text("identifier", b.RecordID), text("canonical-address", native.intent.CanonicalAddress), text("comparison-profile", "email-v1"), text("registration-command", string(native.intent.RegistrationCommandID)), number("user-version", native.intent.Change.ExpectedUserVersion), number("authority-version", 1), number("identifier-version", 1), number("verification-version", 1)}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: native.FeatureOperations()[0], Fields: fields})
	native.expected = command
	plan.Contributors = registry.Descriptors()
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), string(plan.Capability.Purpose), plan.Capability.CapabilityID, plan.Capability.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	seed, err := securityMutationAudit(ctx, b, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", "email.verified", "identifier", b.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, native.FeatureOperations()[0], "identifier", seed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = c.PrepareCommandPlan(b, command, plan)
	if err != nil {
		t.Fatal("native email confirmation cannot prepare atomic phases", err)
	}
	r, _, err := c.ReserveCommand(ctx, b, command, plan)
	if mode == "counter-denied" {
		var forbidden identity.ForbiddenError
		if !errors.As(err, &forbidden) || r.state != nil {
			t.Fatal("counter denial did not retain terminal denial", err)
		}
		var state string
		if err := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID).Scan(&state); err != nil || state != "issued" {
			t.Fatal("counter denial reserved one-use proof", err)
		}
		return
	}
	if err != nil {
		t.Fatal("native email confirmation cannot reserve", err)
	}
	w, err := c.Begin(ctx, r)
	if err != nil {
		t.Fatal("native email confirmation cannot enter protected transaction", err)
	}
	defer c.Abort(w, identity.UnavailableError{})
	result, err := c.ApplyFeature(ctx, w, command)
	if err == nil {
		result, err = c.Commit(w, result)
	}
	if mode != "commit" {
		if err == nil {
			t.Fatal("injected failure committed")
		}
		_, _ = c.Abort(w, err)
		state, readErr := repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
		if readErr != nil || state.User.Version != 1 || state.AuthorityVersion != 1 || state.Identifiers[0].Verified || state.Verifications[0].Version != 1 {
			t.Fatal("failed confirmation changed directory", readErr)
		}
		var effects, audits, outbox int
		if readErr := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.email_verifications WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1)`, string(b.CommandID)).Scan(&effects, &audits, &outbox); readErr != nil || effects != 0 || outbox != 0 {
			t.Fatal("failed confirmation retained success effects", readErr)
		}
		var proofState string
		if readErr := pool.Raw().QueryRow(ctx, `SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$1`, plan.Capability.CapabilityID).Scan(&proofState); readErr != nil || proofState == "consuming" || proofState == "finalized" {
			t.Fatal("failed confirmation consumed proof", readErr)
		}
		return
	}
	if err != nil {
		t.Fatal("native email confirmation cannot apply", err)
	}
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native email confirmation did not commit", err)
	}
	replayReservation, replay, err := c.ReserveCommand(ctx, b, command, plan)
	if err != nil || replayReservation.state != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Binding != b {
		t.Fatal("committed confirmation replay did not retain original receipt", err)
	}
	state, err := repo.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: b.TenantID, UserID: b.UserID, MaximumIdentifiers: 128})
	if err != nil || state.User.Version != 2 || state.AuthorityVersion != 2 || len(state.Identifiers) != 1 || !state.Identifiers[0].Verified || state.Identifiers[0].Version != 2 || state.Verifications[0].Version != 2 {
		t.Fatal("committed confirmation did not verify exact original target", err)
	}
	var proofState string
	var audits, outbox int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$1),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$2)`, plan.Capability.CapabilityID, string(b.CommandID)).Scan(&proofState, &audits, &outbox); err != nil || proofState != "finalized" || audits != 1 || outbox != 1 {
		t.Fatal("proof, audit and outbox did not commit with verification", err)
	}
}
