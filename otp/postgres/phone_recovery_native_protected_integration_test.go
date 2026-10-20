//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// These peers exercise only actual coordinator phase/transaction binding. They
// are deliberate capability/risk doubles, NOT signed recovery authorization or
// native one-use/provider implementations. Their bounded rows observe effects
// and rollback; they issue no credentials, budget, transaction or replay engine.
type phoneRecoveryBoundPeer struct {
	descriptor kernel.ContributorDescriptor
	command    identity.CommandBinding
	capability kernel.CapabilityPlan
	risk       kernel.RiskEvidencePlan
	reserves   int
}

func (p *phoneRecoveryBoundPeer) Descriptor() kernel.ContributorDescriptor { return p.descriptor }
func (*phoneRecoveryBoundPeer) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}
func (p *phoneRecoveryBoundPeer) require(command identity.CommandBinding, fingerprint [32]byte, generation, previous uint64) error {
	if command != p.command || fingerprint == ([32]byte{}) || generation == 0 || previous != 0 {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneRecoveryBoundPeer) reserve(ctx context.Context, exec func(context.Context, string, ...any) (int64, error), command identity.CommandBinding, fingerprint [32]byte, generation, previous uint64) error {
	p.reserves++
	if err := p.require(command, fingerprint, generation, previous); err != nil {
		return err
	}
	_, err := exec(ctx, `INSERT INTO public.phone_recovery_component_peers(owner,command_id,fingerprint,generation) VALUES($1,$2,$3,$4::numeric)`, p.descriptor.Owner, string(command.CommandID), fingerprint[:], strconv.FormatUint(generation, 10))
	return err
}
func (p *phoneRecoveryBoundPeer) check(ctx context.Context, query func(context.Context, string, ...any) (*kernel.WorkRows, error), command identity.CommandBinding, fingerprint [32]byte, generation, previous uint64) error {
	if err := p.require(command, fingerprint, generation, previous); err != nil {
		return err
	}
	rows, err := query(ctx, `SELECT fingerprint,generation::text FROM public.phone_recovery_component_peers WHERE owner=$1 AND command_id=$2 FOR UPDATE`, p.descriptor.Owner, string(command.CommandID))
	if err != nil {
		return err
	}
	defer rows.Close()
	var actual []byte
	var version string
	if !rows.Next() || rows.Scan(&actual, &version) != nil || rows.Next() || rows.Err() != nil || !bytes.Equal(actual, fingerprint[:]) || version != strconv.FormatUint(generation, 10) {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneRecoveryBoundPeer) ReserveCapability(ctx context.Context, w kernel.CapabilityReservationWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.capability {
		return ErrInvalidCommand
	}
	return p.reserve(ctx, w.Exec, b.Command, b.Fingerprint, b.Generation, b.PreviousGeneration)
}
func (*phoneRecoveryBoundPeer) RebindCapability(context.Context, kernel.CapabilityReservationWork) error {
	return errors.New("component takeover not selected")
}
func (p *phoneRecoveryBoundPeer) ApplyCapability(ctx context.Context, w kernel.CapabilityApplyWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.capability {
		return ErrInvalidCommand
	}
	return p.check(ctx, w.Query, b.Command, b.Fingerprint, b.Generation, b.PreviousGeneration)
}
func (p *phoneRecoveryBoundPeer) FinalizeCapability(ctx context.Context, w kernel.CapabilityFinalizeWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.capability {
		return ErrInvalidCommand
	}
	return p.check(ctx, w.Query, b.Command, b.Fingerprint, b.Generation, b.PreviousGeneration)
}
func (p *phoneRecoveryBoundPeer) ReleaseCapability(ctx context.Context, w kernel.CapabilityReleaseWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.capability || b.Generation != b.PreviousGeneration {
		return ErrInvalidCommand
	}
	return p.check(ctx, w.Query, b.Command, b.Fingerprint, b.Generation, 0)
}
func (p *phoneRecoveryBoundPeer) ReserveRiskEvidence(ctx context.Context, w kernel.RiskReservationWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.risk {
		return ErrInvalidCommand
	}
	return p.reserve(ctx, w.Exec, b.Command, b.Fingerprint, b.Generation, b.PreviousGeneration)
}
func (*phoneRecoveryBoundPeer) RebindRiskEvidence(context.Context, kernel.RiskReservationWork) error {
	return errors.New("component takeover not selected")
}
func (p *phoneRecoveryBoundPeer) ValidateRiskEvidenceCommand(c identity.Command, plan kernel.RiskEvidencePlan) error {
	s, ok := c.PhonePasswordResetFeature()
	if !ok || s.Binding != p.command || plan != p.risk {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneRecoveryBoundPeer) CheckRiskEvidence(ctx context.Context, w kernel.RiskApplyWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.risk {
		return ErrInvalidCommand
	}
	return p.check(ctx, w.Query, b.Command, b.Fingerprint, b.Generation, b.PreviousGeneration)
}
func (p *phoneRecoveryBoundPeer) FinalizeRiskEvidence(ctx context.Context, w kernel.RiskFinalizeWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.risk {
		return ErrInvalidCommand
	}
	return p.check(ctx, w.Query, b.Command, b.Fingerprint, b.Generation, b.PreviousGeneration)
}
func (p *phoneRecoveryBoundPeer) ReleaseRiskEvidence(ctx context.Context, w kernel.RiskReleaseWork) error {
	b, e := w.Binding(p)
	if e != nil || b.Plan != p.risk || b.Generation != b.PreviousGeneration {
		return ErrInvalidCommand
	}
	return p.check(ctx, w.Query, b.Command, b.Fingerprint, b.Generation, 0)
}

type phoneRecoveryProtectedDomain struct {
	*phoneRecoveryCountedDomain
	custody             PhoneRecoveryCustody
	owner               *Contributor
	original, generated identity.Command
	plan                kernel.OTPAttemptPlan
	declaration         kernel.CommandPlan
	preparation         PhoneRecoveryPreparation
	applies, restored   int
	mode                string
	origin              kernel.Work // test-only returned-handle rejection, never reused for SQL
	actual              mfapg.PhoneRecoveryTOTPCompletion
	sessions            *sessionpg.PasswordResetEffect
}

func (p *phoneRecoveryProtectedDomain) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, _ identity.Command) error {
	p.admissions++
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.authority.Directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credentialAdmission(p.authority)); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, p.authority.UserAuthorization); err != nil {
		return err
	}
	if err := w.RequireVerifiedIdentifier(ctx, p, kernel.VerifiedIdentifierAdmission{IdentifierID: "phone", Kind: identity.IdentifierPhone, IdentifierVersion: 1, VerificationVersion: 1, User: kernel.UserAuthorityAdmission{UserAuthorityVersion: p.authority.UserAuthorityVersion, IdentifierAuthorityVersion: p.authority.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.authority.CredentialAuthorityVersion}}); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT state FROM otp_store.challenges WHERE tenant_id='tenant' AND challenge_id='challenge'`)
	if err != nil {
		return err
	}
	var state string
	ok := rows.Next() && rows.Scan(&state) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	if !ok {
		return ErrInvalidCommand
	}
	if state == "reserved" {
		// Fixed test-only lock checkpoint: the real reservation already holds
		// the original factor. Queue the peer before commit, so PostgreSQL grants
		// it before the following protected phase. No provider/caller callback,
		// fake Work, mutation or permission is supplied by this checkpoint.
		_, err = w.Exec(ctx, `SELECT pg_advisory_xact_lock(73190808)`)
	}
	return err
}

// Test-only retained marker, not production password hashing/envelope authority.
// The coordinator must still acknowledge generation, retain it and restore the
// exact input/generation; actual OTP/MFA preparation happens only at restoration.
func (p *phoneRecoveryProtectedDomain) ValidateFeaturePreparation(c identity.Command, _ kernel.CommandPlan) error {
	spec, ok := c.PhonePasswordResetInputFeature()
	if !ok || c != p.original || spec.Operation != p.op {
		return ErrInvalidCommand
	}
	return nil
}
func protectedPhoneMarker(generation uint64) []byte {
	return binary.BigEndian.AppendUint64([]byte("phone-component-preparation-v1:"), generation)
}
func (p *phoneRecoveryProtectedDomain) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || c != p.original || generation == 0 {
		return nil, ErrInvalidCommand
	}
	return protectedPhoneMarker(generation), nil
}
func (p *phoneRecoveryProtectedDomain) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.original || generation == 0 || !bytes.Equal(wire, protectedPhoneMarker(generation)) {
		return identity.Command{}, kernel.CommandPlan{}, ErrInvalidCommand
	}
	prepared, err := p.owner.PreparePhoneRecovery(ctx, p.generated, p.plan, p.preparation)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.custody = prepared
	p.restored++
	return p.generated, p.declaration, nil
}

type protectedPhoneAdmission struct{ phase *phoneRecoveryProtectedDomain }

func (a protectedPhoneAdmission) Check(ctx context.Context) error {
	if ctx == nil || a.phase == nil || ctx.Err() != nil || !time.Now().Before(a.phase.preparation.ValidUntil) {
		return ErrInvalidCommand
	}
	return nil
}
func (a protectedPhoneAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.GenerateFeaturePreparation(ctx, a.phase.original, generation)
}
func (p *phoneRecoveryProtectedDomain) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original {
		return nil, ErrInvalidCommand
	}
	a := protectedPhoneAdmission{p}
	return a, a.Check(ctx)
}
func (p *phoneRecoveryProtectedDomain) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if c != p.original || generation == 0 || !bytes.Equal(wire, protectedPhoneMarker(generation)) {
		return nil, ErrInvalidCommand
	}
	a := protectedPhoneAdmission{p}
	return a, a.Check(ctx)
}

func (p *phoneRecoveryProtectedDomain) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.applies++
	// CheckOTP must only fence: the original replay state is still untouched
	// when the real MFA verification/CAS begins in this feature invocation.
	rows, err := w.Query(ctx, `SELECT row_version::text,last_step IS NULL FROM identity_mfa.totp_factors WHERE tenant_id='tenant' AND user_id='user'`)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var version string
	var unused bool
	ok := rows.Next() && rows.Scan(&version, &unused) == nil && !rows.Next() && rows.Err() == nil
	rows.Close()
	if !ok || version != "1" || !unused {
		return identity.FeatureReceipt{}, ErrInvalidCommand
	}
	if p.mode != "protected-absent-receipt" {
		completion, err := p.custody.VerifyAndRecordTOTP(ctx, w, p)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := completion.RequireRecorded(ctx, w, p, c); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.actual = completion
	}
	if _, err := p.sessions.Apply(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.origin = w
	s, _ := c.PhonePasswordResetFeature()
	if _, err := w.Exec(ctx, `INSERT INTO public.native_otp_domain(command_id) VALUES($1)`, string(s.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	switch p.mode {
	case "protected-rollback":
		return identity.FeatureReceipt{}, identity.ConflictError{}
	case "protected-zero-receipt":
		// Deliberate private fixture corruption after an actual CAS: no public
		// caller can write this slot. A present but unusable receipt must abort.
		p.owner.phoneRecovery.mu.Lock()
		p.custody.state.recorded = &mfapg.PhoneRecoveryTOTPCompletion{}
		p.owner.phoneRecovery.mu.Unlock()
	case "protected-expired-receipt":
		// Fixed bounded test checkpoint, not a provider/caller callback. Main
		// releases it only after the original factor deadline has elapsed.
		if _, err := w.Exec(ctx, `SELECT pg_advisory_xact_lock(73190809)`); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: s.Operation, BeforeVersion: 1, AfterVersion: 2}, nil
}
func (p *phoneRecoveryProtectedDomain) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if p.mode == "protected-apply-only-receipt" {
		// The new final OTP method must not widen ordinary RequireRecorded into
		// a feature final-check permission, even with the actual originating Work.
		return p.actual.RequireRecorded(ctx, w, p, command)
	}
	// Current security epochs do not become user/identifier successors merely
	// because a password was reset. Kernel's own receipt owns credential mapping.
	r, err := w.StagedCredentialReplacement()
	if err != nil {
		return err
	}
	if r.BeforeAuthorityVersion != p.intent.Replacement.ExpectedAuthorityVersion || r.BeforeCredentialVersion != p.intent.Replacement.Credential.Version || r.BeforeUserVersion != p.intent.Replacement.ExpectedUserVersion {
		return ErrInvalidCommand
	}
	_, err = w.RequireActiveCredential(ctx, p, kernel.CredentialAdmission{Credential: r.Credential, UserAuthorityVersion: p.authority.UserAuthorityVersion, IdentifierAuthorityVersion: p.authority.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.AfterAuthorityVersion})
	return err
}

type phoneRecoveryProtectedLifecycle struct{ contributorLifecycle }

func (p *phoneRecoveryProtectedLifecycle) PersistCredentialReset(ctx context.Context, w kernel.Work) error {
	return p.PersistLifecycle(ctx, w)
}

// The surrounding existing fixture supplies genuine primary/OTP/MFA custody.
// The selected domain and bound peers below are explicitly labelled test seams;
// The actual session effect below proves stored-row revocation/rollback, not
// session authentication. No password material or whole phone-reset proof is claimed.
func testPhoneRecoveryProtectedFactorOrder(t *testing.T, ctx context.Context, db, peer *pgx.Conn, pool *database.Pool, base kernel.DirectoryAuthorityMigrationSource, owner *Contributor, command identity.Command, attempt kernel.OTPAttemptPlan, custody PhoneRecoveryCustody, admission *phoneRecoveryCountedDomain, now time.Time, mode string) {
	t.Helper()
	reset := kernel.CredentialResetMigrationSource{Base: kernel.CredentialReplacementMigrationSource{Base: base, Version: 15}, Version: 16}
	phoneReset := kernel.PhonePasswordResetMigrationSource{Base: reset, Version: 17}
	preparationSchema := kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: phoneReset, Version: 18}, Version: 19}
	for index, source := range []migrations.Source{preparationSchema, ConsumingMigrationSource{Schema: "otp_store", Version: 102}, sessionpg.PreAuthReleaseMigrationSource{Schema: "session_store", Version: 202}, sessionpg.PasswordResetMigrationSource{Schema: "session_store", Version: 203}, sessionpg.PhonePasswordResetMigrationSource{Schema: "session_store", Version: 204}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if index == 0 && m.Version() < 15 {
				continue
			}
			if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("component install", err)
			}
		}
	}
	if _, err := db.Exec(ctx, `CREATE TABLE public.phone_recovery_component_peers(owner text,command_id text,fingerprint bytea,generation numeric,PRIMARY KEY(owner,command_id))`); err != nil {
		t.Fatal(err)
	}
	preparation := custody.state.preparation
	custody.Destroy()
	domain := &phoneRecoveryProtectedDomain{phoneRecoveryCountedDomain: admission, owner: owner, generated: command, plan: attempt, preparation: preparation, mode: mode}
	effect, err := sessionpg.NewPasswordResetEffect(sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	domain.sessions = effect
	seedPhoneRecoveryEffectSessions(t, ctx, db, now)
	defer func() { domain.custody.Destroy() }()
	spec, _ := command.PhonePasswordResetFeature()
	_, proof, sms, totp, _ := command.PhonePasswordResetCustody()
	cookie, _ := command.PhonePasswordResetPreAuthCookie()
	candidate, err := password.NewSecret([]byte("synthetic component password"))
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	domain.original, err = identity.NewFeaturePhonePasswordResetInputCommand(spec, candidate, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	domain.original, err = identity.BindPhonePasswordResetPreAuth(domain.original, cookie)
	if err != nil {
		t.Fatal(err)
	}
	capPeer := &phoneRecoveryBoundPeer{descriptor: kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}, command: spec.Binding}
	riskPeer := &phoneRecoveryBoundPeer{descriptor: kernel.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}, command: spec.Binding}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{}, &phoneRecoveryProtectedLifecycle{contributorLifecycle{apply: true}}, domain, owner, riskPeer, capPeer})
	if err != nil {
		t.Fatal(err)
	}
	declaration := phoneRecoveryCountedPlan(t, registry, command, attempt, now)
	domain.declaration = declaration
	capPeer.capability = *declaration.Capability
	riskPeer.risk = *declaration.RiskEvidence
	coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 3 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := coordinator.PrepareFeaturePreparationPlan(domain.original, declaration)
	if err != nil {
		t.Fatal("closed protected phone plan", err)
	}
	if _, err := coordinator.PrepareOTPReservationPlan(spec.Binding, command, declaration); err != nil {
		t.Fatal("closed generated consuming phone plan", err)
	}
	if _, err := db.Exec(ctx, `SELECT pg_advisory_lock(73190808)`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), `SELECT pg_advisory_unlock(73190808)`)
	if mode == "protected-expired-receipt" {
		if _, err := db.Exec(ctx, `SELECT pg_advisory_lock(73190809)`); err != nil {
			t.Fatal(err)
		}
		defer db.Exec(context.Background(), `SELECT pg_advisory_unlock(73190809)`)
	}
	blocker, err := peer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	type outcome struct {
		result identity.CommandResult
		err    error
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan outcome, 1)
	joined := false
	blockCtx, stopBlock := context.WithCancel(ctx)
	locked := make(chan error, 1)
	blockStarted, blockJoined := false, false
	defer func() {
		cancel()
		_, _ = db.Exec(context.Background(), `SELECT pg_advisory_unlock(73190808)`)
		if mode == "protected-expired-receipt" {
			_, _ = db.Exec(context.Background(), `SELECT pg_advisory_unlock(73190809)`)
		}
		stopBlock()
		if blockStarted && !blockJoined {
			select {
			case <-locked:
			case <-time.After(3 * time.Second):
				t.Error("factor blocker did not stop")
			}
		}
		_ = blocker.Rollback(context.Background())
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("protected component worker did not stop")
			}
		}
	}()
	go func() {
		result, err := coordinator.ExecutePreparedFeature(runCtx, domain.original, plan)
		done <- outcome{result, err}
	}()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	waitFor := func(sql string) {
		t.Helper()
		for {
			var waiting bool
			if err := db.QueryRow(ctx, sql).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				return
			}
			select {
			case out := <-done:
				joined = true
				var challengeState, preAuthState string
				var retainedPeers int
				if err := db.QueryRow(ctx, `SELECT (SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.preauth_transactions),(SELECT count(*) FROM public.phone_recovery_component_peers)`).Scan(&challengeState, &preAuthState, &retainedPeers); err != nil {
					t.Fatal("component stopped; phase evidence unavailable", err)
				}
				t.Fatal("genuine prepared execution stopped before protected fence", out.err, "outcome", out.result.Outcome, "restored", domain.restored, "admissions", domain.admissions, "applies", domain.applies, "challenge", challengeState, "preauth", preAuthState, "retained peers", retainedPeers, "capability reservations", capPeer.reserves, "risk reservations", riskPeer.reserves)
			case <-tick.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
	}
	waitFor(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock(73190808)%')`)
	blockStarted = true
	go func() {
		_, err := blocker.Exec(blockCtx, `SELECT user_id FROM identity_mfa.factor_authorities WHERE tenant_id='tenant' AND user_id='user' FOR UPDATE`)
		locked <- err
	}()
	waitFor(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%identity_mfa.factor_authorities%FOR UPDATE%')`)
	if _, err := db.Exec(ctx, `SELECT pg_advisory_unlock(73190808)`); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-locked:
		blockJoined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	for {
		var waiting bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%identity_mfa.factor_authorities%FOR UPDATE%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case out := <-done:
			joined = true
			var challengeState, preAuthState string
			var retainedPeers int
			if err := db.QueryRow(ctx, `SELECT (SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.preauth_transactions),(SELECT count(*) FROM public.phone_recovery_component_peers)`).Scan(&challengeState, &preAuthState, &retainedPeers); err != nil {
				t.Fatal("component stopped after reservation; phase evidence unavailable", err)
			}
			t.Fatal("protected Apply did not reach original factor exclusion", out.err, "challenge", challengeState, "preauth", preAuthState, "retained peers", retainedPeers, "capability reservations", capPeer.reserves, "risk reservations", riskPeer.reserves, "applies", domain.applies)
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	probe, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, challengeErr := probe.Exec(ctx, `SELECT challenge_id FROM otp_store.challenges FOR UPDATE NOWAIT`)
	var lockoutErr error
	if challengeErr == nil {
		_, lockoutErr = probe.Exec(ctx, `SELECT scope_digest FROM otp_store.lockouts FOR UPDATE NOWAIT`)
	}
	_ = probe.Rollback(ctx)
	if challengeErr != nil || lockoutErr != nil {
		t.Fatal("protected OTP exclusions acquired before original factor fence")
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if mode == "protected-expired-receipt" {
		waitFor(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock(73190809)%')`)
		deadline := time.NewTimer(time.Until(preparation.ValidUntil.Add(25 * time.Millisecond)))
		select {
		case <-deadline.C:
		case <-ctx.Done():
			deadline.Stop()
			t.Fatal(ctx.Err())
		}
		if _, err := db.Exec(ctx, `SELECT pg_advisory_unlock(73190809)`); err != nil {
			t.Fatal(err)
		}
	}
	var out outcome
	select {
	case out = <-done:
		joined = true
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if mode != "protected-factor-order" {
		if out.err == nil || out.result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("invalidated completion did not abort", mode, out.err, out.result.Outcome)
		}
		var version, credential string
		var unused bool
		var effects, receipts int
		var challenge, preauth string
		if err := db.QueryRow(ctx, `SELECT (SELECT row_version::text FROM identity_mfa.totp_factors),(SELECT last_step IS NULL FROM identity_mfa.totp_factors),(SELECT version::text FROM identity.credential_references),(SELECT count(*) FROM public.native_otp_domain),(SELECT count(*) FROM identity.credential_replacements),(SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.preauth_transactions)`).Scan(&version, &unused, &credential, &effects, &receipts, &challenge, &preauth); err != nil {
			t.Fatal(err)
		}
		if domain.applies != 1 || version != "1" || !unused || credential != "1" || effects != 0 || receipts != 0 || challenge != "released" || preauth != "released" {
			t.Fatal("invalid completion retained protected effects", mode, version, unused, credential, effects, receipts, challenge, preauth)
		}
		requirePhoneRecoveryEffectSessions(t, ctx, db, false)
		return
	}
	if out.err != nil {
		t.Fatal("protected phone Apply", out.err)
	}
	if out.result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("protected phone did not commit", out.result.Outcome)
	}
	var version, step string
	var challenge, preauth string
	if err := db.QueryRow(ctx, `SELECT (SELECT row_version::text FROM identity_mfa.totp_factors),(SELECT last_step::text FROM identity_mfa.totp_factors),(SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.preauth_transactions)`).Scan(&version, &step, &challenge, &preauth); err != nil {
		t.Fatal(err)
	}
	if domain.applies != 1 || version != "2" || step == "" || challenge != "finalized" || preauth != "consumed" {
		t.Fatal("protected original factor/SMS consumption did not commit atomically")
	}
	requirePhoneRecoveryEffectSessions(t, ctx, db, true)
	if err := domain.actual.RequireRecorded(ctx, domain.origin, domain, command); err == nil {
		t.Fatal("returned feature receipt remained usable")
	}
	if err := domain.actual.RequireOTPApplyRecorded(ctx, kernel.OTPApplyWork{}, owner); err == nil {
		t.Fatal("returned receipt acquired an unowned final OTP callback")
	}
}

// Deliberate native storage fixtures: payloads are not authentication evidence.
// Revocation must cover all active-state rows, even expired or unusable payloads,
// without touching another tenant or changing already-revoked rows.
func seedPhoneRecoveryEffectSessions(t *testing.T, ctx context.Context, db *pgx.Conn, now time.Time) {
	t.Helper()
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('other','user','active',1)`); err != nil {
		t.Fatal(err)
	}
	for i, row := range []struct{ tenant, id, state string }{{"tenant", "current", "active"}, {"tenant", "expired", "active"}, {"tenant", "revoked", "revoked"}, {"other", "current", "active"}} {
		issued, expiry := now.Add(-time.Hour), now.Add(time.Hour)
		if row.id == "expired" {
			expiry = now.Add(-time.Minute)
		}
		if _, err := db.Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,'user',1,'active',$3)`, row.tenant, row.id, issued.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record)
VALUES($1::text,$2::text,'user',$2::text,1,1,$3,1,$4,$5,jsonb_build_object('Schema',1,'TenantID',$1::text,'SessionID',$2::text,'UserID','user','FamilyID',$2::text,'Version',1,'FamilyVersion',1,'Audience','identity','Remember','{}'::jsonb,'Authority','{}'::jsonb,'Lookup','{}'::jsonb,'Authentication','{}'::jsonb,'IssuedAt',$6::text,'LastActivityAt',$6::text))`, row.tenant, row.id, row.state, bytes.Repeat([]byte{byte(i + 1)}, 32), expiry.Format("2006-01-02T15:04:05.000000000Z"), issued.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
			t.Fatal(err)
		}
	}
}

func requirePhoneRecoveryEffectSessions(t *testing.T, ctx context.Context, db *pgx.Conn, committed bool) {
	t.Helper()
	var active, revoked, other, receipts int
	if err := db.QueryRow(ctx, `SELECT
(SELECT count(*) FROM session_store.sessions WHERE tenant_id='tenant' AND state='active'),
(SELECT count(*) FROM session_store.sessions WHERE tenant_id='tenant' AND state='revoked'),
(SELECT count(*) FROM session_store.sessions WHERE tenant_id='other' AND state='active'),
(SELECT count(*) FROM session_store.password_resets WHERE purpose='identity.phone.password-reset-complete' AND revoked_count=2)`).Scan(&active, &revoked, &other, &receipts); err != nil {
		t.Fatal(err)
	}
	wantActive, wantRevoked, wantReceipts := 2, 1, 0
	if committed {
		wantActive, wantRevoked, wantReceipts = 0, 3, 1
	}
	if active != wantActive || revoked != wantRevoked || other != 1 || receipts != wantReceipts {
		t.Fatal("canonical session effect lost atomicity, completeness or tenant scope", active, revoked, other, receipts)
	}
}
