//go:build integration

package postgres

import (
	"context"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This SQL seam tests coordinator custody/atomicity, not cryptographic factor
// verification, the production MFA store or real session issuance.
type mfaCompletionAtomicPhase struct {
	mfaCompletionValidationParticipant
	operation             identity.FeatureOperation
	failApply, failCommit bool
	retained              Work
	plan                  CommandPlan
	credential            *CredentialAdmission
	ignoreCredentialError bool
	finalCredentialDenial bool
	openCredentialCursor  bool
	sawCredentialError    bool
	preparationCredential bool
	preparationGenerated  bool
}

// Transaction oracle only: the production MFA owner must perform real locked
// factor verification and shared-budget accounting through this bounded seam.
type sqlMFATOTPAttempt struct {
	*mfaCompletionAtomicPhase
	mode     string
	calls    atomic.Int32
	retained MFATOTPAttemptWork
}

func (p *sqlMFATOTPAttempt) RecordMFATOTPAttemptDenial(ctx context.Context, w MFATOTPAttemptWork) (MFAAttemptDisposition, error) {
	p.calls.Add(1)
	p.retained = w
	b, err := w.Binding(p)
	if err != nil {
		return 0, err
	}
	if _, err := w.Binding(&sqlMFATOTPAttempt{}); err == nil {
		return 0, invalidWork()
	}
	c, err := w.NativeCommand(p)
	if err != nil || c != p.expected {
		return 0, invalidWork()
	}
	if _, err := w.DatabaseTime(ctx); err != nil {
		return 0, err
	}
	if p.credential != nil {
		if _, err := w.RequirePasskeyCredential(ctx, p, *p.credential); err != nil {
			return 0, err
		}
	}
	if _, err := w.Exec(ctx, `INSERT INTO public.identity_test_mfa_attempts(command_id,fingerprint) VALUES($1,$2)`, string(b.Command.CommandID), b.Fingerprint[:]); err != nil {
		return 0, err
	}
	switch p.mode {
	case "counted-unchanged":
		return MFAAttemptUnchanged, nil
	case "counted-error":
		return 0, identity.UnavailableError{}
	case "counted-panic":
		panic("private factor detail")
	case "counted-zero":
		return 0, nil
	case "counted-rows":
		_, err := w.Query(ctx, "SELECT 1")
		return MFAAttemptDenied, err
	}
	return MFAAttemptDenied, nil
}

type mfaCompletionFixtureAdmission struct{ owner *mfaCompletionAtomicPhase }

func (a mfaCompletionFixtureAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (a mfaCompletionFixtureAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	return a.owner.GenerateFeaturePreparation(ctx, a.owner.expected, generation)
}
func (p *mfaCompletionAtomicPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (FeaturePreparationAdmission, error) {
	if c != p.expected || ctx.Err() != nil {
		return nil, invalidPreparation()
	}
	return mfaCompletionFixtureAdmission{p}, nil
}
func (p *mfaCompletionAtomicPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	return mfaCompletionFixtureAdmission{p}, nil
}

func (p *mfaCompletionAtomicPhase) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	if c != p.expected {
		return invalidWork()
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if p.preparationCredential {
		_, err := w.RequireMFAPasskeyPreparationCredential(ctx, p, c, *p.credential)
		if err != nil && !p.ignoreCredentialError {
			return err
		}
	}
	_, err := w.DatabaseTime(ctx)
	return err
}
func (p *mfaCompletionAtomicPhase) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	if c != p.expected || generation == 0 || ctx.Err() != nil {
		return nil, invalidPreparation()
	}
	p.preparationGenerated = true
	return []byte("retained-mfa-test-output"), nil
}
func (p *mfaCompletionAtomicPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, CommandPlan, error) {
	if c != p.expected || generation == 0 || string(wire) != "retained-mfa-test-output" || ctx.Err() != nil {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	return c, p.plan, nil
}

func (p *mfaCompletionAtomicPhase) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, scope, err := w.MFACompletionConsumption(p)
	if err != nil || scope != p.completion || b.Plan != p.proof {
		return identity.FeatureReceipt{}, invalidWork()
	}
	if _, _, err := w.MFACompletionConsumption(&mfaCompletionAtomicPhase{}); err == nil {
		return identity.FeatureReceipt{}, invalidWork()
	}
	p.retained = w
	n, err := w.Exec(ctx, `INSERT INTO public.identity_test_mfa_completion(command_id,tenant_id,continuation_id,scope_digest) VALUES($1,$2,$3,$4)`, string(b.Command.CommandID), string(b.Command.TenantID), string(scope.ID), scope.ScopeDigest[:])
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	if p.credential != nil {
		var rows *WorkRows
		if p.openCredentialCursor {
			rows, err = w.Query(ctx, "SELECT 1")
			if err != nil {
				return identity.FeatureReceipt{}, err
			}
		}
		_, err := w.RequireMFAPasskeyCredential(ctx, p, *p.credential)
		p.sawCredentialError = err != nil
		if rows != nil {
			// Closing the caller's cursor must not erase a rejected guard.
			rows.Close()
		}
		if err != nil && !p.ignoreCredentialError {
			return identity.FeatureReceipt{}, err
		}
	}
	if p.failApply {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: p.operation}, nil
}
func (p *mfaCompletionAtomicPhase) CheckFeatureCommit(ctx context.Context, w Work, c identity.Command) error {
	if c != p.expected {
		return invalidWork()
	}
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return err
	}
	if _, _, err := w.MFACompletionConsumption(p); err == nil {
		return invalidWork()
	}
	if p.credential != nil {
		if p.finalCredentialDenial {
			if _, err := w.Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(p.credential.Credential.TenantID), string(p.credential.Credential.UserID), string(p.credential.Credential.ID)); err != nil {
				return err
			}
		}
		if _, err := w.RequireMFAPasskeyCredential(ctx, p, *p.credential); err != nil {
			return err
		}
	}
	if p.failCommit {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (*mfaCompletionAtomicPhase) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "public.identity_test_mfa_completion")
}

func testMFACompletion(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	// Focused selection can omit the earlier optional credential-history
	// subtests. Install those actual owned suffixes only in that isolated case;
	// a complete suite has already installed them through its migration runner.
	var credentialHistory bool
	if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='identity.users'::regclass AND attname='authority_version' AND NOT attisdropped)`).Scan(&credentialHistory); err != nil {
		t.Fatal(err)
	}
	if !credentialHistory {
		history, err := (CredentialMigrationSource{Base: StatusMigrationSource{Base: MigrationSource{}, Version: 12}, Version: 13}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history[len(history)-2:] {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("owned current-credential fixture history", err)
			}
		}
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_mfa_completion(command_id text PRIMARY KEY,tenant_id text NOT NULL,continuation_id text NOT NULL UNIQUE,scope_digest bytea NOT NULL);
CREATE TABLE public.identity_test_mfa_attempts(command_id text PRIMARY KEY,fingerprint bytea NOT NULL);
CREATE TABLE IF NOT EXISTS identity.capability_recovery_fixture(tenant_id text NOT NULL,purpose text NOT NULL,capability_id text PRIMARY KEY,expiry timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.otp_reservation_fixture(tenant_id text PRIMARY KEY,challenge_id text NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,attempt_id text,generation numeric,version numeric NOT NULL,expiry timestamptz NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "apply-denied", "commit-denied", "audit-failure", "outbox-failure", "finalize-failure", "competing-command", "prepared-otp", "prepared-otp-denied", "prepared-otp-wrong", "prepared-totp", "prepared-totp-denied", "counted-denied", "counted-unchanged", "counted-error", "counted-panic", "counted-zero", "counted-rows", "counted-audit-failure", "passkey-current", "passkey-disabled", "passkey-foreign", "passkey-stale", "passkey-ignored", "passkey-open-ignored", "passkey-final-disabled", "counted-passkey-current", "counted-passkey-disabled", "counted-passkey-foreign", "passkey-preparation-current", "passkey-preparation-disabled", "passkey-preparation-foreign", "passkey-preparation-stale", "passkey-preparation-ignored"} {
		t.Run(mode, func(t *testing.T) {
			preparedOTP := strings.HasPrefix(mode, "prepared-otp")
			preparedTOTP := mode == "prepared-totp" || mode == "prepared-totp-denied" || strings.HasPrefix(mode, "passkey-")
			prepared := preparedOTP || preparedTOTP
			counted := strings.HasPrefix(mode, "counted-")
			method := "totp-verify"
			if preparedOTP {
				method = "otp-verify"
			}
			b, p := mfaCompletionPlanFixture(t, method)
			if prepared || counted {
				b.TenantID = identity.TenantID(mode)
				p.CommandCounters = nil
			}
			var err error
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			p.Capability.CapabilityID = string(id)
			p.MFACompletion.ID = id
			op := p.Feature.Operation
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}}}})
			if prepared || counted {
				s, _ := command.Feature()
				code := "123456"
				if mode == "prepared-otp-wrong" {
					code = "654321"
				}
				command = codeCodecCommand(t, s, code)
			}
			native := &mfaCompletionAtomicPhase{mfaCompletionValidationParticipant: mfaCompletionValidationParticipant{magicLinkPreparationParticipant: magicLinkPreparationParticipant{outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{op}}}, expected: command, proof: *p.Capability}, completion: *p.MFACompletion}, operation: op, failApply: mode == "apply-denied", failCommit: mode == "commit-denied"}
			if strings.Contains(mode, "passkey-") {
				for _, user := range []string{string(p.MFACompletion.UserID), "other-user"} {
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES($1,$2,'active',1,1,1,1)`, string(b.TenantID), user); err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'passkey-a',2,'passkey',1,$3)`, string(b.TenantID), user, !strings.HasSuffix(mode, "disabled") && mode != "passkey-ignored" || mode == "passkey-final-disabled"); err != nil {
						t.Fatal(err)
					}
				}
				native.credential = &CredentialAdmission{Credential: identity.CredentialRef{ID: "passkey-a", TenantID: b.TenantID, UserID: p.MFACompletion.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}
				if strings.HasSuffix(mode, "foreign") {
					native.credential.Credential.UserID = "other-user"
				}
				if strings.HasSuffix(mode, "stale") {
					native.credential.CredentialAuthorityVersion++
				}
				native.preparationCredential = strings.HasPrefix(mode, "passkey-preparation-")
				native.ignoreCredentialError = mode == "passkey-ignored" || mode == "passkey-open-ignored" || mode == "passkey-preparation-ignored"
				if mode == "passkey-preparation-ignored" {
					native.credential.CredentialAuthorityVersion++
				}
				native.openCredentialCursor = mode == "passkey-open-ignored"
				native.finalCredentialDenial = mode == "passkey-final-disabled"
			}
			if mode == "prepared-otp-denied" || mode == "prepared-totp-denied" {
				native.failCommit = true
			}
			entries := []Contributor{repo, &recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: mode == "audit-failure"}}, &recoveryLifecyclePhase{domainLifecyclePhase: domainLifecyclePhase{fail: mode == "outbox-failure"}}, native, &emailVerificationCounterPhase{}, &emailVerificationCapabilityPhase{failFinalize: mode == "finalize-failure"}}
			var attempt *sqlMFATOTPAttempt
			if counted {
				attempt = &sqlMFATOTPAttempt{mfaCompletionAtomicPhase: native, mode: mode}
				entries[3] = attempt
				entries = append(entries[:4], entries[5:]...)
				if mode == "counted-audit-failure" {
					entries[1] = &recoveryAuditPhase{domainAuditPhase: domainAuditPhase{fail: true}}
				}
			}
			var otpOwner *sqlOTPDomain
			if preparedOTP {
				otpOwner = &sqlOTPDomain{}
				otpOwner.registered = otpOwner
				entries = append(entries[:len(entries)-1:len(entries)-1], otpOwner, entries[len(entries)-1])
				entries = append(entries[:4], entries[5:]...)
			}
			if preparedTOTP {
				entries = append(entries[:4], entries[5:]...)
			}
			registry, err := NewContributorRegistry(entries)
			if err != nil {
				t.Fatal(err)
			}
			c, err := NewCoordinator(pool, registry, CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			p.Contributors = registry.Descriptors()
			prepare := func(binding identity.CommandBinding, command identity.Command, p CommandPlan) CommandPlan {
				seed, e := securityMutationAudit(ctx, binding, 0, 0, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, binding.AnonymousFlowID, "protected", true)
				if e != nil {
					t.Fatal(e)
				}
				p.Audits = append([]AuditPlan(nil), p.Audits...)
				p.Audits[0].BindingDigest, e = FeatureAuditBindingDigest(binding, op, p.SubjectType, seed)
				if e != nil {
					t.Fatal(e)
				}
				var got CommandPlan
				if counted {
					got, e = c.PrepareMFATOTPAttemptPlan(binding, command, p)
				} else if prepared {
					got, e = c.PrepareFeaturePreparationPlan(command, p)
				} else {
					got, e = c.PrepareCommandPlan(binding, command, p)
				}
				if e != nil {
					t.Fatal("MFA completion plan", e)
				}
				return got
			}
			p = prepare(b, command, p)
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.capability_recovery_fixture VALUES($1,$2,$3,$4,'issued',NULL,NULL,NULL)`, string(b.TenantID), string(p.Capability.Purpose), p.Capability.CapabilityID, p.Capability.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			if counted {
				result, err := c.RecordMFATOTPAttemptDenial(ctx, b, command, p)
				var state string
				var charges, effects, audits, events int
				if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM public.identity_test_mfa_attempts WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_mfa_completion WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$2) FROM identity.capability_recovery_fixture WHERE capability_id=$1`, p.Capability.CapabilityID, string(b.CommandID)).Scan(&state, &charges, &effects, &audits, &events); e != nil {
					t.Fatal(e)
				}
				if err == nil || state != "issued" || effects != 0 || events != 0 || attempt.calls.Load() != 1 {
					t.Fatal("counted attempt granted completion or discarded error", err)
				}
				if mode == "counted-denied" || mode == "counted-passkey-current" {
					if result.Outcome != identity.CommitOutcomeNotCommitted || charges != 1 || audits != 1 {
						t.Fatal("counted denial not atomic", charges, audits, err)
					}
					got, e := c.RecordMFATOTPAttemptDenial(ctx, b, command, p)
					if e != nil || !reflect.DeepEqual(got, result) || attempt.calls.Load() != 1 {
						t.Fatal("counted replay repeated comparison or charge", e)
					}
					spec, _ := command.Feature()
					changed := codeCodecCommand(t, spec, "654321")
					native.expected = changed
					changedPlan, e := c.PrepareMFATOTPAttemptPlan(b, changed, p)
					if e != nil {
						t.Fatal(e)
					}
					got, e = c.RecordMFATOTPAttemptDenial(ctx, b, changed, changedPlan)
					if e == nil || got.Outcome != identity.CommitOutcomeConflict || attempt.calls.Load() != 1 {
						t.Fatal("changed counted code reused original command", e)
					}
				} else if charges != 0 || audits != 0 {
					t.Fatal("invalid/unchanged attempt retained effects", charges, audits, err)
				}
				if _, e := attempt.retained.Binding(attempt); e == nil {
					t.Fatal("returned counted invocation retained authority")
				}
				return
			}
			if preparedTOTP {
				native.plan = p
				result, err := c.ExecutePreparedFeature(ctx, command, p)
				if native.openCredentialCursor && !native.sawCredentialError {
					t.Fatal("outstanding cursor did not reject the credential guard")
				}
				var state string
				var effects, audits, events int
				if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM public.identity_test_mfa_completion WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$2),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$2) FROM identity.capability_recovery_fixture WHERE capability_id=$1`, p.Capability.CapabilityID, string(b.CommandID)).Scan(&state, &effects, &audits, &events); e != nil {
					t.Fatal(e)
				}
				if mode == "prepared-totp" || mode == "passkey-current" || mode == "passkey-preparation-current" {
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted || state != "finalized" || effects != 1 || audits != 1 || events != 1 {
						t.Fatal("prepared TOTP completion not atomic", state, effects, audits, events, err)
					}
					replay, e := c.ExecutePreparedFeature(ctx, command, p)
					if e != nil || !reflect.DeepEqual(replay, result) {
						t.Fatal("prepared TOTP replay lost original result", e)
					}
					spec, _ := command.Feature()
					changed := codeCodecCommand(t, spec, "654321")
					native.expected = changed
					if _, e := c.ExecutePreparedFeature(ctx, changed, p); e == nil {
						t.Fatal("changed opaque submission replayed completion")
					}
				} else if native.preparationCredential {
					if err == nil || state != "issued" || effects != 0 || audits != 0 || events != 0 || native.preparationGenerated {
						t.Fatal("preparation denial generated credentials or consumed original child", state, effects, audits, events, err)
					}
				} else if err == nil || state != "released" || effects != 0 || audits != 1 || events != 0 {
					t.Fatal("prepared TOTP late denial retained effects", state, effects, audits, events, err)
				}
				if native.credential != nil {
					if _, err := native.retained.RequireMFAPasskeyCredential(ctx, native, *native.credential); err == nil {
						t.Fatal("returned completion retained selected credential permission")
					}
				}
				return
			}
			if preparedOTP {
				native.plan = p
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.otp_reservation_fixture(tenant_id,challenge_id,state,version,expiry) VALUES($1,$2,'issued',$3,clock_timestamp()+interval '1 minute')`, string(b.TenantID), p.OTP.ChallengeID, p.OTP.ExpectedVersion); err != nil {
					t.Fatal(err)
				}
				result, err := c.ExecutePreparedFeature(ctx, command, p)
				var state string
				var effects int
				if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM public.identity_test_mfa_completion WHERE command_id=$2) FROM public.otp_reservation_fixture WHERE tenant_id=$1`, string(b.TenantID), string(b.CommandID)).Scan(&state, &effects); e != nil {
					t.Fatal(e)
				}
				if mode == "prepared-otp-wrong" {
					// This success-path fixture has no durable wrong-attempt
					// ledger. Its rejection must fail closed, not claim a
					// classified denial or consume the legitimate challenge.
					if err == nil || result.Outcome == identity.CommitOutcomeCommitted || state != "issued" || effects != 0 || otpOwner.calls.Load() != 0 {
						t.Fatal("wrong prepared code reached consuming reservation", state, effects, err)
					}
				} else if mode == "prepared-otp" {
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted || state != "finalized" || effects != 1 {
						t.Fatal("prepared OTP completion not atomic", state, effects, err)
					}
					result, err = c.ExecutePreparedFeature(ctx, command, p)
					if err != nil || result.Outcome != identity.CommitOutcomeCommitted || otpOwner.calls.Load() != 1 {
						t.Fatal("prepared OTP replay compared again", err)
					}
				} else if err == nil || state != "released" || effects != 0 || otpOwner.calls.Load() != 1 {
					t.Fatal("prepared OTP denial retained effects", state, effects, err)
				}
				return
			}
			r, _, err := c.ReserveCommand(ctx, b, command, p)
			if err != nil {
				t.Fatal("completion reserve", err)
			}
			if mode == "competing-command" {
				other := b
				other.CommandID, err = identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				s, _ := command.Feature()
				s.Binding = other
				second := featureCodecCommand(t, s)
				native.expected = second
				otherPlan := prepare(other, second, p)
				if got, _, err := c.ReserveCommand(ctx, other, second, otherPlan); err == nil || got.state != nil {
					t.Fatal("child admitted competing completion")
				}
				native.expected = command
			}
			w, err := c.Begin(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(w, identity.UnavailableError{})
			result, err := c.ApplyFeature(ctx, w, command)
			if err == nil {
				result, err = c.Commit(w, result)
			}
			success := mode == "commit" || mode == "competing-command"
			if success {
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("completion did not commit", err)
				}
				retry, replay, e := c.ReserveCommand(ctx, b, command, p)
				if e != nil || retry.state != nil || replay.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("lost original completion replay", e)
				}
			} else {
				if err == nil {
					t.Fatal("denial committed completion")
				}
				_, _ = c.Abort(w, err)
			}
			if _, _, err := native.retained.MFACompletionConsumption(native); err == nil {
				t.Fatal("returned invocation retained custody")
			}
			var effects, events, audits int
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_test_mfa_completion WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_lifecycle WHERE command_id=$1),(SELECT count(*) FROM public.identity_test_audits WHERE command_id=$1),(SELECT state FROM identity.capability_recovery_fixture WHERE capability_id=$2)`, string(b.CommandID), p.Capability.CapabilityID).Scan(&effects, &events, &audits, &state); err != nil {
				t.Fatal(err)
			}
			if success {
				if effects != 1 || events != 1 || audits != 1 || state != "finalized" {
					t.Fatal("split completion", effects, events, audits, state)
				}
			} else if effects != 0 || events != 0 || state == "consuming" || state == "finalized" {
				t.Fatal("denial retained completion", effects, events, state)
			}
		})
	}
}
