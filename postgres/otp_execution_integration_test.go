//go:build integration

package postgres

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// Native SQL fixture proves coordinator atomicity, not OTP cryptography.
type sqlOTPDomain struct {
	sqlOTPReservation
	behavior string
	checks   int
	apply    OTPApplyWork
	finalize OTPFinalizeWork
	release  OTPReleaseWork
}

// Prepared MFA invokes the non-consuming precheck before reservation. Do not
// inherit the denial-only unit probe here: this fixture represents a correct
// synthetic submission against a live SQL challenge, not OTP cryptography or
// production wrong-attempt accounting.
func (p *sqlOTPDomain) RecordOTPAttemptDenial(ctx context.Context, w OTPAttemptWork) (OTPAttemptDisposition, error) {
	b, err := w.Binding(p)
	if err != nil {
		return 0, err
	}
	if _, err := w.Binding(&sqlOTPDomain{}); err == nil {
		return 0, invalidWork()
	}
	command, err := w.NativeCommand(p)
	s, ok := command.Feature()
	if err != nil || !ok || s.Binding != b.Command {
		return 0, invalidWork()
	}
	code, ok := command.OneTimeCode()
	if !ok {
		return 0, invalidWork()
	}
	expected, err := authentication.NewOneTimeCode("123456")
	if err != nil {
		return 0, err
	}
	key, scope := [32]byte{1}, []byte(b.Command.CommandID)
	got, err := code.KeyedDigest(key, scope)
	if err != nil {
		return 0, err
	}
	want, err := expected.KeyedDigest(key, scope)
	if err != nil || !hmac.Equal(got[:], want[:]) {
		return 0, identity.ForbiddenError{}
	}
	rows, err := w.Query(ctx, `SELECT version::text FROM public.otp_reservation_fixture WHERE tenant_id=$1 AND challenge_id=$2 AND state='issued' AND expiry>clock_timestamp() FOR UPDATE`, string(b.Command.TenantID), b.Plan.ChallengeID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var version string
	if !rows.Next() || rows.Scan(&version) != nil || rows.Next() || rows.Err() != nil || version != strconv.FormatUint(b.Plan.ExpectedVersion, 10) {
		return 0, identity.ForbiddenError{}
	}
	return OTPAttemptUnchanged, nil
}

func (p *sqlOTPDomain) CheckOTP(ctx context.Context, w OTPApplyWork) error {
	p.apply = w
	p.checks++
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if _, err := w.Binding(&sqlOTPDomain{}); err == nil {
		return invalidWork()
	}
	s, err := w.CommandSpec(p)
	if err != nil || s.Binding != b.Command {
		return invalidWork()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM public.otp_reservation_fixture WHERE tenant_id=$1 AND challenge_id=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND attempt_id=$5 AND generation=$6::numeric AND version=$7::numeric AND expiry>clock_timestamp())`, string(b.Command.TenantID), b.Plan.ChallengeID, string(b.Command.CommandID), b.Fingerprint[:], b.Plan.AttemptID, strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.Plan.ExpectedVersion, 10))
	if err != nil {
		return err
	}
	var valid bool
	ok := rows.Next() && rows.Scan(&valid) == nil
	if rows.Next() || rows.Err() != nil {
		ok = false
	}
	rows.Close()
	if !ok || !valid || p.behavior == "deny-apply" || p.behavior == "deny-final" && p.checks == 2 || strings.HasPrefix(p.behavior, "release-") {
		return identity.ForbiddenError{}
	}
	switch p.behavior {
	case "panic":
		panic("private OTP current detail")
	case "rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	case "poison":
		_, _ = w.Query(ctx, "SELECT 1/0")
	}
	return nil
}

func (p *sqlOTPDomain) FinalizeOTP(ctx context.Context, w OTPFinalizeWork) error {
	p.finalize = w
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if _, err := w.Binding(&sqlOTPDomain{}); err == nil {
		return invalidWork()
	}
	s, err := w.CommandSpec(p)
	if err != nil || s.Binding != b.Command {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE public.otp_reservation_fixture SET state='finalized' WHERE tenant_id=$1 AND challenge_id=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND attempt_id=$5 AND generation=$6::numeric AND version=$7::numeric AND expiry>clock_timestamp()`, string(b.Command.TenantID), b.Plan.ChallengeID, string(b.Command.CommandID), b.Fingerprint[:], b.Plan.AttemptID, strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.Plan.ExpectedVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	switch p.behavior {
	case "finalize-error":
		return errors.New("private OTP terminal detail")
	case "finalize-panic":
		panic("private OTP terminal detail")
	case "finalize-rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	case "finalize-poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
	}
	return nil
}

func (p *sqlOTPDomain) ReleaseOTP(ctx context.Context, w OTPReleaseWork) error {
	p.release = w
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if _, err := w.Binding(&sqlOTPDomain{}); err == nil {
		return invalidWork()
	}
	n, err := w.Exec(ctx, `UPDATE public.otp_reservation_fixture SET state='released',generation=$7::numeric WHERE tenant_id=$1 AND challenge_id=$2 AND state='reserved' AND command_id=$3 AND fingerprint=$4 AND attempt_id=$5 AND generation=$6::numeric`, string(b.Command.TenantID), b.Plan.ChallengeID, string(b.Command.CommandID), b.Fingerprint[:], b.Plan.AttemptID, strconv.FormatUint(b.PreviousGeneration, 10), strconv.FormatUint(b.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	switch p.behavior {
	case "release-error":
		return errors.New("private OTP release detail")
	case "release-panic":
		panic("private OTP release detail")
	case "release-rows":
		_, err = w.Query(ctx, "SELECT 1")
		return err
	}
	return nil
}

func (p *sqlOTPDomain) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	if p.behavior == "unknown" {
		return RecoveryUnknown, nil
	}
	b, err := w.OTPBinding(p)
	if err != nil {
		return RecoveryUnknown, err
	}
	if _, err := w.OTPBinding(&sqlOTPDomain{}); err == nil {
		return RecoveryUnknown, invalidWork()
	}
	rows, err := w.Query(ctx, `SELECT state FROM public.otp_reservation_fixture WHERE tenant_id=$1 AND challenge_id=$2 AND command_id=$3 AND fingerprint=$4 AND attempt_id=$5 AND generation=$6::numeric`, string(b.Command.TenantID), b.Plan.ChallengeID, string(b.Command.CommandID), b.Fingerprint[:], b.Plan.AttemptID, strconv.FormatUint(b.PreviousGeneration, 10))
	if err != nil {
		return RecoveryUnknown, err
	}
	var state string
	ok := rows.Next() && rows.Scan(&state) == nil
	if rows.Next() || rows.Err() != nil {
		ok = false
	}
	rows.Close()
	if !ok || state != "reserved" {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}

type otpDomainFeature struct {
	scopeFeatureParticipant
	expire      bool
	work        Work
	consumption OTPReservationBinding
}

func (p *otpDomainFeature) ApplyFeature(ctx context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	if _, _, _, err := w.FeatureScope(p); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := c.Feature()
	b, err := w.OTPConsumption(p)
	if err != nil || b.Command != s.Binding || b.Generation == 0 || b.PreviousGeneration != 0 || b.Plan.Mode != OTPConsume || b.Fingerprint == ([32]byte{}) {
		return identity.FeatureReceipt{}, invalidWork()
	}
	if _, err := w.OTPConsumption(&otpDomainFeature{}); err == nil {
		return identity.FeatureReceipt{}, invalidWork()
	}
	p.work, p.consumption = w, b
	if _, err := w.Exec(ctx, `INSERT INTO identity.otp_domain_fixture(command_id) VALUES($1)`, string(s.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.expire {
		if _, err := w.Exec(ctx, `UPDATE public.otp_reservation_fixture SET expiry=clock_timestamp()-interval '1 second' WHERE tenant_id=$1`, string(s.Binding.TenantID)); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
}
func (*otpDomainFeature) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "identity.otp_domain_fixture")
}

type otpDomainAudit struct{ featureExecutionAuditPhase }

func (*otpDomainAudit) PersistAudits(ctx context.Context, w Work) error {
	records, err := w.StagedAudits()
	if err != nil {
		return err
	}
	for _, r := range records {
		if _, err := w.Exec(ctx, `INSERT INTO identity.otp_domain_audit(command_id,event_id,outcome) VALUES($1,$2,$3)`, string(w.state.binding.CommandID), r.Record.ID(), string(r.Record.Outcome())); err != nil {
			return err
		}
	}
	return nil
}
func (*otpDomainAudit) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "identity.otp_domain_audit")
}

type otpDomainOutbox struct{ recoveryLifecyclePhase }

func (*otpDomainOutbox) PersistLifecycle(ctx context.Context, w Work) error {
	events, err := w.StagedLifecycle()
	if err != nil {
		return err
	}
	for _, e := range events {
		if _, err := w.Exec(ctx, `INSERT INTO identity.otp_domain_outbox(command_id,event_id) VALUES($1,$2)`, string(e.CommandID), e.ID); err != nil {
			return err
		}
	}
	return nil
}
func (*otpDomainOutbox) RecoverParticipant(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	return recoveryTestEvidence(ctx, w, "identity.otp_domain_outbox")
}

func testOTPExecution(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE IF NOT EXISTS public.otp_reservation_fixture(tenant_id text PRIMARY KEY,challenge_id text NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,attempt_id text,generation numeric,version numeric NOT NULL,expiry timestamptz NOT NULL); CREATE TABLE identity.otp_domain_fixture(command_id text PRIMARY KEY); CREATE TABLE identity.otp_domain_audit(command_id text NOT NULL,event_id text PRIMARY KEY,outcome text NOT NULL); CREATE TABLE identity.otp_domain_outbox(command_id text PRIMARY KEY,event_id text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"allow", "deny-apply", "deny-final", "expiry", "panic", "rows", "poison", "finalize-error", "finalize-panic", "finalize-rows", "finalize-poison", "release-error", "release-panic", "release-rows", "recover", "unknown", "divergent-recovery"} {
		t.Run(mode, func(t *testing.T) {
			owner := &sqlOTPDomain{behavior: mode}
			owner.registered = owner
			_, command, plan := otpAttemptFixture(t, owner)
			s, _ := command.Feature()
			s.Binding.CommandID, _ = identity.NewCommandID()
			s.Binding.TenantID = identity.TenantID("otp-execute-" + mode)
			b := s.Binding
			feature := &otpDomainFeature{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}, expire: mode == "expiry"}
			r, err := NewContributorRegistry([]Contributor{repo, &otpDomainAudit{}, &otpDomainOutbox{}, feature, owner})
			if err != nil {
				t.Fatal(err)
			}
			policy := &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})}
			c, err := NewCoordinator(pool, r, CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: policy})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = r.Descriptors()
			plan.Feature.Contributor = feature.Descriptor()
			plan.OTP.AttemptID = string(b.CommandID)
			plan.Audits[0].BindingDigest = securityAuditScopeDigest(b, &s.Operation, plan.SubjectType, b.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
			command = codeCodecCommand(t, s, "123456")
			plan, err = c.PrepareOTPReservationPlan(b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.otp_reservation_fixture(tenant_id,challenge_id,state,version,expiry) VALUES($1,$2,'issued',1,clock_timestamp()+interval '1 minute')`, string(b.TenantID), plan.OTP.ChallengeID); err != nil {
				t.Fatal(err)
			}
			reservation, _, err := c.ReserveOTPCommand(ctx, b, command, plan)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var result identity.CommandResult
			if mode == "recover" || mode == "unknown" || mode == "divergent-recovery" {
				if mode == "divergent-recovery" {
					if _, err := pool.Raw().Exec(ctx, `UPDATE public.otp_reservation_fixture SET generation=99 WHERE tenant_id=$1`, string(b.TenantID)); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
					t.Fatal(err)
				}
				q, caller := queryInputs(b)
				result, err = c.RecoverOTPFeatureCommand(ctx, q, *plan.OTP, caller)
				if mode == "recover" && (err == nil || result.Outcome != identity.CommitOutcomeNotCommitted) {
					t.Fatal("noncommit not released", err, result.Outcome)
				}
				if mode != "recover" && (err == nil || result.Outcome != identity.CommitOutcomeInProgress) {
					t.Fatal("unknown released", err, result.Outcome)
				}
			} else {
				w, e := c.Begin(ctx, reservation)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Abort(w, identity.UnavailableError{})
				result, err = c.ApplyFeature(ctx, w, command)
				if err == nil {
					result, err = c.Commit(w, result)
				} else {
					result, err = c.Abort(w, err)
				}
				if mode == "allow" && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || owner.checks != 2) {
					t.Fatal("atomic use failed", err, result.Outcome, owner.checks)
				}
				want := identity.CommitOutcomeNotCommitted
				if strings.HasPrefix(mode, "release-") {
					want = identity.CommitOutcomeUnknown
				}
				if mode != "allow" && (err == nil || result.Outcome != want || strings.Contains(err.Error(), "private")) {
					t.Fatal("failed use escaped", err, result.Outcome)
				}
			}
			var challenge, journal string
			var domain, audits, outbox int
			if err := pool.Raw().QueryRow(ctx, `SELECT e.state,c.state,(SELECT count(*) FROM identity.otp_domain_fixture WHERE command_id=$3),(SELECT count(*) FROM identity.otp_domain_audit WHERE command_id=$3),(SELECT count(*) FROM identity.otp_domain_outbox WHERE command_id=$3) FROM public.otp_reservation_fixture e JOIN identity.commands c ON c.command_id=$1 WHERE e.tenant_id=$2`, raw, string(b.TenantID), string(b.CommandID)).Scan(&challenge, &journal, &domain, &audits, &outbox); err != nil {
				t.Fatal(err)
			}
			if mode == "allow" {
				if challenge != "finalized" || journal != "committed" || domain != 1 || audits != 1 || outbox != 1 {
					t.Fatal("success not atomic", challenge, journal, domain, audits, outbox)
				}
				if feature.consumption.Command != b || feature.consumption.Plan != *plan.OTP || feature.consumption.Generation != 1 {
					t.Fatal("protected effect lost original consuming binding")
				}
			} else if mode == "unknown" || mode == "divergent-recovery" || strings.HasPrefix(mode, "release-") {
				if challenge != "reserved" || journal != "pending" || domain != 0 || audits != 0 || outbox != 0 {
					t.Fatal("unknown lost custody", challenge, journal, domain, audits, outbox)
				}
			} else if challenge != "released" || journal != "aborted" || domain != 0 || audits != 1 || outbox != 0 {
				t.Fatal("failure prefix escaped", challenge, journal, domain, audits, outbox)
			}
			if owner.calls.Load() != 1 {
				t.Fatal("verification repeated")
			}
			if mode == "allow" || mode == "recover" || mode == "unknown" {
				q, caller := queryInputs(b)
				got, recoveryErr := c.RecoverOTPFeatureCommand(ctx, q, *plan.OTP, caller)
				if got.Binding != b || got.Outcome != result.Outcome || (recoveryErr == nil) != (mode == "allow") || owner.calls.Load() != 1 {
					t.Fatal("public consuming recovery changed original outcome or compared again", got.Outcome, recoveryErr)
				}
				other := *plan.OTP
				other.AttemptFingerprint[0]++
				got, recoveryErr = c.RecoverOTPFeatureCommand(ctx, q, other, caller)
				var denied identity.ForbiddenError
				if got.Binding.CommandID != "" || !errors.As(recoveryErr, &denied) {
					t.Fatal("changed consuming correlation disclosed primary history", recoveryErr)
				}
				if mode == "allow" {
					// Simulate a stale preliminary primary observation with another
					// valid plan. The real locked row still holds the original plan.
					// A preflight-only check would incorrectly disclose its receipt.
					read := c.commandRead
					original, readErr := read(ctx, b.CommandID)
					if readErr != nil {
						t.Fatal(readErr)
					}
					pending := "pending"
					original.state, original.resultVersion, original.class, original.result = &pending, nil, nil, nil
					changed := plan
					changed.OTP = &other
					original.plan, readErr = encodeFeaturePlan(b, [32]byte(original.fingerprint), changed)
					if readErr != nil {
						t.Fatal(readErr)
					}
					c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { return original, nil }
					got, recoveryErr = c.RecoverOTPFeatureCommand(ctx, q, other, caller)
					c.commandRead = read
					if got.Binding.CommandID != "" || !errors.As(recoveryErr, &denied) || owner.calls.Load() != 1 {
						t.Fatal("locked original plan was not rechecked", recoveryErr)
					}
				}
			}
			if got, err := feature.work.OTPConsumption(feature); err == nil || got != (OTPReservationBinding{}) {
				t.Fatal("returned feature handle retained consumption access")
			}
			for _, binding := range []func(OTPReservationContributor) (OTPReservationBinding, error){owner.apply.Binding, owner.finalize.Binding, owner.release.Binding} {
				if _, err := binding(owner); err == nil {
					t.Fatal("returned handle revived")
				}
			}
		})
	}
}
