//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresVerificationMFASignin(t *testing.T) {
	for _, profile := range []string{"totp-browser", "totp-persistent"} {
		t.Run(profile, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: profile, mfaEnrollment: true}, true)
		})
	}
}

func TestReferencePostgresVerificationMFASigninKnownEmpty(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "empty-totp"}, true)
}

func TestReferencePostgresVerificationMFASigninWithdrawnParent(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "totp-withdrawn-parent", mfaEnrollment: true}, true)
}

func TestReferencePostgresVerificationMFASigninWithPasswordMFA(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "totp-with-password", mfaEnrollment: true, passwordMFA: true}, true)
}

func TestReferencePostgresVerificationMFASigninOriginalExpiry(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "totp-original-expiry", mfaEnrollment: true}, true)
}

type verificationMFAOriginalExpiryPolicy struct {
	pool    *database.Pool
	elapsed atomic.Bool
}

func (p *verificationMFAOriginalExpiryPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.mfa.totp-verify" && c.Request.Resource.Type == "identity.user" && c.Request.Subject.Kind == authorization.SubjectServiceAccount && !p.elapsed.Load() {
		var expiry time.Time
		if e := p.pool.Raw().QueryRow(ctx, `SELECT expires_at FROM capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.identifier.verify' AND state='finalized'`, string(c.Request.Tenant)).Scan(&expiry); e != nil {
			return authorization.Decision{}, identity.UnavailableError{}
		}
		timer := time.NewTimer(max(0, time.Until(expiry)+10*time.Millisecond))
		defer timer.Stop()
		select {
		case <-timer.C:
			p.elapsed.Store(true)
		case <-ctx.Done():
			return authorization.Decision{}, ctx.Err()
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func TestReferencePostgresVerificationMFASigninCurrentAuthority(t *testing.T) {
	for _, profile := range []string{"totp-late-account", "totp-late-identifier", "totp-late-factor", "totp-late-policy"} {
		t.Run(profile, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: profile, mfaEnrollment: true}, true)
		})
	}
}

func TestReferencePostgresVerificationMFASigninContention(t *testing.T) {
	for _, profile := range []string{"totp-contention-same", "totp-contention-different"} {
		t.Run(profile, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: profile, mfaEnrollment: true}, true)
		})
	}
}

type verificationMFALateAuthorityPolicy struct {
	pool    *database.Pool
	mode    string
	changed atomic.Bool
}

func (p *verificationMFALateAuthorityPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.mfa.totp-verify" && c.Request.Resource.Type == "identity.user" && c.Request.Subject.Kind == authorization.SubjectServiceAccount && !p.changed.Load() {
		query := ""
		switch p.mode {
		case "totp-late-account":
			query = `UPDATE identity.users SET status='suspended',authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`
		case "totp-late-identifier":
			query = `UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id=$2`
		case "totp-late-factor":
			query = `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`
		case "totp-late-policy":
			query = `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id=$1 AND subject_id=$2 AND policy_namespace='users'`
		}
		r, err := p.pool.Raw().Exec(ctx, query, string(c.Request.Tenant), string(c.Request.Resource.ID))
		if err != nil || r.RowsAffected() != 1 {
			return authorization.Decision{}, identity.UnavailableError{}
		}
		p.changed.Store(true)
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func TestReferencePostgresVerificationMFASigninUnknownChild(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "totp-child-unknown", mfaEnrollment: true, completionCommitFault: true}, true)
}

func TestReferencePostgresVerificationMFASigninPreparedRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "totp-prepared-recovery", mfaEnrollment: true}, true)
}

func TestReferencePostgresVerificationMFASigninUnknownCompletion(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: "totp-completion-unknown", mfaEnrollment: true, completionCommitFault: true}, true)
}

func TestReferencePostgresVerificationMFASigninRollback(t *testing.T) {
	for _, profile := range []string{"totp-child-rollback", "totp-completion-rollback"} {
		t.Run(profile, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, verificationSignin: profile, mfaEnrollment: true}, true)
		})
	}
}

// Withdraw retained parent envelope custody after the native primary reader has
// authenticated it, at the public policy seam preceding protected execution.
// The protected parent fence, not another preliminary lookup, must reject it.
type verificationMFAWithdrawnParentPolicy struct {
	pool      *database.Pool
	withdrawn atomic.Bool
}

func (p *verificationMFAWithdrawnParentPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.mfa.totp-verify" && c.Request.Resource.Type == "identity.user" && p.withdrawn.CompareAndSwap(false, true) {
		digest := sha256.Sum256([]byte("withdrawn-verification-parent-test-custody"))
		r, err := p.pool.Raw().Exec(ctx, `UPDATE capability_identity_one_use SET proof_fingerprint=$2 WHERE tenant_id=$1 AND purpose='identity.identifier.verify' AND state='finalized'`, string(c.Request.Tenant), digest[:])
		if err != nil || r.RowsAffected() != 1 {
			return authorization.Decision{}, identity.UnavailableError{}
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

// Pause one preliminary factor read after verification commits, without changing
// any state or policy. The test enrolls through public owners in that real
// concurrent window. No callback runs under a driver lock or open transaction.
type verificationMFAEnrollmentTrace struct {
	armed          atomic.Bool
	entered        chan struct{}
	proceed        chan struct{}
	deadline       time.Time
	cancelPrepared context.CancelFunc
	prepared       atomic.Bool
	cancelled      atomic.Bool
}

type verificationMFACommitQuery struct{}

func (p *verificationMFAEnrollmentTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if q.SQL == `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2` && p.armed.CompareAndSwap(true, false) {
		p.deadline, _ = ctx.Deadline()
		close(p.entered)
		select {
		case <-p.proceed:
		case <-ctx.Done():
		}
	}
	if p.cancelPrepared != nil && strings.HasPrefix(q.SQL, "UPDATE identity.commands SET command_plan=") {
		p.prepared.Store(true)
	}
	return context.WithValue(ctx, verificationMFACommitQuery{}, strings.EqualFold(q.SQL, "commit"))
}
func (p *verificationMFAEnrollmentTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryEndData) {
	if commit, _ := ctx.Value(verificationMFACommitQuery{}).(bool); commit && q.Err == nil && p.cancelPrepared != nil && p.prepared.CompareAndSwap(true, false) {
		p.cancelled.Store(true)
		p.cancelPrepared()
	}
}

func newVerificationMFAEnrollmentTrace(t *testing.T, ctx context.Context, pool *database.Pool) (*database.Pool, *verificationMFAEnrollmentTrace) {
	t.Helper()
	hook := &verificationMFAEnrollmentTrace{entered: make(chan struct{}), proceed: make(chan struct{})}
	traced, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Tracer = hook
		return nil
	}})
	if err != nil {
		t.Fatal("bounded enrollment trace pool unavailable", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := traced.Close(bounded); err != nil {
			t.Error("enrollment trace pool cleanup failed", err)
		}
	})
	return traced, hook
}

func proveReferenceVerificationMFASignin(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, owner email.RegistrationVerificationSigninService, request email.VerificationSigninRequest, client *http.Client, base, origin, profile string) {
	t.Helper()
	hook := f.verificationMFAHook
	if hook == nil {
		t.Fatal("genuine enrollment window unavailable")
	}
	type observation struct {
		result email.VerificationSigninResult
		err    error
	}
	done := make(chan observation, 1)
	callCtx, cancelCall := context.WithCancel(ctx)
	defer cancelCall()
	hook.armed.Store(true)
	go func() {
		result, err := owner.VerificationConfirmAndSignin(callCtx, request)
		done <- observation{result, err}
		close(done)
	}()
	defer func() {
		hook.armed.Store(false)
		select {
		case <-hook.proceed:
		default:
			close(hook.proceed)
		}
		// Join even on test failure; the owner has its original bounded deadline.
		for range done {
		}
	}()
	select {
	case <-hook.entered:
	case out := <-done:
		t.Fatal("verification never reached its preliminary factor read", out.err)
	case <-ctx.Done():
		t.Fatal("verification enrollment window expired")
	}
	enrollmentStarted := time.Now()
	factor, secret := enrollVerificationMFATOTP(t, ctx, features, client, base, origin)
	enrollmentElapsed := time.Since(enrollmentStarted)
	defer clear(secret)
	if f.verificationMFAOriginalExpiry != nil && f.verificationMFAOriginalExpiry.elapsed.Load() {
		t.Fatal("original-expiry fault intercepted enrollment before completion")
	}
	var sessionsBefore, active int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),count(*) FROM identity_mfa.totp_factors WHERE factor_id=$1 AND state=2 AND confirmed_at IS NOT NULL`, string(factor)).Scan(&sessionsBefore, &active); err != nil || sessionsBefore != 1 || active != 1 {
		t.Fatal("genuine password-session/TOTP setup missing", err)
	}
	if f.completionFault != nil && f.completionFault.mfaChallenge {
		f.completionFault.armed.Store(true)
	}
	if profile == "totp-child-rollback" {
		if _, e := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.verification_child_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic child rollback'; END $$; CREATE TRIGGER verification_child_fail BEFORE INSERT ON identity_mfa.continuations FOR EACH ROW EXECUTE FUNCTION public.verification_child_fail()`); e != nil {
			t.Fatal("child rollback fixture unavailable", e)
		}
	}
	if profile == "totp-prepared-recovery" {
		hook.cancelPrepared = cancelCall
	}
	close(hook.proceed)
	out := <-done
	if profile == "totp-prepared-recovery" {
		if !hook.cancelled.Load() || out.err == nil || out.result.Verification.Outcome != identity.CommitOutcomeCommitted || out.result.Challenge != nil || out.result.Issuance.Token != (session.Token{}) {
			t.Fatal("cancelled durable preparation disclosed credentials or lost verification", out.err)
		}
		command, _ := base64.RawURLEncoding.Strict().DecodeString(string(out.result.Recovery.CommandID))
		var final bool
		var until time.Time
		if e := f.pool.Raw().QueryRow(ctx, `SELECT command_plan IS NOT NULL,lease_until FROM identity.commands WHERE command_id=$1`, command).Scan(&final, &until); e != nil || !final {
			t.Fatal("cancelled preparation did not retain a real final plan", e)
		}
		timer := time.NewTimer(max(0, time.Until(until)+10*time.Millisecond))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("original preparation lease did not expire")
		}
		queryCaller := request.Confirmation.Caller.Clone()
		queryCaller.Request.Action = "identity.email.verification-signin"
		queryCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(out.result.Recovery.UserID)}
		recovered, e := owner.VerificationSigninRecover(ctx, out.result.Recovery, queryCaller)
		if recovered.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("expired durable preparation could not reconcile its actual owner", recovered.Outcome, e)
		}
		var sessions, children int
		if e = f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM identity_mfa.continuations)`).Scan(&sessions, &children); e != nil || sessions != sessionsBefore || children != 0 {
			t.Fatal("preparation recovery minted effects", e)
		}
		return
	}
	if profile == "totp-child-rollback" {
		if out.err == nil || out.result.Verification.Outcome != identity.CommitOutcomeCommitted || out.result.Challenge != nil || out.result.Issuance.Token != (session.Token{}) || out.result.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("failed child erased confirmation or disclosed credentials", out.err)
		}
		var sessions, continuations, verified, children int
		if e := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM identity_mfa.continuations),(SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT count(*) FROM capability_identity_one_use WHERE purpose='identity.mfa.complete')`).Scan(&sessions, &continuations, &verified, &children); e != nil || sessions != sessionsBefore || continuations != 0 || verified != 1 || children != 0 {
			t.Fatal("failed child leaked continuation/grant/session or rolled back verification", e)
		}
		return
	}
	if f.completionFault != nil && f.completionFault.mfaChallenge {
		if !f.completionFault.hit.Load() || out.err == nil || out.result.Verification.Outcome != identity.CommitOutcomeCommitted || out.result.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || out.result.Challenge != nil || out.result.Issuance.Token != (session.Token{}) || out.result.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("lost challenge COMMIT acknowledgement disclosed credentials or erased verification", out.err)
		}
		queryCaller := request.Confirmation.Caller.Clone()
		queryCaller.Request.Action = "identity.email.verification-signin"
		queryCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(out.result.Recovery.UserID)}
		for range 2 {
			recovered, e := owner.VerificationSigninRecover(ctx, out.result.Recovery, queryCaller)
			if e != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Feature == nil {
				t.Fatal("unknown challenge did not reconcile original committed metadata", e)
			}
		}
		var sessions, continuations int
		if e := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM identity_mfa.continuations)`).Scan(&sessions, &continuations); e != nil || sessions != sessionsBefore || continuations != 1 {
			t.Fatal("challenge recovery created a session or replacement child", e)
		}
		replay, e := owner.VerificationConfirmAndSignin(ctx, request)
		if e != nil || !replay.Verification.Replayed || replay.Challenge != nil || replay.Issuance.Token != (session.Token{}) {
			t.Fatal("unknown challenge replay recreated credentials", e)
		}
		return
	}
	if out.err != nil || out.result.Validate() != nil || out.result.Verification.Outcome != identity.CommitOutcomeCommitted || out.result.Issuance.Token != (session.Token{}) || out.result.CSRFToken != (session.CSRFToken{}) {
		id, _ := base64.RawURLEncoding.DecodeString(string(out.result.Recovery.CommandID))
		var state string
		var started, output, final bool
		if e := f.pool.Raw().QueryRow(ctx, `SELECT state,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL FROM identity.commands WHERE command_id=$1`, id).Scan(&state, &started, &output, &final); e == nil {
			t.Log("child journal boundary", state, "started", started, "output", output, "final", final)
		}
		t.Fatal("genuinely enrolled verification did not return pending MFA without session", out.err, "enrollment", enrollmentElapsed, "setup deadline remaining", time.Until(hook.deadline))
	}
	if out.result.Challenge == nil || out.result.Challenge.Method != "totp" || out.result.Challenge.Proof == (capability.Proof{}) {
		t.Fatal("pending verification did not disclose one usable TOTP child")
	}
	issuer, err := issuerpg.NewIssuer(f.config.PasswordSignup.VerificationSignin.TOTP.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	grant, originID, _, err := issuer.ReadIssuanceOrigin(ctx, f.pool, out.result.Challenge.Proof, "identity.mfa.complete")
	if err != nil || originID != out.result.Recovery.CommandID {
		t.Fatal("original child issuance provenance lost", err)
	}
	reader, err := mfapg.NewContinuationReader(f.pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := reader.Read(ctx, grant, origin)
	if err != nil {
		t.Fatal("native committed continuation unreadable", err)
	}
	scope, err := continuation.Bindings()
	if err != nil || scope.VerificationCommandID != request.Confirmation.CommandID || grant.Payload().CorrelationID != string(request.Confirmation.CommandID) || len(scope.AllowedMethods) != 1 || scope.AllowedMethods[0] != "totp" || scope.SourcePreAuthID == "" || !scope.ExpiresAt.Equal(out.result.Challenge.ExpiresAt) {
		t.Fatal("verification origin or original scope lost", err)
	}
	registrationIssuer, err := issuerpg.NewIssuer(f.config.PasswordSignup.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	primary, signupID, _, err := registrationIssuer.ReadRegistrationOrigin(ctx, f.pool, request.Confirmation.Token)
	if err != nil || string(scope.PrimaryProofID) != primary.Payload().ID || scope.PrimaryProofDigest != primary.EnvelopeDigest() || !scope.PrimaryProofExpiresAt.Equal(primary.Payload().ExpiresAt) || scope.ExpiresAt.After(primary.Payload().ExpiresAt) {
		t.Fatal("child replaced original verification grant/deadline", err)
	}
	var sessionsPending int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions`).Scan(&sessionsPending); err != nil || sessionsPending != sessionsBefore {
		t.Fatal("pending MFA created an authenticated session", err)
	}
	queryCaller := request.Confirmation.Caller.Clone()
	queryCaller.Request.Action = "identity.email.verification-signin"
	queryCaller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(out.result.Recovery.UserID)}
	recovered, recoverErr := owner.VerificationSigninRecover(ctx, out.result.Recovery, queryCaller)
	if recoverErr != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding.CommandID != out.result.Recovery.CommandID || recovered.Feature == nil {
		t.Fatal("committed MFA challenge cannot be recovered as metadata", recoverErr)
	}
	completion, err := features.VerificationTOTP()
	if err != nil {
		t.Fatal("selected verification TOTP completion unavailable", err)
	}
	id, _ := identity.NewCommandID()
	caller := request.Confirmation.Caller.Clone()
	caller.CorrelationID = string(id)
	caller.Request.Action = "identity.mfa.totp-verify"
	caller.Request.Resource = authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(scope.ID)}
	code, err := auth.NewOneTimeCode(passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	completionRequest := mfa.TotpVerifyRequest{TenantID: request.Confirmation.TenantID, CommandID: id, ChallengeID: mfa.ChallengeID(scope.ID), FactorID: factor, Proof: out.result.Challenge.Proof, Code: code, PreAuthID: scope.SourcePreAuthID, Cookie: request.Browser, Caller: caller, Origin: origin, Callback: request.Confirmation.Callback.String(), Network: "127.0.0.1", Device: "verification-totp-device"}
	if err := completionRequest.Validate(); err != nil {
		t.Fatal("genuine completion request malformed", err)
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	var replayBefore int64
	if profile == "totp-completion-rollback" {
		if e := f.pool.Raw().QueryRow(ctx, `SELECT last_step FROM identity_mfa.totp_factors WHERE factor_id=$1`, string(factor)).Scan(&replayBefore); e != nil {
			t.Fatal("completion replay baseline unavailable", e)
		}
		if _, e := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.verification_completion_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic completion rollback'; END $$; CREATE TRIGGER verification_completion_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.verification_completion_fail()`); e != nil {
			t.Fatal("completion rollback fixture unavailable", e)
		}
	}
	var finished mfa.TotpVerifyResult
	if strings.HasPrefix(profile, "totp-contention-") {
		var results [2]mfa.TotpVerifyResult
		var failures [2]error
		start := make(chan struct{})
		var group sync.WaitGroup
		for index := range 2 {
			candidate := completionRequest
			if index == 1 && profile == "totp-contention-different" {
				candidate.CommandID, _ = identity.NewCommandID()
				candidate.Caller = caller.Clone()
				candidate.Caller.CorrelationID = string(candidate.CommandID)
			}
			group.Go(func() { <-start; results[index], failures[index] = completion.TotpVerify(ctx, candidate) })
		}
		close(start)
		group.Wait()
		delivered := 0
		for index, result := range results {
			if result.Session.Token != (session.Token{}) {
				delivered++
				finished, err = result, failures[index]
			}
		}
		var sessions, uses int
		if e := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),uses FROM capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2`, string(scope.TenantID), string(scope.ID)).Scan(&sessions, &uses); e != nil || sessions != sessionsBefore+1 || uses != 1 || delivered != 1 {
			t.Fatal("contended completion lost or duplicated one-use/session/disclosure", e, delivered)
		}
	} else {
		finished, err = completion.TotpVerify(ctx, completionRequest)
	}
	if f.verificationMFAOriginalExpiry != nil {
		var expired bool
		var sessions, remaining, uses int
		if e := f.pool.Raw().QueryRow(ctx, `SELECT p.expires_at<=clock_timestamp(),(SELECT count(*) FROM session_store.sessions),c.attempts_remaining,k.uses FROM capability_identity_one_use p JOIN identity_mfa.continuations c ON c.tenant_id=p.tenant_id AND c.user_id=p.subject_id JOIN capability_identity_one_use k ON k.tenant_id=c.tenant_id AND k.capability_id=c.continuation_id WHERE p.purpose='identity.identifier.verify' AND c.continuation_id=$1`, string(scope.ID)).Scan(&expired, &sessions, &remaining, &uses); e != nil || !expired || !f.verificationMFAOriginalExpiry.elapsed.Load() || err == nil || sessions != sessionsBefore || remaining != 3 || uses != 0 || finished.Session.Token != (session.Token{}) || finished.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("original parent expiry after snapshot was renewed or consumed", e, err)
		}
		return
	}
	if f.verificationMFALateAuthority != nil {
		if !f.verificationMFALateAuthority.changed.Load() || err == nil || finished.Session.Token != (session.Token{}) || finished.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("changed post-snapshot authority authenticated or fault never ran", err)
		}
		var sessions, attempts, uses int
		if e := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),c.attempts_remaining,k.uses FROM identity_mfa.continuations c JOIN capability_identity_one_use k ON k.tenant_id=c.tenant_id AND k.capability_id=c.continuation_id WHERE c.tenant_id=$1 AND c.continuation_id=$2`, string(scope.TenantID), string(scope.ID)).Scan(&sessions, &attempts, &uses); e != nil || sessions != sessionsBefore || attempts != 3 || uses != 0 {
			t.Fatal("changed authority charged an attempt, consumed child or created session", e)
		}
		return
	}
	if profile == "totp-completion-rollback" {
		if err == nil || finished.Outcome != identity.CommitOutcomeNotCommitted || finished.Session.Token != (session.Token{}) || finished.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("failed completion disclosed session or lost rollback", err)
		}
		var sessions, state, remaining int
		var replayAfter int64
		if e := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),t.last_step,c.state,c.attempts_remaining FROM identity_mfa.totp_factors t JOIN identity_mfa.continuations c ON c.tenant_id=t.tenant_id AND c.user_id=t.user_id WHERE t.factor_id=$1 AND c.continuation_id=$2`, string(factor), string(scope.ID)).Scan(&sessions, &replayAfter, &state, &remaining); e != nil || sessions != sessionsBefore || replayAfter != replayBefore || state != 1 || remaining != 3 {
			t.Fatal("completion rollback leaked session, factor replay or continuation effects", e)
		}
		return
	}
	if profile == "totp-completion-unknown" {
		if !f.completionFault.hit.Load() || err == nil || finished.Outcome != identity.CommitOutcomeUnknown || finished.Session.Token != (session.Token{}) || finished.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("lost actual completion acknowledgement disclosed a session", err)
		}
		var sessions, uses int
		if e := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),uses FROM capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2`, string(scope.TenantID), string(scope.ID)).Scan(&sessions, &uses); e != nil || sessions != sessionsBefore+1 || uses != 1 {
			t.Fatal("lost completion acknowledgement did not retain actual atomic commit", e)
		}
		q := identity.RecoveryQuery{TenantID: scope.TenantID, CommandID: id, AnonymousFlowID: string(scope.SourcePreAuthID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: "identity.mfa.totp-verify"}
		for range 2 {
			recovered, e := completion.RecoverTotpVerify(ctx, q, caller)
			if e != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Session.Token != (session.Token{}) || recovered.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("completion recovery failed to retain committed metadata only", e)
			}
		}
		retry, e := completion.TotpVerify(ctx, completionRequest)
		if e != nil || retry.Outcome != identity.CommitOutcomeCommitted || retry.Session.Token != (session.Token{}) || retry.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("lost completion acknowledgement replay recreated session credentials", e)
		}
		return
	}
	if f.verificationMFAWithdrawnParent != nil {
		var fingerprint []byte
		digest := sha256.Sum256([]byte("withdrawn-verification-parent-test-custody"))
		if e := f.pool.Raw().QueryRow(ctx, `SELECT proof_fingerprint FROM capability_identity_one_use WHERE tenant_id=$1 AND purpose='identity.identifier.verify'`, string(scope.TenantID)).Scan(&fingerprint); e != nil || !bytes.Equal(fingerprint, digest[:]) {
			t.Fatal("parent custody withdrawal fault not installed", e)
		}
		var sessions, attempts, uses int
		var state string
		if !f.verificationMFAWithdrawnParent.withdrawn.Load() {
			t.Fatal("parent withdrawal did not follow authenticated preliminary read")
		}
		if err == nil || finished.Session.Token != (session.Token{}) || finished.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("withdrawn verification parent authenticated through stale preliminary custody")
		}
		if e := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),c.state,c.attempts_remaining,k.uses FROM identity_mfa.continuations c JOIN capability_identity_one_use k ON k.tenant_id=c.tenant_id AND k.capability_id=c.continuation_id WHERE c.tenant_id=$1 AND c.continuation_id=$2`, string(scope.TenantID), string(scope.ID)).Scan(&sessions, &state, &attempts, &uses); e != nil || sessions != sessionsBefore || state != "1" || attempts != 3 || uses != 0 {
			t.Fatal("withdrawn parent charged a factor, consumed a child or created a session", e, "sessions", sessions, "state", state, "attempts", attempts, "uses", uses)
		}
		return
	}
	if err != nil || finished.Outcome != identity.CommitOutcomeCommitted || finished.Session.Token == (session.Token{}) || finished.CSRFToken == (session.CSRFToken{}) {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Log("completion input boundary", invalid.Field)
		}
		t.Fatal("real verification-origin TOTP did not issue session", err)
	}
	issued, _ := finished.Session.Session.Bindings()
	if (issued.Remember.Choice() == session.PersistentSession) != strings.Contains(profile, "persistent") || (finished.Session.Cookie.MaxAge > 0) != strings.Contains(profile, "persistent") {
		t.Fatal("MFA completion changed original signup remember policy")
	}
	metadata, err := finished.Session.Session.MFAAuthentication().Bindings()
	emailPrimary, primaryErr := finished.Session.Session.MagicLinkAuthentication().Bindings()
	if err != nil || primaryErr != nil || metadata.PrimaryCommandID != out.result.Recovery.CommandID || emailPrimary.CommandID != metadata.PrimaryCommandID || emailPrimary.RequestCommandID != signupID || emailPrimary.CapabilityID != primary.Payload().ID || metadata.Method != "totp" || metadata.FactorID != string(factor) || emailPrimary.AuthenticatedAt != scope.IssuedAt {
		t.Fatal("completed session relabeled email possession or actual TOTP", err, primaryErr)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialCookie, finished.Session.Token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: request.Confirmation.TenantID, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("completed verification TOTP session unreadable", err)
	}
	logoutID, _ := identity.NewCommandID()
	logout, err := sessions.SignOut(ctx, session.SignOutRequest{TenantID: request.Confirmation.TenantID, CommandID: logoutID, CorrelationID: string(logoutID), Transport: session.CredentialCookie, Credential: credential}, finished.CSRFToken)
	if err != nil || !logout.SignedOut || logout.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("completed verification TOTP session cannot logout", err)
	}
	current, err = sessions.Get(ctx, session.GetRequest{TenantID: request.Confirmation.TenantID, Credential: credential})
	if err == nil && current.Authenticated {
		t.Fatal("verification TOTP session survived logout")
	}
}

// Produce a real SFA password session, action-bound reauthentication, pending
// enrollment, one-time URI disclosure and code-confirmed TOTP. No domain rows,
// factor secret, proof, credential or session authority is injected.
func enrollVerificationMFATOTP(t *testing.T, ctx context.Context, features reference.FeatureSet, client *http.Client, base, origin string) (mfa.FactorID, []byte) {
	t.Helper()
	post := func(path string, body any, cookies []*http.Cookie, target any) *http.Response {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("genuine setup transport unavailable", err)
		}
		defer response.Body.Close()
		if json.NewDecoder(http.MaxBytesReader(nil, response.Body, 16384)).Decode(target) != nil || response.StatusCode != http.StatusOK {
			t.Fatal("genuine setup request rejected", path, response.StatusCode)
		}
		return response
	}
	var flow sessionhttp.PreAuthResponse
	r := post("/v1/session/preauth-issue", map[string]string{"method": "password"}, nil, &flow)
	var signin passwordhttp.SigninResponse
	r = post("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": "verified-signin@example.invalid", "password": "synthetic-verification-password", "callbackURL": origin + "/reset"}, r.Cookies(), &signin)
	if !signin.SignedIn || len(r.Cookies()) != 1 {
		t.Fatal("real setup password signin unavailable")
	}
	token, err := session.ParseToken(r.Cookies()[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.ParseCSRFToken(r.Header.Get("X-CSRF-Token"))
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("real setup session unreadable", err)
	}
	spec, _ := current.Session.Bindings()
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	verifier, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := primitive.NewSecret([]byte("synthetic-verification-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Destroy()
	bearer := auth.NewBearerCredential(r.Cookies()[0].Value)
	proof, err := verifier.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{TenantID: otpTenant, Session: bearer, Password: candidate, Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "reference-mfa-enable"}, Caller: caller, Network: "127.0.0.1", Device: "verification-mfa-setup"}, CSRFToken: csrf})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine setup reauthentication rejected", err)
	}
	enrollment, err := features.MFAEnrollment()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := identity.NewIdempotencyKey([]byte("verification-mfa-genuine-enrollment"))
	caller.Request.Action = "identity.mfa.enable"
	pending, err := enrollment.Enable(ctx, mfa.EnableRequest{TenantID: otpTenant, PrimaryProof: spec.Authentication.Proof, Reauthentication: proof.Proof, Session: bearer, IdempotencyKey: key, Caller: caller, Network: "127.0.0.1", FactorPolicy: mfa.FactorPolicy{Method: "totp", RecoveryCodes: 10}, CSRFToken: csrf})
	for _, code := range pending.RecoveryMaterial.Codes {
		code.Destroy()
	}
	clear(pending.RecoveryMaterial.Codes)
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine setup enrollment rejected", err)
	}
	uriOwner, err := features.MFAProvisioningURI()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := identity.NewCommandID()
	caller.Request.Action = "identity.mfa.totp-uri"
	uri, err := uriOwner.TotpUri(ctx, mfa.TotpUriRequest{TenantID: otpTenant, CommandID: id, EnrollmentID: pending.Enrollment.ID, Session: bearer, CSRFToken: csrf, Caller: caller, Origin: origin, Network: "127.0.0.1"})
	if err != nil || uri.URI.URI == "" {
		t.Fatal("genuine provisioning disclosure rejected", err)
	}
	parsed, err := url.Parse(uri.URI.URI)
	if err != nil {
		t.Fatal("genuine URI malformed")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	if err != nil || len(secret) != 32 {
		t.Fatal("genuine disclosed factor malformed")
	}
	ok := false
	defer func() {
		if !ok {
			clear(secret)
		}
	}()
	confirm, err := features.MFAEnrollmentConfirmation()
	if err != nil {
		t.Fatal(err)
	}
	id, _ = identity.NewCommandID()
	caller.Request.Action = "identity.mfa.totp-verify"
	code, err := auth.NewOneTimeCode(passwordMFAFixtureCode(secret, time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	active, err := confirm.TotpVerify(ctx, mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: id, FactorID: mfa.FactorID(pending.Enrollment.ID), Code: code, Caller: caller, Origin: origin, Network: "127.0.0.1", Enrollment: &mfa.TOTPEnrollmentConfirmation{Session: bearer, CSRFToken: csrf}})
	if err != nil || active.Outcome != identity.CommitOutcomeCommitted || active.Enrollment.Version == 0 {
		t.Fatal("genuine code confirmation rejected", err)
	}
	ok = true
	return mfa.FactorID(pending.Enrollment.ID), secret
}
