//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

type verificationSigninDenyPolicy struct{}

// Keep original-browser and preparation time valid, then expire the original
// grant precisely at the issuer's separate pre-executor clock check.
type verificationSigninExpiryClock struct {
	armed atomic.Bool
	calls atomic.Uint32
}

func (c *verificationSigninExpiryClock) Now() time.Time {
	now := time.Now()
	if c.armed.Load() && c.calls.Add(1) >= 2 {
		return now.Add(time.Hour)
	}
	return now
}

type verificationSigninExpiryPolicy struct {
	clock *verificationSigninExpiryClock
}

func (p verificationSigninExpiryPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.email.verification-signin" {
		p.clock.armed.Store(true)
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func (verificationSigninDenyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.email.verification-signin" {
		return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, ctx.Err()
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

// Authorization runs after the preliminary factor snapshot. Advance primary
// authority here so only the protected transaction's freshness check can deny.
type verificationSigninLateFactorPolicy struct{ pool *database.Pool }

func (p verificationSigninLateFactorPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == "identity.email.verification-signin" {
		result, err := p.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(c.Request.Tenant), string(c.Request.Resource.ID))
		if err != nil {
			return authorization.Decision{}, err
		}
		if result.RowsAffected() != 1 {
			return authorization.Decision{Outcome: authorization.Deny, Revision: c.PolicyRevision}, nil
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func proveVerificationSigninFault(t *testing.T, ctx context.Context, f liveStores, owner email.RegistrationVerificationSigninService, request email.VerificationSigninRequest, signup identity.CommandID, profile string) bool {
	t.Helper()
	if profile == "browser" || profile == "persistent" || strings.HasPrefix(profile, "upgrade") || profile == "empty-totp" || strings.HasSuffix(profile, "-http") {
		return false
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(signup))
	var user string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT user_id FROM identity.registration_bindings WHERE command_id=$1`, command).Scan(&user); err != nil {
		t.Fatal("actual registered subject unavailable", err)
	}
	snapshot := func() (verified, sessions, grants int) {
		t.Helper()
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND verified),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use WHERE tenant_id=$1 AND subject_id=$2)`, otpTenant, user).Scan(&verified, &sessions, &grants); err != nil {
			t.Fatal("primary outcome observation", err)
		}
		return
	}
	if profile == "missing-factor" {
		if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, otpTenant, user); err != nil {
			t.Fatal("owned missing-factor fault", err)
		}
	}
	if profile == "nonempty-factor-authority" {
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1,version=version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, user); err != nil {
			t.Fatal("owned authoritative nonempty-factor fault", err)
		}
	}
	if profile == "blocked-user" {
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, user); err != nil {
			t.Fatal("owned blocked-account fault", err)
		}
	}
	for mode, table := range map[string]string{"rollback": "session_store.session_issuances", "verification-rollback": "identity.email_verifications", "risk-unavailable": "risk_store.durable_counter_attempts"} {
		if profile == mode {
			if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.verification_signin_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic protected failure'; END $$; CREATE TRIGGER verification_signin_fail BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.verification_signin_fail()`); err != nil {
				t.Fatal("owned failure fixture", err)
			}
		}
	}
	if profile == "contention" {
		var results [2]email.VerificationSigninResult
		var failures [2]error
		var group sync.WaitGroup
		start := make(chan struct{})
		for i := range results {
			contender := request
			contender.Confirmation.CommandID, _ = identity.NewCommandID()
			group.Go(func() { <-start; results[i], failures[i] = owner.VerificationConfirmAndSignin(ctx, contender) })
		}
		close(start)
		group.Wait()
		delivered := 0
		for i, result := range results {
			if result.Issuance.Token != (session.Token{}) {
				if failures[i] != nil || result.Validate() != nil {
					t.Fatal("contending failed invocation disclosed credentials")
				}
				delivered++
			}
		}
		verified, sessions, grants := snapshot()
		if delivered != 1 || verified != 1 || sessions != 1 || grants != 1 {
			t.Fatal("contending confirmations duplicated verification/signin", delivered, verified, sessions, grants)
		}
		return true
	}
	if strings.HasSuffix(profile, "-unknown") {
		f.completionFault.armed.Store(true)
	}
	out, err := owner.VerificationConfirmAndSignin(ctx, request)
	if f.completionFault != nil {
		f.completionFault.armed.Store(false)
	}
	if err == nil || out.Issuance.Token != (session.Token{}) || out.Issuance.Cookie.Name != "" || out.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("failed/unknown verification signin disclosed credentials", err)
	}
	verified, sessions, grants := snapshot()
	if profile == "blocked-user" {
		if out.Verification.Outcome == identity.CommitOutcomeCommitted || verified != 0 || sessions != 0 || grants != 0 || out.Recovery.CommandID != "" {
			t.Fatal("blocked account verified or authenticated")
		}
		return true
	}
	if profile == "verification-rollback" {
		if out.Verification.Outcome != identity.CommitOutcomeNotCommitted || verified != 0 || sessions != 0 || grants != 0 || out.Recovery.CommandID != "" {
			t.Fatal("verification rollback attempted login or leaked effects", out.Verification.Outcome)
		}
		return true
	}
	if profile == "verification-unknown" {
		if out.Verification.Outcome != identity.CommitOutcomeUnknown || !f.completionFault.hit.Load() || verified != 1 || sessions != 0 || grants != 1 || out.Recovery.CommandID != "" {
			t.Fatal("unknown verification attempted login or lost actual commit", out.Verification.Outcome)
		}
		return true
	}
	if out.Verification.Outcome != identity.CommitOutcomeCommitted || verified != 1 || grants != 1 {
		t.Fatal("later login failure erased known committed verification", out.Verification.Outcome, verified, grants)
	}
	wantSessions := 0
	if profile == "child-unknown" {
		wantSessions = 1
		if out.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || !f.completionFault.hit.Load() {
			t.Fatal("lost actual child commit acknowledgement claimed success", out.Issuance.CommitOutcome)
		}
		queryCaller := request.Confirmation.Caller.Clone()
		queryCaller.Request.Action = "identity.email.verification-signin"
		queryCaller.Request.Resource.ID = authorization.ResourceID(user)
		retained, err := owner.VerificationSigninRecover(ctx, out.Recovery, queryCaller)
		if err != nil || retained.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("unknown child did not reconcile actual committed history", err)
		}
	}
	if sessions != wantSessions {
		t.Fatal("denied/unknown login disagrees with durable sessions", sessions)
	}
	if profile == "late-issuer-expiry" {
		if out.Validate() != nil || out.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || out.Recovery.CommandID == "" {
			t.Fatal("pre-executor expiry lost independent parent/child observations", out.Issuance.CommitOutcome)
		}
		retry, retryErr := owner.VerificationConfirmAndSignin(ctx, request)
		if retryErr == nil || retry.Issuance.Token != (session.Token{}) || retry.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("expired original browser renewed signin")
		}
		return true
	}
	if profile == "late-factor" {
		var active int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, otpTenant, user).Scan(&active); err != nil || active != 1 {
			t.Fatal("late-factor callback did not change actual primary authority", err)
		}
	}
	replay, err := owner.VerificationConfirmAndSignin(ctx, request)
	if err != nil || !replay.Verification.Replayed || replay.Issuance.Token != (session.Token{}) || replay.Recovery.CommandID != "" {
		t.Fatal("failed/unknown login retry created replacement credentials", err)
	}
	return true
}
