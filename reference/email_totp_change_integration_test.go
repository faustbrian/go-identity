//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresEmailTOTPChange(t *testing.T) {
	for _, mode := range []string{"totp-change", "totp-change-http", "totp-change-mfa-http", "totp-change-mfa-recovery", "totp-change-mfa-totp", "totp-change-rollback", "totp-change-factor-stale-request", "totp-change-factor-stale-confirm", "totp-change-enrollment-stale-confirm", "totp-change-origin-revoked-confirm", "totp-change-unknown-request", "totp-change-unknown-confirm", "totp-change-expiry"} {
		t.Run(mode, func(t *testing.T) {
			selected := signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailChangeCase: mode, mfaEnrollment: true, activeStepUp: true, passwordRecovery: true, completionCommitFault: mode == "totp-change-unknown-request" || mode == "totp-change-unknown-confirm"}
			if mode == "totp-change-mfa-recovery" || mode == "totp-change-mfa-http" {
				selected.replacementSourceMethod = "recovery-code"
			} else if mode == "totp-change-mfa-totp" {
				selected.replacementSourceMethod = "totp"
				selected.passwordMFA = true
			}
			proveReferenceSignupGraphExtensions(t, false, selected, true)
		})
	}
}

func TestReferencePostgresRetainedEmailFactorConsumers(t *testing.T) {
	for name, selected := range map[string]signupGraphExtensions{
		"step-up":         {mfaEnrollment: true, activeStepUp: true},
		"step-up-unknown": {mfaEnrollment: true, activeStepUp: true, completionCommitFault: true},
		"regeneration":    {mfaEnrollment: true, activeStepUp: true, regeneration: true, passwordRecovery: true},
		"rename":          {mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true},
		"disable":         {disable: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true},
	} {
		t.Run(name, func(t *testing.T) {
			selected.postgresBaseline = true
			proveReferenceSignupGraphExtensions(t, false, selected, true)
		})
	}
}

func proveReferenceEmailTOTPChange(t *testing.T, ctx context.Context, f liveStores, features, defaults reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, notices <-chan string, deliveries <-chan emailChangeDelivery, user identity.UserID, proof auth.ReauthenticationProof, cookies []*http.Cookie, csrfWire string, recovery []string, defaultRequest passwordpg.EmailManagementRequest, browserProof auth.ProofID, mode string) {
	t.Helper()
	const previous = "new-primary@example.invalid"
	const candidate = "totp-primary@example.invalid"
	var oldID string
	var oldVersion, oldVerification uint64
	var verifiedAt time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,version,verification_version,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND canonical_value=$3 AND verified AND is_primary`, otpTenant, string(user), previous).Scan(&oldID, &oldVersion, &oldVerification, &verifiedAt); err != nil {
		t.Fatal("selected TOTP change must start with genuine verified primary", err)
	}
	defaultOwner, err := defaults.EmailChange()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := defaultOwner.ChangeRequest(ctx, defaultRequest); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("password-only email profile admitted enrolled MFA")
	}
	// Prior bootstrap messages were already consumed; drain only the parallel
	// sender observations, never domain authority or queued delivery effects.
drain:
	for {
		select {
		case <-deliveries:
		default:
			break drain
		}
	}
	owner, err := features.EmailChange()
	if err != nil {
		t.Fatal(err)
	}
	command, _ := identity.NewCommandID()
	csrf, _ := session.ParseCSRFToken(csrfWire)
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.email.change-request", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	r := passwordpg.EmailManagementRequest{Primary: passwordpg.EmailPrimaryRequest{TenantID: otpTenant, CommandID: command, AddressID: "totp-email-candidate", Session: auth.NewBearerCredential(cookies[0].Value), CSRFToken: csrf, Proof: proof, Caller: caller}, Address: candidate, CallbackURL: origin + "/login", Network: "127.0.0.1"}
	for _, mutate := range []func(*auth.ReauthenticationProof){
		func(p *auth.ReauthenticationProof) { p.Proof.Method = "password" },
		func(p *auth.ReauthenticationProof) { p.Proof.Assurance = auth.AssuranceSingleFactor },
		func(p *auth.ReauthenticationProof) {
			p.Proof.Purpose = "identity.mfa.factor-update"
			p.Action = string(p.Proof.Purpose)
		},
		func(p *auth.ReauthenticationProof) { p.Proof.Audience = "foreign-email-audience" },
		func(p *auth.ReauthenticationProof) { p.Proof.Subject = "foreign-user" },
		func(p *auth.ReauthenticationProof) { p.Proof.Tenant = "foreign-tenant" },
		func(p *auth.ReauthenticationProof) { p.SessionID = "foreign-session" },
		func(p *auth.ReauthenticationProof) { p.SessionVersion++ },
		func(p *auth.ReauthenticationProof) { p.Proof.ExpiresAt = p.Proof.IssuedAt },
	} {
		bad := r
		bad.Primary.CommandID, _ = identity.NewCommandID()
		mutate(&bad.Primary.Proof)
		if out, err := owner.ChangeRequest(ctx, bad); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.AddressID != "" {
			t.Fatal("wrong original factor projection acquired email authority")
		}
	}
	var unused, absent int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_mfa.factor_verifications WHERE proof_id=$1 AND used_command_id IS NULL),(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$2 AND user_id=$3 AND canonical_value=$4)`, string(proof.Proof.ID), otpTenant, string(user), candidate).Scan(&unused, &absent); err != nil || unused != 1 || absent != 0 {
		t.Fatal("denied factor projections consumed proof or attached candidate", err)
	}
	key, _ := identity.NewIdempotencyKey([]byte(command))
	keyedRequest := r
	keyedRequest.Primary.CommandID, keyedRequest.Primary.AddressID = "", ""
	// Failure injection is after protected effects have reached the existing
	// lifecycle owner. Rollback must restore authority, not only hide output.
	snapshot := func() [7]int64 {
		t.Helper()
		var out [7]int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2),
(SELECT coalesce(sum(version+verification_version),0) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2),
(SELECT count(*) FROM identity.delivery_intents),
(SELECT coalesce(sum(uses),0) FROM capability_identity_one_use),
(SELECT count(*) FROM public.identity_outbox_bindings),
(SELECT count(*) FROM audit.records WHERE action IN ('identity.email.change-request','identity.email.change-confirm') AND outcome=1),
(SELECT count(*) FROM identity_mfa.factor_verifications WHERE proof_id=$3 AND used_command_id IS NOT NULL)`, otpTenant, string(user), string(proof.Proof.ID)).Scan(&out[0], &out[1], &out[2], &out[3], &out[4], &out[5], &out[6]); err != nil {
			t.Fatal("protected TOTP email metadata unavailable", err)
		}
		return out
	}
	withLateFailure := func(run func()) {
		t.Helper()
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION reject_totp_email_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned late TOTP email rollback'; END $$; CREATE TRIGGER reject_totp_email_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION reject_totp_email_lifecycle()`); err != nil {
			t.Fatal("late TOTP email fault unavailable", err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if _, err := f.pool.Raw().Exec(cleanup, `DROP TRIGGER reject_totp_email_lifecycle ON public.identity_outbox_bindings; DROP FUNCTION reject_totp_email_lifecycle()`); err != nil {
				t.Error("late TOTP email fault cleanup failed", err)
			}
		}()
		run()
	}
	if mode == "totp-change-factor-stale-request" {
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user)); err != nil {
			t.Fatal("owned authoritative factor-generation fault", err)
		}
		before := snapshot()
		if out, err := owner.ChangeRequestKeyed(ctx, keyedRequest, key); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.AddressID != "" || snapshot() != before {
			t.Fatal("stale actual factor authority admitted a request", err)
		}
		return
	}
	if browserProof == "" {
		before := snapshot()
		withLateFailure(func() {
			out, err := owner.ChangeRequest(ctx, r)
			if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.AddressID != "" || snapshot() != before {
				t.Fatal("late request failure leaked factor use or protected effects", out.Outcome, err)
			}
		})
	}
	var pending passwordpg.EmailManagementResult
	if browserProof != "" {
		// Positive HTTP input is the ID captured from the real step-up response,
		// not a proof projection reconstructed from native evidence storage.
		r.Primary.Proof.Proof.ID = browserProof
		pending, err = invokeSelectedEmailRequest(t, ctx, f, client, base, origin, r, false, true)
	} else if mode == "totp-change-unknown-request" {
		f.completionFault.armed.Store(true)
		pending, err = owner.ChangeRequestKeyed(ctx, keyedRequest, key)
		f.completionFault.armed.Store(false)
		if err == nil || pending.Outcome != identity.CommitOutcomeUnknown || pending.AddressID != "" || !f.completionFault.hit.Load() {
			t.Fatal("lost actual factor-consumption commit acknowledged success", pending.Outcome, err)
		}
		pending, err = owner.ChangeRequestKeyed(ctx, keyedRequest, key)
	} else {
		keys := [2]identity.IdempotencyKey{key}
		keys[1], _ = identity.NewIdempotencyKey([]byte(string(command) + "-contender"))
		var outcomes [2]passwordpg.EmailManagementResult
		var errors [2]error
		var group sync.WaitGroup
		start := make(chan struct{})
		group.Add(2)
		for n := range 2 {
			go func() {
				defer group.Done()
				<-start
				outcomes[n], errors[n] = owner.ChangeRequestKeyed(ctx, keyedRequest, keys[n])
			}()
		}
		close(start)
		group.Wait()
		winners := 0
		for n, out := range outcomes {
			if errors[n] == nil && out.Outcome == identity.CommitOutcomeCommitted {
				pending, key = out, keys[n]
				winners++
			} else if out.AddressID != "" {
				t.Fatal("losing factor request disclosed a candidate")
			}
		}
		if winners != 1 {
			t.Fatal("one original factor admitted multiple protected requests", winners)
		}
	}
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted || pending.AddressID == "" {
		t.Fatal("actual TOTP proof did not reach protected email request", pending.Outcome, err)
	}
	r.Primary.CommandID, r.Primary.AddressID = pending.CommandID, pending.AddressID
	command = pending.CommandID
	for range 2 {
		replayed, err := owner.ChangeRequestKeyed(ctx, keyedRequest, key)
		if err != nil || replayed != pending {
			t.Fatal("keyed factor retry lost original metadata or repeated work", err)
		}
		gotUser, address, err := owner.RequestRateSourceKeyed(ctx, keyedRequest, key, false)
		if err != nil || gotUser != user || address != candidate {
			t.Fatal("keyed rate discovery lost original custody", err)
		}
	}
	var used int
	raw, _ := base64.RawURLEncoding.Strict().DecodeString(string(command))
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.factor_verifications WHERE proof_id=$1 AND used_command_id=$2 AND used_purpose='identity.email.change-request'`, string(proof.Proof.ID), raw).Scan(&used); err != nil || used != 1 {
		t.Fatal("request did not consume exactly its original factor proof", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	var token capability.Proof
	var deliveredToken string
	select {
	case body := <-messages:
		link, err := url.Parse(body)
		if err != nil {
			t.Fatal("selected new-address link malformed")
		}
		deliveredToken = link.Query().Get("token")
		token, err = capability.ParseProof(deliveredToken, capability.DefaultLimits())
		if err != nil {
			t.Fatal("selected new-address link has no owned proof")
		}
	case <-ctx.Done():
		t.Fatal("selected new-address delivery missing")
	}
	select {
	case delivered := <-deliveries:
		if delivered.recipient != candidate {
			t.Fatal("TOTP change delivered possession link to wrong mailbox")
		}
	case <-ctx.Done():
		t.Fatal("actual new-address recipient not observed")
	}
	if len(recovery) == 0 {
		t.Fatal("genuine enrolled recovery login unavailable")
	}
	credential, bearer, _ := proveReplacementRecoveryLogin(t, ctx, features, client, base, origin, recovery[0], true)
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	get := func() bool {
		out, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		return err == nil && out.Authenticated
	}
	if bearer == "" || !get() {
		t.Fatal("post-request MFA session not genuinely authenticated")
	}
	confirmationCaller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "totp-email-confirm", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.change-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	for range 2 {
		if valid, err := owner.ValidateManagedVerification(ctx, token, r.CallbackURL, confirmationCaller); err != nil || !valid || !get() {
			t.Fatal("scanner validation consumed possession or changed session", err)
		}
	}
	id, _ := identity.NewCommandID()
	callback, _ := url.Parse(r.CallbackURL)
	confirm := email.ChangeConfirmRequest{TenantID: otpTenant, CommandID: id, Token: token, Callback: *callback, Caller: confirmationCaller, Network: "127.0.0.1"}
	if mode == "totp-change-expiry" {
		// Use the original signed deadline and authoritative database clock;
		// no stored proof/session timestamp is forged to make it stale.
		before := snapshot()
		deadline := proof.Proof.ExpiresAt
		for {
			var now time.Time
			if err := f.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal("original factor deadline clock unavailable", err)
			}
			if !now.Before(deadline) {
				break
			}
			timer := time.NewTimer(min(deadline.Sub(now), 100*time.Millisecond))
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				t.Fatal("original factor expiry not reached within owned budget")
			}
		}
		if valid, err := owner.ValidateManagedVerification(ctx, token, r.CallbackURL, confirmationCaller); err == nil || valid {
			t.Fatal("expired original factor/link passed inspection")
		}
		if out, err := owner.ChangeConfirm(ctx, confirm); err == nil || out.Outcome == identity.CommitOutcomeCommitted || snapshot() != before || !get() {
			t.Fatal("expired original factor changed primary or session", out.Outcome, err)
		}
		if out, err := owner.ChangeRequestKeyed(ctx, keyedRequest, key); err != nil || out != pending || snapshot() != before {
			t.Fatal("expired factor retry renewed original work", err)
		}
		return
	}
	if mode == "totp-change-factor-stale-confirm" || mode == "totp-change-enrollment-stale-confirm" || mode == "totp-change-origin-revoked-confirm" {
		switch mode {
		case "totp-change-factor-stale-confirm":
			_, err = f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user))
		case "totp-change-enrollment-stale-confirm":
			_, err = f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET enrollment_version=enrollment_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(user), proofIDFactor(t, ctx, f, proof.Proof.ID))
		case "totp-change-origin-revoked-confirm":
			// Revoke only the actual initiating family; the independent newer
			// recovery-code session must remain valid and cannot replace it.
			_, err = f.pool.Raw().Exec(ctx, `UPDATE session_store.families SET state='revoked',version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND family_id=(SELECT family_id FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND session_id=$3)`, otpTenant, string(user), proof.SessionID)
		}
		if err != nil {
			t.Fatal("owned actual originating-authority fault", err)
		}
		before := snapshot()
		if valid, err := owner.ValidateManagedVerification(ctx, token, r.CallbackURL, confirmationCaller); err == nil || valid {
			t.Fatal("stale original authority passed scanner discovery")
		}
		if out, err := owner.ChangeConfirm(ctx, confirm); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) || snapshot() != before {
			t.Fatal("stale original authority changed email", out.Outcome, err)
		}
		if mode == "totp-change-origin-revoked-confirm" && !get() {
			t.Fatal("origin revocation did not isolate a still-valid newer session")
		}
		return
	}
	if mode == "totp-change-rollback" {
		before := snapshot()
		var failed email.ChangeConfirmResult
		withLateFailure(func() {
			out, err := owner.ChangeConfirm(ctx, confirm)
			if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Address != (identity.IdentifierProjection{}) || snapshot() != before || !get() {
				t.Fatal("late confirmation leaked consumption, promotion or session effects", out.Outcome, err)
			}
			failed = out
		})
		for range 2 {
			out, err := owner.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: failed.Recovery, Caller: confirmationCaller})
			var unavailable identity.UnavailableError
			if err != nil && !errors.As(err, &unavailable) || out.Outcome != identity.CommitOutcomeNotCommitted || snapshot() != before || !get() {
				t.Fatal("rollback recovery executed protected change", out.Outcome, err)
			}
		}
		if valid, err := owner.ValidateManagedVerification(ctx, token, r.CallbackURL, confirmationCaller); err == nil || valid {
			t.Fatal("terminal rollback resurrected original link")
		}
		return
	}
	if browserProof != "" {
		proveSelectedEmailChangeConfirmation(t, ctx, client, base, origin, confirm, deliveredToken)
	}
	var out email.ChangeConfirmResult
	if browserProof != "" {
		out, err = owner.ChangeConfirm(ctx, confirm)
	} else if mode == "totp-change-unknown-confirm" {
		f.completionFault.armed.Store(true)
		out, err = owner.ChangeConfirm(ctx, confirm)
		f.completionFault.armed.Store(false)
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.Address != (identity.IdentifierProjection{}) || !f.completionFault.hit.Load() {
			t.Fatal("lost actual primary-change commit acknowledged success", out.Outcome, err)
		}
		before := snapshot()
		for range 2 {
			history, e := owner.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: out.Recovery, Caller: confirmationCaller})
			if e != nil || history.Outcome != identity.CommitOutcomeCommitted || snapshot() != before {
				t.Fatal("unknown recovery lost commit or repeated effects", history.Outcome, e)
			}
			out.Outcome = history.Outcome
		}
		err = nil
	} else {
		requests := [2]email.ChangeConfirmRequest{confirm, confirm}
		requests[1].CommandID, _ = identity.NewCommandID()
		var outcomes [2]email.ChangeConfirmResult
		var errors [2]error
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		for n := range 2 {
			go func() {
				defer group.Done()
				<-start
				outcomes[n], errors[n] = owner.ChangeConfirm(ctx, requests[n])
			}()
		}
		close(start)
		group.Wait()
		winners := 0
		for n, result := range outcomes {
			if errors[n] == nil && result.Outcome == identity.CommitOutcomeCommitted {
				out = result
				winners++
			} else if result.Address != (identity.IdentifierProjection{}) {
				t.Fatal("losing link confirmation disclosed a primary")
			}
		}
		if winners != 1 {
			t.Fatal("one possession link did not have exactly one winner", winners, outcomes[0].Outcome, errors[0], outcomes[1].Outcome, errors[1])
		}
	}
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("selected TOTP link confirmation did not complete", out.Outcome, err)
	}
	if get() {
		t.Fatal("confirmation left post-request MFA session admitted")
	}
	var primary, retained int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER(WHERE is_primary),count(*) FILTER(WHERE canonical_value=$3 AND verified AND is_primary) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(user), candidate).Scan(&primary, &retained); err != nil || primary != 1 || retained != 1 {
		t.Fatal("TOTP change did not establish exactly one verified successor", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND NOT is_primary AND verified AND version=$4 AND verification_version=$5 AND verified_at=$6`, otpTenant, string(user), oldID, oldVersion+1, oldVerification, verifiedAt).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("TOTP change rewrote original verification history", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-messages:
		if body != emailChangeNotice {
			t.Fatal("old notice contains possession material")
		}
	case <-ctx.Done():
		t.Fatal("old notice missing")
	}
	select {
	case mailbox := <-notices:
		if mailbox != previous {
			t.Fatal("notice did not reach original old primary")
		}
	case <-ctx.Done():
		t.Fatal("old recipient missing")
	}
	history, err := owner.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: out.Recovery, Caller: confirmationCaller})
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("factor-free change recovery lost original outcome", err)
	}
}

func proofIDFactor(t *testing.T, ctx context.Context, f liveStores, id auth.ProofID) string {
	t.Helper()
	var factor string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT factor_id FROM identity_mfa.factor_verifications WHERE proof_id=$1`, string(id)).Scan(&factor); err != nil {
		t.Fatal("original factor identity unavailable", err)
	}
	return factor
}
