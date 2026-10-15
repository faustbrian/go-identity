//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferenceDisableOneTOTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true}, true)
}

func TestReferenceDisableOnePreservesPendingTOTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, disablePending: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true}, true)
}

func TestReferenceDisableHTTPPreservesPendingTOTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, disablePending: true, disableHTTP: true, mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true, factorRemoval: true}, true)
}

func TestReferenceDisableAllTOTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, disableAll: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true}, true)
}

func TestReferenceDisableHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, disableHTTP: true, mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true, factorRemoval: true}, true)
}

func TestReferenceDisableHTTPCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, disableHTTP: true, mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true, factorRemoval: true, factorManagementRace: true}, true)
}

func TestReferenceDisableHTTPCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, disableHTTP: true, mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true, factorRemoval: true, completionCommitFault: true}, true)
}

func TestReferenceDisableCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true, factorManagementRace: true}, true)
}

func TestReferenceDisableCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true, completionCommitFault: true}, true)
}

func TestReferenceDisableThenEmailReset(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true, factorRemovalReset: true}, true)
}

func TestReferenceDisableRejectsChangedAuthority(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{disable: true, mfaEnrollment: true, activeStepUp: true, factorRemoval: true, factorManagementDenials: true}, true)
}

func proveReferenceDisable(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer, csrfWire, origin string, factor mfa.FactorID, proof auth.ReauthenticationProof, client *http.Client, base, cookieName string) {
	t.Helper()
	owner, err := features.MFADisable()
	if err != nil {
		t.Fatal("selected native disable unavailable", err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(bearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("genuine disable source unavailable")
	}
	b, _ := current.Session.Bindings()
	csrf, _ := session.ParseCSRFToken(csrfWire)
	key, _ := identity.NewIdempotencyKey([]byte("native-explicit-disable"))
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: "identity.mfa.disable", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	r := mfa.DisableRequest{TenantID: otpTenant, Target: mfa.OneFactor, FactorID: factor, FactorProof: proof.Proof, Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Caller: caller, Origin: origin, Network: "127.0.0.1", IdempotencyKey: key}
	if f.disableAll {
		r.Target, r.FactorID = mfa.AllFactors, ""
	}
	if err := r.Validate(); err != nil {
		t.Fatal("well-formed explicit disable rejected", err)
	}
	if f.factorManagementDenials {
		proveReferenceDisableDenials(t, ctx, f, owner, r)
		return
	}
	before := disableProtectedSnapshot(t, ctx, f)
	execute := func(request mfa.DisableRequest, key string) (mfa.DisableResult, error) {
		if f.disableHTTP {
			return invokeReferenceDisableHTTP(t, ctx, client, base, origin, bearer, csrfWire, cookieName, key, request)
		}
		return owner.Disable(ctx, request)
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.disable_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic disable rollback'; END $$; CREATE TRIGGER disable_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.disable_fixture_fail()`); err != nil {
		t.Fatal("disable rollback fixture unavailable", err)
	}
	failed, failErr := execute(r, "native-explicit-disable")
	if failErr == nil || failed.Outcome != identity.CommitOutcomeNotCommitted || failed.CommandID == "" || failed.Factors != nil {
		t.Fatal("failed lifecycle published disable or lost rollback outcome", failed.Outcome, failErr)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER disable_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION public.disable_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	if after := disableProtectedSnapshot(t, ctx, f); after != before {
		t.Fatal("disable rollback changed protected factor/code/proof/session state")
	}
	var active, used int
	var intact bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT t.state=2 AND t.encrypted_secret IS NOT NULL AND t.last_step IS NOT NULL,(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active'),(SELECT count(*) FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND used_purpose='identity.mfa.disable') FROM identity_mfa.totp_factors t WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(b.UserID), string(factor)).Scan(&intact, &active, &used); err != nil || !intact || active != 2 || used != 0 {
		t.Fatal("disable rollback erased custody, consumed proof or revoked genuine sessions", err)
	}
	r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("disable-after-rollback"))
	var out mfa.DisableResult
	if f.disableHTTP {
		if denied, err := invokeReferenceDisableHTTP(t, ctx, client, base, origin, bearer, "", cookieName, "disable-no-csrf", r); err == nil || denied.Factors != nil {
			t.Fatal("HTTP disable bypassed original CSRF")
		}
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	if f.factorManagementRace {
		type attempt struct {
			req mfa.DisableRequest
			key string
			out mfa.DisableResult
			err error
		}
		attempts := [2]attempt{{req: r, key: "disable-after-rollback"}, {req: r, key: "disable-other-key"}}
		attempts[1].req.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("disable-other-key"))
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := range attempts {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				attempts[i].out, attempts[i].err = execute(attempts[i].req, attempts[i].key)
			}()
		}
		close(start)
		workers.Wait()
		winners := 0
		for _, a := range attempts {
			if a.err == nil && a.out.Outcome == identity.CommitOutcomeCommitted {
				winners++
				r, out, err = a.req, a.out, a.err
			} else if a.err == nil || a.out.Factors != nil || a.out.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("competing disable loser returned fresh state")
			}
		}
		if winners != 1 {
			t.Fatal("disable did not select exactly one proof-use winner", winners)
		}
	} else {
		out, err = execute(r, "disable-after-rollback")
	}
	if f.completionFault != nil {
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.CommandID == "" || out.Factors != nil || !f.completionFault.hit.Load() {
			t.Fatal("lost disable acknowledgement disclosed state or lost uncertainty", out.Outcome, err)
		}
	} else {
		wantRemaining := 0
		if f.disablePending {
			wantRemaining = 1
		}
		if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID == "" || out.Factors == nil || len(out.Factors) != wantRemaining {
			t.Fatal("public disable did not report accurate remaining factors", out.Outcome, err)
		}
		if f.disablePending && (string(out.Factors[0].ID) != f.pendingDisableFactor || out.Factors[0].State != mfa.FactorPending || out.Factors[0].Method != "totp" || out.Factors[0].Version != 1 || out.Factors[0].CreatedAt.IsZero()) {
			t.Fatal("one-target disable lost safe pending sibling metadata")
		}
	}
	var remaining, state, sets, uses, effects, revoked int
	var erased bool
	wantSets := 0
	if f.disablePending {
		wantSets = 1
		var preserved bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT state=1 AND encrypted_secret IS NOT NULL AND last_step IS NULL AND row_version=1 FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(b.UserID), string(f.pendingDisableFactor)).Scan(&preserved); err != nil || !preserved {
			t.Fatal("one-target disable erased or changed untargeted pending custody", err)
		}
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT a.active_factors,t.state,t.encrypted_secret IS NULL AND t.last_step IS NULL,
(SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state<>3),
(SELECT count(*) FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND used_purpose='identity.mfa.disable'),
(SELECT count(*) FROM identity_mfa.factor_update_effects WHERE tenant_id=$1 AND user_id=$2 AND purpose='identity.mfa.disable' AND disable_target=$4),
(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked')
FROM identity_mfa.totp_factors t JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id)
WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3`, otpTenant, string(b.UserID), string(factor), int16(r.Target)).Scan(&remaining, &state, &erased, &sets, &uses, &effects, &revoked); err != nil || remaining != 0 || state != 3 || !erased || sets != wantSets || uses != 1 || effects != 1 || revoked != 2 {
		t.Fatal("disable lost atomic factor/proof/session disposition", err)
	}
	if got, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err == nil && got.Authenticated {
		t.Fatal("disable left original session usable")
	}
	if f.disableAll {
		var live, present int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER(WHERE state<>3),count(*) FILTER(WHERE encrypted_secret IS NOT NULL OR last_step IS NOT NULL) FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(b.UserID)).Scan(&live, &present); err != nil || live != 0 || present != 0 {
			t.Fatal("all-target disable retained genuine pending factor custody", err)
		}
	}
	q := identity.RecoveryQuery{TenantID: otpTenant, UserID: b.UserID, ActorID: identity.ActorID(b.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.disable", CommandID: out.CommandID}
	if f.completionFault != nil {
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, otpTenant, string(b.UserID)); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := owner.RecoverDisable(ctx, q, caller); err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Factors != nil {
		t.Fatal("disable could not recover original outcome without credentials", err)
	}
	r.CommandID = out.CommandID
	if got, err := owner.Disable(ctx, r); err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.CommandID != out.CommandID || got.Factors != nil {
		t.Fatal("disable replay mutated or disclosed fresh factor state", err)
	}
	changed := r
	if r.Target == mfa.OneFactor {
		changed.Target, changed.FactorID = mfa.AllFactors, ""
	} else {
		changed.Target, changed.FactorID = mfa.OneFactor, factor
	}
	if got, err := owner.Disable(ctx, changed); err == nil || got.Factors != nil || got.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("same key changed original disable scope")
	}
	if f.afterFactorRemoval != nil {
		f.afterFactorRemoval(ctx, b.UserID)
	}
}

func disableProtectedSnapshot(t *testing.T, ctx context.Context, f liveStores) string {
	t.Helper()
	var value string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,version,active_factors) ORDER BY tenant_id,user_id) FROM identity_mfa.factor_authorities),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,label,state,row_version,encrypted_secret IS NOT NULL,last_step IS NOT NULL) ORDER BY tenant_id,user_id,factor_id) FROM identity_mfa.totp_factors),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,state,row_version) ORDER BY tenant_id,user_id,factor_id,state,row_version) FROM identity_mfa.recovery_sets),
 (SELECT jsonb_agg(jsonb_build_array(proof_id,used_command_id IS NOT NULL) ORDER BY proof_id) FROM identity_mfa.factor_verifications),
 (SELECT count(*) FROM identity_mfa.factor_update_effects),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,session_id,state,version) ORDER BY tenant_id,user_id,session_id) FROM session_store.sessions),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c USING(command_id) WHERE c.purpose='identity.mfa.disable')
)::text`).Scan(&value); err != nil {
		t.Fatal("protected disable snapshot unavailable", err)
	}
	return value
}

func proveReferenceDisableDenials(t *testing.T, ctx context.Context, f liveStores, owner mfa.DisableService, original mfa.DisableRequest) {
	t.Helper()
	before := disableProtectedSnapshot(t, ctx, f)
	deny := func(name string, r mfa.DisableRequest) {
		t.Helper()
		r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("disable-denial-" + name))
		if err := r.Validate(); err != nil {
			t.Fatal(name, "did not reach native authority")
		}
		out, err := owner.Disable(ctx, r)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Factors != nil {
			t.Fatal(name, "did not deny without projections", out.Outcome, err)
		}
		if disableProtectedSnapshot(t, ctx, f) != before {
			t.Fatal(name, "changed protected state")
		}
	}
	other := original
	other.Session = auth.NewBearerCredential(f.secondBearer)
	other.CSRFToken, _ = session.ParseCSRFToken(f.secondCSRF)
	deny("other-live-session", other)
	wrong := original
	wrong.FactorID = "AAAAAAAAAAAAAAAAAAAABQ"
	deny("other-target", wrong)
	for _, enabled := range []bool{true, false} {
		if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password-secondary',1,'identity/password',1,$3)`, original.TenantID, original.FactorProof.Subject, enabled); err != nil {
			t.Fatal(err)
		}
		deny("ambiguous-password", original)
		if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id='password-secondary'`, original.TenantID, original.FactorProof.Subject); err != nil {
			t.Fatal(err)
		}
	}
	var identifier string
	var verifiedAt time.Time
	if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND verified`, original.TenantID, original.FactorProof.Subject).Scan(&identifier, &verifiedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, original.TenantID, original.FactorProof.Subject, identifier); err != nil {
		t.Fatal(err)
	}
	deny("unverified-email", original)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, original.TenantID, original.FactorProof.Subject, identifier, verifiedAt); err != nil {
		t.Fatal(err)
	}
	foreign := original
	foreign.TenantID = "AAAAAAAAAAAAAAAAAAAAAg"
	foreign.Caller = original.Caller.Clone()
	foreign.Caller.Request.Tenant = authorization.TenantID(foreign.TenantID)
	foreign.FactorProof.Tenant = string(foreign.TenantID)
	deny("foreign-tenant", foreign)
	forged := original
	forged.FactorProof.IssuedAt = forged.FactorProof.IssuedAt.Add(time.Microsecond)
	deny("altered-original-proof", forged)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, original.TenantID, original.FactorProof.Subject); err != nil {
		t.Fatal(err)
	}
	before = disableProtectedSnapshot(t, ctx, f)
	deny("changed-factor-authority", original)
	if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, original.TenantID, original.FactorProof.Subject); err != nil {
		t.Fatal(err)
	}
	before = disableProtectedSnapshot(t, ctx, f)
	deny("blocked-account", original)
}

func invokeReferenceDisableHTTP(t *testing.T, ctx context.Context, client *http.Client, base, origin, bearer, csrf, cookieName, key string, r mfa.DisableRequest) (mfa.DisableResult, error) {
	t.Helper()
	body := map[string]any{"target": "all", "proofID": r.FactorProof.ID}
	if r.Target == mfa.OneFactor {
		body["target"], body["factorID"] = "one", r.FactorID
	}
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/disable", strings.NewReader(string(wire)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Set("Idempotency-Key", key)
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	request.AddCookie(&http.Cookie{Name: cookieName, Value: bearer})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("actual disable HTTP unavailable")
	}
	defer response.Body.Close()
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("disable leaked cacheable state or successor session")
	}
	var payload struct {
		Outcome string             `json:"commitOutcome"`
		Command identity.CommandID `json:"commandID"`
		Error   string             `json:"error"`
		Factors []json.RawMessage  `json:"factors"`
	}
	d := json.NewDecoder(io.LimitReader(response.Body, 262145))
	d.DisallowUnknownFields()
	if d.Decode(&payload) != nil || d.Decode(new(any)) != io.EOF {
		t.Fatal("disable HTTP returned malformed disposition")
	}
	out := mfa.DisableResult{CommandID: payload.Command}
	switch payload.Outcome {
	case "committed":
		out.Outcome = identity.CommitOutcomeCommitted
	case "not_committed":
		out.Outcome = identity.CommitOutcomeNotCommitted
	case "unknown":
		out.Outcome = identity.CommitOutcomeUnknown
	case "conflict":
		out.Outcome = identity.CommitOutcomeConflict
	case "in_progress":
		out.Outcome = identity.CommitOutcomeInProgress
	case "none":
	default:
		t.Fatal("disable lost outcome semantics")
	}
	if response.StatusCode != http.StatusOK {
		if payload.Factors != nil {
			t.Fatal("failed disable disclosed fresh factors")
		}
		return out, identity.UnavailableError{}
	}
	if out.Outcome != identity.CommitOutcomeCommitted || payload.Error != "" || payload.Factors == nil || len(payload.Factors) > 100 {
		t.Fatal("HTTP disable success lost safe remaining set")
	}
	out.Factors = []mfa.FactorProjection{}
	for _, raw := range payload.Factors {
		var factor struct {
			ID        mfa.FactorID    `json:"id"`
			Method    string          `json:"method"`
			Label     string          `json:"label"`
			State     mfa.FactorState `json:"state"`
			CreatedAt time.Time       `json:"createdAt"`
			Version   uint64          `json:"version"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&factor) != nil || decoder.Decode(new(any)) != io.EOF {
			t.Fatal("disable exposed undeclared remaining-factor metadata")
		}
		out.Factors = append(out.Factors, mfa.FactorProjection{ID: factor.ID, Method: factor.Method, Label: factor.Label, State: factor.State, CreatedAt: factor.CreatedAt, Version: factor.Version})
	}
	return out, nil
}
