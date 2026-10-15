//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferenceServerHTTPPasswordRecoveryFromRealEnrollment(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, passwordRecovery: true}, true)
}

func TestReferenceServerHTTPPasswordRecoveryCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, passwordRecovery: true, completionCommitFault: true}, true)
}

func TestReferenceServerHTTPCompetingPasswordRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, passwordRecovery: true, recoveryRace: true}, true)
}

func configureReferencePasswordRecovery(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	configureReferencePasswordMFA(t, c, origin)
	totp := c.PasswordSignin.TOTP
	c.PasswordSignin.Recovery = &reference.PasswordRecoveryConfiguration{MaximumDuration: totp.MaximumDuration, ConfigurationID: "reference-password-recovery-v1", PolicyID: "password-recovery", Counters: totp.Counters, RiskKeys: totp.RiskKeys, VerificationKeys: map[uint32][32]byte{1: {182}}, ActiveEnvelopeKeyID: totp.ActiveEnvelopeKeyID}
	c.PasswordSignin.MFA.AllowedMethods = []string{"totp", "recovery-code"}
	// No TOTP login-completion owner or route is needed by recovery. Enrollment
	// confirmation remains explicitly selected by its separate owner.
	c.PasswordSignin.TOTP = nil
	c.HTTPMFA.PasswordTOTPVerify = false
	c.HTTPMFA.PasswordRecoveryUse = true
}

// Every account/factor/code/primary is produced by actual public workflows.
// The supplied code was captured once from enrollment transport, not seeded.
func proveReferencePasswordRecoveryHTTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin, code string, rejected ...string) {
	t.Helper()
	invoke := func(path string, body any, cookies []*http.Cookie) (*http.Response, []byte) {
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(wire))
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
			t.Fatal("recovery HTTP unavailable")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(data) > 16384 {
			t.Fatal("recovery response bounds")
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("recovery response cacheable")
		}
		return response, data
	}
	response, data := invoke("/v1/session/preauth-issue", map[string]string{"method": "password"}, nil)
	var flow sessionhttp.PreAuthResponse
	if response.StatusCode != 200 || json.Unmarshal(data, &flow) != nil || !flow.Issued {
		t.Fatal("recovery original flow unavailable")
	}
	cookies := response.Cookies()
	response, data = invoke("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, cookies)
	var challenge passwordhttp.SigninResponse
	if response.StatusCode != 200 || json.Unmarshal(data, &challenge) != nil || !challenge.ChallengeRequired || challenge.SignedIn || response.Header.Get("X-MFA-Token") == "" {
		t.Fatal("recovery primary did not remain non-final", response.StatusCode, challenge.Error)
	}
	command, _ := identity.NewCommandID()
	body := map[string]any{"commandID": command, "preAuthID": flow.FlowID, "continuationID": challenge.ChallengeID, "token": response.Header.Get("X-MFA-Token"), "recoveryCode": code, "callbackURL": origin + "/reset"}
	if f.recoveryRace {
		proveCompetingPublicRecovery(t, ctx, f, features, client, base, origin, body, cookies)
		return
	}
	foreign, _ := invoke("/v1/session/preauth-issue", map[string]string{"method": "password"}, nil)
	response, _ = invoke("/v1/mfa/recovery-use", body, foreign.Cookies())
	if response.StatusCode != 403 || len(response.Cookies()) != 0 {
		t.Fatal("foreign browser completed recovery", response.StatusCode)
	}
	wrong := map[string]any{}
	for k, v := range body {
		wrong[k] = v
	}
	wrong["commandID"], _ = identity.NewCommandID()
	wrong["recoveryCode"] = "synthetic-wrong-recovery-code"
	if len(rejected) > 0 {
		wrong["recoveryCode"] = rejected[0]
	}
	response, _ = invoke("/v1/mfa/recovery-use", wrong, cookies)
	if response.StatusCode != 403 || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("wrong recovery code did not deny", response.StatusCode)
	}
	var sessionsBefore int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions`).Scan(&sessionsBefore); err != nil {
		t.Fatal(err)
	}
	if f.completionFault == nil {
		// Fail the actual lifecycle participant after recovery burn and session
		// work. The original one-use child is retired on proven abort; obtain a
		// new primary afterward rather than resurrecting that grant.
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.recovery_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic recovery rollback'; END $$; CREATE TRIGGER recovery_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.recovery_fixture_fail()`); err != nil {
			t.Fatal("recovery rollback fixture unavailable")
		}
		cleanup := func() {
			bounded, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER IF EXISTS recovery_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION IF EXISTS public.recovery_fixture_fail()`); err != nil {
				t.Error("owned rollback fixture cleanup failed", err)
			}
		}
		t.Cleanup(cleanup)
		response, data = invoke("/v1/mfa/recovery-use", body, cookies)
		var aborted struct {
			SignedIn      bool
			CommitOutcome string
		}
		if response.StatusCode != 503 || json.Unmarshal(data, &aborted) != nil || aborted.SignedIn || aborted.CommitOutcome != "not_committed" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("late recovery failure delivered credentials", response.StatusCode, aborted.CommitOutcome)
		}
		cleanup()
		id, _ := base64.RawURLEncoding.DecodeString(string(command))
		var sessions, burns, charges, lifecycle int
		// ExecutePreparedFeature commits abuse quota before generation and
		// intentionally retains it on final abort. That is not consumption of
		// factor/child/session authority; refunding it would change its contract.
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM identity_mfa.recovery_codes WHERE consumed_command_id=$1),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id).Scan(&sessions, &burns, &charges, &lifecycle); err != nil || sessions != sessionsBefore || burns != 0 || charges != 1 || lifecycle != 0 {
			t.Fatal("late recovery rollback leaked effects", err, sessions, burns, charges, lifecycle)
		}
		response, data = invoke("/v1/session/preauth-issue", map[string]string{"method": "password"}, nil)
		flow = sessionhttp.PreAuthResponse{}
		if response.StatusCode != 200 || json.Unmarshal(data, &flow) != nil || !flow.Issued {
			t.Fatal("replacement recovery flow unavailable")
		}
		cookies = response.Cookies()
		response, data = invoke("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, cookies)
		challenge = passwordhttp.SigninResponse{}
		if response.StatusCode != 200 || json.Unmarshal(data, &challenge) != nil || !challenge.ChallengeRequired || response.Header.Get("X-MFA-Token") == "" {
			t.Fatal("replacement recovery primary unavailable", response.StatusCode)
		}
		command, _ = identity.NewCommandID()
		body["commandID"], body["preAuthID"], body["continuationID"], body["token"] = command, flow.FlowID, challenge.ChallengeID, response.Header.Get("X-MFA-Token")
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	response, data = invoke("/v1/mfa/recovery-use", body, cookies)
	var result struct {
		SignedIn                        bool
		CommitOutcome, SessionID, Error string
	}
	if f.completionFault != nil {
		if response.StatusCode != 503 || json.Unmarshal(data, &result) != nil || result.SignedIn || result.CommitOutcome != "unknown" || !f.completionFault.hit.Load() || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("recovery lost commit acknowledgement disclosed credentials", response.StatusCode, result.CommitOutcome)
		}
		owner, err := features.PasswordRecovery()
		if err != nil {
			t.Fatal(err)
		}
		caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.recovery-use", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.FlowID)}}}
		query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: command, AnonymousFlowID: string(flow.FlowID), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.recovery-use"}
		history, err := owner.RecoverRecoveryUse(ctx, query, caller)
		if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Session.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("ambiguous recovery lost outcome or redelivered", err)
		}
		assertPublicRecoveryAtomicity(t, ctx, f, command, string(challenge.ChallengeID), sessionsBefore)
		response, _ = invoke("/v1/mfa/recovery-use", body, cookies)
		if response.StatusCode == 200 || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("ambiguous recovery retry redelivered")
		}
		return
	}
	if response.StatusCode != 200 || json.Unmarshal(data, &result) != nil || !result.SignedIn || result.CommitOutcome != "committed" || len(response.Cookies()) != 1 || response.Header.Get("X-CSRF-Token") == "" {
		t.Fatal("recovery did not create usable session", response.StatusCode, result.Error, result.CommitOutcome)
	}
	completed, csrf := response.Cookies(), response.Header.Get("X-CSRF-Token")
	assertPublicRecoveryAtomicity(t, ctx, f, command, string(challenge.ChallengeID), sessionsBefore)
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(completed[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	factor, factorErr := admitted.Session.MFAAuthentication().Bindings()
	wantSetVersion := uint64(1)
	if f.regeneration {
		var epoch string
		if f.pool.Raw().QueryRow(ctx, `SELECT set_version::text FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND state=2`, otpTenant).Scan(&epoch) != nil {
			t.Fatal("regenerated set epoch unavailable")
		}
		wantSetVersion, err = strconv.ParseUint(epoch, 10, 64)
		if err != nil || wantSetVersion <= 1 {
			t.Fatal("replacement did not advance recovery epoch")
		}
	}
	if err != nil || !admitted.Authenticated || factorErr != nil || factor.Method != "recovery-code" || factor.RecoverySetVersion != wantSetVersion {
		t.Fatal("recovery session unreadable or lost provenance", err)
	}
	activeReader, err := mfapg.NewTOTPFactorReader(f.pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	active, err := activeReader.ReadForStepUp(ctx, admitted, factor.FactorID)
	metadata, metadataErr := active.Metadata()
	spec, specErr := admitted.Session.Bindings()
	if err != nil || metadataErr != nil || specErr != nil || metadata.Factor.FactorID != factor.FactorID || metadata.Factor.EnrollmentVersion != factor.EnrollmentVersion || metadata.Factor.FactorAuthorityVersion != factor.FactorAuthorityVersion || metadata.SessionID != spec.SessionID || metadata.SessionVersion != spec.Version || !metadata.ValidUntil.Equal(admitted.ValidUntil()) {
		t.Fatal("active factor read lost original owned session or factor fences")
	}
	if _, err := active.Envelope(); err != nil {
		t.Fatal("active factor read did not retain actual enrolled ciphertext")
	}
	if _, err := active.EncryptionContext(); err != nil {
		t.Fatal("active factor read lost envelope authentication binding")
	}
	if _, err := activeReader.ReadForStepUp(ctx, session.GetResult{Authenticated: true, Session: admitted.Session}, factor.FactorID); err == nil {
		t.Fatal("fabricated authentication flag supplied active factor custody")
	}
	otherFactor, _ := identity.NewCommandID()
	if _, err := activeReader.ReadForStepUp(ctx, admitted, string(otherFactor)); err == nil {
		t.Fatal("unrelated factor supplied active custody")
	}
	response, _ = invoke("/v1/mfa/recovery-use", body, cookies)
	if response.StatusCode != 409 || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("recovery retry redelivered", response.StatusCode)
	}
	owner, err := features.PasswordRecovery()
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.recovery-use", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow.FlowID)}}}
	query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: command, AnonymousFlowID: string(flow.FlowID), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.recovery-use"}
	history, err := owner.RecoverRecoveryUse(ctx, query, caller)
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Session.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("recovery history lost or redelivered", err)
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, completed, csrf, result.SessionID, f, features)
}

func assertPublicRecoveryAtomicity(t *testing.T, ctx context.Context, f liveStores, command identity.CommandID, child string, sessionsBefore int) {
	t.Helper()
	id, _ := base64.RawURLEncoding.DecodeString(string(command))
	var sessions, burns, uses, charges, snapshots, lifecycle, remaining int
	wantRemaining := 2
	if f.completionFault != nil {
		wantRemaining = 1
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM identity_mfa.recovery_codes WHERE consumed_command_id=$1 AND consumed_at IS NOT NULL),(SELECT uses FROM public.capability_identity_one_use WHERE tenant_id=$2 AND capability_id=$3),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1),(SELECT count(*) FROM risk_store.counter_snapshots WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT attempts_remaining FROM identity_mfa.continuations WHERE tenant_id=$2 AND continuation_id=$3)`, id, otpTenant, child).Scan(&sessions, &burns, &uses, &charges, &snapshots, &lifecycle, &remaining); err != nil || sessions != sessionsBefore+1 || burns != 1 || uses != 1 || charges != 1 || snapshots != 4 || lifecycle != 1 || remaining != wantRemaining {
		t.Fatal("public recovery did not conserve atomic effects", err, sessions, burns, uses, charges, snapshots, lifecycle, remaining)
	}
}

func proveCompetingPublicRecovery(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, body map[string]any, cookies []*http.Cookie) {
	t.Helper()
	var before int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM session_store.sessions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	type observation struct {
		status    int
		signed    bool
		sessionID string
		cookies   []*http.Cookie
		csrf      string
		err       error
		outcome   string
		code      string
	}
	requests := make([]*http.Request, 2)
	commands := make([]identity.CommandID, 2)
	for i := range requests {
		copy := make(map[string]any, len(body))
		for k, v := range body {
			copy[k] = v
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		copy["commandID"] = id
		commands[i] = id
		wire, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		requests[i], err = http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/recovery-use", bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		requests[i].Header.Set("Origin", origin)
		requests[i].Header.Set("Content-Type", "application/json")
		for _, cookie := range cookies {
			requests[i].AddCookie(cookie)
		}
	}
	var wg sync.WaitGroup
	results := make([]observation, 2)
	start := make(chan struct{})
	for i, request := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			response, err := client.Do(request)
			if err != nil {
				results[i].err = err
				return
			}
			defer response.Body.Close()
			data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
			defer clear(data)
			if err != nil || len(data) > 16384 {
				results[i].err = io.ErrUnexpectedEOF
				return
			}
			var result struct {
				SignedIn      bool
				SessionID     string
				CommitOutcome string
				Error         string
			}
			if err = json.Unmarshal(data, &result); err != nil {
				results[i].err = err
				return
			}
			results[i] = observation{status: response.StatusCode, signed: result.SignedIn, sessionID: result.SessionID, cookies: response.Cookies(), csrf: response.Header.Get("X-CSRF-Token"), outcome: result.CommitOutcome, code: result.Error}
		}()
	}
	close(start)
	wg.Wait()
	winners := 0
	for _, out := range results {
		if out.err != nil {
			t.Fatal("competing recovery request failed")
		}
		if out.status == 200 {
			winners++
			if !out.signed || len(out.cookies) != 1 || out.csrf == "" {
				t.Fatal("winner lost delivery")
			}
		} else if out.status == 503 && out.outcome == "unknown" && out.code == "unavailable" {
			if out.signed || len(out.cookies) != 0 || out.csrf != "" {
				t.Fatal("uncertain loser delivered credentials")
			}
		} else if out.status != 403 && out.status != 409 {
			t.Fatal("unexpected competing denial", out.status, out.outcome, out.code)
		} else if out.signed || len(out.cookies) != 0 || out.csrf != "" {
			t.Fatal("loser delivered credentials")
		}
	}
	if winners != 1 {
		t.Fatal("same recovery credential completed twice", winners)
	}
	owner, err := features.PasswordRecovery()
	if err != nil {
		t.Fatal(err)
	}
	for i, out := range results {
		if out.status == 200 || out.status == 403 {
			continue
		}
		flow := body["preAuthID"].(identity.PreAuthTransactionID)
		caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.recovery-use", Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(flow)}}}
		query := identity.RecoveryQuery{TenantID: otpTenant, CommandID: commands[i], AnonymousFlowID: string(flow), ActorID: "AAAAAAAAAAAAAAAAAAAAAw", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.mfa.recovery-use"}
		raw, _ := base64.RawURLEncoding.DecodeString(string(commands[i]))
		var state string
		var planMissing, prepared, output bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT state,command_plan IS NULL,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL FROM identity.commands WHERE command_id=$1`, raw).Scan(&state, &planMissing, &prepared, &output); err != nil {
			t.Fatal("cannot inspect competing journal")
		}
		if out.status == 409 && (state != "aborted" || planMissing || !prepared || !output) {
			t.Fatal("competing attachment denial lost its terminal preparation receipt")
		}
		history, recoveryErr := owner.RecoverRecoveryUse(ctx, query, caller)
		if history.Outcome != identity.CommitOutcomeNotCommitted || history.Session.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("uncertain competing outcome did not reconcile without credentials", history.Outcome, fmt.Sprintf("%T", recoveryErr))
		}
	}
	var after, burns, uses int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM identity_mfa.recovery_codes WHERE consumed_at IS NOT NULL),(SELECT uses FROM public.capability_identity_one_use WHERE tenant_id=$1 AND capability_id=$2)`, otpTenant, body["continuationID"]).Scan(&after, &burns, &uses); err != nil || after != before+1 || burns != 1 || uses != 1 {
		t.Fatal("competing recovery split its one-use effects", err, after, burns, uses)
	}
	for _, out := range results {
		if out.status == 200 {
			proveRegistrationSessionLogout(t, ctx, client, base, origin, out.cookies, out.csrf, out.sessionID, f, features)
		}
	}
}
