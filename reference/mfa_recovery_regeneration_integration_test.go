//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	primitive "github.com/faustbrian/go-password/v2"
)

func TestReferenceRecoveryRegenerationFromFreshTOTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, regeneration: true, passwordRecovery: true}, true)
}

func TestReferenceRecoveryRegenerationCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, regeneration: true, passwordRecovery: true, completionCommitFault: true}, true)
}

func TestReferenceRecoveryRegenerationCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, regeneration: true, regenerationRace: true, passwordRecovery: true}, true)
}

func TestReferenceRecoveryRegenerationHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true, regeneration: true, regenerationHTTP: true, passwordRecovery: true}, true)
}

func TestReferenceRecoveryRegenerationHTTPCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true, regeneration: true, regenerationHTTP: true, passwordRecovery: true, completionCommitFault: true}, true)
}

func TestReferenceRecoveryRegenerationHTTPCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true, regeneration: true, regenerationHTTP: true, regenerationRace: true, passwordRecovery: true}, true)
}

func TestReferenceRecoveryRegenerationRejectsChangedAuthority(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, regeneration: true, regenerationDenials: true}, true)
}

func proveReferenceRecoveryRegeneration(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer, csrfWire, origin string, proof auth.ReauthenticationProof, client *http.Client, base, cookieName string) string {
	t.Helper()
	service, err := features.MFARecoveryRegeneration()
	if err != nil {
		t.Fatal("selected recovery replacement unavailable", err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(bearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("real regeneration source session unavailable")
	}
	spec, _ := current.Session.Bindings()
	csrf, _ := session.ParseCSRFToken(csrfWire)
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Action: "identity.mfa.recovery-regenerate", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	command, _ := identity.NewCommandID()
	r := mfa.RecoveryRegenerateRequest{TenantID: otpTenant, CommandID: command, FactorProof: proof.Proof, Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Caller: caller, Origin: origin, Network: "127.0.0.1"}
	if err := r.Validate(); err != nil {
		t.Fatal("real factor request failed its public contract", err)
	}
	if f.regenerationDenials {
		proveRecoveryRegenerationDenials(t, ctx, f, service, sessions, r)
		return ""
	}
	execute := service.RecoveryRegenerate
	if f.regenerationHTTP {
		execute = func(ctx context.Context, r mfa.RecoveryRegenerateRequest) (mfa.RecoveryRegenerateResult, error) {
			return invokeReferenceRegenerationHTTP(t, ctx, client, base, origin, bearer, csrfWire, cookieName, r)
		}
		_, denied := invokeReferenceRegenerationHTTP(t, ctx, client, base, origin, bearer, "", cookieName, r)
		if denied == nil {
			t.Fatal("replacement without synchronizer succeeded")
		}
	}
	var epoch string
	if f.pool.Raw().QueryRow(ctx, `SELECT version::text FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(spec.UserID)).Scan(&epoch) != nil {
		t.Fatal("original factor epoch unavailable")
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.regeneration_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic regeneration rollback'; END $$; CREATE TRIGGER regeneration_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.regeneration_fixture_fail()`); err != nil {
		t.Fatal("regeneration rollback fixture unavailable")
	}
	out, err := execute(ctx, r)
	if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || len(out.RecoveryCodes.Codes) != 0 {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatalf("replacement failed before intended rollback: field=%s outcome=%d", invalid.Field, out.Outcome)
		}
		t.Fatal("failed lifecycle delivered replacement recovery codes", out.Outcome, err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER regeneration_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION public.regeneration_fixture_fail()`); err != nil {
		t.Fatal("regeneration rollback fixture cleanup failed")
	}
	var after string
	var used, replacements, revoked int
	if f.pool.Raw().QueryRow(ctx, `SELECT a.version::text,(SELECT count(*) FROM identity_mfa.factor_verifications v WHERE v.tenant_id=$1 AND v.user_id=$2 AND v.used_command_id IS NOT NULL),(SELECT count(*) FROM identity_mfa.recovery_sets r WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.created_purpose='identity.mfa.recovery-regenerate'),(SELECT count(*) FROM session_store.sessions s WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.state='revoked') FROM identity_mfa.factor_authorities a WHERE a.tenant_id=$1 AND a.user_id=$2`, otpTenant, string(spec.UserID)).Scan(&after, &used, &replacements, &revoked) != nil || after != epoch || used != 0 || replacements != 0 || revoked != 0 {
		t.Fatal("rollback leaked proof use, replacement, factor epoch or session effects")
	}
	r.CommandID, _ = identity.NewCommandID()
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	if f.regenerationRace {
		type attempt struct {
			request mfa.RecoveryRegenerateRequest
			result  mfa.RecoveryRegenerateResult
			err     error
		}
		attempts := [2]attempt{{request: r}, {request: r}}
		attempts[1].request.CommandID, _ = identity.NewCommandID()
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := range attempts {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				attempts[i].result, attempts[i].err = execute(ctx, attempts[i].request)
			}()
		}
		close(start)
		workers.Wait()
		winners := 0
		for _, a := range attempts {
			if a.err == nil && a.result.Outcome == identity.CommitOutcomeCommitted {
				winners++
				r, out, err = a.request, a.result, a.err
			} else if a.err == nil || len(a.result.RecoveryCodes.Codes) != 0 || a.result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("competing replacement loser delivered codes or committed", a.result.Outcome, a.err)
			}
		}
		if winners != 1 {
			t.Fatal("fresh proof did not select exactly one replacement winner", winners)
		}
	} else {
		out, err = execute(ctx, r)
	}
	if f.completionFault != nil {
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || len(out.RecoveryCodes.Codes) != 0 || !f.completionFault.hit.Load() {
			t.Fatal("lost replacement acknowledgement disclosed codes or lost uncertainty", out.Outcome, err)
		}
	} else if err != nil || out.Outcome != identity.CommitOutcomeCommitted || len(out.RecoveryCodes.Codes) != 10 {
		t.Fatal("fresh factor proof did not replace full recovery set", out.Outcome, err)
	}
	defer func() {
		for _, code := range out.RecoveryCodes.Codes {
			code.Destroy()
		}
	}()
	id, _ := base64.RawURLEncoding.DecodeString(string(r.CommandID))
	var active, retired, remaining int
	if f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state=2),(SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state=3),(SELECT count(*) FROM identity_mfa.recovery_codes WHERE tenant_id=$1 AND set_id=$3 AND consumed_command_id IS NULL),(SELECT count(*) FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND used_command_id=$4),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='revoked')`, otpTenant, string(spec.UserID), string(r.CommandID), id).Scan(&active, &retired, &remaining, &used, &revoked) != nil || active != 1 || retired != 1 || remaining != 10 || used != 1 || revoked < 1 {
		t.Fatal("replacement, proof and session effects not atomic")
	}
	if current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || current.Authenticated {
		t.Fatal("regeneration left source session usable")
	}
	if f.regenerationHTTP {
		denied, err := execute(ctx, r)
		if err == nil || len(denied.RecoveryCodes.Codes) != 0 {
			t.Fatal("revoked source session redelivered replacement through HTTP")
		}
	}
	replay, err := service.RecoveryRegenerate(ctx, r)
	if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || len(replay.RecoveryCodes.Codes) != 0 {
		t.Fatal("replacement replay redelivered codes", err)
	}
	query := identity.RecoveryQuery{TenantID: otpTenant, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.recovery-regenerate", CommandID: r.CommandID}
	history, err := service.RecoverRecoveryRegenerate(ctx, query, caller)
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted || len(history.RecoveryCodes.Codes) != 0 {
		t.Fatal("replacement recovery lost outcome or redelivered")
	}
	if f.completionFault != nil {
		return ""
	}
	var wire string
	if err := out.RecoveryCodes.Codes[0].Use(func(raw []byte) error { wire = string(raw); return nil }); err != nil {
		t.Fatal("known-commit replacement delivery unavailable")
	}
	return wire
}

func proveRecoveryRegenerationDenials(t *testing.T, ctx context.Context, f liveStores, service mfa.RecoveryRegenerationService, sessions reference.SessionService, original mfa.RecoveryRegenerateRequest) {
	t.Helper()
	// Capture protected state across all tenants. Denial may retain an abuse charge
	// or command receipt, but must not use a proof, change any set/code or revoke a
	// session. No secret verifier or bearer is included in this snapshot.
	state := func() string {
		t.Helper()
		var snapshot string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,version,active_factors) ORDER BY tenant_id,user_id) FROM identity_mfa.factor_authorities),
 (SELECT jsonb_agg(jsonb_build_array(proof_id,used_command_id IS NOT NULL) ORDER BY proof_id) FROM identity_mfa.factor_verifications),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,set_id,state,row_version) ORDER BY tenant_id,user_id,set_id) FROM identity_mfa.recovery_sets),
 (SELECT count(*) FROM identity_mfa.recovery_codes WHERE consumed_command_id IS NOT NULL),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,session_id,state,version) ORDER BY tenant_id,user_id,session_id) FROM session_store.sessions),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c USING(command_id) WHERE c.purpose='identity.mfa.recovery-regenerate')
)::text`).Scan(&snapshot); err != nil {
			t.Fatal("protected denial snapshot unavailable", err)
		}
		return snapshot
	}
	before := state()
	deny := func(name string, request mfa.RecoveryRegenerateRequest) {
		t.Helper()
		request.CommandID, _ = identity.NewCommandID()
		if err := request.Validate(); err != nil {
			t.Fatal(name, "did not reach native admission")
		}
		out, err := service.RecoveryRegenerate(ctx, request)
		defer func() {
			for _, code := range out.RecoveryCodes.Codes {
				code.Destroy()
			}
		}()
		var forbidden identity.ForbiddenError
		var unavailable identity.UnavailableError
		// The sealed graph rejects an unselected tenant as unavailable before
		// exposing its native owners. Selected-tenant authority denials must be
		// Forbidden; do not let a broken database satisfy those assertions.
		denied := errors.As(err, &forbidden) || name == "foreign-tenant" && errors.As(err, &unavailable)
		if !denied || out.Outcome == identity.CommitOutcomeCommitted || len(out.RecoveryCodes.Codes) != 0 {
			t.Fatal(name, "did not deny without replacement material", out.Outcome, err)
		}
		if state() != before {
			t.Fatal(name, "changed protected proof, recovery or session state")
		}
	}
	// Both sessions were issued through the real public password-login flow. The
	// second is live and belongs to the same subject, but did not issue this proof.
	other := original
	other.Session = auth.NewBearerCredential(f.secondBearer)
	other.CSRFToken, _ = session.ParseCSRFToken(f.secondCSRF)
	token, _ := session.ParseToken(f.secondBearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: original.TenantID, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("substituted session was not genuinely live")
	}
	bindings, err := current.Session.Bindings()
	if err != nil || string(bindings.UserID) != original.FactorProof.Subject {
		t.Fatal("substituted session did not belong to proof subject")
	}
	deny("other-live-session", other)
	foreign := original
	foreign.TenantID = "AAAAAAAAAAAAAAAAAAAAAg"
	foreign.Caller = original.Caller.Clone()
	foreign.Caller.Request.Tenant = authorization.TenantID(foreign.TenantID)
	foreign.FactorProof.Tenant = string(foreign.TenantID)
	deny("foreign-tenant", foreign)
	// A monotonic authoritative change occurs after genuine proof issuance. Never
	// reset the epoch to make the old proof valid again; this isolated graph ends.
	changed, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, original.TenantID, original.FactorProof.Subject)
	if err != nil || changed.RowsAffected() != 1 {
		t.Fatal("authoritative factor invalidation failed")
	}
	before = state()
	deny("changed-factor-authority", original)
}

func invokeReferenceRegenerationHTTP(t *testing.T, ctx context.Context, client *http.Client, base, origin, bearer, csrf, cookieName string, r mfa.RecoveryRegenerateRequest) (mfa.RecoveryRegenerateResult, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/recovery-regenerate", strings.NewReader(`{"commandID":"`+string(r.CommandID)+`","proofID":"`+string(r.FactorProof.ID)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	request.AddCookie(&http.Cookie{Name: cookieName, Value: bearer})
	response, err := client.Do(request)
	if err != nil {
		return mfa.RecoveryRegenerateResult{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	defer clear(data)
	var wire struct {
		Regenerated   bool
		CommitOutcome string
		CommandID     identity.CommandID
		RecoveryCodes []string
	}
	if err != nil || len(data) > 16384 || json.Unmarshal(data, &wire) != nil || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("replacement HTTP lost bounded/no-store custody")
	}
	out := mfa.RecoveryRegenerateResult{CommandID: wire.CommandID}
	switch wire.CommitOutcome {
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
		t.Fatal("replacement HTTP lost original outcome")
	}
	if response.StatusCode != 200 {
		if wire.Regenerated || len(wire.RecoveryCodes) != 0 {
			t.Fatal("failed/uncertain replacement HTTP disclosed codes")
		}
		if response.StatusCode == 401 || response.StatusCode == 403 {
			return out, identity.ForbiddenError{}
		}
		return out, identity.UnavailableError{}
	}
	if !wire.Regenerated || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID != r.CommandID || len(wire.RecoveryCodes) != 10 {
		t.Fatal("fresh replacement HTTP response lost native custody")
	}
	for i, code := range wire.RecoveryCodes {
		secret, err := primitive.NewSecret([]byte(code))
		wire.RecoveryCodes[i] = ""
		if err != nil {
			for _, owned := range out.RecoveryCodes.Codes {
				owned.Destroy()
			}
			t.Fatal("replacement wire code invalid")
		}
		out.RecoveryCodes.Codes = append(out.RecoveryCodes.Codes, secret)
	}
	return out, nil
}
