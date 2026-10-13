//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	mfahttp "github.com/faustbrian/go-identity/http/mfa"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferenceActiveTOTPProofFromRealEnrollment(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true}, true)
}

func TestReferenceActiveTOTPProofCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, completionCommitFault: true}, true)
}

func TestReferenceActiveTOTPProofHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, activeStepUp: true, activeStepUpHTTP: true}, true)
}

func configureReferenceActiveStepUp(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{194}, ed25519.SeedSize))
	defer clear(key)
	signing, err := mfapg.NewFactorVerificationSigningKey("reference-factor-proof", key)
	if err != nil {
		t.Fatal(err)
	}
	c.MFAEnrollment.ActiveStepUp = &mfapg.TOTPActiveStepUpConfig{AllowedOrigins: []string{origin}, ComparisonKey: [32]byte{193}, ComparisonKeyVersion: 1, SigningKey: signing, VerificationKeys: map[string]ed25519.PublicKey{"reference-factor-proof": key.Public().(ed25519.PublicKey)}, Issuer: origin, Environment: "reference", Audience: "reference-mfa-regenerate", TTL: time.Minute}
}

func proveReferenceActiveStepUp(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer, csrfWire, origin string, factor mfa.FactorID, secret []byte, client *http.Client, base, cookieName string) auth.ReauthenticationProof {
	t.Helper()
	service, err := features.MFAActiveStepUp()
	if err != nil {
		t.Fatal("selected native step-up unavailable", err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(bearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("real step-up source session unavailable")
	}
	spec, _ := current.Session.Bindings()
	csrf, _ := session.ParseCSRFToken(csrfWire)
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	var now time.Time
	var before string
	if f.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp(),row_version::text FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(spec.UserID), string(factor)).Scan(&now, &before) != nil {
		t.Fatal("step-up authoritative fixture time unavailable")
	}
	codeWire := passwordMFAFixtureCode(secret, now.Add(30*time.Second))
	code, _ := auth.NewOneTimeCode(codeWire)
	command, _ := identity.NewCommandID()
	r := mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: command, FactorID: factor, Code: code, Caller: caller, Origin: origin, Network: "127.0.0.1", StepUp: &mfa.TOTPAuthenticatedStepUp{Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Purpose: "identity.mfa.recovery-regenerate"}}
	if f.factorManagement {
		r.StepUp.Purpose = "identity.mfa.factor-update"
	}
	if f.disable {
		r.StepUp.Purpose = "identity.mfa.disable"
	}
	rateSource, ok := service.(mfahttp.ActiveStepUpService)
	if !ok {
		t.Fatal("selected step-up has no native original quota source")
	}
	lifetime, until, err := rateSource.ActiveStepUpRateSource(ctx, r)
	if err != nil || lifetime != time.Minute || until.IsZero() || until.After(time.Now().Add(20*time.Second)) {
		t.Fatal("step-up quota renewed original validity or lost fixed policy", err)
	}
	wrong := r
	wrong.StepUp = &mfa.TOTPAuthenticatedStepUp{Session: r.StepUp.Session, CSRFToken: session.CSRFToken{}, Purpose: r.StepUp.Purpose}
	if out, err := service.TotpVerify(ctx, wrong); err == nil || out.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("missing synchronizer issued factor proof")
	}
	// The actual lifecycle participant fails after comparison, replay advancement
	// and proof insertion. Rollback must erase the proof and restore replay.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.step_up_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic step-up rollback'; END $$; CREATE TRIGGER step_up_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.step_up_fixture_fail()`); err != nil {
		t.Fatal("step-up rollback fixture unavailable")
	}
	out, err := service.TotpVerify(ctx, r)
	if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("failed lifecycle delivered factor proof", out.Outcome, err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER step_up_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION public.step_up_fixture_fail()`); err != nil {
		t.Fatal("step-up rollback fixture cleanup failed")
	}
	var row string
	var proofs int
	if f.pool.Raw().QueryRow(ctx, `SELECT row_version::text,(SELECT count(*) FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2) FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(spec.UserID), string(factor)).Scan(&row, &proofs) != nil || row != before || proofs != 0 {
		t.Fatal("failed step-up leaked replay or signed evidence")
	}
	r.CommandID, _ = identity.NewCommandID()
	if f.completionFault != nil && !f.regeneration && !f.factorManagement && !f.disable {
		f.completionFault.armed.Store(true)
	}
	if f.activeStepUpHTTP {
		proveReferenceActiveStepUpHTTP(t, ctx, client, base, origin, bearer, csrfWire, cookieName, r.CommandID, factor, codeWire, r.StepUp.Purpose)
	} else {
		out, err = service.TotpVerify(ctx, r)
	}
	proof := out.StepUpProof.Bindings()
	if f.completionFault != nil && !f.regeneration && !f.factorManagement && !f.disable {
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || proof.Proof.ID != "" || !f.completionFault.hit.Load() {
			t.Fatal("lost factor-proof commit acknowledgement disclosed proof", out.Outcome, err)
		}
	} else if !f.activeStepUpHTTP && (err != nil || out.Outcome != identity.CommitOutcomeCommitted || proof.Proof.ID != auth.ProofID(r.CommandID) || proof.Proof.Method != "totp" || proof.Proof.Assurance != auth.AssuranceMultiFactor || proof.SessionID != spec.SessionID || proof.SessionVersion != spec.Version || proof.Action != string(r.StepUp.Purpose)) {
		t.Fatal("actual TOTP did not issue exact original factor proof", out.Outcome, err)
	}
	source, err := mfapg.NewFactorVerificationSource(f.pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := source.Reauthentication(ctx, auth.ProofID(r.CommandID))
	if f.activeStepUpHTTP || f.completionFault != nil && !f.regeneration && !f.factorManagement && !f.disable {
		proof = signed.Proof
	}
	if err != nil || signed.Proof != proof {
		t.Fatal("committed original factor evidence unavailable")
	}
	frame, err := signed.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(frame)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{194}, ed25519.SeedSize))
	defer clear(key)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), frame, signed.Signature) {
		t.Fatal("native factor evidence did not use original authentication frame")
	}
	replayed, err := service.TotpVerify(ctx, r)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("terminal step-up replay redelivered original proof", err)
	}
	r.CommandID, _ = identity.NewCommandID()
	denied, err := service.TotpVerify(ctx, r)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || denied.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("same TOTP step won twice", err)
	}
	query := identity.RecoveryQuery{TenantID: otpTenant, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.totp-verify", CommandID: identity.CommandID(proof.Proof.ID), RecordID: string(factor)}
	history, err := service.RecoverTotpVerify(ctx, query, caller)
	if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("step-up recovery lost outcome or redelivered")
	}
	return proof
}

func proveReferenceActiveStepUpHTTP(t *testing.T, ctx context.Context, client *http.Client, base, origin, bearer, csrf, cookieName string, command identity.CommandID, factor mfa.FactorID, code string, purpose auth.Purpose) {
	t.Helper()
	for _, attempt := range []string{"missing-csrf", "fresh", "replay"} {
		body := `{"commandID":"` + string(command) + `","factorID":"` + string(factor) + `","code":"` + code + `"}`
		if purpose != "identity.mfa.recovery-regenerate" {
			body = strings.TrimSuffix(body, "}") + `,"purpose":"` + string(purpose) + `"}`
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/totp-verify", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("X-MFA-Variant", "step-up")
		if attempt != "missing-csrf" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		r.AddCookie(&http.Cookie{Name: cookieName, Value: bearer})
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("step-up HTTP unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
		response.Body.Close()
		var result struct {
			Verified           bool
			CommitOutcome      string
			CommandID, ProofID string
		}
		decodeErr := json.Unmarshal(data, &result)
		clear(data)
		if readErr != nil || decodeErr != nil || len(data) > 4096 || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("step-up HTTP lost bounded/no-store custody")
		}
		if attempt == "fresh" {
			if response.StatusCode != 200 || !result.Verified || result.CommitOutcome != "committed" || result.CommandID != string(command) || result.ProofID != string(command) {
				t.Fatal("fresh public step-up failed", response.StatusCode)
			}
		} else if response.StatusCode == 200 || result.Verified || result.ProofID != "" {
			t.Fatal("denied/replayed step-up disclosed proof", attempt, response.StatusCode)
		}
	}
}
