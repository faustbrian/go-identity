//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password"
)

func TestReferenceFactorRenameFromFreshTOTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true}, true)
}

func TestReferenceFactorRenameHTTP(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorManagementHTTP: true}, true)
}

func TestReferenceFactorRenameHTTPFromHTTPStepUp(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true}, true)
}

func TestReferenceFactorRenameCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorManagementRace: true}, true)
}

func TestReferenceFactorRenameHTTPCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true, factorManagementRace: true}, true)
}

func TestReferenceFactorRenameCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, completionCommitFault: true}, true)
}

func TestReferenceFactorRenameHTTPCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true, completionCommitFault: true}, true)
}

func TestReferenceFactorRenameRejectsChangedAuthority(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorManagementDenials: true}, true)
}

func TestReferenceFactorRenameHTTPClearsExistingLabel(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true, factorManagementClear: true}, true)
}

func TestReferenceFactorRemovalWithEmailRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorRemoval: true}, true)
}

func TestReferenceFactorRemovalHTTPWithEmailRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true, factorRemoval: true}, true)
}

func TestReferenceFactorRemovalRejectsLostRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorManagementDenials: true, factorRemoval: true}, true)
}

func TestReferenceFactorRemovalCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorManagementRace: true, factorRemoval: true}, true)
}

func TestReferenceFactorRemovalHTTPCompetingCommands(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true, factorManagementRace: true, factorRemoval: true}, true)
}

func TestReferenceFactorRemovalCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, completionCommitFault: true, factorRemoval: true}, true)
}

func TestReferenceFactorRemovalHTTPCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true, completionCommitFault: true, factorRemoval: true}, true)
}

func TestReferenceFactorRemovalThenNativeEmailReset(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorRemoval: true, factorRemovalReset: true}, true)
}

func TestReferenceFactorRemovalThenHTTPEmailReset(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorManagementHTTP: true, factorRemoval: true, factorRemovalReset: true}, true)
}

func TestReferenceFactorRemovalSerializesRecoveryAuthority(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorRemoval: true, factorRemovalLocks: true}, true)
}

func proveReferenceFactorRename(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer, csrfWire, origin string, factor mfa.FactorID, proof auth.ReauthenticationProof, client *http.Client, base, cookieName string) {
	t.Helper()
	management, err := features.MFAFactorManagement()
	if err != nil {
		t.Fatal("selected management owner unavailable", err)
	}
	listing, err := features.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session.ParseToken(bearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("actual management source session unavailable")
	}
	spec, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	originalLabel := ""
	if f.factorManagementClear {
		// Populate only presentation metadata in the owned database, not a
		// credential, account, session or proof. Read the new optimistic version
		// through public listing before asking the public HTTP owner to clear it.
		originalLabel = "previous authenticator label"
		changed, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET label=$4,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(spec.UserID), string(factor), originalLabel)
		if err != nil || changed.RowsAffected() != 1 {
			t.Fatal("owned presentation fixture unavailable")
		}
	}
	before, err := listing.List(ctx, mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "management-before"})
	if err != nil || len(before.Factors) != 1 || before.Factors[0].ID != factor || before.Factors[0].Label != originalLabel || before.RecoveryCodeCount != 10 {
		t.Fatal("actual pre-management inventory unavailable", err)
	}
	keyText := "factor-rename-fixture"
	key, err := identity.NewIdempotencyKey([]byte(keyText))
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.ParseCSRFToken(csrfWire)
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Action: "identity.mfa.factor-update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	r := mfa.FactorUpdateRequest{TenantID: otpTenant, FactorID: factor, Action: mfa.Rename, Name: "authenticator <work>", ExpectedVersion: before.Factors[0].Version, FactorProof: proof.Proof, Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Caller: caller, Origin: origin, Network: "127.0.0.1", IdempotencyKey: key}
	wantedState := mfa.FactorActive
	if f.factorRemoval {
		r.Action, r.Name, wantedState = mfa.Remove, "", mfa.FactorRevoked
	}
	if f.factorManagementClear {
		r.Name = ""
	}
	if f.factorRemovalLocks {
		proveReferenceFactorRemovalLocks(t, ctx, f, management, r)
		return
	}
	if f.factorManagementDenials {
		proveReferenceFactorRenameDenials(t, ctx, f, management, sessions, r)
		return
	}
	wrong := r
	wrong.FactorProof.Purpose = "identity.mfa.recovery-regenerate"
	if out, err := management.FactorUpdate(ctx, wrong); err == nil || out.Factor.ID != "" {
		t.Fatal("regeneration proof selected factor mutation")
	}
	execute := func(ctx context.Context, r mfa.FactorUpdateRequest, _ string) (mfa.FactorUpdateResult, error) {
		return management.FactorUpdate(ctx, r)
	}
	if f.factorManagementHTTP {
		execute = func(ctx context.Context, r mfa.FactorUpdateRequest, wireKey string) (mfa.FactorUpdateResult, error) {
			return invokeReferenceFactorUpdateHTTP(t, ctx, client, base, origin, bearer, csrfWire, cookieName, wireKey, r)
		}
		if out, err := invokeReferenceFactorUpdateHTTP(t, ctx, client, base, origin, bearer, "", cookieName, keyText, r); err == nil || out.Factor.ID != "" {
			t.Fatal("HTTP rename without synchronizer disclosed metadata")
		}
	}
	var epoch string
	if f.pool.Raw().QueryRow(ctx, `SELECT version::text FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(spec.UserID)).Scan(&epoch) != nil {
		t.Fatal("original management epoch unavailable")
	}
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.factor_rename_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic factor-rename rollback'; END $$; CREATE TRIGGER factor_rename_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.factor_rename_fail()`); err != nil {
		t.Fatal("owned rollback fixture unavailable")
	}
	out, err := execute(ctx, r, keyText)
	if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.CommandID == "" || out.Factor.ID != "" {
		t.Fatal("failed lifecycle published rename", out.Outcome, err)
	}
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER factor_rename_fail ON public.identity_outbox_bindings; DROP FUNCTION public.factor_rename_fail()`); err != nil {
		t.Fatal("owned rollback fixture cleanup failed")
	}
	var label, version, afterEpoch string
	var uses, effects, revoked int
	if f.pool.Raw().QueryRow(ctx, `SELECT t.label,t.row_version::text,a.version::text,(SELECT count(*) FROM identity_mfa.factor_verifications v WHERE v.tenant_id=$1 AND v.user_id=$2 AND v.used_purpose='identity.mfa.factor-update'),(SELECT count(*) FROM identity_mfa.factor_update_effects e WHERE e.tenant_id=$1 AND e.user_id=$2),(SELECT count(*) FROM session_store.sessions s WHERE s.tenant_id=$1 AND s.user_id=$2 AND s.state='revoked') FROM identity_mfa.totp_factors t JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id) WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3`, otpTenant, string(spec.UserID), string(factor)).Scan(&label, &version, &afterEpoch, &uses, &effects, &revoked) != nil || label != originalLabel || version != strconv.FormatUint(r.ExpectedVersion, 10) || afterEpoch != epoch || uses != 0 || effects != 0 || revoked != 0 {
		t.Fatal("rollback left factor, proof or session effects")
	}
	if f.factorRemoval {
		var intact, replayPresent bool
		var codeSets, active int
		if f.pool.Raw().QueryRow(ctx, `SELECT t.state=2 AND t.encrypted_secret IS NOT NULL,t.last_step IS NOT NULL,(SELECT count(*) FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND state=2),(SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND state='active') FROM identity_mfa.totp_factors t WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(spec.UserID), string(factor)).Scan(&intact, &replayPresent, &codeSets, &active) != nil || !intact || !replayPresent || codeSets != 1 || active != 2 {
			t.Fatal("removal rollback erased material, retired codes or revoked genuine sessions")
		}
	}
	keyText = "factor-rename-after-rollback"
	r.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(keyText))
	if err != nil {
		t.Fatal(err)
	}
	if f.completionFault != nil {
		f.completionFault.armed.Store(true)
	}
	if f.factorManagementRace {
		type attempt struct {
			request mfa.FactorUpdateRequest
			wireKey string
			result  mfa.FactorUpdateResult
			err     error
		}
		attempts := [2]attempt{{request: r, wireKey: keyText}, {request: r, wireKey: "factor-rename-competing-key"}}
		attempts[1].request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("factor-rename-competing-key"))
		if err != nil {
			t.Fatal(err)
		}
		if r.Action == mfa.Rename {
			attempts[1].request.Name = "other authenticator"
		}
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := range attempts {
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-start
				attempts[i].result, attempts[i].err = execute(ctx, attempts[i].request, attempts[i].wireKey)
			}()
		}
		close(start)
		workers.Wait()
		winners := 0
		for _, a := range attempts {
			if a.err == nil && a.result.Outcome == identity.CommitOutcomeCommitted {
				winners++
				r, out, err = a.request, a.result, a.err
			} else if a.err == nil || a.result.Factor.ID != "" || a.result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("competing rename loser returned metadata or committed", a.result.Outcome, a.err)
			}
		}
		if winners != 1 {
			t.Fatal("fresh proof did not select exactly one rename winner", winners)
		}
	} else {
		out, err = execute(ctx, r, keyText)
	}
	if f.completionFault != nil {
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.CommandID == "" || out.Factor.ID != "" || !f.completionFault.hit.Load() {
			t.Fatal("lost rename acknowledgement disclosed metadata or lost uncertainty", out.Outcome, err)
		}
	} else if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID == "" || out.Factor.ID != factor || out.Factor.Label != r.Name || out.Factor.Version != r.ExpectedVersion+1 || out.Factor.State != wantedState {
		t.Fatal("actual rename not committed", out.Outcome, err)
	}
	if got, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err == nil && got.Authenticated {
		t.Fatal("rename left source session usable")
	}
	if f.factorRemoval && f.completionFault != nil {
		// Historical reconciliation must conserve the committed disposition,
		// even after the formerly usable recovery path loses current eligibility.
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, otpTenant, string(spec.UserID)); err != nil {
			t.Fatal("owned post-commit recovery-path change unavailable", err)
		}
	}
	r.CommandID = out.CommandID
	query := identity.RecoveryQuery{TenantID: otpTenant, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.factor-update", CommandID: out.CommandID}
	if historical, err := management.RecoverFactorUpdate(ctx, query, caller); err != nil || historical.Outcome != identity.CommitOutcomeCommitted || historical.Factor.ID != "" {
		t.Fatal("credential-free management recovery lost original outcome", err)
	}
	if replay, err := management.FactorUpdate(ctx, r); err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.CommandID != out.CommandID || replay.Factor.ID != "" {
		t.Fatal("rename replay repeated mutation or lost original outcome", err)
	}
	if f.pool.Raw().QueryRow(ctx, `SELECT t.label,t.row_version::text,(SELECT count(*) FROM identity_mfa.factor_update_effects e WHERE e.tenant_id=t.tenant_id AND e.user_id=t.user_id),(SELECT count(*) FROM identity_mfa.factor_verifications v WHERE v.tenant_id=t.tenant_id AND v.user_id=t.user_id AND v.used_purpose='identity.mfa.factor-update') FROM identity_mfa.totp_factors t WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3`, otpTenant, string(spec.UserID), string(factor)).Scan(&label, &version, &effects, &uses) != nil || label != r.Name || effects != 1 || uses != 1 {
		t.Fatal("rename effect was not one-time and durable")
	}
	if f.factorRemoval {
		var remaining, state, sets int
		var erased bool
		if f.pool.Raw().QueryRow(ctx, `SELECT a.active_factors,t.state,t.encrypted_secret IS NULL AND t.last_step IS NULL,(SELECT count(*) FROM identity_mfa.recovery_sets s WHERE s.tenant_id=t.tenant_id AND s.user_id=t.user_id AND s.state=2) FROM identity_mfa.totp_factors t JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id) WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3`, otpTenant, string(spec.UserID), string(factor)).Scan(&remaining, &state, &erased, &sets) != nil || remaining != 0 || state != 3 || !erased || sets != 0 {
			t.Fatal("removal retained factor authority, secret or dependent recovery set")
		}
		command, decodeErr := base64.RawURLEncoding.DecodeString(string(out.CommandID))
		var audits, lifecycle, count int
		if decodeErr != nil || f.pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),
(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
(SELECT revoked_count FROM session_store.mfa_recovery_dispositions WHERE command_id=$1 AND purpose='identity.mfa.factor-update')`, command).Scan(&audits, &lifecycle, &count) != nil || audits != 1 || lifecycle != 1 || count != 2 {
			t.Fatal("removal did not bind atomic audit/lifecycle and both genuine session effects")
		}
		second, _ := session.ParseToken(f.secondBearer)
		secondCredential, _ := session.NewCredential(session.CredentialCookie, second)
		if current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: secondCredential}); err == nil && current.Authenticated {
			t.Fatal("removal left the second genuine session usable")
		}
		if f.afterFactorRemoval != nil {
			f.afterFactorRemoval(ctx, spec.UserID)
		}
	}
}

func proveReferenceFactorRenameDenials(t *testing.T, ctx context.Context, f liveStores, service mfa.FactorManagementService, sessions reference.SessionService, original mfa.FactorUpdateRequest) {
	t.Helper()
	// Compare only protected metadata, never factor material or bearer bytes.
	state := func() string {
		t.Helper()
		var snapshot string
		if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,version,active_factors) ORDER BY tenant_id,user_id) FROM identity_mfa.factor_authorities),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,label,state,row_version,encrypted_secret IS NOT NULL,last_step IS NOT NULL) ORDER BY tenant_id,user_id,factor_id) FROM identity_mfa.totp_factors),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,state,row_version) ORDER BY tenant_id,user_id,state,row_version) FROM identity_mfa.recovery_sets),
 (SELECT jsonb_agg(jsonb_build_array(proof_id,used_command_id IS NOT NULL) ORDER BY proof_id) FROM identity_mfa.factor_verifications),
 (SELECT count(*) FROM identity_mfa.factor_update_effects),
 (SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,session_id,state,version) ORDER BY tenant_id,user_id,session_id) FROM session_store.sessions),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c USING(command_id) WHERE c.purpose='identity.mfa.factor-update')
)::text`).Scan(&snapshot); err != nil {
			t.Fatal("protected rename snapshot unavailable", err)
		}
		return snapshot
	}
	before := state()
	deny := func(name string, request mfa.FactorUpdateRequest, conflict bool) {
		t.Helper()
		request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("rename-denial-" + name))
		if err := request.Validate(); err != nil {
			t.Fatal(name, "did not reach native admission")
		}
		out, err := service.FactorUpdate(ctx, request)
		var forbidden identity.ForbiddenError
		var unavailable identity.UnavailableError
		var stale identity.ConflictError
		// The existing keyed preparation owner deliberately conceals callback
		// rejections as Unavailable before exposing a command. This is not a
		// protected commit; only later authoritative denials retain a command.
		concealedPreparation := errors.As(err, &unavailable) && out.CommandID == "" && out.Outcome == 0
		denied := errors.As(err, &forbidden) || conflict && errors.As(err, &stale) || concealedPreparation
		if !denied || out.Outcome == identity.CommitOutcomeCommitted || out.Factor.ID != "" || out.Replacement != nil {
			t.Fatal(name, "did not deny without factor metadata", out.Outcome, err)
		}
		if state() != before {
			t.Fatal(name, "changed protected factor/proof/session state")
		}
	}
	if original.Action == mfa.Remove {
		// The actual reset owner rejects multiple password references, even if
		// one is disabled. Removal must use that same unambiguous ownership rule.
		for _, enabled := range []bool{true, false} {
			if _, err := f.pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password-secondary',1,'identity/password',1,$3)`, original.TenantID, original.FactorProof.Subject, enabled); err != nil {
				t.Fatal("owned duplicate recovery credential fixture unavailable", err)
			}
			deny("ambiguous-recovery-password", original, false)
			if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM identity.credential_references WHERE tenant_id=$1 AND user_id=$2 AND credential_id='password-secondary'`, original.TenantID, original.FactorProof.Subject); err != nil {
				t.Fatal("owned duplicate recovery credential cleanup failed", err)
			}
		}
		var identifier string
		var verifiedAt time.Time
		if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND kind='email' AND verified`, original.TenantID, original.FactorProof.Subject).Scan(&identifier, &verifiedAt); err != nil {
			t.Fatal("original recovery identifier unavailable", err)
		}
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=false,verification_state=1,verified_at=NULL WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, original.TenantID, original.FactorProof.Subject, identifier); err != nil {
			t.Fatal("owned recovery-email loss fixture unavailable", err)
		}
		deny("unverified-recovery-email", original, false)
		if _, err := f.pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET verified=true,verification_state=2,verified_at=$4 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, original.TenantID, original.FactorProof.Subject, identifier, verifiedAt); err != nil {
			t.Fatal("owned recovery-email fixture restoration failed", err)
		}
	}
	other := original
	other.Session = auth.NewBearerCredential(f.secondBearer)
	other.CSRFToken, _ = session.ParseCSRFToken(f.secondCSRF)
	token, _ := session.ParseToken(f.secondBearer)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: original.TenantID, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("substituted rename session not genuinely live")
	}
	bindings, err := current.Session.Bindings()
	if err != nil || string(bindings.UserID) != original.FactorProof.Subject {
		t.Fatal("substituted session subject mismatch")
	}
	deny("other-live-session", other, false)
	foreign := original
	foreign.TenantID = "AAAAAAAAAAAAAAAAAAAAAg"
	foreign.Caller = original.Caller.Clone()
	foreign.Caller.Request.Tenant = authorization.TenantID(foreign.TenantID)
	foreign.FactorProof.Tenant = string(foreign.TenantID)
	deny("foreign-tenant", foreign, false)
	stale := original
	stale.ExpectedVersion++
	deny("stale-factor-version", stale, true)
	changedProof := original
	changedProof.FactorProof.IssuedAt = changedProof.FactorProof.IssuedAt.Add(time.Microsecond)
	deny("altered-proof-time", changedProof, false)
	changed, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, original.TenantID, original.FactorProof.Subject)
	if err != nil || changed.RowsAffected() != 1 {
		t.Fatal("factor authority invalidation failed")
	}
	before = state()
	deny("changed-factor-authority", original, false)
	changed, err = f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, original.TenantID, original.FactorProof.Subject)
	if err != nil || changed.RowsAffected() != 1 {
		t.Fatal("account authority invalidation failed")
	}
	before = state()
	deny("blocked-account", original, false)
}

func invokeReferenceFactorUpdateHTTP(t *testing.T, ctx context.Context, client *http.Client, base, origin, bearer, csrf, cookieName, key string, r mfa.FactorUpdateRequest) (mfa.FactorUpdateResult, error) {
	t.Helper()
	body := map[string]any{"factorID": r.FactorID, "proofID": r.FactorProof.ID, "expectedVersion": r.ExpectedVersion}
	switch r.Action {
	case mfa.Rename:
		body["action"], body["name"] = "rename", r.Name
	case mfa.Remove:
		body["action"] = "remove"
	case mfa.Replace:
		body["action"] = "replace"
	default:
		t.Fatal("unsupported fixture action")
	}
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/mfa/factor-update", strings.NewReader(string(wire)))
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
		t.Fatal("actual factor-update HTTP request failed")
	}
	defer response.Body.Close()
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("factor-update HTTP leaked credentials or cacheable metadata")
	}
	var payload struct {
		Outcome   string             `json:"commitOutcome"`
		CommandID identity.CommandID `json:"commandID"`
		Error     string             `json:"error"`
		Factor    struct {
			ID        mfa.FactorID    `json:"id"`
			Method    string          `json:"method"`
			Label     string          `json:"label"`
			State     mfa.FactorState `json:"state"`
			CreatedAt time.Time       `json:"createdAt"`
			Version   uint64          `json:"version"`
		} `json:"factor"`
		Replacement *struct {
			EnrollmentID  mfa.EnrollmentID `json:"enrollmentID"`
			FactorMethod  string           `json:"factorMethod"`
			ExpiresAt     time.Time        `json:"expiresAt"`
			Version       uint64           `json:"version"`
			RecoveryCodes []string         `json:"recoveryCodes"`
		} `json:"replacement"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil {
		t.Fatal("factor-update HTTP payload malformed")
	}
	if payload.Replacement != nil {
		defer clear(payload.Replacement.RecoveryCodes)
	}
	out := mfa.FactorUpdateResult{CommandID: payload.CommandID}
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
		t.Fatal("factor-update HTTP outcome malformed")
	}
	if response.StatusCode != 200 {
		if payload.Factor.ID != "" || payload.Replacement != nil {
			t.Fatal("failed HTTP update returned factor metadata")
		}
		return out, identity.UnavailableError{}
	}
	if payload.Error != "" || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("HTTP success did not conserve commitment")
	}
	out.Factor = mfa.FactorProjection{ID: payload.Factor.ID, Method: payload.Factor.Method, Label: payload.Factor.Label, State: payload.Factor.State, CreatedAt: payload.Factor.CreatedAt, Version: payload.Factor.Version}
	if payload.Replacement != nil {
		p := payload.Replacement
		if r.Action != mfa.Replace || len(p.RecoveryCodes) < 1 || len(p.RecoveryCodes) > 64 {
			t.Fatal("unexpected replacement delivery")
		}
		out.Replacement = &mfa.TOTPReplacementEnrollment{Enrollment: mfa.Enrollment{ID: p.EnrollmentID, FactorMethod: p.FactorMethod, ExpiresAt: p.ExpiresAt, Version: p.Version}}
		for _, raw := range p.RecoveryCodes {
			code, err := primitive.NewSecret([]byte(raw))
			if err != nil {
				t.Fatal("replacement recovery wire invalid")
			}
			out.Replacement.RecoveryMaterial.Codes = append(out.Replacement.RecoveryMaterial.Codes, code)
		}
	}
	return out, nil
}
