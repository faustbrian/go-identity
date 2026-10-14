//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferenceTOTPReplacementBeginsPendingWithoutDisablingPredecessor(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementRefreshesAuthorityWithoutRenewingCeremony(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorReplacementDelayed: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementHTTPFromFreshStepUpToNewFactorLogin(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementInitiationCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, completionCommitFault: true}, true)
}

func TestReferenceTOTPReplacementHTTPInitiationCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, completionCommitFault: true}, true)
}

func TestReferenceTOTPReplacementConfirmationRollback(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorReplacementRollback: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementHTTPConfirmationRollback(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, factorReplacementRollback: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementConfirmationCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorReplacementConfirmationFault: true, completionCommitFault: true}, true)
}

func TestReferenceTOTPReplacementHTTPConfirmationCommitRecovery(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, factorReplacementConfirmationFault: true, completionCommitFault: true}, true)
}

func TestReferenceTOTPReplacementCompetingInitiations(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorManagementRace: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementHTTPCompetingInitiations(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, factorManagementRace: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementCompetingConfirmations(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorReplacementConfirmationRace: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementHTTPCompetingConfirmations(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, factorReplacementConfirmationRace: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementOriginalAuthorityDenials(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorManagementDenials: true}, true)
}

func TestReferenceTOTPReplacementPreservesPredecessorLoginWhilePending(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorReplacementPredecessorUse: true, passwordMFA: true}, true)
}

func TestReferenceTOTPReplacementRecoveryCodesFollowActivation(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, factorReplacementRecovery: true, passwordRecovery: true}, true)
}

func TestReferenceTOTPReplacementFromMFAAuthenticatedSession(t *testing.T) {
	for _, method := range []string{"totp", "recovery-code"} {
		t.Run(method, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, passwordMFA: method == "totp", passwordRecovery: method == "recovery-code", replacementSourceMethod: method}, true)
		})
	}
}

func TestReferenceTOTPReplacementRejectsUnfinishableVersion(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, factorManagement: true, factorReplacement: true, replacementContinuationDenial: "begin-version-exhaustion"}, true)
}

func TestReferenceTOTPReplacementLastFinishableVersion(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: true, factorManagement: true, factorReplacement: true, factorManagementHTTP: true, passwordMFA: true, replacementContinuationDenial: "begin-last-finishable-version"}, true)
}

func TestReferenceTOTPReplacementContinuationDenials(t *testing.T) {
	for _, scenario := range []struct {
		name string
		http bool
	}{
		{"uri-revoked-session", false},
		{"uri-other-session", false},
		{"uri-changed-factor", false},
		{"uri-blocked-account", true},
		{"uri-expired-proof", false},
		{"confirmation-revoked-session", true},
		{"confirmation-other-session", true},
		{"confirmation-blocked-account", false},
		{"confirmation-changed-factor", false},
		{"confirmation-primary-unavailable", false},
		{"confirmation-primary-unavailable", true},
	} {
		name := scenario.name
		if scenario.http {
			name += "-http"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{mfaEnrollment: true, mfaListing: true, activeStepUp: true, activeStepUpHTTP: scenario.http, factorManagement: true, factorReplacement: true, factorManagementHTTP: scenario.http, replacementContinuationDenial: scenario.name}, true)
		})
	}
}

func proveReferenceFactorReplacementBegin(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, bearer, csrfWire, origin string, predecessor mfa.FactorID, predecessorSecret []byte, predecessorCodes []string, proof auth.ReauthenticationProof, client *http.Client, base, cookieName string) {
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
	source, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !source.Authenticated {
		t.Fatal("genuine replacement source session unavailable", err)
	}
	binding, _ := source.Session.Bindings()
	var authorityBefore int64
	if err := f.pool.Raw().QueryRow(ctx, `SELECT version::bigint FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(binding.UserID)).Scan(&authorityBefore); err != nil || authorityBefore <= 0 {
		t.Fatal("genuine predecessor authority unavailable", err)
	}
	query := mfa.ListRequest{TenantID: otpTenant, Credential: credential, CorrelationID: "replacement-before"}
	before, err := listing.List(ctx, query)
	wantRecovery := uint32(10)
	if f.replacementSourceMethod == "recovery-code" {
		wantRecovery = 9
	}
	if err != nil || len(before.Factors) != 1 || before.Factors[0].ID != predecessor || before.Factors[0].State != mfa.FactorActive || before.RecoveryCodeCount != wantRecovery {
		t.Fatal("genuine predecessor inventory unavailable", err)
	}
	csrf, _ := session.ParseCSRFToken(csrfWire)
	key, _ := identity.NewIdempotencyKey([]byte("native-totp-replacement-begin"))
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(binding.UserID)}, Action: "identity.mfa.factor-update", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	r := mfa.FactorUpdateRequest{TenantID: otpTenant, FactorID: predecessor, Action: mfa.Replace, ExpectedVersion: before.Factors[0].Version, FactorProof: proof.Proof, Session: auth.NewBearerCredential(bearer), CSRFToken: csrf, Caller: caller, Origin: origin, Network: "127.0.0.1", IdempotencyKey: key}
	if f.replacementContinuationDenial == "begin-last-finishable-version" && r.ExpectedVersion != ^uint64(0)-2 {
		t.Fatal("last-finishable fixture did not reach the original two-increment boundary")
	}
	if f.replacementContinuationDenial == "begin-version-exhaustion" {
		if r.ExpectedVersion != ^uint64(0)-1 {
			t.Fatal("near-exhaustion fixture did not reach the original pre-initiation boundary")
		}
		before := replacementProtectedSnapshot(t, ctx, f)
		out, err := management.FactorUpdate(ctx, r)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Replacement != nil || out.Factor.ID != "" {
			if out.Replacement != nil {
				for _, code := range out.Replacement.RecoveryMaterial.Codes {
					code.Destroy()
				}
			}
			t.Fatal("unfinishable replacement consumed authority or delivered a pending ceremony")
		}
		if after := replacementProtectedSnapshot(t, ctx, f); after != before {
			t.Fatal("unfinishable replacement changed protected proof/factor/session state", replacementChangedParts(before, after))
		}
		return
	}
	execute := func(r mfa.FactorUpdateRequest, wireKey string) (mfa.FactorUpdateResult, error) {
		if f.factorManagementHTTP {
			return invokeReferenceFactorUpdateHTTP(t, ctx, client, base, origin, bearer, csrfWire, cookieName, wireKey, r)
		}
		return management.FactorUpdate(ctx, r)
	}
	if r.Validate() != nil {
		t.Fatal("replacement did not reach native operation")
	}
	if f.factorManagementDenials {
		proveReferenceFactorRenameDenials(t, ctx, f, management, sessions, r)
		return
	}
	protected := replacementProtectedSnapshot(t, ctx, f)
	if f.replacementContinuationDenial == "" {
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.replacement_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic replacement rollback'; END $$; CREATE TRIGGER replacement_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.replacement_fixture_fail()`); err != nil {
			t.Fatal("replacement rollback fixture unavailable", err)
		}
		failed, failErr := execute(r, "native-totp-replacement-begin")
		if failErr == nil || failed.Outcome != identity.CommitOutcomeNotCommitted || failed.Factor.ID != "" || failed.Replacement != nil {
			t.Fatal("replacement rollback published pending authority or recovery custody", failed.Outcome, failErr)
		}
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER replacement_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION public.replacement_fixture_fail()`); err != nil {
			t.Fatal(err)
		}
		if after := replacementProtectedSnapshot(t, ctx, f); after != protected {
			t.Fatal("replacement rollback changed protected state", replacementChangedParts(protected, after))
		}
	}
	beginWireKey := "replacement-after-rollback"
	r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(beginWireKey))
	if f.completionFault != nil && !f.factorReplacementConfirmationFault {
		f.completionFault.armed.Store(true)
	}
	var out mfa.FactorUpdateResult
	if f.factorManagementRace {
		type attempt struct {
			request mfa.FactorUpdateRequest
			key     string
			result  mfa.FactorUpdateResult
			err     error
		}
		attempts := [2]attempt{{request: r, key: beginWireKey}, {request: r, key: "replacement-competing-begin"}}
		attempts[1].request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(attempts[1].key))
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := range attempts {
			workers.Go(func() {
				<-start
				attempts[i].result, attempts[i].err = execute(attempts[i].request, attempts[i].key)
			})
		}
		close(start)
		workers.Wait()
		for _, attempt := range attempts {
			if attempt.result.Replacement != nil {
				defer func() {
					for _, code := range attempt.result.Replacement.RecoveryMaterial.Codes {
						code.Destroy()
					}
					clear(attempt.result.Replacement.RecoveryMaterial.Codes)
				}()
			}
		}
		winners := 0
		for _, attempt := range attempts {
			if attempt.err == nil && attempt.result.Outcome == identity.CommitOutcomeCommitted {
				winners++
				r, beginWireKey, out, err = attempt.request, attempt.key, attempt.result, attempt.err
			} else {
				if attempt.result.Replacement != nil {
					for _, code := range attempt.result.Replacement.RecoveryMaterial.Codes {
						code.Destroy()
					}
				}
				if attempt.err == nil || attempt.result.Outcome == identity.CommitOutcomeCommitted || attempt.result.Factor.ID != "" || attempt.result.Replacement != nil {
					t.Fatal("competing replacement loser published commitment/custody", attempt.result.Outcome, attempt.err)
				}
			}
		}
		if winners != 1 {
			t.Fatal("competing replacement did not select exactly one original proof/version winner", winners)
		}
	} else {
		out, err = execute(r, beginWireKey)
	}
	if out.Replacement != nil {
		defer func() {
			for _, code := range out.Replacement.RecoveryMaterial.Codes {
				code.Destroy()
			}
			clear(out.Replacement.RecoveryMaterial.Codes)
		}()
	}
	if f.completionFault != nil && !f.factorReplacementConfirmationFault {
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.CommandID == "" || out.Replacement != nil || out.Factor.ID != "" || !f.completionFault.hit.Load() {
			t.Fatal("ambiguous replacement initiation disclosed fresh custody or lost uncertainty", out.Outcome, err)
		}
		query := identity.RecoveryQuery{TenantID: otpTenant, UserID: binding.UserID, ActorID: identity.ActorID(binding.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.factor-update", CommandID: out.CommandID}
		if recovered, err := management.RecoverFactorUpdate(ctx, query, caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Factor.ID != "" || recovered.Replacement != nil {
			t.Fatal("ambiguous replacement initiation did not recover its original outcome", recovered.Outcome, err)
		}
		r.CommandID = out.CommandID
		if replay, err := management.FactorUpdate(ctx, r); err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.CommandID != out.CommandID || replay.Factor.ID != "" || replay.Replacement != nil {
			t.Fatal("ambiguous replacement replay minted another successor/delivery", replay.Outcome, err)
		}
		if current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || !current.Authenticated {
			t.Fatal("ambiguous pending initiation revoked its original session", err)
		}
		command, _ := base64.RawURLEncoding.Strict().DecodeString(string(out.CommandID))
		var pending, effects, uses, lifecycle, audits int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND created_command_id=$3 AND state=1),
(SELECT count(*) FROM identity_mfa.factor_update_effects WHERE tenant_id=$1 AND user_id=$2 AND command_id=$3 AND action=3),
(SELECT count(*) FROM identity_mfa.factor_verifications WHERE tenant_id=$1 AND user_id=$2 AND used_command_id=$3),
(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3),
(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$3)`, otpTenant, string(binding.UserID), command).Scan(&pending, &effects, &uses, &lifecycle, &audits); err != nil || pending != 1 || effects != 1 || uses != 1 || lifecycle != 1 || audits != 1 {
			t.Fatal("ambiguous initiation did not conserve one pending child/proof/effect/audit/lifecycle", err)
		}
		return
	}
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CommandID == "" || out.Factor.ID == "" || out.Factor.ID == predecessor || out.Factor.State != mfa.FactorPending || out.Factor.Method != "totp" || out.Factor.Version != 1 {
		t.Fatal("public Replace did not begin a distinct pending successor", out.Outcome, err)
	}
	if out.Replacement == nil || string(out.Replacement.Enrollment.ID) != string(out.Factor.ID) || out.Replacement.Enrollment.Version != 1 || !time.Now().Before(out.Replacement.Enrollment.ExpiresAt) || len(out.Replacement.RecoveryMaterial.Codes) != 10 {
		t.Fatal("replacement omitted usable pending metadata or fresh recovery delivery")
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("replacement initiation stranded original URI/confirmation session", err)
	}
	query.CorrelationID = "replacement-after"
	after, err := listing.List(ctx, query)
	if err != nil || len(after.Factors) != 2 || after.RecoveryCodeCount != before.RecoveryCodeCount {
		t.Fatal("replacement initiation hid or retired predecessor recovery", err)
	}
	var old, next bool
	for _, factor := range after.Factors {
		old = old || factor.ID == predecessor && factor.State == mfa.FactorActive && factor.Version == before.Factors[0].Version+1
		next = next || factor.ID == out.Factor.ID && factor.State == mfa.FactorPending && factor.Version == 1
	}
	if !old || !next {
		t.Fatal("pending replacement became authoritative or lost predecessor")
	}
	var intact bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT state=2 AND encrypted_secret IS NOT NULL AND last_step IS NOT NULL FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(binding.UserID), string(predecessor)).Scan(&intact); err != nil || !intact {
		t.Fatal("replacement initiation erased active predecessor custody", err)
	}
	q := identity.RecoveryQuery{TenantID: otpTenant, UserID: binding.UserID, ActorID: identity.ActorID(binding.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.factor-update", CommandID: out.CommandID}
	if recovered, err := management.RecoverFactorUpdate(ctx, q, caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Factor.ID != "" || recovered.Replacement != nil {
		t.Fatal("replacement outcome recovery repeated mutation or secret delivery", recovered.Outcome, err)
	}
	r.CommandID = out.CommandID
	if replay, err := execute(r, beginWireKey); err != nil && !f.factorManagementHTTP || replay.Outcome != identity.CommitOutcomeCommitted || replay.CommandID != out.CommandID || replay.Factor.ID != "" || replay.Replacement != nil {
		t.Fatal("replacement keyed replay regenerated successor or recovery material", replay.Outcome, err)
	}
	uriOwner, err := features.MFAProvisioningURI()
	if err != nil {
		t.Fatal("selected replacement provisioning owner unavailable", err)
	}
	uriCaller := caller
	uriCaller.Request.Action = "identity.mfa.totp-uri"
	uriCommand, _ := identity.NewCommandID()
	uriRequest := mfa.TotpUriRequest{TenantID: otpTenant, CommandID: uriCommand, EnrollmentID: out.Replacement.Enrollment.ID, Session: r.Session, CSRFToken: csrf, Caller: uriCaller, Origin: origin, Network: r.Network}
	if f.replacementContinuationDenial == "uri-other-session" {
		uriRequest.Session = auth.NewBearerCredential(f.secondBearer)
		uriRequest.CSRFToken, _ = session.ParseCSRFToken(f.secondCSRF)
	}
	var predecessorLogin session.Credential
	var successorRecoveryCode string
	defer func() { successorRecoveryCode = "" }()
	if f.factorReplacementRecovery {
		if len(predecessorCodes) < 2 || out.Replacement.RecoveryMaterial.Codes[0].Use(func(raw []byte) error {
			successorRecoveryCode = string(raw)
			return nil
		}) != nil {
			t.Fatal("genuine replacement recovery custody unavailable")
		}
		proveReplacementRecoveryLogin(t, ctx, features, client, base, origin, successorRecoveryCode, false)
		predecessorLogin, _, _ = proveReplacementRecoveryLogin(t, ctx, features, client, base, origin, predecessorCodes[0], true)
	}
	if f.factorReplacementPredecessorUse {
		// The original step-up used the next admissible counter. Wait a genuine
		// period, not a rewritten DB timestamp, then use the preserved factor.
		timer := time.NewTimer(31 * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("predecessor-use fixture did not reach the next real TOTP period")
		}
		timer.Stop()
		// Velocity activation is immutable and has no in-place lease renewal.
		// Obtain new native covered custody after this actual long wait; do not
		// widen limits or reuse an expired positive admission to allow login.
		if _, err := f.stores.RecoverVelocity(ctx, otpTenant); err != nil {
			t.Fatal("native velocity recovery after predecessor wait failed", err)
		}
		predecessorLogin, _, _ = proveReplacementPasswordLogin(t, ctx, f, features, client, base, origin, predecessor, predecessorSecret)
		var advanced bool
		if err := f.pool.Raw().QueryRow(ctx, `SELECT row_version>$4::numeric AND state=2 AND encrypted_secret IS NOT NULL FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, otpTenant, string(binding.UserID), string(predecessor), before.Factors[0].Version+1).Scan(&advanced); err != nil || !advanced {
			t.Fatal("pending predecessor login did not advance genuine replay state", err)
		}
	}
	uriDenied := strings.HasPrefix(f.replacementContinuationDenial, "uri-")
	var uriBefore [10][32]byte
	if uriDenied {
		uriBefore = replacementProtectedSnapshot(t, ctx, f)
		release := invalidateReplacementContinuation(t, ctx, f, features, credential, csrf)
		defer release()
		if !strings.HasSuffix(f.replacementContinuationDenial, "primary-unavailable") {
			uriBefore = replacementProtectedSnapshot(t, ctx, f)
		}
	}
	if f.factorReplacementDelayed {
		// Actual time, not a rewritten stored timestamp: the parent's <=20-second
		// positive observation expires while its original proof/ceremony remains
		// live. The continuation must acquire new primary-authority evidence.
		timer := time.NewTimer(21 * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("delayed replacement fixture expired before continuation")
		}
		timer.Stop()
	}
	var uri mfa.TotpUriResult
	if f.factorManagementHTTP {
		uri, err = invokeReplacementURIHTTP(t, ctx, client, base, bearer, csrfWire, cookieName, uriRequest)
	} else {
		uri, err = uriOwner.TotpUri(ctx, uriRequest)
	}
	if uriDenied {
		if err == nil || uri.Outcome == identity.CommitOutcomeCommitted || uri.URI.URI != "" {
			t.Fatal("lost original authority admitted replacement URI/custody", f.replacementContinuationDenial, uri.Outcome, err)
		}
		if after := replacementProtectedSnapshot(t, ctx, f); after != uriBefore {
			t.Fatal("denied replacement URI changed protected state", replacementChangedParts(uriBefore, after))
		}
		return
	}
	if err != nil || uri.Outcome != identity.CommitOutcomeCommitted || uri.URI.URI == "" || uri.URI.EnrollmentID != out.Replacement.Enrollment.ID {
		t.Fatal("authentic replacement provenance did not allow pending URI reveal", uri.Outcome, err)
	}
	parsed, parseErr := url.Parse(uri.URI.URI)
	if parseErr != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Fatal("replacement URI did not contain usable provisioning material")
	}
	secret, decodeErr := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
	validSecret := decodeErr == nil && len(secret) == 32
	defer clear(secret)
	parsed = nil
	if !validSecret {
		t.Fatal("replacement URI did not contain a valid TOTP secret")
	}
	uri.URI = mfa.RevealOnceURI{}
	if replay, err := uriOwner.TotpUri(ctx, uriRequest); err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.URI.URI != "" {
		t.Fatal("replacement URI replay disclosed material again", replay.Outcome, err)
	}
	if current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || !current.Authenticated {
		t.Fatal("replacement URI reveal retired the original session before confirmation", err)
	}
	confirmation, err := features.MFAEnrollmentConfirmation()
	if err != nil {
		t.Fatal("selected replacement confirmation unavailable", err)
	}
	confirmCaller := caller
	confirmCaller.Request.Action = "identity.mfa.totp-verify"
	confirmCommand, _ := identity.NewCommandID()
	codeWire := passwordMFAFixtureCode(secret, time.Now())
	code, _ := auth.NewOneTimeCode(codeWire)
	confirmRequest := mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: confirmCommand, FactorID: out.Factor.ID, Code: code, Caller: confirmCaller, Origin: origin, Network: r.Network, Enrollment: &mfa.TOTPEnrollmentConfirmation{Session: r.Session, CSRFToken: csrf}}
	confirmationBearer, confirmationCSRF := bearer, csrfWire
	if f.replacementContinuationDenial == "confirmation-other-session" {
		confirmationBearer, confirmationCSRF = f.secondBearer, f.secondCSRF
		confirmRequest.Enrollment.Session = auth.NewBearerCredential(confirmationBearer)
		confirmRequest.Enrollment.CSRFToken, _ = session.ParseCSRFToken(confirmationCSRF)
	}
	executeConfirmation := func(request mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
		if f.factorManagementHTTP {
			return invokeReplacementConfirmationHTTP(t, ctx, client, base, confirmationBearer, confirmationCSRF, cookieName, request, codeWire)
		}
		return confirmation.TotpVerify(ctx, request)
	}
	if strings.HasPrefix(f.replacementContinuationDenial, "confirmation-") {
		before := replacementProtectedSnapshot(t, ctx, f)
		release := invalidateReplacementContinuation(t, ctx, f, features, credential, csrf)
		defer release()
		if !strings.HasSuffix(f.replacementContinuationDenial, "primary-unavailable") {
			before = replacementProtectedSnapshot(t, ctx, f)
		}
		denied, err := executeConfirmation(confirmRequest)
		release()
		if err == nil || denied.Outcome == identity.CommitOutcomeCommitted || denied.Enrollment.ID != "" || denied.Session.Token != (session.Token{}) || denied.StepUpProof.Bindings().Proof.ID != "" {
			t.Fatal("lost original authority admitted replacement activation/authentication", f.replacementContinuationDenial, denied.Outcome, err)
		}
		if after := replacementProtectedSnapshot(t, ctx, f); after != before {
			t.Fatal("denied confirmation changed protected state", replacementChangedParts(before, after))
		}
		return
	}
	if f.factorReplacementRollback {
		before := replacementProtectedSnapshot(t, ctx, f)
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.replacement_confirmation_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic confirmation rollback'; END $$; CREATE TRIGGER replacement_confirmation_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.replacement_confirmation_fail()`); err != nil {
			t.Fatal("confirmation rollback fixture unavailable", err)
		}
		failed, err := executeConfirmation(confirmRequest)
		if err == nil || failed.Outcome != identity.CommitOutcomeNotCommitted || failed.Enrollment.ID != "" || failed.Session.Token != (session.Token{}) {
			t.Fatal("failed confirmation published activation or authentication", failed.Outcome, err)
		}
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER replacement_confirmation_fail ON public.identity_outbox_bindings; DROP FUNCTION public.replacement_confirmation_fail()`); err != nil {
			t.Fatal(err)
		}
		if after := replacementProtectedSnapshot(t, ctx, f); after != before {
			t.Fatal("confirmation rollback changed protected state", replacementChangedParts(before, after))
		}
		if current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || !current.Authenticated {
			t.Fatal("confirmation rollback stranded the original ceremony session", err)
		}
		confirmCommand, _ = identity.NewCommandID()
		confirmRequest.CommandID = confirmCommand
	}
	if f.factorReplacementConfirmationFault {
		f.completionFault.armed.Store(true)
	}
	var activated mfa.TotpVerifyResult
	if f.factorReplacementConfirmationRace {
		type attempt struct {
			request mfa.TotpVerifyRequest
			result  mfa.TotpVerifyResult
			err     error
		}
		attempts := [2]attempt{{request: confirmRequest}, {request: confirmRequest}}
		attempts[1].request.CommandID, _ = identity.NewCommandID()
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := range attempts {
			workers.Go(func() {
				<-start
				attempts[i].result, attempts[i].err = executeConfirmation(attempts[i].request)
			})
		}
		close(start)
		workers.Wait()
		winners := 0
		for _, attempt := range attempts {
			if attempt.err == nil && attempt.result.Outcome == identity.CommitOutcomeCommitted {
				winners++
				confirmRequest, activated, err = attempt.request, attempt.result, attempt.err
				confirmCommand = confirmRequest.CommandID
			} else if attempt.err == nil || attempt.result.Outcome == identity.CommitOutcomeCommitted || attempt.result.Enrollment.ID != "" || attempt.result.Session.Token != (session.Token{}) || attempt.result.StepUpProof.Bindings().Proof.ID != "" {
				t.Fatal("competing confirmation loser published activation/authentication", attempt.result.Outcome, attempt.err)
			}
		}
		if winners != 1 {
			t.Fatal("competing confirmation did not select exactly one successor activation", winners)
		}
	} else {
		activated, err = executeConfirmation(confirmRequest)
	}
	if f.factorReplacementConfirmationFault {
		if err == nil || activated.Outcome != identity.CommitOutcomeUnknown || activated.Enrollment.ID != "" || activated.Session.Token != (session.Token{}) || activated.StepUpProof.Bindings().Proof.ID != "" || !f.completionFault.hit.Load() {
			t.Fatal("ambiguous confirmation lost uncertainty or returned fresh custody", activated.Outcome, err)
		}
	} else if err != nil || activated.Outcome != identity.CommitOutcomeCommitted || activated.Enrollment.ID != out.Replacement.Enrollment.ID || activated.Enrollment.Version != 3 || activated.Session.Token != (session.Token{}) || activated.StepUpProof.Bindings().Proof.ID != "" {
		t.Fatal("replacement confirmation did not atomically activate the successor", activated.Outcome, err)
	}
	if current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential}); err != nil || current.Authenticated {
		t.Fatal("replacement confirmation left the source session authenticated", err)
	}
	if predecessorLogin != (session.Credential{}) {
		if current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: predecessorLogin}); err != nil || current.Authenticated {
			t.Fatal("replacement confirmation left the genuine pending-predecessor login authenticated", err)
		}
	}
	var retired, active bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT p.state=3 AND p.encrypted_secret IS NULL AND p.last_step IS NULL AND ps.state=3,n.state=2 AND n.confirmed_at IS NOT NULL AND ns.state=2 AND a.active_factors=1 AND a.version=$5::numeric FROM identity_mfa.totp_factors p JOIN identity_mfa.recovery_sets ps ON ps.tenant_id=p.tenant_id AND ps.user_id=p.user_id AND ps.factor_id=p.factor_id JOIN identity_mfa.totp_factors n ON n.tenant_id=p.tenant_id AND n.user_id=p.user_id JOIN identity_mfa.recovery_sets ns ON ns.tenant_id=n.tenant_id AND ns.user_id=n.user_id AND ns.factor_id=n.factor_id JOIN identity_mfa.factor_authorities a ON a.tenant_id=n.tenant_id AND a.user_id=n.user_id WHERE p.tenant_id=$1 AND p.user_id=$2 AND p.factor_id=$3 AND n.factor_id=$4`, otpTenant, string(binding.UserID), string(predecessor), string(out.Factor.ID), authorityBefore+1).Scan(&retired, &active); err != nil || !retired || !active {
		t.Fatal("replacement did not retire predecessor/recovery and advance authority together", err)
	}
	confirmQuery := q
	confirmQuery.CommandID, confirmQuery.OperationID = confirmCommand, "identity.mfa.totp-verify"
	confirmQuery.RecordID = string(out.Factor.ID)
	if recovered, err := confirmation.RecoverTotpVerify(ctx, confirmQuery, confirmCaller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Enrollment.ID != "" || recovered.Session.Token != (session.Token{}) {
		t.Fatal("replacement activation outcome recovery failed or returned fresh custody", recovered.Outcome, err)
	}
	if replay, err := confirmation.TotpVerify(ctx, confirmRequest); err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.Session.Token != (session.Token{}) {
		t.Fatal("replacement activation replay repeated authority or session delivery", replay.Outcome, err)
	}
	if f.factorReplacementRecovery {
		proveReplacementRecoveryLogin(t, ctx, features, client, base, origin, successorRecoveryCode, true, predecessorCodes[1])
	}
	if f.replacementSourceMethod == "recovery-code" {
		if out.Replacement.RecoveryMaterial.Codes[0].Use(func(raw []byte) error {
			successorRecoveryCode = string(raw)
			return nil
		}) != nil {
			t.Fatal("fresh MFA-origin successor recovery custody unavailable")
		}
		proveReplacementRecoveryLogin(t, ctx, features, client, base, origin, successorRecoveryCode, true)
	} else if !f.factorReplacementDelayed && !f.factorReplacementConfirmationFault && !f.factorReplacementPredecessorUse && !f.factorReplacementRecovery {
		proveReplacementPasswordLogin(t, ctx, f, features, client, base, origin, out.Factor.ID, secret)
	}
}

// Exercise only the replacement's set transition through actual password/
// recovery HTTP. The unchanged recovery suite owns its rollback/replay matrix.
func proveReplacementRecoveryLogin(t *testing.T, ctx context.Context, features reference.FeatureSet, client *http.Client, base, origin, code string, allowed bool, retired ...string) (session.Credential, string, string) {
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
			t.Fatal("replacement recovery HTTP unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("replacement recovery response invalid")
		}
		return response, data
	}
	response, data := invoke("/v1/session/preauth-issue", map[string]string{"method": "password"}, nil)
	var flow sessionhttp.PreAuthResponse
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &flow) != nil || !flow.Issued {
		clear(data)
		t.Fatal("replacement recovery flow unavailable", response.StatusCode)
	}
	clear(data)
	cookies := response.Cookies()
	response, data = invoke("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, cookies)
	var challenge passwordhttp.SigninResponse
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &challenge) != nil || !challenge.ChallengeRequired || challenge.SignedIn || response.Header.Get("X-MFA-Token") == "" || len(response.Cookies()) != 0 {
		clear(data)
		t.Fatal("replacement recovery primary unavailable", response.StatusCode)
	}
	clear(data)
	command, _ := identity.NewCommandID()
	body := map[string]any{"commandID": command, "preAuthID": flow.FlowID, "continuationID": challenge.ChallengeID, "token": response.Header.Get("X-MFA-Token"), "recoveryCode": code, "callbackURL": origin + "/reset"}
	defer func() { delete(body, "token"); delete(body, "recoveryCode") }()
	assertDenied := func(response *http.Response, data []byte) {
		defer clear(data)
		var denied struct{ SignedIn bool }
		if response.StatusCode != http.StatusForbidden || json.Unmarshal(data, &denied) != nil || denied.SignedIn || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("pending or retired recovery code authenticated", response.StatusCode)
		}
	}
	if len(retired) > 0 {
		body["recoveryCode"] = retired[0]
		response, data = invoke("/v1/mfa/recovery-use", body, cookies)
		assertDenied(response, data)
		body["commandID"], _ = identity.NewCommandID()
		body["recoveryCode"] = code
	}
	response, data = invoke("/v1/mfa/recovery-use", body, cookies)
	if !allowed {
		assertDenied(response, data)
		return session.Credential{}, "", ""
	}
	defer clear(data)
	var completed struct {
		SignedIn      bool
		CommitOutcome string
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &completed) != nil || !completed.SignedIn || completed.CommitOutcome != "committed" || len(response.Cookies()) != 1 || response.Header.Get("X-CSRF-Token") == "" {
		t.Fatal("current replacement recovery code did not authenticate", response.StatusCode)
	}
	token, err := session.ParseToken(response.Cookies()[0].Value)
	if err != nil {
		t.Fatal("replacement recovery session malformed")
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	bound, factorErr := current.Session.MFAAuthentication().Bindings()
	if err != nil || !current.Authenticated || factorErr != nil || bound.Method != "recovery-code" {
		t.Fatal("replacement recovery session lacks current factor authority", err)
	}
	return credential, response.Cookies()[0].Value, response.Header.Get("X-CSRF-Token")
}

func invalidateReplacementContinuation(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, credential session.Credential, csrf session.CSRFToken) func() {
	t.Helper()
	_, reason, ok := strings.Cut(f.replacementContinuationDenial, "-")
	if !ok {
		t.Fatal("invalid continuation denial fixture")
	}
	var held []interface{ Release() }
	release := func() {
		for _, connection := range held {
			connection.Release()
		}
		held = nil
	}
	t.Cleanup(release)
	if reason == "primary-unavailable" {
		// Exhaust only this fixture's native pool. Previously successful URI
		// custody cannot become a stale fallback when bounded primary IO fails.
		for range int(f.pool.Raw().Config().MaxConns) {
			connection, err := f.pool.Raw().Acquire(ctx)
			if err != nil {
				release()
				t.Fatal("owned primary-unavailability fixture failed")
			}
			held = append(held, connection)
		}
		return release
	}
	if reason == "expired-proof" {
		timer := time.NewTimer(11 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("absolute proof expiry fixture did not reach its real deadline")
		}
		return release
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("continuation authority-loss fixture lacks an original live session")
	}
	binding, _ := current.Session.Bindings()
	switch reason {
	case "other-session":
		token, err := session.ParseToken(f.secondBearer)
		if err != nil {
			t.Fatal("substituted original-session fixture unavailable")
		}
		otherCredential, _ := session.NewCredential(session.CredentialCookie, token)
		other, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: otherCredential})
		otherBinding, bindingErr := other.Session.Bindings()
		if err != nil || !other.Authenticated || bindingErr != nil || otherBinding.UserID != binding.UserID || otherBinding.SessionID == binding.SessionID {
			t.Fatal("replacement substitute is not a distinct genuine same-user live session")
		}
	case "revoked-session":
		command, _ := identity.NewCommandID()
		out, err := sessions.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, CommandID: command, CorrelationID: string(command), Transport: session.CredentialCookie, Credential: credential}, csrf)
		if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("public source-session revocation did not commit", err)
		}
	case "changed-factor":
		tag, err := f.pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, otpTenant, string(binding.UserID))
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("owned factor authority loss fixture failed")
		}
	case "blocked-account":
		tag, err := f.pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, otpTenant, string(binding.UserID))
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("owned account block fixture failed")
		}
	default:
		t.Fatal("unsupported continuation denial fixture")
	}
	return release
}

func replacementProtectedSnapshot(t *testing.T, ctx context.Context, f liveStores) [10][32]byte {
	t.Helper()
	var wire string
	// Failed-command audit remains durable by design. Rollback must conserve
	// successful protected effects, not erase the record of the failed attempt.
	if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_array(
(SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,version,active_factors) ORDER BY tenant_id,user_id) FROM identity_mfa.factor_authorities),
(SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,label,state,row_version,last_step,encode(sha256(encrypted_secret),'hex'),confirmed_at,reveal_consumed,reveal_command_id,activation_command_id,activation_before_version,activation_authority_before,replaces_factor_id,replaces_version) ORDER BY tenant_id,user_id,factor_id) FROM identity_mfa.totp_factors),
(SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,factor_id,set_id,state,row_version,code_count,key_version) ORDER BY tenant_id,user_id,set_id) FROM identity_mfa.recovery_sets),
(SELECT jsonb_agg(jsonb_build_array(tenant_id,set_id,code_index,consumed_command_id,consumed_purpose,consumed_at) ORDER BY tenant_id,set_id,code_index) FROM identity_mfa.recovery_codes),
(SELECT jsonb_agg(jsonb_build_array(proof_id,used_command_id,used_purpose,used_at) ORDER BY proof_id) FROM identity_mfa.factor_verifications),
(SELECT count(*) FROM identity_mfa.factor_update_effects),
(SELECT jsonb_agg(jsonb_build_array(tenant_id,user_id,session_id,state,version) ORDER BY tenant_id,user_id,session_id) FROM session_store.sessions),
(SELECT count(*) FROM session_store.mfa_recovery_dispositions),
(SELECT count(*) FROM public.identity_outbox_bindings b JOIN identity.commands c USING(command_id) WHERE c.purpose IN('identity.mfa.factor-update','identity.mfa.totp-uri','identity.mfa.totp-verify')),
(SELECT count(*) FROM audit.identity_command_bindings b JOIN identity.commands c USING(command_id) JOIN audit.records r ON r.record_id=b.event_id WHERE c.purpose IN('identity.mfa.factor-update','identity.mfa.totp-uri','identity.mfa.totp-verify') AND r.outcome=$1)
)::text`, int64(audit.OutcomeSucceeded)).Scan(&wire); err != nil {
		t.Fatal("protected replacement snapshot unavailable", err)
	}
	var parts []json.RawMessage
	if err := json.Unmarshal([]byte(wire), &parts); err != nil || len(parts) != 10 {
		t.Fatal("protected replacement snapshot shape unavailable")
	}
	var result [10][32]byte
	for i, part := range parts {
		result[i] = sha256.Sum256(part)
	}
	return result
}

func replacementChangedParts(before, after [10][32]byte) []string {
	names := [...]string{"factor authority", "factors", "recovery sets", "recovery codes", "factor proofs", "update effects", "sessions", "session dispositions", "lifecycle", "audit"}
	var changed []string
	for i := range before {
		if before[i] != after[i] {
			changed = append(changed, names[i])
		}
	}
	return changed
}

func replacementHTTPResponse(t *testing.T, ctx context.Context, client *http.Client, base, path, bearer, csrf, cookieName, origin string, body any, variant string) (*http.Response, []byte) {
	t.Helper()
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
	r.Header.Set("X-CSRF-Token", csrf)
	if variant != "" {
		r.Header.Set("X-MFA-Variant", variant)
	}
	r.AddCookie(&http.Cookie{Name: cookieName, Value: bearer})
	response, err := client.Do(r)
	if err != nil {
		t.Fatal("replacement ceremony transport unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 8193))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || len(data) > 8192 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Pragma") != "no-cache" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("X-CSRF-Token") != "" {
		t.Fatal("replacement ceremony response unbounded/cacheable or issued a session")
	}
	return response, data
}

func invokeReplacementURIHTTP(t *testing.T, ctx context.Context, client *http.Client, base, bearer, csrf, cookieName string, r mfa.TotpUriRequest) (mfa.TotpUriResult, error) {
	t.Helper()
	response, data := replacementHTTPResponse(t, ctx, client, base, "/v1/mfa/totp-uri", bearer, csrf, cookieName, r.Origin, map[string]any{"commandID": r.CommandID, "enrollmentID": r.EnrollmentID}, "")
	defer clear(data)
	var payload struct {
		URI           string
		EnrollmentID  mfa.EnrollmentID
		CommitOutcome string
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal("replacement URI payload malformed")
	}
	if response.StatusCode != http.StatusOK || payload.CommitOutcome != "committed" || payload.URI == "" || payload.EnrollmentID != r.EnrollmentID {
		return mfa.TotpUriResult{}, identity.UnavailableError{}
	}
	return mfa.TotpUriResult{Outcome: identity.CommitOutcomeCommitted, URI: mfa.RevealOnceURI{URI: payload.URI, EnrollmentID: payload.EnrollmentID}}, nil
}

func invokeReplacementConfirmationHTTP(t *testing.T, ctx context.Context, client *http.Client, base, bearer, csrf, cookieName string, r mfa.TotpVerifyRequest, code string) (mfa.TotpVerifyResult, error) {
	t.Helper()
	body := map[string]any{"commandID": r.CommandID, "factorID": r.FactorID, "code": code}
	response, data := replacementHTTPResponse(t, ctx, client, base, "/v1/mfa/totp-verify", bearer, csrf, cookieName, r.Origin, body, "enrollment")
	delete(body, "code")
	code = ""
	defer clear(data)
	var payload struct {
		Activated     bool
		FactorID      mfa.FactorID
		Version       uint64
		CommitOutcome string
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal("replacement confirmation payload malformed")
	}
	out := mfa.TotpVerifyResult{}
	switch payload.CommitOutcome {
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
		t.Fatal("confirmation outcome malformed")
	}
	if response.StatusCode != http.StatusOK {
		if payload.Activated || payload.FactorID != "" || payload.Version != 0 {
			t.Fatal("failed confirmation disclosed activation")
		}
		return out, identity.UnavailableError{}
	}
	if !payload.Activated || payload.FactorID != r.FactorID || payload.CommitOutcome != "committed" {
		t.Fatal("confirmation success lost its original scope")
	}
	return mfa.TotpVerifyResult{Outcome: identity.CommitOutcomeCommitted, Enrollment: mfa.Enrollment{ID: mfa.EnrollmentID(payload.FactorID), FactorMethod: "totp", Version: payload.Version}}, nil
}

// The password-login baseline already covers its own foreign-cookie, wrong-code,
// rollback and lost-ack cases. This slice proves the new authoritative factor
// actually composes with that unchanged login owner, not a second baseline run.
func proveReplacementPasswordLogin(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, client *http.Client, base, origin string, factor mfa.FactorID, secret []byte) (session.Credential, string, string) {
	t.Helper()
	invoke := func(path string, body any, cookies []*http.Cookie, variant string) (*http.Response, []byte) {
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
		if variant != "" {
			r.Header.Set("X-MFA-Variant", variant)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("replacement-factor login transport unavailable")
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("replacement-factor login response invalid")
		}
		return response, data
	}
	response, data := invoke("/v1/session/preauth-issue", map[string]string{"method": "password"}, nil, "")
	var flow sessionhttp.PreAuthResponse
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &flow) != nil || !flow.Issued {
		t.Fatal("new-factor login preauthentication unavailable", response.StatusCode)
	}
	clear(data)
	cookies := response.Cookies()
	var challengeToken string
	var challenge passwordhttp.SigninResponse
	response, data = invoke("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": "registered@example.invalid", "password": "synthetic-registration-password", "callbackURL": origin + "/reset"}, cookies, "")
	challengeDecodeErr := json.Unmarshal(data, &challenge)
	if response.StatusCode != http.StatusOK || challengeDecodeErr != nil || !challenge.ChallengeRequired || challenge.SignedIn || len(response.Cookies()) != 0 || response.Header.Get("X-MFA-Token") == "" {
		t.Fatal("replacement-factor password primary did not require MFA", response.StatusCode, challenge.CommitOutcome, challenge.Error, "has-command", challenge.CommandID != "", "decoded", challengeDecodeErr == nil)
	}
	clear(data)
	challengeToken = response.Header.Get("X-MFA-Token")
	command, _ := identity.NewCommandID()
	body := map[string]any{"commandID": command, "preAuthID": flow.FlowID, "challengeID": challenge.ChallengeID, "factorID": factor, "token": challengeToken, "code": passwordMFAFixtureCode(secret, time.Now().Add(30*time.Second)), "callbackURL": origin + "/reset", "trustDevice": false}
	owner, ownerErr := features.PasswordTOTP()
	source, ok := owner.(interface {
		TotpVerificationRateSource(context.Context, mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error)
	})
	if ownerErr != nil || !ok {
		t.Fatal("new-factor native login owner unavailable", ownerErr)
	}
	proof, parseErr := capability.ParseProof(challengeToken, capability.DefaultLimits())
	challengeToken = ""
	if parseErr != nil {
		t.Fatal("new-factor password challenge malformed")
	}
	code, _ := auth.NewOneTimeCode(body["code"].(string))
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.mfa.totp-verify", Resource: authorization.Resource{Type: "identity.mfa-continuation", ID: authorization.ResourceID(challenge.ChallengeID)}}}
	request := mfa.TotpVerifyRequest{TenantID: otpTenant, CommandID: command, ChallengeID: mfa.ChallengeID(challenge.ChallengeID), FactorID: factor, PreAuthID: flow.FlowID, Proof: proof, Code: code, Cookie: auth.NewBearerCredential(cookies[0].Value), Caller: caller, Origin: origin, Callback: origin + "/reset", Network: "127.0.0.1"}
	if _, _, _, err := source.TotpVerificationRateSource(ctx, request); err != nil {
		t.Fatal("replacement-factor login original primary/browser authority denied before factor comparison", err)
	}
	response, data = invoke("/v1/mfa/totp-verify", body, cookies, "password")
	delete(body, "token")
	delete(body, "code")
	defer clear(data)
	var result struct {
		SignedIn      bool
		CommitOutcome string
		Error         string
	}
	decodeErr := json.Unmarshal(data, &result)
	if response.StatusCode != http.StatusOK || decodeErr != nil || !result.SignedIn || result.CommitOutcome != "committed" || len(response.Cookies()) != 1 || response.Header.Get("X-CSRF-Token") == "" {
		var remaining, maximum int32
		var counter string
		attemptErr := f.pool.Raw().QueryRow(ctx, `SELECT attempts_remaining,max_attempts FROM identity_mfa.continuations WHERE tenant_id=$1 AND continuation_id=$2`, otpTenant, string(challenge.ChallengeID)).Scan(&remaining, &maximum)
		counterErr := f.pool.Raw().QueryRow(ctx, `SELECT COALESCE(max(value),0)::text FROM risk_store.counter_windows WHERE tenant_id=$1 AND operation='identity.mfa.totp-verify'`, otpTenant).Scan(&counter)
		t.Fatal("replacement TOTP did not produce a genuine login", response.StatusCode, result.CommitOutcome, result.Error, "attempts", remaining, maximum, "counter", counter, "read errors", attemptErr, counterErr)
	}
	token, _ := session.ParseToken(response.Cookies()[0].Value)
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	binding, factorErr := current.Session.MFAAuthentication().Bindings()
	if err != nil || !current.Authenticated || factorErr != nil || binding.FactorID != string(factor) {
		t.Fatal("new-factor login is not backed by current successor authority", err)
	}
	return credential, response.Cookies()[0].Value, response.Header.Get("X-CSRF-Token")
}
