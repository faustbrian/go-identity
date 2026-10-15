//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// This public enrollment call uses actual native primary, kernel, protected
// risk SQL, encrypted pending/recovery stores, audit and lifecycle participants.
// The status-provider boundary is deterministic; it cannot substitute for any
// current account/session/factor authority or protected counter reservation.
func testPublicTOTPEnrollment(t *testing.T, ctx context.Context, pool *database.Pool, sourceConfig passworddb.ReauthenticationConfig, source *passworddb.ReauthenticationService, verification passworddb.ReauthenticationRequest, original session.Session, keys *keyring.Provider, primary *passworddb.MFAEnablePrimarySource, csrf session.CSRFToken, csrfKey session.CSRFKey, otpConfirmation string) {
	t.Helper()
	base := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialReplacementMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}, Version: 13, GlobalAuthorityID: "reauth-deployment", TenantIDs: []identity.TenantID{verification.TenantID}}
	var history migrations.Source = kernel.RequestKeyMigrationSource{Base: base, Version: 14}
	history = kernel.RequestKeyPreparationMigrationSource{Base: history, Version: 15}
	history = kernel.PreparationMigrationSource{Base: history, Version: 16}
	history = kernel.AdmissionPreparationMigrationSource{Base: history, Version: 17}
	history = kernel.CounterPreparationMigrationSource{Base: history, Version: 18}
	items, err := history.Load(ctx)
	if err != nil {
		t.Fatal("owned enrollment kernel history rejected")
	}
	for _, item := range items {
		if item.Version() > 13 {
			if _, err := pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
				t.Fatal("owned enrollment kernel install failed", err)
			}
		}
	}
	recoveryHistory, err := (mfapg.RecoveryMigrationSource{Base: mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}).Load(ctx)
	if err != nil {
		t.Fatal("owned recovery history rejected")
	}
	if _, err := pool.Raw().Exec(ctx, recoveryHistory[len(recoveryHistory)-1].UpSQL()); err != nil {
		t.Fatal("owned recovery install failed", err)
	}
	uriHistory, err := (mfapg.URIRevealMigrationSource{Base: mfapg.RecoveryMigrationSource{Base: mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal("owned URI history rejected", err)
	}
	if _, err := pool.Raw().Exec(ctx, uriHistory[len(uriHistory)-1].UpSQL()); err != nil {
		t.Fatal("owned URI install failed", err)
	}
	activationHistory, err := (mfapg.TOTPActivationMigrationSource{Base: mfapg.URIRevealMigrationSource{Base: mfapg.RecoveryMigrationSource{Base: mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}, Version: 6}).Load(ctx)
	if err != nil {
		t.Fatal("owned activation history rejected", err)
	}
	if _, err = pool.Raw().Exec(ctx, activationHistory[len(activationHistory)-1].UpSQL()); err != nil {
		t.Fatal("owned activation install failed", err)
	}
	riskHistory, err := (riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "mfa_enrollment_risk", Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal("owned protected risk history rejected")
	}
	for _, item := range riskHistory {
		if _, err := pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
			t.Fatal("owned protected risk install failed", err)
		}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}})
	if err != nil {
		t.Fatal("fixture risk policy rejected")
	}
	counterKey, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{77}, 32))
	outside := &reauthenticationRiskFixture{onCharge: func() { t.Error("protected enrollment dispatched a nontransactional counter") }}
	counted, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{counterKey}, Clock: time.Now, Timeout: time.Second, Store: outside})
	if err != nil {
		t.Fatal(err)
	}
	var beforeProvider func(context.Context)
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: time.Second, Counters: &counted, Sources: []risk.Source{{Name: "status", Version: "fixture-v1", Timeout: time.Second, Read: func(ctx context.Context, c risk.Context) (risk.Signal, error) {
		if beforeProvider != nil {
			beforeProvider(ctx)
		}
		return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(20 * time.Second)}, nil
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{78}, 32), bytes.Repeat([]byte{79}, 32))
	lookup, err := kernel.NewRequestKeyConfig("mfa-enrollment-test", [32]byte{83}, *sourceConfig.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mfapg.NewTOTPEnrollmentConfig(lookup, [32]byte{84}, [32]byte{85}, 1, "totp-v1")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConfigurationID, cfg.PolicyID, cfg.MaximumDuration, cfg.TTL, cfg.Primary = "mfa-enrollment-test", "identity-mfa", 3*time.Second, 5*time.Minute, primary
	cfg.Profile = mfa.TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, AllowedSkewSteps: 1, Issuer: "Example"}
	cfg.Coordinator = sourceConfig.Coordinator
	cfg.Risk = risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "mfa-enrollment-risk-v1", Keys: []risk.EvidenceKey{evidence}}
	cfg.Counters = riskpg.Config{Schema: "mfa_enrollment_risk", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"test": bytes.Repeat([]byte{86}, 32)}, CurrentEnvelopeKey: "test", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{counterKey}}, EnforceLockouts: true}
	service, err := mfapg.NewTOTPEnrollmentService(pool, cfg, keys)
	if err != nil {
		t.Fatalf("public native enrollment composition rejected: %T", err)
	}
	issued, err := source.Verify(ctx, verification)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh enrollment-specific primary proof unavailable")
	}
	spec, _ := original.Bindings()
	// The pre-existing-account fixture previously populated only password's
	// private login identity. Explicitly reconcile the directory's verified
	// primary email before exercising URI labeling; absence must remain a denial,
	// not a fallback to a caller-supplied account label. This is bootstrap fixture
	// evidence, not public signup/email-verification acceptance.
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,'mfa-fixture-email','email','mfa@example.test',true,true,1,2,1,clock_timestamp())`, string(verification.TenantID), string(spec.UserID)); err != nil {
		t.Fatal("fixture verified directory identifier unavailable", err)
	}
	caller := verification.Caller.Clone()
	caller.PolicyRevision = 9
	caller.Request.Tenant, caller.Request.Action = authorization.TenantID(verification.TenantID), "identity.mfa.enable"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}
	key, _ := identity.NewIdempotencyKey([]byte("public-totp-enrollment"))
	r := mfa.EnableRequest{TenantID: verification.TenantID, PrimaryProof: spec.Authentication.Proof, Reauthentication: issued.Proof, Session: verification.Session, IdempotencyKey: key, Caller: caller, Network: "192.0.2.1", FactorPolicy: mfa.FactorPolicy{Method: "totp", RecoveryCodes: 10}}
	probeID, _ := identity.NewCommandID()
	probeFactor, _ := identity.NewCommandID()
	if _, err := primary.PrepareEnrollment(ctx, r, probeID, mfa.FactorID(probeFactor)); err != nil {
		t.Fatalf("public source admission rejected before keyed execution: %T", err)
	}
	cookieEnable, err := passworddb.NewCookieMFAEnablePrimarySource(primary, []session.CSRFKey{csrfKey})
	if err != nil {
		t.Fatal("cookie enrollment source unavailable")
	}
	r.CSRFToken = csrf
	if _, err := primary.PrepareEnrollment(ctx, r, probeID, mfa.FactorID(probeFactor)); err == nil {
		t.Fatal("cookie enrollment fell back to bearer-only source")
	}
	cookieCustody, err := cookieEnable.PrepareEnrollment(ctx, r, probeID, mfa.FactorID(probeFactor))
	if err != nil {
		t.Fatal("exact cookie enrollment custody denied")
	}
	cookieSnapshot, err := cookieCustody.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(cookieSnapshot)
	withoutCSRF := r
	withoutCSRF.CSRFToken = session.CSRFToken{}
	if _, err := cookieEnable.RestoreEnrollment(ctx, withoutCSRF, probeID, mfa.FactorID(probeFactor), cookieSnapshot); err == nil {
		t.Fatal("cookie snapshot restored as bearer enrollment")
	}
	cfg.Primary = cookieEnable
	t.Run("public-otp-enrollment", func(t *testing.T) {
		testPublicOTPEnrollment(t, ctx, pool, source, verification, original, keys, cfg, r, &beforeProvider, sourceConfig, otpConfirmation)
	})
	if otpConfirmation != "" {
		return
	}
	service, err = mfapg.NewTOTPEnrollmentService(pool, cfg, keys)
	if err != nil {
		t.Fatal(err)
	}
	wrongCSRF, _ := session.NewCSRFToken()
	invalidCookie := r
	invalidCookie.CSRFToken = wrongCSRF
	invalidCookie.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("wrong-cookie-enrollment"))
	if denied, err := service.Enable(ctx, invalidCookie); err == nil || len(denied.RecoveryMaterial.Codes) != 0 {
		t.Fatal("invalid enrollment synchronizer admitted")
	}
	result, err := service.Enable(ctx, r)
	defer func() {
		for _, code := range result.RecoveryMaterial.Codes {
			code.Destroy()
		}
	}()
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.CommandID == "" || result.Enrollment.ID == "" || len(result.RecoveryMaterial.Codes) != 10 {
		t.Fatalf("public enable did not complete pending factor/recovery creation: outcome=%d error=%T", result.Outcome, err)
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(result.CommandID))
	var pending int16
	var active int32
	var codes, charges int64
	var used bool
	if pool.Raw().QueryRow(ctx, `SELECT f.state,a.active_factors,(SELECT count(*) FROM identity_mfa.recovery_codes c WHERE c.tenant_id=f.tenant_id AND c.set_id=f.factor_id),p.consumed_command_id=$3,(SELECT count(*) FROM mfa_enrollment_risk.counter_charges c WHERE c.command_id=$3 AND c.allowed)
FROM identity_mfa.totp_factors f JOIN identity_mfa.factor_authorities a USING(tenant_id,user_id) JOIN identity_password.reauthentication_records p ON p.tenant_id=f.tenant_id AND p.proof_id=$4
WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(r.TenantID), string(result.Enrollment.ID), id, string(issued.Proof.Proof.ID)).Scan(&pending, &active, &codes, &used, &charges) != nil || pending != 1 || active != 0 || codes != 10 || !used || charges != 1 {
		t.Fatal("public enable proof/risk/pending/recovery state is not atomic")
	}
	for _, code := range result.RecoveryMaterial.Codes {
		if code.Len() != 22 {
			t.Fatal("unbounded recovery delivery")
		}
	}
	t.Run("public-uri-reveal-once", func(t *testing.T) {
		cookiePrimary, err := passworddb.NewCookieMFAEnablePrimarySource(primary, []session.CSRFKey{csrfKey})
		if err != nil {
			t.Fatal(err)
		}
		uriService, err := mfapg.NewTOTPURIService(service, mfapg.TOTPURIConfig{Primary: cookiePrimary, AllowedOrigins: []string{"https://app.test"}})
		if err != nil {
			t.Fatal("native public URI composition unavailable", err)
		}
		command, _ := identity.NewCommandID()
		uriCaller := caller.Clone()
		uriCaller.Request.Action = "identity.mfa.totp-uri"
		reveal := mfa.TotpUriRequest{TenantID: r.TenantID, EnrollmentID: result.Enrollment.ID, CommandID: command, Session: r.Session, CSRFToken: csrf, Caller: uriCaller, Origin: "https://app.test", Network: r.Network}
		wrongCSRF, _ := session.NewCSRFToken()
		for _, change := range []func(*mfa.TotpUriRequest){
			func(r *mfa.TotpUriRequest) { r.CSRFToken = wrongCSRF },
			func(r *mfa.TotpUriRequest) { r.Origin = "https://foreign.test" },
			func(r *mfa.TotpUriRequest) {
				r.Session = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			},
			func(r *mfa.TotpUriRequest) {
				r.Caller.Request.Subject.ID = "foreign"
				r.Caller.Request.Resource.ID = "foreign"
			},
		} {
			candidate := reveal
			candidate.Caller = reveal.Caller.Clone()
			candidate.CommandID, _ = identity.NewCommandID()
			change(&candidate)
			if denied, err := uriService.TotpUri(ctx, candidate); err == nil || denied.URI.URI != "" {
				t.Fatal("foreign URI possession, synchronizer or origin admitted")
			}
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if denied, err := uriService.TotpUri(canceled, reveal); err == nil || denied.URI.URI != "" {
			t.Fatal("cancellation disclosed URI")
		}
		// Fail after the actual marker update. The domain transaction must roll
		// back revelation. The separately journal-owned attempt charge is retained
		// exactly once: failed attempts must not refund or reset abuse budgets.
		if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_mfa_uri_fixture() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN IF NEW.reveal_consumed THEN RAISE EXCEPTION 'fixture rollback'; END IF; RETURN NEW; END $fn$;
CREATE TRIGGER reject_mfa_uri_fixture AFTER UPDATE ON identity_mfa.totp_factors FOR EACH ROW EXECUTE FUNCTION public.reject_mfa_uri_fixture()`); err != nil {
			t.Fatal("URI rollback fixture unavailable")
		}
		rolledBack, err := uriService.TotpUri(ctx, reveal)
		if _, cleanupErr := pool.Raw().Exec(ctx, `DROP TRIGGER reject_mfa_uri_fixture ON identity_mfa.totp_factors; DROP FUNCTION public.reject_mfa_uri_fixture()`); cleanupErr != nil {
			t.Fatal("URI rollback fixture cleanup failed")
		}
		if err == nil || rolledBack.URI.URI != "" || rolledBack.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("failed marker transaction disclosed URI or ambiguous rollback")
		}
		rollbackID, _ := base64.RawURLEncoding.Strict().DecodeString(string(reveal.CommandID))
		var charged int64
		var consumed bool
		if pool.Raw().QueryRow(ctx, `SELECT reveal_consumed,(SELECT count(*) FROM mfa_enrollment_risk.counter_charges WHERE command_id=$3) FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2`, string(r.TenantID), string(result.Enrollment.ID), rollbackID).Scan(&consumed, &charged) != nil || consumed || charged != 1 {
			t.Fatal("URI rollback lost reveal atomicity or exact attempt charge")
		}
		if replay, err := uriService.TotpUri(ctx, reveal); replay.URI.URI != "" || replay.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatalf("aborted reveal regenerated or delivered material: outcome=%d error=%T", replay.Outcome, err)
		}
		if pool.Raw().QueryRow(ctx, `SELECT count(*) FROM mfa_enrollment_risk.counter_charges WHERE command_id=$1`, rollbackID).Scan(&charged) != nil || charged != 1 {
			t.Fatal("aborted URI retry charged its attempt twice")
		}
		// Distinct commands compete for this same pending enrollment. Only the
		// final mutation winner may deliver; generated loser custody is not access.
		type attempt struct {
			request mfa.TotpUriRequest
			result  mfa.TotpUriResult
			err     error
		}
		ready := make(chan struct{})
		attempts := make(chan attempt, 2)
		var workers sync.WaitGroup
		for range 2 {
			candidate := reveal
			candidate.CommandID, _ = identity.NewCommandID()
			workers.Add(1)
			go func() {
				defer workers.Done()
				<-ready
				out, err := uriService.TotpUri(ctx, candidate)
				attempts <- attempt{candidate, out, err}
			}()
		}
		close(ready)
		workers.Wait()
		close(attempts)
		var out mfa.TotpUriResult
		var deliveries int
		var dispositions []string
		for attempt := range attempts {
			dispositions = append(dispositions, fmt.Sprintf("outcome=%d error=%T", attempt.result.Outcome, attempt.err))
			if attempt.result.URI.URI != "" {
				if attempt.err != nil || attempt.result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("URI returned without first known commit")
				}
				deliveries++
				out = attempt.result
				reveal = attempt.request
			}
		}
		if deliveries != 1 || out.URI.EnrollmentID != result.Enrollment.ID {
			t.Fatalf("competing URI commands did not produce exactly one disclosure: %v", dispositions)
		}
		parsed, err := url.Parse(out.URI.URI)
		if err != nil || parsed.Scheme != "otpauth" || parsed.Host != "totp" || parsed.Query().Get("issuer") != "Example" || parsed.Query().Get("algorithm") != "SHA1" || parsed.Query().Get("digits") != "6" || parsed.Query().Get("period") != "30" {
			t.Fatal("public URI changed stored provisioning profile")
		}
		secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get("secret"))
		defer clear(secret)
		if err != nil || len(secret) != 32 {
			t.Fatal("public URI did not retain exact bounded enrollment secret")
		}
		var revealed bool
		if err := pool.Raw().QueryRow(ctx, `SELECT reveal_consumed FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND factor_id=$2`, string(r.TenantID), string(result.Enrollment.ID)).Scan(&revealed); err != nil || !revealed {
			t.Fatal("URI delivered without durable reveal consumption")
		}
		replay, err := uriService.TotpUri(ctx, reveal)
		if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.URI.URI != "" {
			t.Fatal("matching retry redelivered URI")
		}
		alternate := reveal
		alternate.CommandID, _ = identity.NewCommandID()
		if denied, err := uriService.TotpUri(ctx, alternate); err == nil || denied.URI.URI != "" {
			t.Fatal("alternate command redelivered consumed URI")
		}
		q := identity.RecoveryQuery{TenantID: r.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, RecordID: string(result.Enrollment.ID), OperationID: "identity.mfa.totp-uri", CommandID: reveal.CommandID}
		if recovered, err := uriService.RecoverTotpUri(ctx, q, uriCaller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.URI.URI != "" {
			t.Fatal("URI recovery failed or redelivered material")
		}
		for _, before := range []bool{true, false} {
			t.Run(fmt.Sprintf("unknown-commit-before-%t", before), func(t *testing.T) {
				testPublicTOTPURIAmbiguity(t, ctx, pool, source, verification, r, service, cfg, keys, cookiePrimary, reveal, before)
			})
		}
		testPublicTOTPConfirmation(t, ctx, pool, service, cookiePrimary, reveal, secret, sourceConfig.Session.Schema, cfg, keys)
	})
	restarted, err := mfapg.NewTOTPEnrollmentService(pool, cfg, keys)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Enable(ctx, r)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.CommandID != result.CommandID || replayed.Enrollment != result.Enrollment || len(replayed.RecoveryMaterial.Codes) != 0 {
		t.Fatal("matching restart retry generated or redelivered recovery material")
	}
	changed := r
	changed.FactorPolicy.RecoveryCodes = 9
	conflicted, err := restarted.Enable(ctx, changed)
	if !errors.As(err, new(identity.ConflictError)) || len(conflicted.RecoveryMaterial.Codes) != 0 {
		t.Fatal("changed enrollment intent was not rejected before generation")
	}
	q := identity.RecoveryQuery{TenantID: r.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, RecordID: string(result.Enrollment.ID), OperationID: "identity.mfa.enable", CommandID: result.CommandID}
	recovered, err := restarted.RecoverEnable(ctx, q, caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.CommandID != result.CommandID || len(recovered.RecoveryMaterial.Codes) != 0 {
		t.Fatalf("secret-free enrollment recovery lost original outcome: outcome=%d id-match=%t error=%T", recovered.Outcome, recovered.CommandID == result.CommandID, err)
	}
}
