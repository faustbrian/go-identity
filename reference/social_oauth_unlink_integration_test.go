//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
)

const nativeUnlinkAudience = "reference-native-account-unlink"

func TestReferenceNativeSocialUnlink(t *testing.T) {
	for _, mode := range []string{"success", "rollback", "unknown", "migration-resume"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
				postgresBaseline: true, socialOIDC: true, socialOIDCLinkOnly: true,
				socialOIDCUnlink: mode, socialOIDCHTTPSignin: mode == "success", completionCommitFault: mode == "unknown",
			}, true)
		})
	}
}

func failUnlinkMigrationValidation(t *testing.T, ctx context.Context, d reference.ReferenceDependencies) {
	t.Helper()
	if _, err := d.PostgreSQL.Raw().Exec(ctx, `CREATE FUNCTION public.fail_unlink_validation_test() RETURNS event_trigger LANGUAGE plpgsql AS $$
BEGIN
  IF position('VALIDATE CONSTRAINT reauthentication_unlink_consumption_complete' IN current_query()) > 0 THEN
    RAISE EXCEPTION 'test: interrupt unlink constraint validation';
  END IF;
END $$;
CREATE EVENT TRIGGER fail_unlink_validation_test ON ddl_command_start WHEN TAG IN ('ALTER TABLE') EXECUTE FUNCTION public.fail_unlink_validation_test()`); err != nil {
		t.Fatal("set disposable migration validation fault", err)
	}
}

func resumeUnlinkMigrationValidation(t *testing.T, ctx context.Context, stores reference.StoreSet, d reference.ReferenceDependencies) {
	t.Helper()
	if _, err := d.PostgreSQL.Raw().Exec(ctx, `DROP EVENT TRIGGER fail_unlink_validation_test; DROP FUNCTION public.fail_unlink_validation_test()`); err != nil {
		t.Fatal("remove disposable migration validation fault", err)
	}
	modules := []reference.ModuleID{"identity/password/postgres"}
	status, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: modules})
	if err != nil || len(status.Statuses) != 1 || status.Statuses[0].Compatibility != reference.MigrationRequired ||
		status.Statuses[0].CurrentVersion != 44 || status.Statuses[0].RequiredVersion != 45 {
		t.Fatal("recorded expansion was mistaken for unmanaged objects", status, err)
	}
	plan, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil || len(plan.Plan.Steps) != 1 || plan.Plan.Steps[0].ToVersion != 45 {
		t.Fatal("could not discover the sole outstanding validation", err)
	}
}

func configureReferenceNativeUnlink(c *reference.StoreConfiguration) {
	c.PasswordVerification.Native.Targets = append(c.PasswordVerification.Native.Targets,
		passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.account.unlink", Audience: nativeUnlinkAudience})
	query := identity.UserQueryConfig{
		PolicyID: c.SocialOAuth.PolicyID, PolicyVersion: c.SocialOAuth.Coordinator.AdmissionPolicy.PolicyVersion,
		Clock: clock.System{}, MaximumDuration: c.SocialOAuth.MaximumDuration, RedactionReasons: []identity.PolicyReason{"own-unlink"},
		ValidateCanonicalUserID: func(_ context.Context, id identity.UserID) error {
			_, err := identity.ParseIdentifierID(string(id))
			return err
		},
	}
	c.SocialOAuth.Unlink = &reference.SocialOAuthUnlinkConfiguration{
		Primary: passwordpg.AccountUnlinkPrimaryConfig{Audience: nativeUnlinkAudience, MaximumAge: time.Minute, Transport: session.CredentialCookie, CSRFKeys: c.Session.CSRFKeys},
		Query:   query,
		Redact: func(_ context.Context, input identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{VisibleFields: input.Fields, PolicyID: query.PolicyID, PolicyVersion: query.PolicyVersion, Reason: "own-unlink"}, nil
		},
	}
}

func proveReferenceNativeUnlink(t *testing.T, ctx context.Context, d reference.ReferenceDependencies, features reference.FeatureSet, user identity.UserID,
	fresh func(...string) ([]*http.Cookie, string), readSession func([]*http.Cookie) bool, mode string, fault *completionCommitFault) {
	t.Helper()
	cookies, csrfWire := fresh()
	if len(cookies) == 0 || !readSession(cookies) {
		t.Fatal("fresh real password session unavailable after social link")
	}
	csrf, err := session.ParseCSRFToken(csrfWire)
	if err != nil {
		t.Fatal("fresh session omitted synchronizer", err)
	}
	owner, err := features.SocialAccountUnlink()
	if err != nil {
		t.Fatal("selected graph did not expose native unlink", err)
	}
	verifier, err := features.CookiePasswordVerification()
	if err != nil {
		t.Fatal("selected graph omitted actual password proof owner", err)
	}
	var account identity.AccountID
	if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT account_id FROM identity.accounts WHERE tenant_id=$1 AND user_id=$2 AND linked`, otpTenant, string(user)).Scan(&account); err != nil {
		t.Fatal("real social link missing", err)
	}
	directory, err := kernel.NewRepository(d.PostgreSQL, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	link, err := directory.GetAccountUnlinkState(ctx, identity.AccountUnlinkQuery{TenantID: otpTenant, UserID: user, AccountID: account})
	if err != nil || len(link.Access.Accounts) != 1 {
		t.Fatal("native account snapshot did not see linked account", err)
	}
	factors, err := mfapg.ReadOAuthUnlinkFactors(ctx, d.PostgreSQL, otpTenant, user, time.Second)
	if err != nil {
		t.Fatal("original native factor generation missing", err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{
		Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)},
		Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)},
		Environment: authorization.Environment{Time: time.Now().UTC()},
	}}
	secret, err := primitive.NewSecret([]byte("synthetic-registration-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	bearer := auth.NewBearerCredential(cookies[0].Value)
	proof, err := verifier.Verify(ctx, password.CookieVerificationRequest{Request: password.VerificationRequest{
		TenantID: otpTenant, Session: bearer, Password: secret,
		Target: password.VerificationTarget{Purpose: "identity.password.verify", Action: "identity.account.unlink", Audience: nativeUnlinkAudience},
		Caller: caller, Network: "127.0.0.1", Device: "reference-native-unlink-device",
	}, CSRFToken: csrf})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatalf("genuine unlink-bound proof failed: outcome=%d error=%T", proof.Outcome, err)
	}
	caller.Request.Action = "identity.account.unlink"
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r := oauthpg.UnlinkRequest{CommandID: id, Change: identity.AccountUnlinkChange{
		TenantID: otpTenant, UserID: user, AccountID: account, ExpectedUserVersion: link.Access.User.Version,
		ExpectedAccountVersion: link.Access.Accounts[0].Version, ExpectedSocialLinkVersion: link.SocialLinkVersion, ExpectedCredentialVersion: link.CredentialVersion,
	}, Session: bearer, CSRF: csrf, Primary: proof.Proof, ActorScope: caller, FactorAuthorityVersion: factors.Version(), Network: "127.0.0.1"}
	different := r
	different.FactorAuthorityVersion++
	if outcome, err := owner.Unlink(ctx, different); err == nil || outcome.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("changed MFA authority was accepted")
	}
	different = r
	different.Primary.Proof.ExpiresAt = different.Primary.Proof.ExpiresAt.Add(time.Second)
	if outcome, err := owner.Unlink(ctx, different); err == nil || outcome.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("forged freshness was accepted")
	}
	rawID, err := base64.RawURLEncoding.DecodeString(string(id))
	if err != nil {
		t.Fatal(err)
	}
	if mode == "rollback" {
		var before []byte
		if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT token_ciphertext FROM identity_social.token_sets WHERE tenant_id=$1 AND account_id=$2`, otpTenant, string(account)).Scan(&before); err != nil || len(before) == 0 {
			t.Fatal("missing genuine encrypted token custody", err)
		}
		if _, err := d.PostgreSQL.Raw().Exec(ctx, `CREATE FUNCTION public.reject_unlink_audit_test() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.action='identity.oauth.unlink_account' THEN RAISE EXCEPTION 'test: reject provisional unlink audit'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER reject_unlink_audit_test BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_unlink_audit_test()`); err != nil {
			t.Fatal("could not set disposable audit fault", err)
		}
		result, err := owner.Unlink(ctx, r)
		if err == nil || result.CommitOutcome == identity.CommitOutcomeCommitted {
			t.Fatal("unlink reported success despite mandatory audit failure")
		}
		var after []byte
		var linked, unused bool
		var effects int
		if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT token_ciphertext,
EXISTS(SELECT 1 FROM identity.accounts WHERE tenant_id=$1 AND account_id=$2 AND linked AND version=$3::numeric),
EXISTS(SELECT 1 FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND proof_id=$4 AND consumed_command_id IS NULL AND unlink_consumed_command_id IS NULL),
(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$5)
FROM identity_social.token_sets WHERE tenant_id=$1 AND account_id=$2`,
			otpTenant, string(account), r.Change.ExpectedAccountVersion, string(proof.Proof.Proof.ID), rawID).Scan(&after, &linked, &unused, &effects); err != nil ||
			!bytes.Equal(before, after) || !linked || !unused || effects != 0 || !readSession(cookies) {
			t.Fatal("audit failure left a provisional unlink effect behind", err)
		}
		return
	}
	recovery := identity.AccountUnlinkRecoveryRequest{CommandID: id, TenantID: otpTenant, UserID: user, AccountID: account, ActorScope: caller}
	if mode == "unknown" {
		fault.armed.Store(true)
	}
	result, err := owner.Unlink(ctx, r)
	if mode == "unknown" {
		var unknown identity.UnknownCommitError
		if !fault.hit.Load() || !errors.As(err, &unknown) || result.CommitOutcome != identity.CommitOutcomeUnknown || result.Version != 0 {
			t.Fatalf("lost COMMIT acknowledgement was not scoped Unknown: outcome=%d err=%T %v", result.CommitOutcome, err, err)
		}
		result, err = owner.Recover(ctx, recovery)
	}
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Version != link.Access.User.Version+1 {
		t.Fatalf("real unlink did not commit: outcome=%d err=%T %v", result.CommitOutcome, err, err)
	}
	again, err := owner.Unlink(ctx, r)
	if err != nil || again != result {
		t.Fatalf("exact retry did not return original unlink result: outcome=%d err=%T %v", again.CommitOutcome, err, err)
	}
	withoutCSRF := r
	withoutCSRF.CSRF = session.CSRFToken{}
	if result, err := owner.Unlink(ctx, withoutCSRF); err == nil || result.CommitOutcome == identity.CommitOutcomeCommitted {
		t.Fatal("cookie replay without original synchronizer disclosed a committed outcome")
	}
	observed, err := owner.Recover(ctx, recovery)
	if err != nil || observed != result {
		t.Fatalf("scoped recovery did not return original receipt: outcome=%d err=%T %v", observed.CommitOutcome, err, err)
	}
	var tombstoned, tokensGone, used bool
	var audits, effects int
	if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT
EXISTS(SELECT 1 FROM identity.accounts WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3 AND NOT linked AND version=$5::numeric),
NOT EXISTS(SELECT 1 FROM identity_social.token_sets WHERE tenant_id=$1 AND user_id=$2 AND account_id=$3),
EXISTS(SELECT 1 FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$4 AND unlink_consumed_purpose='identity.account.unlink' AND unlink_consumed_command_id=$6 AND consumed_command_id IS NULL),
(SELECT count(DISTINCT a.action) FROM audit.records a JOIN audit.identity_command_bindings b ON a.record_id=b.event_id WHERE b.command_id=$6 AND a.action IN ('identity.account.unlink','identity.oauth.unlink_account')),
(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$6)`,
		otpTenant, string(user), string(account), string(proof.Proof.Proof.ID), r.Change.ExpectedAccountVersion+1, rawID).Scan(&tombstoned, &tokensGone, &used, &audits, &effects); err != nil || !tombstoned || !tokensGone || !used || audits != 2 || effects != 1 {
		t.Fatal("unlink committed without its account, token or one-use effect", err)
	}
	if readSession(cookies) {
		t.Fatal("old password session remained current after unlink")
	}
	current, _ := fresh()
	if !readSession(current) {
		t.Fatal("unlink removed working password access")
	}
}
