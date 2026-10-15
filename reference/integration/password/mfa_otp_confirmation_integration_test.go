//go:build integration

package passwordintegration_test

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
)

// This selected journey uses a separate real database, so confirming OTP does
// not change the independent TOTP fixture's known-empty factor policy. It reuses
// the same genuine password-primary setup, not fake grants or comparison stores.
func TestSecondaryOTPEnrollmentConfirmationIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "commit")
}

func TestSecondaryOTPPasswordLoginSendIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "login-send")
}

func TestSecondaryOTPPasswordLoginHTTPIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "login-http")
}

func TestSecondaryOTPPasswordLoginCompletionRollbackIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "login-rollback")
}

func TestSecondaryOTPPasswordLoginCompletionUnknownBeforeIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "login-unknown-before")
}

func TestSecondaryOTPPasswordLoginCompletionUnknownAfterIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "login-unknown-after")
}

func TestSecondaryOTPPasswordLoginCompletionContentionIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "login-contention")
}

func TestSecondaryOTPEnrollmentConfirmationRollbackIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "rollback")
}

func TestSecondaryOTPEnrollmentConfirmationRecipientAuthorityIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "recipient-authority")
}

func TestSecondaryOTPEnrollmentConfirmationAccountAuthorityIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "account-authority")
}

func TestSecondaryOTPEnrollmentConfirmationContentionIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "contention")
}

func TestSecondaryOTPEnrollmentConfirmationUnknownBeforeIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "unknown-before")
}

func TestSecondaryOTPEnrollmentConfirmationUnknownAfterIntegration(t *testing.T) {
	testSecondaryOTPEnrollmentConfirmationIntegration(t, "unknown-after")
}

func testSecondaryOTPEnrollmentConfirmationIntegration(t *testing.T, scenario string) {
	port, file := os.Getenv("IDENTITY_REFERENCE_POSTGRES_PORT"), os.Getenv("IDENTITY_REFERENCE_PASSWORD_FILE")
	password, err := os.ReadFile(file)
	if err != nil || port == "" || file == "" {
		t.Fatal("disposable loopback PostgreSQL required")
	}
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", strings.TrimSpace(string(password))), Host: net.JoinHostPort("127.0.0.1", port), Path: "/postgres", RawQuery: "sslmode=disable"}).String()
	clear(password)
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	admin, err := pgx.Connect(ctx, dsn)
	stop()
	if err != nil {
		t.Fatal("isolated fixture administrator unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if admin.Close(cleanup) != nil {
			t.Error("fixture administrator cleanup failed")
		}
	}()
	// Fixed audit-role names are owned by the reused real fixture. Remember
	// pre-existing roles and remove only those created by this invocation,
	// after its task-owned database is gone.
	var priorRoles []string
	roleContext, roleStop := context.WithTimeout(context.Background(), 3*time.Second)
	defer roleStop()
	rows, err := admin.Query(roleContext, `SELECT rolname FROM pg_roles WHERE rolname IN('audit_writer','audit_reader','audit_retention')`)
	if err != nil {
		t.Fatal("audit role ownership unavailable")
	}
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			rows.Close()
			t.Fatal("audit role ownership unavailable")
		}
		priorRoles = append(priorRoles, name)
	}
	rowErr := rows.Err()
	rows.Close()
	roleStop()
	if rowErr != nil {
		t.Fatal("audit role ownership unavailable")
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	name := "identity_otp_" + string(id)
	ctx, stop = context.WithTimeout(context.Background(), 3*time.Second)
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	stop()
	if err != nil {
		t.Fatal("task-owned confirmation database unavailable")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error("confirmation database cleanup failed")
			return
		}
		for _, role := range []string{"audit_writer", "audit_reader", "audit_retention"} {
			if slices.Contains(priorRoles, role) {
				continue
			}
			var exists bool
			if err := admin.QueryRow(cleanup, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&exists); err != nil {
				t.Error("fixture audit role cleanup unresolved")
				continue
			}
			if exists {
				if _, err := admin.Exec(cleanup, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
					t.Error("fixture audit role cleanup failed")
				}
			}
		}
	}()
	testPrimaryPasswordCredentialIntegration(t, name, scenario)
}

func testPublicOTPEnrollmentConfirmation(t *testing.T, ctx context.Context, pool *database.Pool, sender *mfapg.OTPEnrollmentSendService, senderConfig mfapg.OTPEnrollmentSendConfig, cfg mfapg.OTPEnrollmentConfig, keys *keyring.Provider, sent mfa.OtpSendRequest, code, wrong auth.OneTimeCode, scenario string, beforeProvider *func(context.Context)) {
	t.Helper()
	items, err := (otppg.ConsumingMigrationSource{Schema: "mfa_otp", Version: 104}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, items[0].UpSQL()); err != nil {
		t.Fatal("native consuming history unavailable", err)
	}
	primary, ok := cfg.Primary.(mfapg.OTPEnrollmentConfirmationPrimarySource)
	if !ok {
		t.Fatal("actual primary has no OTP confirmation restoration")
	}
	config := mfapg.OTPEnrollmentConfirmationConfig{Primary: primary, AttemptKeyVersion: 1}
	missingKey := config
	missingKey.AttemptKeyVersion = 99
	if service, err := mfapg.NewOTPEnrollmentConfirmationService(sender, missingKey); err == nil || service != nil {
		t.Fatal("missing retained key produced an unfinishable confirmation service")
	}
	service, err := mfapg.NewOTPEnrollmentConfirmationService(sender, config)
	if err != nil {
		t.Fatal("actual confirmation composition unavailable", err)
	}
	caller := sent.Caller.Clone()
	caller.Request.Action = "identity.mfa.otp-verify"
	r := mfa.OtpVerifyRequest{TenantID: sent.TenantID, FactorID: sent.FactorID, Code: code, Caller: caller, Origin: sent.Origin, Network: sent.Network, Enrollment: sent.Enrollment}
	r.CommandID, _ = identity.NewCommandID()
	if scenario == "contention" {
		type attempt struct {
			request mfa.OtpVerifyRequest
			result  mfa.OtpVerifyResult
			err     error
		}
		ready := make(chan struct{})
		results := make(chan attempt, 2)
		var workers sync.WaitGroup
		for range 2 {
			candidate := r
			candidate.CommandID, _ = identity.NewCommandID()
			workers.Add(1)
			go func() {
				defer workers.Done()
				select {
				case <-ctx.Done():
					results <- attempt{request: candidate, err: ctx.Err()}
					return
				case <-ready:
				}
				out, err := service.OtpVerify(ctx, candidate)
				results <- attempt{candidate, out, err}
			}()
		}
		close(ready)
		workers.Wait()
		close(results)
		commits := 0
		for attempted := range results {
			if attempted.result.Outcome == identity.CommitOutcomeCommitted {
				if attempted.err != nil || attempted.result.Enrollment.ID != mfa.EnrollmentID(r.FactorID) || attempted.result.Session.Token != (session.Token{}) {
					t.Fatal("contending confirmation returned incomplete committed state")
				}
				commits++
			} else if attempted.result.Enrollment.ID != "" || attempted.result.Session.Token != (session.Token{}) {
				t.Fatal("losing confirmation disclosed activation or a session")
			}
			if attempted.result.Outcome == identity.CommitOutcomeUnknown || attempted.result.Outcome == identity.CommitOutcomeInProgress {
				id, _ := base64.RawURLEncoding.Strict().DecodeString(string(attempted.request.CommandID))
				var state string
				var started, output, attached, declaration bool
				readErr := pool.Raw().QueryRow(ctx, `SELECT state,preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL,preparation_declaration IS NOT NULL FROM identity.commands WHERE command_id=$1`, id).Scan(&state, &started, &output, &attached, &declaration)
				t.Logf("contending original state: outcome=%d error=%T journal=%s started=%t output=%t attached=%t declaration=%t read=%T", attempted.result.Outcome, attempted.err, state, started, output, attached, declaration, readErr)
				q := otpConfirmationRecoveryQuery(attempted.request)
				awaitOTPConfirmationRecovery(t, ctx, service, q, caller, identity.CommitOutcomeNotCommitted)
			}
		}
		if commits != 1 {
			t.Fatalf("contending native confirmations produced %d winners", commits)
		}
		assertOTPConfirmationCommitState(t, ctx, pool, r, true)
		return
	}
	if scenario == "unknown-before" || scenario == "unknown-after" {
		before := scenario == "unknown-before"
		fault := &reauthenticationCommitFault{before: before, marker: []byte("UPDATE identity_mfa.otp_factors SET state=2")}
		faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
		if err != nil {
			t.Fatal("isolated native OTP commit-fault pool unavailable")
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if faultPool.Close(cleanup) != nil {
				t.Error("OTP commit-fault pool cleanup failed")
			}
		}()
		cfg.Coordinator.LeaseDuration = 500 * time.Millisecond
		faultEnrollment, err := mfapg.NewOTPEnrollmentService(faultPool, cfg, keys)
		if err != nil {
			t.Fatal("native OTP fault enrollment composition unavailable", err)
		}
		faultSender, err := mfapg.NewOTPEnrollmentSendService(faultEnrollment, senderConfig)
		if err != nil {
			t.Fatal("native OTP fault send composition unavailable", err)
		}
		faultService, err := mfapg.NewOTPEnrollmentConfirmationService(faultSender, config)
		if err != nil {
			t.Fatal("native OTP fault confirmation composition unavailable", err)
		}
		out, err := faultService.OtpVerify(ctx, r)
		if err == nil || out.Outcome != identity.CommitOutcomeUnknown || out.Enrollment.ID != "" || out.Session.Token != (session.Token{}) || !fault.hit.Load() {
			t.Fatal("ambiguous native confirmation fabricated an outcome or activation/session metadata")
		}
		want := identity.CommitOutcomeCommitted
		if before {
			want = identity.CommitOutcomeNotCommitted
		}
		awaitOTPConfirmationRecovery(t, ctx, faultService, otpConfirmationRecoveryQuery(r), caller, want)
		assertOTPConfirmationCommitState(t, ctx, pool, r, !before)
		replay, replayErr := faultService.OtpVerify(ctx, r)
		if replay.Outcome != want || replay.Session.Token != (session.Token{}) || before && replay.Enrollment.ID != "" || !before && replayErr != nil {
			t.Fatalf("ambiguous confirmation replay changed original outcome: outcome=%d error=%T", replay.Outcome, replayErr)
		}
		assertOTPConfirmationCommitState(t, ctx, pool, r, !before)
		return
	}
	if scenario == "recipient-authority" || scenario == "account-authority" {
		*beforeProvider = func(providerContext context.Context) {
			*beforeProvider = nil
			if scenario == "recipient-authority" {
				if _, err := pool.Raw().Exec(providerContext, `UPDATE identity.identifiers SET version=version+1,verification_version=verification_version+1,verified=false,verification_state=3,is_primary=false WHERE tenant_id=$1 AND user_id=$2 AND identifier_id='mfa-fixture-email'`, string(r.TenantID), string(caller.Request.Subject.ID)); err != nil {
					t.Error("fixture recipient revocation failed")
				}
			} else {
				if _, err := pool.Raw().Exec(providerContext, `UPDATE identity.users SET status='banned',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(caller.Request.Subject.ID)); err != nil {
					t.Error("fixture account block failed")
				}
			}
		}
		out, err := service.OtpVerify(ctx, r)
		*beforeProvider = nil
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Enrollment.ID != "" || out.Session.Token != (session.Token{}) {
			t.Fatal("authority loss after original preparation confirmed a factor")
		}
		var factor, recovery int16
		var active, used, failures int32
		var challenge string
		if err := pool.Raw().QueryRow(ctx, `SELECT f.state,r.state,a.active_factors,c.state,c.used_attempts,c.failed_attempts FROM identity_mfa.otp_factors f JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.factor_id=f.factor_id JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id JOIN mfa_otp.challenges c ON c.tenant_id=f.tenant_id AND c.issue_command_id=f.last_send_command_id WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(r.TenantID), string(r.FactorID)).Scan(&factor, &recovery, &active, &challenge, &used, &failures); err != nil || factor != 1 || recovery != 1 || active != 0 || challenge != "issued" || used != 0 || failures != 0 {
			t.Fatal("authority denial compared or consumed OTP or activated factor/recovery state", err)
		}
		return
	}
	if scenario == "rollback" {
		if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_otp_confirmation_fixture() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $fn$; CREATE TRIGGER reject_otp_confirmation_fixture AFTER UPDATE ON identity_mfa.otp_factors FOR EACH ROW WHEN (NEW.state=2) EXECUTE FUNCTION public.reject_otp_confirmation_fixture()`); err != nil {
			t.Fatal(err)
		}
		out, err := service.OtpVerify(ctx, r)
		if _, cleanupErr := pool.Raw().Exec(ctx, `DROP TRIGGER reject_otp_confirmation_fixture ON identity_mfa.otp_factors; DROP FUNCTION public.reject_otp_confirmation_fixture()`); cleanupErr != nil {
			t.Fatal("rollback trigger cleanup failed")
		}
		if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Enrollment.ID != "" || out.Session.Token != (session.Token{}) {
			t.Fatalf("activation failure claimed commitment or disclosed metadata: outcome=%d error=%T", out.Outcome, err)
		}
		var factor, recovery int16
		var active int32
		var used, failures int32
		var challenge string
		if err := pool.Raw().QueryRow(ctx, `SELECT f.state,r.state,a.active_factors,c.state,c.used_attempts,c.failed_attempts FROM identity_mfa.otp_factors f JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.factor_id=f.factor_id JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id JOIN mfa_otp.challenges c ON c.tenant_id=f.tenant_id AND c.issue_command_id=f.last_send_command_id WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(r.TenantID), string(r.FactorID)).Scan(&factor, &recovery, &active, &challenge, &used, &failures); err != nil || factor != 1 || recovery != 1 || active != 0 || challenge != "released" || used != 1 || failures != 0 {
			t.Fatal("failed activation retained factor/recovery/OTP consumption", err)
		}
		q := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: r.CommandID, UserID: identity.UserID(caller.Request.Subject.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.otp-verify", RecordID: string(r.FactorID)}
		if recovered, _ := service.RecoverOtpVerify(ctx, q, caller); recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Enrollment.ID != "" {
			t.Fatal("failed activation recovery changed original history")
		}
		if replay, err := service.OtpVerify(ctx, r); err == nil || replay.Outcome != identity.CommitOutcomeNotCommitted || replay.Enrollment.ID != "" {
			t.Fatal("failed activation replay repeated consumption")
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM mfa_otp.challenges WHERE tenant_id=$1`, string(r.TenantID)).Scan(&used, &failures); err != nil || used != 1 || failures != 0 {
			t.Fatal("failed activation replay debited again", err)
		}
		return
	}
	for _, alter := range []func(*mfa.OtpVerifyRequest){
		func(r *mfa.OtpVerifyRequest) { r.TrustDevice = true },
		func(r *mfa.OtpVerifyRequest) {
			r.TenantID = "foreign-tenant"
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Tenant = "foreign-tenant"
		},
		func(r *mfa.OtpVerifyRequest) { id, _ := identity.NewCommandID(); r.FactorID = mfa.FactorID(id) },
		func(r *mfa.OtpVerifyRequest) {
			e := *r.Enrollment
			e.CSRFToken, _ = session.NewCSRFToken()
			r.Enrollment = &e
		},
		func(r *mfa.OtpVerifyRequest) {
			e := *r.Enrollment
			e.Session = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			r.Enrollment = &e
		},
	} {
		bad := r
		bad.CommandID, _ = identity.NewCommandID()
		alter(&bad)
		if out, err := service.OtpVerify(ctx, bad); err == nil || out.Enrollment.ID != "" || out.Session.Token != (session.Token{}) {
			t.Fatal("foreign primary/factor/CSRF or unsupported trust confirmed a factor")
		}
	}
	denied := r
	denied.Code = wrong
	failed, err := service.OtpVerify(ctx, denied)
	if err == nil || failed.Outcome != identity.CommitOutcomeNotCommitted || failed.Enrollment.ID != "" {
		t.Fatalf("wrong OTP did not retain a counted denial: outcome=%d error=%T", failed.Outcome, err)
	}
	var used, failures int32
	if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM mfa_otp.challenges WHERE tenant_id=$1`, string(r.TenantID)).Scan(&used, &failures); err != nil || used != 1 || failures != 1 {
		t.Fatal("wrong OTP did not debit exactly once", err)
	}
	if out, err := service.OtpVerify(ctx, denied); err == nil || out.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("original denial retry changed history")
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM mfa_otp.challenges WHERE tenant_id=$1`, string(r.TenantID)).Scan(&used, &failures); err != nil || used != 1 || failures != 1 {
		t.Fatal("denial retry debited twice", err)
	}
	r.CommandID, _ = identity.NewCommandID()
	confirmed, err := service.OtpVerify(ctx, r)
	if err != nil || confirmed.Outcome != identity.CommitOutcomeCommitted || confirmed.Enrollment.ID != mfa.EnrollmentID(r.FactorID) || confirmed.Enrollment.FactorMethod != "otp" || confirmed.Enrollment.Version != 3 || confirmed.Session.Token != (session.Token{}) {
		id, _ := base64.RawURLEncoding.Strict().DecodeString(string(r.CommandID))
		var journal, otpState string
		var retained, attached bool
		var version string
		readErr := pool.Raw().QueryRow(ctx, `SELECT j.state,j.preparation_ciphertext IS NOT NULL,j.command_plan IS NOT NULL,c.state,c.version::text FROM identity.commands j JOIN mfa_otp.challenges c ON c.tenant_id=j.tenant_id WHERE j.command_id=$1 AND j.tenant_id=$2`, id, string(r.TenantID)).Scan(&journal, &retained, &attached, &otpState, &version)
		t.Fatalf("actual delivered OTP did not confirm without a login session: outcome=%d error=%v journal=%s retained=%t attached=%t otp=%s version=%s read-error=%T", confirmed.Outcome, err, journal, retained, attached, otpState, version, readErr)
	}
	var factor, recovery int16
	var active int32
	var challenge string
	if err := pool.Raw().QueryRow(ctx, `SELECT f.state,r.state,a.active_factors,c.state,c.used_attempts,c.failed_attempts FROM identity_mfa.otp_factors f JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.factor_id=f.factor_id JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id JOIN mfa_otp.challenges c ON c.tenant_id=f.tenant_id AND c.issue_command_id=f.last_send_command_id WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(r.TenantID), string(r.FactorID)).Scan(&factor, &recovery, &active, &challenge, &used, &failures); err != nil || factor != 2 || recovery != 2 || active != 1 || challenge != "finalized" || used != 2 || failures != 1 {
		t.Fatal("OTP/factor/recovery authority did not commit atomically", err)
	}
	restarted, err := mfapg.NewOTPEnrollmentConfirmationService(sender, config)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.OtpVerify(ctx, r)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted || replayed.Enrollment.ID != confirmed.Enrollment.ID || replayed.Enrollment.Version != confirmed.Enrollment.Version {
		t.Fatal("confirmation restart changed original outcome", err)
	}
	changed := r
	changed.Code = wrong
	if out, err := restarted.OtpVerify(ctx, changed); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("same command adopted a different submitted code")
	}
	q := identity.RecoveryQuery{TenantID: r.TenantID, CommandID: r.CommandID, UserID: identity.UserID(caller.Request.Subject.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.otp-verify", RecordID: string(r.FactorID)}
	if recovered, err := restarted.RecoverOtpVerify(ctx, q, caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Session.Token != (session.Token{}) {
		t.Fatal("code/proof-free confirmation recovery failed", err)
	}
}

func otpConfirmationRecoveryQuery(r mfa.OtpVerifyRequest) identity.RecoveryQuery {
	user := r.Caller.Request.Subject.ID
	return identity.RecoveryQuery{TenantID: r.TenantID, CommandID: r.CommandID, UserID: identity.UserID(user), ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.otp-verify", RecordID: string(r.FactorID)}
}

func awaitOTPConfirmationRecovery(t *testing.T, ctx context.Context, service *mfapg.OTPEnrollmentConfirmationService, q identity.RecoveryQuery, caller authorization.DecisionContext, want identity.CommitOutcome) {
	t.Helper()
	bounded, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		recovered, err := service.RecoverOtpVerify(bounded, q, caller)
		if recovered.Enrollment.ID != "" || recovered.Session.Token != (session.Token{}) || recovered.StepUpProof.Bindings().Proof.ID != "" || recovered.CSRFToken != (session.CSRFToken{}) {
			t.Fatal("confirmation recovery disclosed new authentication metadata")
		}
		if recovered.Outcome == want {
			if want == identity.CommitOutcomeCommitted && err != nil {
				t.Fatal("committed confirmation recovery failed", err)
			}
			return
		}
		select {
		case <-bounded.Done():
			t.Fatalf("native OTP uncertainty did not reconcile: outcome=%d error=%T", recovered.Outcome, err)
		case <-ticker.C:
		}
	}
}

func assertOTPConfirmationCommitState(t *testing.T, ctx context.Context, pool *database.Pool, r mfa.OtpVerifyRequest, committed bool) {
	t.Helper()
	var factor, recovery int16
	var active, used, failures int32
	var challenge string
	if err := pool.Raw().QueryRow(ctx, `SELECT f.state,r.state,a.active_factors,c.state,c.used_attempts,c.failed_attempts FROM identity_mfa.otp_factors f JOIN identity_mfa.recovery_sets r ON r.tenant_id=f.tenant_id AND r.factor_id=f.factor_id JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id JOIN mfa_otp.challenges c ON c.tenant_id=f.tenant_id AND c.issue_command_id=f.last_send_command_id WHERE f.tenant_id=$1 AND f.factor_id=$2`, string(r.TenantID), string(r.FactorID)).Scan(&factor, &recovery, &active, &challenge, &used, &failures); err != nil {
		t.Fatal("native confirmation state unavailable", err)
	}
	if used != 1 || failures != 0 {
		t.Fatal("native confirmation repeated its original attempt debit")
	}
	if committed {
		if factor != 2 || recovery != 2 || active != 1 || challenge != "finalized" {
			t.Fatal("committed confirmation lost atomic factor/recovery/OTP state")
		}
	} else if factor != 1 || recovery != 1 || active != 0 || challenge != "released" {
		t.Fatal("noncommitted confirmation retained active or finalized state")
	}
}
