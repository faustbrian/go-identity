//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

func TestPublicSigninPostgresActualSendAndRecovery(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, persistent := range []bool{false, true} {
			t.Run(map[bool]string{false: "user", true: "anonymous"}[anonymous]+"/"+map[bool]string{false: "browser", true: "persistent"}[persistent], func(t *testing.T) {
				testPublicSendPostgresScenario(t, false, false, &publicSigninScenario{anonymous: anonymous, persistent: persistent})
			})
		}
	}
}

func TestPublicSigninPostgresCompetingCorrectAndIncorrect(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		t.Run(map[bool]string{false: "user", true: "anonymous"}[anonymous], func(t *testing.T) {
			testPublicSendPostgresScenario(t, false, false, &publicSigninScenario{anonymous: anonymous, mixedRace: true})
		})
	}
}

func TestPublicSigninSourcePostgresCurrentAuthority(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for name, change := range map[string]string{
			"blocked-recipient": `UPDATE identity.users SET status='banned'`,
			"identifier-epoch":  `UPDATE identity.users SET identifier_version=identifier_version+1`,
			"missing-flow":      `DELETE FROM session_store.preauth_transactions`,
		} {
			t.Run(map[bool]string{false: "user", true: "anonymous"}[anonymous]+"/"+name, func(t *testing.T) {
				testPublicSendPostgresScenario(t, false, false, &publicSigninScenario{anonymous: anonymous, sourceDenialSQL: change})
			})
		}
	}
}

// Actual public Send and captured delivered code feed public Signin. No test
// challenge, attempt, recipient, proof or session is injected into the login.
func TestPublicSigninPostgresRollback(t *testing.T) {
	testPublicSendPostgresScenario(t, false, false, &publicSigninScenario{rollback: true})
}

func proveSigninSourceDiscovery(t *testing.T, ctx context.Context, db *pgx.Conn, service *SigninService, request otp.SendRequest, command identity.CommandID) {
	t.Helper()
	snapshot := func() [4]int {
		t.Helper()
		var state [4]int
		if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM identity.commands),(SELECT count(*) FROM session_store.session_issuances) FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(request.TenantID), string(command)).Scan(&state[0], &state[1], &state[2], &state[3]); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := snapshot()
	r := otp.SigninSourceRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, SendCommandID: command}
	for range 2 {
		source, err := service.ResolveSigninSource(ctx, r)
		b, bindingErr := source.Bindings()
		if err != nil || bindingErr != nil || b.TenantID != request.TenantID || b.SendCommandID != command || b.Channel != request.Channel || b.Destination.Value() != request.Destination.Value() {
			t.Fatal("native original source changed or unavailable", err, bindingErr)
		}
	}
	bad := r
	bad.SendCommandID, _ = identity.NewCommandID()
	if source, err := service.ResolveSigninSource(ctx, bad); err == nil || source != (otp.SigninSource{}) {
		t.Fatal("unknown Send disclosed source")
	}
	kind, id, _, _ := r.Flow.Bindings()
	if kind != otp.FlowAuthorizationPreAuthTransaction {
		t.Fatal("signin fixture lacks pre-auth variant")
	}
	bad = r
	bad.Flow, _ = otp.NewPreAuthSendFlow(identity.PreAuthTransactionID(id), auth.NewBearerCredential(strings.Repeat("Z", 42)+"A"))
	if source, err := service.ResolveSigninSource(ctx, bad); err == nil || source != (otp.SigninSource{}) {
		t.Fatal("foreign bearer disclosed original destination")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if source, err := service.ResolveSigninSource(cancelled, r); err == nil || source != (otp.SigninSource{}) {
		t.Fatal("cancelled discovery disclosed source")
	}
	if after := snapshot(); after != before {
		t.Fatal("source discovery mutated attempts, commands or sessions")
	}
}

type publicSigninScenario struct {
	anonymous, persistent, rollback, expiryWait, authorityChange bool
	mixedRace                                                    bool
	commitFault                                                  *signinCommitFault
	sourceDenialSQL                                              string
}

func TestPublicSigninPostgresLostCommitAcknowledgment(t *testing.T) {
	for _, denial := range []bool{false, true} {
		t.Run(map[bool]string{false: "session", true: "wrong-code"}[denial], func(t *testing.T) {
			testPublicSendPostgresScenario(t, false, false, &publicSigninScenario{anonymous: true, commitFault: &signinCommitFault{denial: denial}})
		})
	}
}

func TestPublicSigninPostgresAdmissionWait(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(map[bool]string{false: "authority-change", true: "expiry"}[expiry], func(t *testing.T) {
			testPublicSendPostgresScenario(t, false, false, &publicSigninScenario{anonymous: true, expiryWait: expiry, authorityChange: !expiry})
		})
	}
}

func testPublicSigninAndRecovery(t *testing.T, ctx context.Context, db *pgx.Conn, sender *SendService, config SendConfig, request otp.SendRequest, remember session.RememberPolicy, scenario publicSigninScenario) {
	t.Helper()
	issue := sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: "session_store", Version: 200}, Version: 202}, Version: 203}
	for _, source := range []migrations.Source{ConsumingMigrationSource{Schema: "otp_store", Version: 104}, issue, sessionpg.PreAuthReleaseMigrationSource{Schema: "session_store", Version: 204}, sessionpg.CSRFMigrationSource{Schema: "session_store", Version: 205}, sessionpg.OTPMigrationSource{Schema: "session_store", Version: 206}, sessionpg.OTPIssueMigrationSource{Schema: "session_store", Version: 207}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if m.Version() == 200 {
				continue
			}
			if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("owned signin migration", err)
			}
		}
	}
	coordinator := config.Coordinator
	policy := config.RequestKeys.Policy
	coordinator.QueryPolicy = &policy
	key, err := session.NewDigestKey(11, bytes.Repeat([]byte{0x79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFKey(12, bytes.Repeat([]byte{0x7a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	if err != nil {
		t.Fatal(err)
	}
	c := SigninConfig{Coordinator: coordinator, CurrentAttemptKeyVersion: 7, Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: sessionpg.OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "service-a"}, Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 3 * time.Second, LookupKey: key, TokenSize: 32, Cookie: cookie}, CSRFKey: csrf}
	service, err := NewSigninService(sender, c)
	if err != nil {
		t.Fatal("public signin composition", err)
	}
	sent, err := sender.Send(ctx, request)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual Send", err)
	}
	proveSigninSourceDiscovery(t, ctx, db, service, request, sent.CommandID)
	if scenario.sourceDenialSQL != "" {
		if _, err := db.Exec(ctx, scenario.sourceDenialSQL); err != nil {
			t.Fatal(err)
		}
		source, err := service.ResolveSigninSource(ctx, otp.SigninSourceRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, SendCommandID: sent.CommandID})
		if err == nil || source != (otp.SigninSource{}) {
			t.Fatal("changed primary authority disclosed original source")
		}
		var used, failed, sessions int
		if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM session_store.session_issuances) FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(request.TenantID), string(sent.CommandID)).Scan(&used, &failed, &sessions); err != nil || used != 0 || failed != 0 || sessions != 0 {
			t.Fatal("source rejection mutated attempts or sessions", err)
		}
		return
	}
	rawSendID, _ := base64.RawURLEncoding.DecodeString(string(sent.CommandID))
	message := persistedSendMessage(t, ctx, db, rawSendID)
	code, err := auth.NewOneTimeCode(message.Body)
	if err != nil {
		t.Fatal(err)
	}
	if scenario.commitFault != nil {
		if scenario.commitFault.denial {
			wrong := "000000"
			if message.Body == wrong {
				wrong = "000001"
			}
			code, _ = auth.NewOneTimeCode(wrong)
		}
		scenario.commitFault.enabled.Store(true)
		unknown, err := service.Signin(ctx, otp.SigninRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, SendCommandID: sent.CommandID, Code: code})
		if err == nil || unknown.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || !scenario.commitFault.hit.Load() || unknown.SessionID != "" {
			t.Fatal("lost commit acknowledgment fabricated a terminal outcome", err, unknown.Issuance.CommitOutcome)
		}
		if _, err := unknown.Issuance.Token.Reveal(); err == nil {
			t.Fatal("ambiguous signin delivered bearer")
		}
		if _, err := unknown.CSRFToken.Reveal(); err == nil {
			t.Fatal("ambiguous signin delivered CSRF")
		}
		if scenario.commitFault.denial {
			restarted, err := NewSigninService(sender, c)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				history, err := restarted.RecoverSignin(ctx, otp.SigninRecoveryRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, Recovery: unknown.Recovery})
				if err == nil || history.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || history.SessionID != "" {
					t.Fatal("lost denial acknowledgment changed original outcome", err)
				}
			}
			var used, failed, issuances int
			if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM session_store.session_issuances) FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(request.TenantID), string(sent.CommandID)).Scan(&used, &failed, &issuances); err != nil || used != 1 || failed != 1 || issuances != 0 {
				t.Fatal("lost denial acknowledgment recharged or created session", err, used, failed, issuances)
			}
			return
		}
		// The server's COMMIT response was observed and withheld by the owned
		// transport fault. Independently read actual committed state, then
		// reconstruct the public service without retaining the code/request.
		var originalSession string
		if err := db.QueryRow(ctx, `SELECT session_id FROM session_store.session_issuances WHERE purpose='identity.otp.signin'`).Scan(&originalSession); err != nil {
			t.Fatal("server commit not independently established", err)
		}
		restarted, err := NewSigninService(sender, c)
		if err != nil {
			t.Fatal(err)
		}
		history, err := restarted.RecoverSignin(ctx, otp.SigninRecoveryRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, Recovery: unknown.Recovery})
		if err != nil || history.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || history.SessionID != originalSession || !history.Issuance.Replayed {
			t.Fatal("lost acknowledgment did not recover original committed identity", err)
		}
		if _, err := history.Issuance.Token.Reveal(); err == nil {
			t.Fatal("lost acknowledgment recovery redelivered credential")
		}
		return
	}
	if scenario.expiryWait || scenario.authorityChange {
		interleave := &signinAdmissionInterleave{db: db, expiry: scenario.expiryWait}
		changedPolicy := policy
		changedPolicy.Authorization = interleave
		changedConfig := c
		changedConfig.Coordinator.AdmissionPolicy = &changedPolicy
		changed, err := NewSigninService(sender, changedConfig)
		if err != nil {
			t.Fatal(err)
		}
		denied, err := changed.Signin(ctx, otp.SigninRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, SendCommandID: sent.CommandID, Code: code})
		if err == nil || denied.SessionID != "" || !interleave.observed {
			t.Fatal("stale admission produced session", err)
		}
		if _, err := denied.Issuance.Token.Reveal(); err == nil {
			t.Fatal("stale admission delivered credential")
		}
		var issuances, finalized, consumed int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.session_issuances),(SELECT count(*) FROM otp_store.challenges WHERE state='finalized'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed')`).Scan(&issuances, &finalized, &consumed); err != nil || issuances != 0 || finalized != 0 || consumed != 0 {
			t.Fatal("stale admission committed protected effects", err)
		}
		return
	}
	mfaPolicy := &signinRequireMFA{}
	mfaConfig := c
	admissionPolicy := policy
	admissionPolicy.Authorization = mfaPolicy
	mfaConfig.Coordinator.AdmissionPolicy = &admissionPolicy
	mfaService, err := NewSigninService(sender, mfaConfig)
	if err != nil {
		t.Fatal(err)
	}
	spoofedCaller := request.Caller.Clone()
	spoofedCaller.Request.Subject.Attributes = authorization.Attributes{"identity.authentication.profile": authorization.StringValue("mfa")}
	spoofedCaller.Request.Environment.Attributes = authorization.Attributes{"identity.authentication.factor-count": authorization.IntValue(2)}
	if source, err := mfaService.ResolveSigninSource(ctx, otp.SigninSourceRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: spoofedCaller, Flow: request.Flow, SendCommandID: sent.CommandID}); err == nil || source != (otp.SigninSource{}) || !mfaPolicy.observed {
		t.Fatal("source disclosure bypassed single-factor policy", err)
	}
	if denied, err := mfaService.Signin(ctx, otp.SigninRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: spoofedCaller, Flow: request.Flow, SendCommandID: sent.CommandID, Code: code}); err == nil || denied.SessionID != "" || !mfaPolicy.observed {
		t.Fatal("single-factor login bypassed actual-user MFA policy", err)
	}
	var untouched int
	if err := db.QueryRow(ctx, `SELECT used_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(request.TenantID), string(sent.CommandID)).Scan(&untouched); err != nil || untouched != 0 {
		t.Fatal("policy rejection charged code attempt", err)
	}
	wrongCode := "000000"
	if message.Body == wrongCode {
		wrongCode = "000001"
	}
	wrong, _ := auth.NewOneTimeCode(wrongCode)
	denied, err := service.Signin(ctx, otp.SigninRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, SendCommandID: sent.CommandID, Code: wrong})
	if err == nil || denied.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || denied.SessionID != "" {
		t.Fatal("wrong code issued session", err)
	}
	deniedRecovery := otp.SigninRecoveryRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, Recovery: denied.Recovery}
	for range 2 {
		history, err := service.RecoverSignin(ctx, deniedRecovery)
		if err == nil || history.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || history.SessionID != "" {
			t.Fatal("wrong-code recovery changed outcome", err)
		}
	}
	var used, failed int
	if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(request.TenantID), string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 1 || failed != 1 {
		t.Fatal("wrong code or recovery charged incorrectly", err, used, failed)
	}
	if scenario.rollback {
		// Fail a genuine database write after provisional family creation. This
		// is an owned fault, not a substituted contributor or transaction owner.
		if _, err := db.Exec(ctx, `CREATE FUNCTION session_store.reject_signin_session() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'owned signin rollback'; END$$;
CREATE TRIGGER reject_signin_session BEFORE INSERT ON session_store.sessions FOR EACH ROW EXECUTE FUNCTION session_store.reject_signin_session()`); err != nil {
			t.Fatal(err)
		}
		aborted, err := service.Signin(ctx, otp.SigninRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, SendCommandID: sent.CommandID, Code: code})
		if err == nil || aborted.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || aborted.SessionID != "" {
			t.Fatal("failed session write not classified as noncommit", err)
		}
		if _, err := aborted.Issuance.Token.Reveal(); err == nil {
			t.Fatal("rollback delivered credential")
		}
		var families, sessions, receipts, finalized, consumed, lifecycle int
		if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.families),(SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM session_store.session_issuances),(SELECT count(*) FROM otp_store.challenges WHERE state='finalized'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed'),(SELECT count(*) FROM public.outbox_messages WHERE topic='otp.signed-in.v1')`).Scan(&families, &sessions, &receipts, &finalized, &consumed, &lifecycle); err != nil || families != 1 || sessions != 1 || receipts != 0 || finalized != 0 || consumed != 0 || lifecycle != 0 {
			t.Fatal("provisional signin effects escaped rollback", err, families, sessions, receipts, finalized, consumed, lifecycle)
		}
		restarted, err := NewSigninService(sender, c)
		if err != nil {
			t.Fatal(err)
		}
		history, err := restarted.RecoverSignin(ctx, otp.SigninRecoveryRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, Recovery: aborted.Recovery})
		if err == nil || history.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || history.SessionID != "" {
			t.Fatal("rollback history changed after reconstruction", err)
		}
		return
	}
	type signinResponse struct {
		result otp.SigninResult
		err    error
		wrong  bool
	}
	responses := make(chan signinResponse, 4)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for index := range 4 {
		incorrect := scenario.mixedRace && index >= 2
		workers.Go(func() {
			<-start
			submitted := code
			if incorrect {
				submitted = wrong
			}
			result, err := service.Signin(ctx, otp.SigninRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, SendCommandID: sent.CommandID, Code: submitted})
			responses <- signinResponse{result, err, incorrect}
		})
	}
	close(start)
	workers.Wait()
	close(responses)
	var result otp.SigninResult
	winners := 0
	for response := range responses {
		if response.err == nil && response.result.Issuance.CommitOutcome == identity.CommitOutcomeCommitted {
			if response.wrong {
				t.Fatal("incorrect competing submission issued session")
			}
			winners++
			result = response.result
		} else {
			if _, err := response.result.Issuance.Token.Reveal(); err == nil {
				t.Fatal("losing signin delivered bearer")
			}
			if _, err := response.result.CSRFToken.Reveal(); err == nil {
				t.Fatal("losing signin delivered CSRF")
			}
		}
	}
	if scenario.mixedRace {
		// A wrong attempt can advance the challenge version before every correct
		// contender reserves. Such stale submissions must fail closed, not be
		// transparently retried under another fingerprint or generation.
		var finalized, issuances int
		if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts,(SELECT count(*) FROM otp_store.challenges WHERE challenge_id=$2 AND state='finalized'),(SELECT count(*) FROM session_store.session_issuances WHERE purpose='identity.otp.signin') FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(request.TenantID), string(sent.CommandID)).Scan(&used, &failed, &finalized, &issuances); err != nil || winners > 1 || failed < 1 || failed > 3 || used != failed+winners || finalized != winners || issuances != winners {
			t.Fatal("competing submissions corrupted attempt or issuance accounting", err, winners, used, failed, finalized, issuances)
		}
		return
	}
	if winners != 1 || result.SessionID == "" || result.Issuance.Replayed {
		t.Fatal("concurrent signin did not produce exactly one new winner", winners)
	}
	record, err := result.Issuance.Session.Bindings()
	if err != nil || record.SessionID != result.SessionID || record.UserID != "AAAAAAAAAAAAAAAAAAAAAg" || record.Remember != remember {
		t.Fatal("wrong selected session user", err)
	}
	_, _, originalBearer, _ := request.Flow.Bindings()
	if _, err := result.CSRFToken.Reveal(); err != nil {
		t.Fatal("original CSRF not deliverable", err)
	}
	wire, err := result.Issuance.Token.Reveal()
	if err != nil || wire == originalBearer.Token() {
		t.Fatal("new session bearer missing or fixed", err)
	}
	if result.Issuance.Cookie.Value != "" {
		t.Fatal("implicit cookie credential disclosure")
	}
	token, err := session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sessionpg.NewOTPSessionService(sender.pool, sessionpg.OTPSessionServiceConfig{Repository: c.Session, Profile: c.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := reader.Get(ctx, session.GetRequest{TenantID: request.TenantID, Credential: credential})
	if err != nil || !accepted.Authenticated {
		t.Fatal("reconstructed reader rejected real issued credential", err)
	}
	var finalized, consumed, issuances, audits, lifecycle int
	if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges WHERE challenge_id=$1 AND state='finalized'),(SELECT count(*) FROM session_store.preauth_transactions WHERE state='consumed'),(SELECT count(*) FROM session_store.session_issuances WHERE purpose='identity.otp.signin'),(SELECT count(*) FROM audit.records WHERE action='otp.signin' AND correlation_id=$2),(SELECT count(*) FROM public.outbox_messages WHERE topic='otp.signed-in.v1')`, string(sent.CommandID), string(result.Issuance.CommandID)).Scan(&finalized, &consumed, &issuances, &audits, &lifecycle); err != nil {
		t.Fatal(err)
	}
	if finalized != 1 || consumed != 1 || issuances != 1 || audits != 1 || lifecycle != 1 {
		t.Fatal("atomic signin effects missing", finalized, consumed, issuances, audits, lifecycle)
	}
	restarted, err := NewSigninService(sender, c)
	if err != nil {
		t.Fatal(err)
	}
	recoverRequest := otp.SigninRecoveryRequest{TenantID: request.TenantID, UserID: request.UserID, Caller: request.Caller, Flow: request.Flow, Recovery: result.Recovery}
	for _, erase := range []bool{false, true} {
		if erase {
			if _, err := db.Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(request.TenantID), result.SessionID); err != nil {
				t.Fatal(err)
			}
		}
		history, err := restarted.RecoverSignin(ctx, recoverRequest)
		if err != nil || history.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || history.SessionID != result.SessionID || !history.Issuance.Replayed {
			t.Fatal("original code-free history lost", err)
		}
		if _, err := history.Issuance.Token.Reveal(); err == nil {
			t.Fatal("recovery redelivered bearer")
		}
		if _, err := history.CSRFToken.Reveal(); err == nil {
			t.Fatal("recovery redelivered CSRF")
		}
	}
	for _, mutate := range []func(*otp.SigninRecoveryRequest){
		func(r *otp.SigninRecoveryRequest) {
			b, _ := r.Recovery.Bindings()
			b.ExpectedVersion++
			r.Recovery, err = otp.NewSigninRecovery(b)
			if err != nil {
				t.Fatal(err)
			}
		},
		func(r *otp.SigninRecoveryRequest) {
			b, _ := r.Recovery.Bindings()
			b.ScopeDigest[0] ^= 1
			r.Recovery, err = otp.NewSigninRecovery(b)
			if err != nil {
				t.Fatal(err)
			}
		},
		func(r *otp.SigninRecoveryRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Subject.ID = "AAAAAAAAAAAAAAAAAAAABA"
		},
		func(r *otp.SigninRecoveryRequest) {
			_, id, _, _ := r.Flow.Bindings()
			r.Flow, err = otp.NewPreAuthSendFlow(identity.PreAuthTransactionID(id), auth.NewBearerCredential(strings.Repeat("A", 43)))
			if err != nil {
				t.Fatal(err)
			}
		},
	} {
		changed := recoverRequest
		mutate(&changed)
		if history, err := restarted.RecoverSignin(ctx, changed); err == nil || history.SessionID != "" || history.Issuance.CommandID != "" {
			t.Fatal("changed recovery scope or possession disclosed history")
		}
	}
	if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(request.TenantID), string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 2 || failed != 1 {
		t.Fatal("concurrent losers or hostile history recharged original challenge", err, used, failed)
	}
	// Admission may permit new login while current query policy independently
	// denies historical disclosure about the actual recipient.
	query := policy
	query.Authorization = signinDenyRecipientHistory{}
	denyingConfig := c
	denyingConfig.Coordinator.QueryPolicy = &query
	denyingConfig.Coordinator.AdmissionPolicy = &policy
	denying, err := NewSigninService(sender, denyingConfig)
	if err != nil {
		t.Fatal(err)
	}
	if history, err := denying.RecoverSignin(ctx, recoverRequest); err == nil || history.SessionID != "" || history.Issuance.CommandID != "" {
		t.Fatal("admission permission substituted for recipient history permission")
	}
}

type signinDenyRecipientHistory struct{}

func (signinDenyRecipientHistory) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	outcome := authorization.Allow
	if c.Request.Action == "identity.otp.signin.recover" && c.Request.Resource.Type == "identity.user" {
		outcome = authorization.Deny
	}
	return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
}

type signinRequireMFA struct{ observed bool }

func (p *signinRequireMFA) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	outcome := authorization.Allow
	method, _ := c.Request.Attributes["identity.authentication.method"].String()
	if c.Request.Action == "identity.otp.signin" && c.Request.Resource.Type == "identity.user" && method == "otp" {
		profile, _ := c.Request.Attributes["identity.authentication.profile"].String()
		phase, _ := c.Request.Attributes["identity.authentication.phase"].String()
		count, _ := c.Request.Attributes["identity.authentication.factor-count"].Int()
		_, subjectSpoof := c.Request.Subject.Attributes["identity.authentication.profile"]
		_, environmentSpoof := c.Request.Environment.Attributes["identity.authentication.factor-count"]
		p.observed = profile == "single-factor" && phase == "proposed" && count == 1 && !subjectSpoof && !environmentSpoof && c.Request.Resource.ID == "AAAAAAAAAAAAAAAAAAAAAg"
		outcome = authorization.Deny
	}
	return authorization.Decision{Outcome: outcome, Revision: c.PolicyRevision}, nil
}

type signinAdmissionInterleave struct {
	db               *pgx.Conn
	expiry, observed bool
}

func (p *signinAdmissionInterleave) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	method, _ := c.Request.Attributes["identity.authentication.method"].String()
	if method == "otp" && c.Request.Action == "identity.otp.signin" && c.Request.Resource.Type == "identity.user" {
		p.observed = true
		var err error
		if p.expiry {
			_, err = p.db.Exec(ctx, `SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM expires_at::timestamptz-clock_timestamp()))+0.02) FROM session_store.preauth_transactions`)
		} else {
			_, err = p.db.Exec(ctx, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id=$1 AND subject_id=$2`, string(c.Request.Tenant), string(c.Request.Resource.ID))
		}
		if err != nil {
			return authorization.Decision{}, err
		}
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}
