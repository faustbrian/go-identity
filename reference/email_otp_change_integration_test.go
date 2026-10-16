//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/otp"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresEmailOTPPrimaryChange(t *testing.T) {
	for _, mode := range []string{"otp-change", "otp-change-factor-missing", "otp-change-factor-enrolled", "otp-change-factor-generation", "otp-change-rollback", "otp-change-unknown", "otp-change-contention", "otp-change-link-race", "otp-change-https", "otp-change-reference-https", "otp-change-expiry", "otp-change-exhaustion", "otp-change-generic", "otp-change-candidate-stale", "otp-change-previous-stale", "otp-change-origin-revoked-send", "otp-change-origin-revoked-confirm", "otp-change-final-expiry"} {
		t.Run(mode, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailChangeCase: mode, completionCommitFault: mode == "otp-change-unknown"})
		})
	}
}

func configureReferenceEmailOTPChange(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeEmailChange, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.NewRequestKeyConfig("reference-email-otp-change", [32]byte{224}, c.OTP.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	c.Email.OTPChange = &reference.EmailOTPChangeConfiguration{Policy: policy, Domain: c.Email.Change.Native.Domain, SessionKeys: map[uint32][]byte{11: bytes.Repeat([]byte{0x79}, 32)}, FreshnessLimit: 5 * time.Minute, CurrentAttemptKeyVersion: c.OTP.Signin.CurrentAttemptKeyVersion, RequestKeys: keys, IntentKey: [32]byte{225}, IdentifierKey: [32]byte{226}, TemplateID: "email-otp-change", TemplateVersion: 1, LocaleChain: []string{"en"}}
	c.Delivery.Templates = append(c.Delivery.Templates, delivery.Template{ID: "email-otp-change", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128})
}

func assertEmailChangeOTPRecipient(t *testing.T, ctx context.Context, captured <-chan emailChangeDelivery, code, candidate, previous string) {
	t.Helper()
	for range 16 {
		select {
		case message := <-captured:
			if message.body == code {
				if message.recipient != candidate || message.recipient == previous {
					t.Fatal("actual OTP delivery retargeted original candidate")
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("actual OTP recipient observation missing")
		}
	}
	t.Fatal("actual OTP delivery not in bounded sender observations")
}

func proveReferenceEmailOTPChange(t *testing.T, ctx context.Context, f liveStores, links emailManagementConsumer, workers reference.WorkerSet, messages <-chan string, options referenceEmailChangeOptions, user identity.UserID, origin passwordpg.EmailManagementRequest, cookies []*http.Cookie, csrf, oldAddress, oldID string, oldVersion, oldVerification uint64, oldVerified time.Time, link capability.Proof) bool {
	t.Helper()
	service := options.otpChange
	var token string
	for _, cookie := range cookies {
		if cookie.Name == "__Host-session" {
			token = cookie.Value
		}
	}
	parsed, err := session.ParseToken(token)
	if err != nil {
		t.Fatal("genuine current token", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, parsed)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := options.features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !current.Authenticated {
		t.Fatal("genuine post-request session", err)
	}
	b, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewSessionSendFlow(b.SessionID, auth.NewBearerCredential(token))
	if err != nil {
		t.Fatal(err)
	}
	caller := origin.Primary.Caller.Clone()
	caller.Request.Action = "identity.otp.email-change-request"
	key, _ := identity.NewIdempotencyKey([]byte("genuine-primary-otp-change"))
	request := otp.EmailChangeRequest{TenantID: otpTenant, UserID: user, OriginCommandID: origin.Primary.CommandID, AddressID: origin.Primary.AddressID, Caller: caller, Flow: flow, Network: "127.0.0.1", Device: "native-email-change", IdempotencyKey: key}
	revokeOriginFamily := func() {
		t.Helper()
		source, ok := links.(email.ChangeOriginSource)
		if !ok {
			t.Fatal("real original change source unavailable")
		}
		q := identity.RecoveryQuery{CommandID: origin.Primary.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, RecordID: string(origin.Primary.AddressID), OperationID: "identity.otp.email-change-request"}
		readCaller := caller.Clone()
		readCaller.Request.Action = authorization.Action(q.OperationID)
		stored, err := source.ReadChangeOrigin(ctx, q, readCaller)
		if err != nil {
			t.Fatal("authentic initiating session custody", err)
		}
		initial, err := stored.Session.Bindings()
		if err != nil || initial.SessionID == b.SessionID || initial.FamilyID == b.FamilyID {
			t.Fatal("fixture did not establish independent original and current sessions", err)
		}
		// Controlled authoritative revocation fault, using the session owner's
		// real family tombstone shape. No session, proof or timestamp is invented.
		schema := pgx.Identifier{options.configuration.Session.Native.Execution.Repository.Schema}.Sanitize()
		updated, err := f.pool.Raw().Exec(ctx, `UPDATE `+schema+`.families SET state='revoked',version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND family_id=$3 AND version=$4`, otpTenant, string(user), initial.FamilyID, initial.FamilyVersion)
		if err != nil || updated.RowsAffected() != 1 || !options.readSession(cookies) {
			t.Fatal("original family revocation did not retain independent current authority", err)
		}
	}
	if options.mode == "otp-change-origin-revoked-send" {
		revokeOriginFamily()
		var before, after int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if out, err := service.EmailChangeRequest(ctx, request); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("newer signin issued OTP after initiating family revocation")
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges`).Scan(&after); err != nil || after != before {
			t.Fatal("revoked originating authority created OTP state", err)
		}
		return false
	}
	if options.mode == "otp-change-generic" {
		var before, after, primary, notices int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		if _, err := service.EmailChangeSendDestination(ctx, request); err == nil {
			t.Fatal("generic pending-add disclosed replacement destination")
		}
		if out, err := service.EmailChangeRequest(ctx, request); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("generic committed pending-add issued replacement OTP")
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges`).Scan(&after); err != nil || after != before {
			t.Fatal("generic origin denial issued OTP state", err)
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND is_primary AND verified_at=$6`, otpTenant, string(user), oldID, oldVersion, oldVerification, oldVerified).Scan(&primary); err != nil || primary != 1 {
			t.Fatal("generic origin denial changed genuine primary", err)
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil || notices != 1 || !options.readSession(cookies) {
			t.Fatal("generic origin denial notified or invalidated session", err)
		}
		return false
	}
	destination, err := service.EmailChangeSendDestination(ctx, request)
	if err != nil || destination.Value() != string(origin.Address) {
		t.Fatal("original change transport destination", err)
	}
	if options.mode == "otp-change-final-expiry" {
		proveEmailChangeFinalIssuanceExpiry(t, ctx, f, service, request, options, cookies, oldID, oldVersion, oldVerification, oldVerified)
		return false
	}
	var beforeNotices int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&beforeNotices); err != nil {
		t.Fatal(err)
	}
	var beforeChallenges, afterChallenges int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges`).Scan(&beforeChallenges); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*otp.EmailChangeRequest){
		func(r *otp.EmailChangeRequest) { r.OriginCommandID, _ = identity.NewCommandID() },
		func(r *otp.EmailChangeRequest) { r.AddressID = identity.IdentifierID(oldID) },
		func(r *otp.EmailChangeRequest) {
			r.UserID = "foreign-user"
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Subject.ID = "foreign-user"
			r.Caller.Request.Resource.ID = "foreign-user"
		},
		func(r *otp.EmailChangeRequest) {
			r.Flow, _ = otp.NewSessionSendFlow(b.SessionID, auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
		},
	} {
		other := request
		mutate(&other)
		if out, err := service.EmailChangeRequest(ctx, other); err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("foreign/noncommitted change source issued OTP")
		}
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM otp_store.challenges`).Scan(&afterChallenges); err != nil || afterChallenges != beforeChallenges {
		t.Fatal("origin/session denial generated OTP state", err)
	}
	sent, err := service.EmailChangeRequest(ctx, request)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("independent actual change OTP issuance", sent.Outcome, err)
	}
	again, err := service.EmailChangeRequest(ctx, request)
	if err != nil || again.CommandID != sent.CommandID || again.Outcome != sent.Outcome {
		t.Fatal("original change Send regenerated custody", err)
	}
	var notices, untouched int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil || notices != beforeNotices {
		t.Fatal("OTP request notified before confirmation", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND is_primary AND verified_at=$6`, otpTenant, string(user), oldID, oldVersion, oldVerification, oldVerified).Scan(&untouched); err != nil || untouched != 1 {
		t.Fatal("OTP request replaced original primary", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("actual change OTP delivery", err)
	}
	var code, wrong auth.OneTimeCode
	var deliveredCode string
	select {
	case body := <-messages:
		deliveredCode = body
		code, err = auth.NewOneTimeCode(body)
		if err != nil || len(body) != 6 {
			t.Fatal("captured purpose-bound OTP", err)
		}
		bad := "000000"
		if body == bad {
			bad = "000001"
		}
		wrong, _ = auth.NewOneTimeCode(bad)
	case <-ctx.Done():
		t.Fatal("change OTP delivery missing")
	}
	assertEmailChangeOTPRecipient(t, ctx, options.deliveries, deliveredCode, string(origin.Address), oldAddress)
	caller.Request.Action = "identity.otp.email-change-confirm"
	confirmation := otp.EmailChangeConfirmRequest{TenantID: otpTenant, UserID: user, Caller: caller, Flow: flow, SendCommandID: sent.CommandID, Code: wrong}
	challenge, err := service.EmailChangeChallenge(ctx, confirmation)
	if err != nil || challenge.UserID != user || challenge.Lifetime <= 0 || challenge.Lifetime > 5*time.Minute {
		t.Fatal("original change transport challenge", err)
	}
	selected, err := challenge.Target.Bindings()
	if err != nil || selected.OriginCommandID != origin.Primary.CommandID || selected.IdentifierID != origin.Primary.AddressID || selected.IdentifierVersion != 1 || selected.VerificationVersion != 1 {
		t.Fatal("transport challenge retargeted original change", err)
	}
	assertUnchanged := func(attempts int) {
		t.Helper()
		assertEmailOTPUnchanged(t, ctx, f, user, origin.Primary.AddressID, sent.CommandID, attempts)
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND is_primary AND verified_at=$6`, otpTenant, string(user), oldID, oldVersion, oldVerification, oldVerified).Scan(&untouched); err != nil || untouched != 1 {
			t.Fatal("denied/rolled-back OTP changed original primary", err)
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil || notices != beforeNotices {
			t.Fatal("denied/rolled-back OTP emitted old notice", err)
		}
		if !options.readSession(cookies) {
			t.Fatal("denied/rolled-back OTP invalidated original session")
		}
	}
	if options.mode == "otp-change-candidate-stale" || options.mode == "otp-change-previous-stale" {
		intervening := origin
		if options.mode == "otp-change-previous-stale" {
			intervening = options.newChangeRequest(cookies, csrf)
			intervening.Address = "intervening-primary@example.invalid"
			pending, err := links.ChangeRequest(ctx, intervening)
			if err != nil || pending.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("genuine intervening fresh-password request", err)
			}
			intervening.Primary.AddressID = pending.AddressID
			if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
				t.Fatal(err)
			}
			select {
			case body := <-messages:
				linkURL, err := url.Parse(body)
				if err != nil {
					t.Fatal(err)
				}
				link, err = capability.ParseProof(linkURL.Query().Get("token"), capability.DefaultLimits())
				if err != nil {
					t.Fatal("genuine intervening link", err)
				}
			case <-ctx.Done():
				t.Fatal("intervening link missing")
			}
		}
		id, _ := identity.NewCommandID()
		callback, _ := url.Parse(intervening.CallbackURL)
		linkCaller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.change-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
		linkCaller.CorrelationID = string(id)
		if out, err := links.ChangeConfirm(ctx, email.ChangeConfirmRequest{TenantID: otpTenant, CommandID: id, Token: link, Callback: *callback, Caller: linkCaller, Network: "127.0.0.1"}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
			var invalid identity.InvalidInputError
			if errors.As(err, &invalid) {
				t.Log("intervening native boundary:", invalid.Field)
			}
			t.Fatal("supported intervening primary mutation", err)
		}
		var candidateVersion, previousVersion uint64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT version FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), string(origin.Primary.AddressID)).Scan(&candidateVersion); err != nil {
			t.Fatal(err)
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT version FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, otpTenant, string(user), oldID).Scan(&previousVersion); err != nil || previousVersion != oldVersion+1 || candidateVersion != map[bool]uint64{true: 2, false: 1}[options.mode == "otp-change-candidate-stale"] {
			t.Fatal("intervening mutation did not isolate expected stale input", err)
		}
		snapshot := func() string {
			t.Helper()
			var state string
			if err := f.pool.Raw().QueryRow(ctx, `SELECT jsonb_build_object('identifiers',(SELECT jsonb_agg(to_jsonb(i) ORDER BY identifier_id) FROM identity.identifiers i WHERE tenant_id=$1 AND user_id=$2),'users',(SELECT jsonb_agg(to_jsonb(u)) FROM identity.users u WHERE tenant_id=$1 AND user_id=$2),'notices',(SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'),'lifecycle',(SELECT count(*) FROM public.identity_outbox_bindings))::text`, otpTenant, string(user)).Scan(&state); err != nil {
				t.Fatal(err)
			}
			return state
		}
		baseline := snapshot()
		for _, input := range []auth.OneTimeCode{wrong, code} {
			confirmation.Code = input
			if out, err := service.EmailChangeConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("stale original candidate/previous authority admitted OTP")
			}
			var used, failed int
			if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 0 || failed != 0 || snapshot() != baseline || options.readSession(cookies) {
				t.Fatal("stale submission compared/debited or changed post-mutation state", err)
			}
		}
		return false
	}
	if strings.HasPrefix(options.mode, "otp-change-factor-") {
		sql := `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`
		if options.mode == "otp-change-factor-missing" {
			sql = `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`
		}
		if options.mode == "otp-change-factor-enrolled" {
			sql = `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1 WHERE tenant_id=$1 AND user_id=$2`
		}
		if _, err := f.pool.Raw().Exec(ctx, sql, otpTenant, string(user)); err != nil {
			t.Fatal("owned authoritative factor fault", err)
		}
		if out, err := service.EmailChangeConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("unknown/enrolled/changed factor admitted email-only OTP")
		}
		assertUnchanged(0)
		return false
	}
	if options.mode == "otp-change-expiry" {
		source, ok := links.(email.ChangeOriginSource)
		if !ok {
			t.Fatal("actual origin source unavailable")
		}
		q := identity.RecoveryQuery{CommandID: origin.Primary.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, RecordID: string(origin.Primary.AddressID), OperationID: "identity.otp.email-change-confirm"}
		original, err := source.ReadChangeOrigin(ctx, q, caller)
		if err != nil {
			t.Fatal(err)
		}
		var expiry time.Time
		if err := f.pool.Raw().QueryRow(ctx, `SELECT expires_at FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&expiry); err != nil || !expiry.Equal(original.Spec.ExpiresAt) {
			t.Fatal("OTP renewed original shorter change validity", err)
		}
		bounded, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			var now time.Time
			if err := f.pool.Raw().QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal("authoritative expiry wait failed", err)
			}
			if !now.Before(expiry) {
				break
			}
			select {
			case <-ticker.C:
			case <-bounded.Done():
				t.Fatal("original change deadline did not expire")
			}
		}
		confirmation.Code = code
		if out, err := service.EmailChangeConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("expired original change admitted a correct code")
		}
		assertUnchanged(0)
		return false
	}
	denied, err := service.EmailChangeConfirm(ctx, confirmation)
	if err == nil || denied.Outcome == identity.CommitOutcomeCommitted || denied.Address != (identity.IdentifierProjection{}) {
		t.Fatal("wrong OTP replaced primary")
	}
	assertUnchanged(1)
	if options.mode == "otp-change-origin-revoked-confirm" {
		revokeOriginFamily()
		recoveryCaller := caller.Clone()
		recoveryCaller.Request.Action = "identity.otp.email-change-confirm.recover"
		if history, err := service.RecoverEmailChange(ctx, otp.EmailChangeRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: recoveryCaller, Flow: flow, Recovery: denied.Recovery}); err != nil || history.Outcome != identity.CommitOutcomeNotCommitted || history.Address != (identity.IdentifierProjection{}) {
			t.Fatal("original-family revocation erased authorized metadata-only history", err)
		}
		for _, input := range []auth.OneTimeCode{wrong, code} {
			confirmation.Code = input
			if out, err := service.EmailChangeConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("newer signin bypassed initiating family revocation")
			}
			assertUnchanged(1)
		}
		return false
	}
	if options.mode == "otp-change-exhaustion" {
		for range 2 {
			if out, err := service.EmailChangeConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
				t.Fatal("wrong-code budget permitted primary replacement")
			}
		}
		assertUnchanged(3)
		confirmation.Code = code
		if out, err := service.EmailChangeConfirm(ctx, confirmation); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("correct code escaped exhausted budget")
		}
		assertUnchanged(3)
		return false
	}
	confirmation.Code = code
	if options.mode == "otp-change-rollback" {
		if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION reject_primary_otp_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned late primary OTP rollback'; END $$; CREATE TRIGGER reject_primary_otp_notice BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION reject_primary_otp_notice()`); err != nil {
			t.Fatal(err)
		}
		out, err := service.EmailChangeConfirm(ctx, confirmation)
		if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("late OTP change failure fabricated success", out.Outcome, err)
		}
		assertUnchanged(2)
		if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER reject_primary_otp_notice ON public.identity_outbox_bindings; DROP FUNCTION reject_primary_otp_notice()`); err != nil {
			t.Fatal(err)
		}
		recoveryCaller := caller.Clone()
		recoveryCaller.Request.Action = "identity.otp.email-change-confirm.recover"
		for range 2 {
			history, err := service.RecoverEmailChange(ctx, otp.EmailChangeRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: recoveryCaller, Flow: flow, Recovery: out.Recovery})
			if err != nil || history.Outcome != identity.CommitOutcomeNotCommitted || history.Address != (identity.IdentifierProjection{}) {
				t.Fatal("late rollback recovery became execution", history.Outcome, err)
			}
		}
		assertUnchanged(2)
		return false
	}
	if options.mode == "otp-change-unknown" {
		f.completionFault.armed.Store(true)
	}
	var confirmed otp.EmailChangeResult
	var linkWinner email.ChangeConfirmResult
	if options.mode == "otp-change-contention" || options.mode == "otp-change-link-race" {
		var group sync.WaitGroup
		var completed [2]bool
		var attempts [2]otp.EmailChangeResult
		start := make(chan struct{})
		group.Add(2)
		for n := range 2 {
			go func() {
				defer group.Done()
				<-start
				if n == 1 && options.mode == "otp-change-link-race" {
					id, _ := identity.NewCommandID()
					callback, _ := url.Parse(origin.CallbackURL)
					linkCaller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.change-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
					linkCaller.CorrelationID = string(id)
					out, e := links.ChangeConfirm(ctx, email.ChangeConfirmRequest{TenantID: otpTenant, CommandID: id, Token: link, Callback: *callback, Caller: linkCaller, Network: "127.0.0.1"})
					completed[n] = e == nil && out.Outcome == identity.CommitOutcomeCommitted
					if completed[n] {
						linkWinner = out
					} else if out.Address != (identity.IdentifierProjection{}) {
						t.Error("losing link disclosed a primary projection")
					}
					return
				}
				out, e := service.EmailChangeConfirm(ctx, confirmation)
				attempts[n] = out
				completed[n] = e == nil && out.Outcome == identity.CommitOutcomeCommitted
				if !completed[n] && out.Address != (identity.IdentifierProjection{}) {
					t.Error("losing OTP disclosed a primary projection")
				}
			}()
		}
		close(start)
		group.Wait()
		winners := 0
		for n, success := range completed {
			if success {
				winners++
				if attempts[n].CommandID != "" {
					confirmed = attempts[n]
				}
			}
		}
		if winners != 1 {
			t.Fatal("competing OTP/link changes did not have exactly one winner", winners)
		}
		if linkWinner.Outcome == identity.CommitOutcomeCommitted {
			q, e := linkWinner.Recovery.Bindings()
			if e != nil {
				t.Fatal(e)
			}
			confirmed = otp.EmailChangeResult{CommandID: q.CommandID, Outcome: linkWinner.Outcome, Address: linkWinner.Address}
		}
		err = nil
	} else {
		confirmed, err = service.EmailChangeConfirm(ctx, confirmation)
	}
	if options.mode == "otp-change-unknown" {
		f.completionFault.armed.Store(false)
		if err == nil || confirmed.Outcome != identity.CommitOutcomeUnknown || confirmed.Address != (identity.IdentifierProjection{}) || !f.completionFault.hit.Load() {
			t.Fatal("lost actual commit acknowledgement did not preserve original ambiguity", err)
		}
		recoveryCaller := caller.Clone()
		recoveryCaller.Request.Action = "identity.otp.email-change-confirm.recover"
		history, err := service.RecoverEmailChange(ctx, otp.EmailChangeRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: recoveryCaller, Flow: flow, Recovery: confirmed.Recovery})
		if err != nil || history.Outcome != identity.CommitOutcomeCommitted || history.CommandID != confirmed.CommandID || history.Address != (identity.IdentifierProjection{}) {
			t.Fatal("ambiguous actual primary change not recovered metadata-only", history.Outcome, err)
		}
		if options.readSession(cookies) {
			t.Fatal("committed unknown primary change preserved old session")
		}
		var primary int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=2 AND verification_version=2 AND is_primary AND verified`, otpTenant, string(user), string(origin.Primary.AddressID)).Scan(&primary); err != nil || primary != 1 {
			t.Fatal("unknown recovery did not preserve sole primary successor", err)
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil || notices != beforeNotices+1 {
			t.Fatal("ambiguous recovery omitted or duplicated original notice", err)
		}
		var used, failed int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed); err != nil || used != 2 || failed != 1 {
			t.Fatal("unknown recovery repeated OTP comparison", err)
		}
		return true
	}
	if err != nil || confirmed.Outcome != identity.CommitOutcomeCommitted {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Log("rejected native boundary", invalid.Field)
		}
		t.Fatal("atomic OTP primary replacement", confirmed.Outcome, err)
	}
	projection, err := confirmed.Address.Bindings()
	if err != nil || projection.IdentifierID != origin.Primary.AddressID || !projection.Primary || !projection.Verified || projection.IdentifierVersion != 2 || projection.VerificationVersion != 2 {
		t.Fatal("OTP primary projection", err)
	}
	var primaries, retained, used, failed int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND is_primary`, otpTenant, string(user)).Scan(&primaries); err != nil || primaries != 1 {
		t.Fatal("ambiguous primary", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND verified AND NOT is_primary AND verified_at=$6`, otpTenant, string(user), oldID, oldVersion+1, oldVerification, oldVerified).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("OTP swap changed verification history", err)
	}
	if options.readSession(cookies) {
		t.Fatal("pre-confirm session survived OTP primary replacement")
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(confirmed.CommandID))
	var path string
	if err := f.pool.Raw().QueryRow(ctx, `SELECT COALESCE(convert_from(r.canonical_record,'UTF8')::jsonb #>> '{attributes,authentication.recovery_path}','') FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1`, command).Scan(&path); err != nil || linkWinner.Outcome != identity.CommitOutcomeCommitted && path != otp.EmailChangeRecoveryPath {
		t.Fatal("primary OTP audit attribution", err)
	}
	caller.Request.Action = "identity.otp.email-change-confirm.recover"
	if linkWinner.Outcome != identity.CommitOutcomeCommitted {
		deniedCaller := caller.Clone()
		deniedCaller.PolicyRevision++
		if out, err := service.RecoverEmailChange(ctx, otp.EmailChangeRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: deniedCaller, Flow: flow, Recovery: confirmed.Recovery}); err == nil || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("withdrawn current recovery policy disclosed original change")
		}
	}
	for range 2 {
		if linkWinner.Outcome == identity.CommitOutcomeCommitted {
			linkCaller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.change-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
			history, err := links.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: linkWinner.Recovery, Caller: linkCaller})
			if err != nil || history.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original winning link recovery", err)
			}
			continue
		}
		recovered, err := service.RecoverEmailChange(ctx, otp.EmailChangeRecoveryRequest{TenantID: otpTenant, UserID: user, Caller: caller, Flow: flow, Recovery: confirmed.Recovery})
		if err != nil || recovered.CommandID != confirmed.CommandID || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Address != (identity.IdentifierProjection{}) {
			t.Fatal("original code-free primary-change recovery", recovered.Outcome, err)
		}
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges WHERE tenant_id=$1 AND challenge_id=$2`, otpTenant, string(sent.CommandID)).Scan(&used, &failed); err != nil || failed != 1 || linkWinner.Outcome != identity.CommitOutcomeCommitted && used != 2 || linkWinner.Outcome == identity.CommitOutcomeCommitted && (used < 1 || used > 2) {
		t.Fatal("OTP/recovery attempt accounting", used, failed, err)
	}
	id, _ := identity.NewCommandID()
	callback, _ := url.Parse(origin.CallbackURL)
	linkCaller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.change-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	linkCaller.CorrelationID = string(id)
	if out, err := links.ChangeConfirm(ctx, email.ChangeConfirmRequest{TenantID: otpTenant, CommandID: id, Token: link, Callback: *callback, Caller: linkCaller, Network: "127.0.0.1"}); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
		t.Fatal("original link repeated OTP replacement")
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("committed old-address notice", err)
	}
	select {
	case body := <-messages:
		if body != emailChangeNotice {
			t.Fatal("old notice leaked code or link")
		}
	case <-ctx.Done():
		t.Fatal("old notice missing")
	}
	select {
	case recipient := <-options.recipients:
		if recipient != oldAddress {
			t.Fatal("notice sent to substituted old address")
		}
	case <-ctx.Done():
		t.Fatal("old notice recipient missing")
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil || notices != beforeNotices+1 {
		t.Fatal("OTP recovery/link duplicated old notice", err)
	}
	return true
}

// Delay the actual success-journal statement after issuance, delivery freshness
// and ordinary current-flow checks. A sequence observes reaching that boundary
// even when the protected transaction rolls back; it grants no domain authority.
func proveEmailChangeFinalIssuanceExpiry(t *testing.T, ctx context.Context, f liveStores, service *reference.EmailOTPChangeService, request otp.EmailChangeRequest, options referenceEmailChangeOptions, cookies []*http.Cookie, oldID string, oldVersion, oldVerification uint64, oldVerified time.Time) {
	t.Helper()
	counts := func() [5]int64 {
		t.Helper()
		var out [5]int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT
(SELECT count(*) FROM otp_store.challenges),
(SELECT COALESCE(sum(cardinality(sent_at)),0) FROM otp_store.send_families),
(SELECT count(*) FROM identity.delivery_intents),
(SELECT count(*) FROM audit.records WHERE action='identity.otp.send' AND outcome=$1),
(SELECT count(*) FROM public.identity_outbox_bindings)`, int16(audit.OutcomeSucceeded)).Scan(&out[0], &out[1], &out[2], &out[3], &out[4]); err != nil {
			t.Fatal("issuance effects observation", err)
		}
		return out
	}
	before := counts()
	if _, err := f.pool.Raw().Exec(ctx, `CREATE SEQUENCE public.email_change_final_boundary;
CREATE FUNCTION public.wait_email_change_final() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE original_expiry timestamptz;
BEGIN
 SELECT expires_at INTO STRICT original_expiry FROM otp_store.challenges
 WHERE tenant_id=NEW.tenant_id AND issue_command_id=NEW.command_id;
 IF original_expiry<=clock_timestamp() THEN RAISE EXCEPTION 'fixture arrived after expiry'; END IF;
 PERFORM nextval('public.email_change_final_boundary');
 PERFORM pg_sleep(extract(epoch FROM original_expiry-clock_timestamp())+0.02);
 RETURN NEW;
END $$;
CREATE TRIGGER wait_email_change_final BEFORE UPDATE ON identity.commands
FOR EACH ROW WHEN (NEW.state='committed' AND NEW.purpose='identity.otp.send')
EXECUTE FUNCTION public.wait_email_change_final()`); err != nil {
		t.Fatal("owned final issuance pause", err)
	}
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(clean, `DROP TRIGGER wait_email_change_final ON identity.commands; DROP FUNCTION public.wait_email_change_final(); DROP SEQUENCE public.email_change_final_boundary`); err != nil {
			t.Error("owned final issuance pause cleanup", err)
		}
	}()
	out, err := service.EmailChangeRequest(ctx, request)
	if err == nil || out.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("OTP issuance committed after original validity expired at final boundary")
	}
	var reached bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT is_called FROM public.email_change_final_boundary`).Scan(&reached); err != nil || !reached {
		t.Fatal("issuance never reached the final original-authority fence", err)
	}
	if after := counts(); after != before {
		t.Fatal("final original expiry retained challenge, send, delivery or success effects", before, after)
	}
	var intact int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND is_primary AND verified_at=$6`, otpTenant, string(request.UserID), oldID, oldVersion, oldVerification, oldVerified).Scan(&intact); err != nil || intact != 1 || !options.readSession(cookies) {
		t.Fatal("final issuance expiry changed original primary or newer session", err)
	}
}
