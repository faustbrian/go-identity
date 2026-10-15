//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/reference"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
)

const emailChangeNotice = "Your primary email address was changed."

type referenceEmailChangeOptions struct {
	readSession func([]*http.Cookie) bool
	recipients  <-chan string
	mode        string
}

// Only the external sender seam is controlled. Native domain, session,
// transaction, key custody, policy, queue and worker owners are real.
type emailChangeCaptureSender struct {
	messages   chan<- string
	recipients chan<- string
}

func (s emailChangeCaptureSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	if a.Body == emailChangeNotice {
		select {
		case s.recipients <- a.Recipient:
		case <-ctx.Done():
			return delivery.DeliveryResult{}, ctx.Err()
		}
	}
	select {
	case s.messages <- a.Body:
		return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
	case <-ctx.Done():
		return delivery.DeliveryResult{}, ctx.Err()
	}
}

func TestReferencePostgresEmailManagementChange(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true})
}

func TestReferencePostgresEmailChangeRollback(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailChangeCase: "rollback"})
}

func TestReferencePostgresEmailChangeConcurrentConfirmation(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailChangeCase: "race"})
}

func TestReferencePostgresEmailChangeHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, emailManagementChange: true, emailChangeCase: "http"})
}

func configureReferenceEmailChange(t *testing.T, ctx context.Context, f liveStores, c *passwordpg.EmailManagementConfig) {
	t.Helper()
	items, err := (riskpg.EmailChangeCounterMigrationSource{Schema: "risk_store", Version: 1701}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, items[0].UpSQL()); err != nil {
		t.Fatal("selected email-change counter migration", err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "email-change-notice", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: emailChangeNotice, ContentType: "text/plain", MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	c.Change = &email.ChangeProfile{CurrentAddress: email.PrimaryOrSoleVerifiedAddress, Sessions: email.InvalidateIdentifierSessions}
	c.ChangeNotification = &passwordpg.EmailChangeNotificationConfig{Renderer: renderer, TemplateID: "email-change-notice", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: [32]byte{214}, Timeout: time.Second}
	// No clock/authority is fabricated; this explicit supported profile has the
	// same bounded five-minute configured email lifetime and genuine fresh proof.
	c.Lifetime = 5 * time.Minute
}

func proveReferenceEmailChangeJourney(t *testing.T, ctx context.Context, f liveStores, service emailManagementConsumer, workers reference.WorkerSet, messages <-chan string, options referenceEmailChangeOptions, origin string, user identity.UserID, cookies []*http.Cookie, csrf string, freshLogin func(...string) ([]*http.Cookie, string), request func([]*http.Cookie, string) passwordpg.EmailManagementRequest) {
	t.Helper()
	if !options.readSession(cookies) {
		t.Fatal("genuine source session unavailable")
	}
	previousID, previousAddress := "", "registered@example.invalid"
	for n, candidate := range []string{"new-primary@example.invalid", "replacement-primary@example.invalid"} {
		intent := request(cookies, csrf)
		intent.Address = email.AddressInput(candidate)
		if n == 1 {
			intent.Primary.AddressID = "managed-second-candidate"
		}
		var oldVersion, oldVerification uint64
		var oldPrimary bool
		var verifiedAt time.Time
		if err := f.pool.Raw().QueryRow(ctx, `SELECT identifier_id,version,verification_version,is_primary,verified_at FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND canonical_value=$3`, otpTenant, string(user), previousAddress).Scan(&previousID, &oldVersion, &oldVerification, &oldPrimary, &verifiedAt); err != nil || oldPrimary != (n == 1) {
			t.Fatal("real original-address profile mismatch", err)
		}
		pending, err := service.ChangeRequest(ctx, intent)
		if err != nil || pending.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("public native change request", pending.Outcome, err)
		}
		intent.Primary.CommandID, intent.Primary.AddressID = pending.CommandID, pending.AddressID
		query := identity.RecoveryQuery{CommandID: intent.Primary.CommandID, TenantID: otpTenant, UserID: user, ActorID: identity.ActorID(user), ActorKind: authorization.SubjectUser, OperationID: "identity.email.change-request", RecordID: string(intent.Primary.AddressID)}
		observed, e := service.ChangeRequestRecover(ctx, query, intent.Primary.Caller)
		if e != nil || observed.Outcome != identity.CommitOutcomeCommitted || observed.AddressID != intent.Primary.AddressID || observed.IdentifierVersion != 1 {
			t.Fatal("pending change request has no original metadata recovery", e)
		}
		var untouched int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND is_primary=$6 AND verified_at=$7`, otpTenant, string(user), previousID, oldVersion, oldVerification, oldPrimary, verifiedAt).Scan(&untouched); err != nil || untouched != 1 {
			t.Fatal("request replaced original before possession", err)
		}
		if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
			t.Fatal(err)
		}
		var proof capability.Proof
		var deliveredToken string
		select {
		case body := <-messages:
			link, e := url.Parse(body)
			if e != nil {
				t.Fatal("candidate delivery malformed")
			}
			deliveredToken = link.Query().Get("token")
			proof, e = capability.ParseProof(deliveredToken, capability.DefaultLimits())
			if e != nil {
				t.Fatal("candidate delivery has no owned proof")
			}
		case <-ctx.Done():
			t.Fatal("candidate delivery missing")
		}
		// A genuine new login carries the post-request authority. Confirmation
		// must invalidate it, not merely the already-stale initiating cookie.
		currentCookies, currentCSRF := freshLogin(previousAddress)
		if !options.readSession(currentCookies) {
			t.Fatal("post-request source session unavailable")
		}
		caller := authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "reference-change-confirm", Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Action: "identity.email.change-confirm", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
		for range 2 {
			rateUser, challenge, lifetime, err := service.ChangeConfirmationRateSource(ctx, proof, intent.CallbackURL, caller)
			if err != nil || rateUser != user || challenge == "" || lifetime != 5*time.Minute {
				t.Fatal("native change transport has no original challenge-rate source", err)
			}
		}
		for range 2 {
			if valid, e := service.ValidateManagedVerification(ctx, proof, intent.CallbackURL, caller); e != nil || !valid {
				t.Fatal("change inspection consumed or denied original", e)
			}
		}
		if !options.readSession(currentCookies) {
			t.Fatal("scanner changed current session")
		}
		command, _ := identity.NewCommandID()
		callback, _ := url.Parse(intent.CallbackURL)
		confirmation := email.ChangeConfirmRequest{TenantID: otpTenant, CommandID: command, Token: proof, Callback: *callback, Caller: caller, Network: "127.0.0.1"}
		wrong := confirmation
		wrong.Callback.RawQuery = "changed=true"
		if out, e := service.ChangeConfirm(ctx, wrong); e == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("foreign callback authorized primary change")
		}
		if options.mode == "rollback" {
			proveReferenceEmailChangeRollback(t, ctx, f, service, options, currentCookies, confirmation, previousID, oldVersion, oldVerification, verifiedAt)
			return
		}
		var confirmed email.ChangeConfirmResult
		if options.mode == "race" {
			type completion struct {
				result email.ChangeConfirmResult
				err    error
			}
			results := make(chan completion, 2)
			start := make(chan struct{})
			var group sync.WaitGroup
			group.Add(2)
			other := confirmation
			other.CommandID, _ = identity.NewCommandID()
			for _, input := range []email.ChangeConfirmRequest{confirmation, other} {
				go func(r email.ChangeConfirmRequest) {
					defer group.Done()
					<-start
					out, err := service.ChangeConfirm(ctx, r)
					results <- completion{out, err}
				}(input)
			}
			close(start)
			group.Wait()
			close(results)
			winners := 0
			for completed := range results {
				if completed.err == nil && completed.result.Outcome == identity.CommitOutcomeCommitted {
					winners++
					confirmed = completed.result
					q, _ := confirmed.Recovery.Bindings()
					confirmation.CommandID = q.CommandID
				} else if completed.result.Address != (identity.IdentifierProjection{}) {
					t.Fatal("losing confirmation disclosed candidate")
				}
			}
			if winners != 1 {
				t.Fatal("concurrent original proof did not have exactly one winner", winners)
			}
		} else if options.mode == "http" || f.afterManagedChangeConfirmation != nil {
			if f.afterManagedChangeConfirmation != nil {
				f.afterManagedChangeConfirmation(confirmation, deliveredToken)
			} else {
				proveReferenceEmailChangeHTTPS(t, ctx, f, service, confirmation, intent.Primary.AddressID, deliveredToken, origin)
			}
			// Observe the genuine original command after HTTP completion rather
			// than constructing domain authority from a response projection.
			confirmed, e = service.ChangeConfirm(ctx, confirmation)
			if e != nil || !confirmed.Replayed || confirmed.Address != (identity.IdentifierProjection{}) {
				t.Fatal("HTTP completion did not retain native original receipt", e)
			}
		} else {
			confirmed, e = service.ChangeConfirm(ctx, confirmation)
		}
		if e != nil {
			var rejected identity.InvalidInputError
			if errors.As(e, &rejected) {
				t.Logf("rejected native boundary: %s", rejected.Field)
			}
		}
		if e != nil || confirmed.Outcome != identity.CommitOutcomeCommitted || confirmed.Validate() != nil {
			t.Fatal("atomic new-address confirmed change", confirmed.Outcome, e)
		}
		if options.mode != "http" && f.afterManagedChangeConfirmation == nil {
			projection, e := confirmed.Address.Bindings()
			if e != nil || !projection.Primary || !projection.Verified || projection.IdentifierVersion != 2 || projection.VerificationVersion != 2 {
				t.Fatal("candidate not verified/promoted once")
			}
		}
		var primaries, retained int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND is_primary`, otpTenant, string(user)).Scan(&primaries); err != nil || primaries != 1 {
			t.Fatal("ambiguous primary after change", err)
		}
		expectedOldVersion := oldVersion
		if oldPrimary {
			expectedOldVersion++
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND NOT is_primary AND verified AND verified_at=$6`, otpTenant, string(user), previousID, expectedOldVersion, oldVerification, verifiedAt).Scan(&retained); err != nil || retained != 1 {
			t.Fatal("primary swap rewrote original verification history", err)
		}
		if options.readSession(currentCookies) {
			t.Fatal("identifier-session invalidation left a saved current session admitted")
		}
		_ = currentCSRF
		replayed, e := service.ChangeConfirm(ctx, confirmation)
		if e != nil || replayed.Outcome != identity.CommitOutcomeCommitted || !replayed.Replayed || replayed.Address != (identity.IdentifierProjection{}) {
			t.Fatal("exact change replay repeated domain/disclosure", e)
		}
		recovered, e := service.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: confirmed.Recovery, Caller: caller})
		if e != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("proof-free original change recovery", e)
		}
		foreign := caller.Clone()
		foreign.Request.Tenant = "foreign"
		if _, err := service.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: confirmed.Recovery, Caller: foreign}); err == nil {
			t.Fatal("foreign change recovery disclosed history")
		}
		second := confirmation
		second.CommandID, _ = identity.NewCommandID()
		if out, err := service.ChangeConfirm(ctx, second); err == nil || out.Outcome == identity.CommitOutcomeCommitted || out.Address != (identity.IdentifierProjection{}) {
			t.Fatal("second command reused consumed change")
		}
		if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
			t.Fatal("old notification dispatch", err)
		}
		select {
		case body := <-messages:
			if body != emailChangeNotice {
				t.Fatal("old notice contains link or unexpected private content")
			}
		case <-ctx.Done():
			t.Fatal("old notification missing")
		}
		select {
		case address := <-options.recipients:
			if address != previousAddress {
				t.Fatal("notice did not reach exact original old address")
			}
		case <-ctx.Done():
			t.Fatal("old recipient absent")
		}
		var uses, notices int
		if err := f.pool.Raw().QueryRow(ctx, `SELECT COALESCE(sum(uses),0) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$2`, otpTenant, string(intent.Primary.CommandID)).Scan(&uses); err != nil || uses != 1 {
			t.Fatal("inspection/replay repeated proof consumption", err)
		}
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'`).Scan(&notices); err != nil || notices != n+1 {
			t.Fatal("old notification duplicated or absent", err)
		}
		cookies, csrf = freshLogin(candidate)
		if !options.readSession(cookies) {
			t.Fatal("new verified primary cannot authenticate a fresh session")
		}
		previousAddress = candidate
		if options.mode == "race" {
			return
		}
	}
}

func proveReferenceEmailChangeRollback(t *testing.T, ctx context.Context, f liveStores, service emailManagementConsumer, options referenceEmailChangeOptions, cookies []*http.Cookie, r email.ChangeConfirmRequest, oldID string, oldVersion, oldVerification uint64, verifiedAt time.Time) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION managed_change_fixture_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic late change rollback'; END $$; CREATE TRIGGER managed_change_fixture_fail BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION managed_change_fixture_fail()`); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(bounded, `DROP TRIGGER IF EXISTS managed_change_fixture_fail ON public.identity_outbox_bindings; DROP FUNCTION IF EXISTS managed_change_fixture_fail()`); err != nil {
			t.Error("late change fixture cleanup", err)
		}
	}
	t.Cleanup(cleanup)
	failed, err := service.ChangeConfirm(ctx, r)
	if err == nil || failed.Outcome != identity.CommitOutcomeNotCommitted || failed.Address != (identity.IdentifierProjection{}) {
		t.Fatal("late change failure fabricated success", failed.Outcome, err)
	}
	cleanup()
	q, e := failed.Recovery.Bindings()
	if e != nil {
		t.Fatal("failed original change lost recovery", e)
	}
	var unchanged, pending, uses, notices, audits, events, failedAudits int
	command, _ := base64.RawURLEncoding.DecodeString(string(r.CommandID))
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4 AND verification_version=$5 AND verified AND NOT is_primary AND verified_at=$6`, otpTenant, string(q.UserID), oldID, oldVersion, oldVerification, verifiedAt).Scan(&unchanged); err != nil || unchanged != 1 {
		t.Fatal("late failure changed original address", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=1 AND verification_version=1 AND NOT verified AND NOT is_primary`, otpTenant, string(q.UserID), q.RecordID).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("late failure verified/promoted pending candidate", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE purpose='identity.email.change-notification'),(SELECT COALESCE(sum(uses),0) FROM public.capability_identity_one_use WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records a ON a.record_id=b.event_id WHERE b.command_id=$2 AND a.outcome=$3),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$2),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records a ON a.record_id=b.event_id WHERE b.command_id=$2 AND a.outcome=$4)`, string(r.CommandID), command, int16(audit.OutcomeSucceeded), int16(audit.OutcomeFailed)).Scan(&notices, &uses, &audits, &events, &failedAudits); err != nil || notices != 0 || uses != 0 || audits != 0 || events != 0 || failedAudits != 1 {
		t.Fatal("late failure effects", "notices", notices, "uses", uses, "auditBindings", audits, "events", events, err)
	}
	if !options.readSession(cookies) {
		t.Fatal("failed primary change invalidated post-request session")
	}
	recovered, err := service.ChangeRecover(ctx, email.ChangeRecoveryRequest{Recovery: failed.Recovery, Caller: r.Caller})
	var dependencyFailure identity.UnavailableError
	if recovered.Outcome != identity.CommitOutcomeNotCommitted || recovered.Validate() != nil || err != nil && !errors.As(err, &dependencyFailure) {
		t.Fatal("late failure recovery invented commit or lost proven rollback", recovered.Outcome, err)
	}
	if valid, err := service.ValidateManagedVerification(ctx, r.Token, r.Callback.String(), r.Caller); err == nil || valid {
		t.Fatal("terminal aborted change grant was resurrected")
	}
}
