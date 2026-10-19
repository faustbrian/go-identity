//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identifierlib "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// All account, phone, proof, session and challenge authority comes from the
// genuine enrollment consumer. A new-number request must not replace its phone.
func TestNativePhoneChangeSendIntegration(t *testing.T) {
	for _, transport := range []session.CredentialKind{session.CredentialBearer, session.CredentialCookie} {
		name := map[session.CredentialKind]string{session.CredentialBearer: "bearer", session.CredentialCookie: "cookie"}[transport]
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{"normal", "before-commit", "lost-commit", "concurrent", "concurrent-account-withdrawn", "concurrent-credential-withdrawn", "concurrent-query-withdrawn", "late-factor", "risk-unavailable"} {
				t.Run(mode, func(t *testing.T) {
					testNativeSigninPhaseIntegration(t, "phone replacement", func(t *testing.T, ctx context.Context, pool *database.Pool, signup *SignupService, c SignupConfig, keys *keyring.Provider, fresh func(string, byte) password.SignupRequest) {
						testNativePhoneEnrollment(t, ctx, pool, signup, c, keys, fresh, transport, "change-send:"+mode)
					})
				})
			}
		})
	}
}

func requirePhoneChangeAudit(t *testing.T, ctx context.Context, pool *database.Pool, b identity.CommandBinding, action string) {
	t.Helper()
	subject := "identifier"
	if b.OperationID == phoneChangeSendingOperation().OperationID {
		subject = "otp_challenge"
	}
	// The real risk owner deliberately shares correlation with this command.
	// Select the changed aggregate, not unrelated risk-decision audit records.
	rows, err := pool.Raw().Query(ctx, `SELECT action,canonical_record FROM audit.records WHERE tenant_id=$1 AND correlation_id=$2 AND convert_from(canonical_record,'UTF8')::jsonb->'subject'->>'type'=$3`, string(b.TenantID), b.CorrelationID, subject)
	if err != nil {
		t.Fatal("phone change audit read", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var actual string
		var wire []byte
		if err := rows.Scan(&actual, &wire); err != nil {
			t.Fatal(err)
		}
		record, err := audit.ParseCanonicalJSON(wire, audit.DefaultLimits())
		clear(wire)
		if err != nil || actual != action || record.Attributes()["retention.class"] != "standard" {
			t.Fatalf("phone change persisted audit: canonical=%t action=%s retention=%s", err == nil, actual, record.Attributes()["retention.class"])
		}
		count++
	}
	if rows.Err() != nil || count != 1 {
		t.Fatal("phone change did not persist exactly one canonical audit record")
	}
}

func testNativePhoneChangeSend(t *testing.T, ctx context.Context, pool *database.Pool, signup SignupConfig, keys *keyring.Provider, signinConfig SigninConfig, enrollment PhoneVerificationConfig, sms otppg.PhoneEnrollmentIssuerConfig, deliveryConfig deliverypg.ContributorConfig, proofConfig ReauthenticationConfig, numberPolicy *phone.NumberPolicy, registration password.SignupRequest, user identity.UserID, mode string, transport session.CredentialKind) {
	t.Helper()
	// Apply only the new suffix to the genuinely populated account/proof/phone
	// histories. The native owners provide the SQL; no synthetic authority rows.
	directoryHistory, err := (kernel.PhoneChangeCascadeMigrationSource{Base: kernel.PhoneRemovalCascadeMigrationSource{Base: kernel.IdentifierRemovalCascadeMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 51}, Version: 52}, Version: 53}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range directoryHistory {
		if step.Version() >= 51 {
			if _, err = pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("populated phone change cascade upgrade", err)
			}
		}
	}
	proofHistory, err := (PhoneChangeReauthenticationMigrationSource{Base: PhoneReauthenticationMigrationSource{Base: ActionReauthenticationMigrationSource{Base: EmailReauthenticationMigrationSource{}, Version: 70}, Version: 71}, Version: 72}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range proofHistory {
		if step.Version() == migrations.Version(72) {
			if _, err = pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("populated phone update proof upgrade", err)
			}
		}
	}
	signin, err := NewSigninService(pool, signinConfig)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, _ := nativeSigninFlow(t)
	r.TenantID, r.Caller.Request.Tenant = registration.TenantID, registration.Caller.Request.Tenant
	r.Identifier, r.Password, r.Device = "phone-owner@example.test", registration.Password, "replacement-browser"
	r.PreAuthID, err = identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := session.PreAuthBinding{ID: r.PreAuthID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{160}, Remember: r.Remember, PolicyID: signinConfig.PolicyID, PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.PreAuthDigest(signinConfig.FlowKeys[0], binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: binding, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, signinConfig.Session, flow) != nil {
		t.Fatal("replacement original browser", err)
	}
	authenticated, err := signin.Signin(ctx, r)
	if err != nil || authenticated.State != auth.SignInStateAuthenticated {
		t.Fatal("replacement current genuine session", err)
	}
	bearer, err := authenticated.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	original, err := authenticated.Issuance.Session.Bindings()
	if err != nil || original.UserID != user {
		t.Fatal(err)
	}
	updateTarget := ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.phone.update", Audience: "phone-change-update"}
	proofConfig.Targets = append(proofConfig.Targets, updateTarget)
	proofOwner, err := NewReauthenticationService(pool, proofConfig)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 3, Request: authorization.Request{Tenant: authorization.TenantID(r.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Action: "identity.phone.send-verification", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}}}
	proof, err := proofOwner.Verify(ctx, ReauthenticationRequest{TenantID: r.TenantID, Session: auth.NewBearerCredential(bearer), Password: registration.Password, Target: proofConfig.Targets[0], Caller: caller, Network: "192.0.2.10", Device: "phone-browser"})
	if err != nil || proof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("replacement genuine sending proof", err)
	}
	csrf := session.CSRFToken{}
	sendConfig := ActionPrimaryConfig{Action: "identity.phone.send-verification", Audience: proofConfig.Targets[0].Audience, MaximumAge: 2 * time.Minute, Transport: transport}
	if transport == session.CredentialCookie {
		sendConfig.CSRFKeys, csrf = []session.CSRFKey{signinConfig.CSRFKey}, authenticated.CSRFToken
	}
	updateConfig := sendConfig
	updateConfig.Action, updateConfig.Audience = updateTarget.Action, updateTarget.Audience
	sendPrimary, err := NewActionPrimarySource(proofOwner, sendConfig)
	if err != nil {
		t.Fatal(err)
	}
	updatePrimary, err := NewActionPrimarySource(proofOwner, updateConfig)
	if err != nil {
		t.Fatal(err)
	}
	reset := phoneChangeResetOwner(t, pool, signup, signinConfig, keys)
	issuer, err := otppg.NewPhoneChangeIssuer(sms)
	if err != nil {
		t.Fatal(err)
	}
	var protectedHook atomic.Bool
	var protectedCalls atomic.Uint32
	ready, release := make(chan struct{}, 2), make(chan struct{})
	firstRelease := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	providerBudget := time.Second
	if strings.HasPrefix(mode, "concurrent") {
		// This test provider deliberately waits for the other invocation's
		// full preparation. Give that rendezvous the existing coordinator IO
		// budget; a shorter provider timer tests scheduling, not history fences.
		// Production limits and the outage/factor partitions stay unchanged.
		providerBudget = signinConfig.Coordinator.MaximumDuration
	}
	counters, protected := phoneChangeCounterConfig(t, ctx, pool, enrollment.Risk, providerBudget, func(call context.Context) error {
		if !protectedHook.Load() {
			return nil
		}
		if mode == "risk-unavailable" {
			return errors.New("synthetic protected-provider outage")
		}
		if mode == "late-factor" {
			// Deliberate authority withdrawal in this disposable database, not
			// a fabricated factor or a weaker proof admitted as authentication.
			_, err := pool.Raw().Exec(call, `UPDATE identity_mfa.factor_authorities SET version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(user))
			return err
		}
		position := protectedCalls.Add(1)
		ready <- struct{}{}
		if position == 1 {
			select {
			case <-firstRelease:
				return nil
			case <-release:
				return nil
			case <-call.Done():
				return call.Err()
			}
		}
		select {
		case <-release:
			return nil
		case <-call.Done():
			return call.Err()
		}
	})
	cascade := kernel.IdentifierChangeCascadeConfig{PolicyVersion: 1, Reasons: []string{"user-requested"}, MaximumDuration: time.Hour, ConsumerContracts: map[string]kernel.StatusConsumerContract{}}
	for _, consumer := range identity.IdentifierChangeConsumers() {
		cascade.ConsumerContracts[consumer] = kernel.StatusConsumerContract{Version: 1, Fingerprint: sha256.Sum256([]byte("synthetic-phone-change-contract-v1:" + consumer))}
	}
	requestKeys, err := kernel.NewRequestKeyConfig("phone-change", [32]byte{161}, *signinConfig.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config := PhoneChangeConfig{PolicyID: "phone-change", ConfigurationID: "phone-change-v1", Reason: "user-requested", MaximumDuration: 5 * time.Second, Domain: kernel.PhoneChangeDomainConfig{Directory: enrollment.Domain, Cascade: cascade}, RequestKeys: requestKeys, IntentKey: [32]byte{162}, IdentifierKey: [32]byte{163}, AuthenticationRisk: enrollment.Risk, UpdateRisk: protected, Counters: counters, ActiveEnvelopeKeyID: signup.ActiveEnvelopeKeyID, Issuer: issuer, CurrentAttemptKeyVersion: 1, Notice: PhoneRemovalNoticeConfig{Delivery: deliveryConfig, Templates: []delivery.Template{{ID: "phone-changed", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Your phone number was changed.", ContentType: "text/plain", MaxRenderedBytes: 4096}}, TemplateID: "phone-changed", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, TTL: time.Hour}}
	service, err := NewPhoneChangeService(sendPrimary, updatePrimary, signin, reset, numberPolicy, config, keys)
	if err != nil {
		t.Fatal("replacement actual owner composition", err)
	}
	if err = service.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	old, err := numberPolicy.Canonicalize(ctx, "+12025550123")
	if err != nil {
		t.Fatal(err)
	}
	next, err := numberPolicy.Canonicalize(ctx, "+12025550125")
	if err != nil {
		t.Fatal(err)
	}
	var id identity.IdentifierID
	var oldVersion, verification, userVersion, authority uint64
	if err = pool.Raw().QueryRow(ctx, `SELECT i.identifier_id,i.version,i.verification_version,u.version,u.identifier_version FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id) WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.kind='phone'`, string(r.TenantID), string(user)).Scan(&id, &oldVersion, &verification, &userVersion, &authority); err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("original-phone-replacement-send"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := phone.NewChangeRequest(phone.ChangeRequestSpec{Enrollment: phone.EnrollmentRequestSpec{TenantID: r.TenantID, UserID: user, Number: next, Session: auth.NewBearerCredential(bearer), Proof: proof.Proof, Caller: caller, CSRFToken: csrf, IdempotencyKey: key, Network: "192.0.2.10", Device: "phone-browser"}, PreviousNumber: old, IdentifierID: id, ExpectedIdentifierVersion: oldVersion, ExpectedVerificationVersion: verification})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := service.SendChange(ctx, request)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted {
		t.Fatalf("actual new-number send: outcome=%v error=%v", sent.Outcome, err)
	}
	again, err := service.SendChange(ctx, request)
	if err != nil || again.Binding != sent.Binding || again.Outcome != sent.Outcome {
		t.Fatal("original replacement send was not replayed", err)
	}
	requirePhoneChangeAudit(t, ctx, pool, sent.Binding, "identity.identifier.request_verification")
	command, err := base64.RawURLEncoding.DecodeString(string(sent.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var unchanged bool
	var challenges, deliveries int
	if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT i.canonical_value=$4 AND i.verified AND i.version=$5::numeric AND i.verification_version=$6::numeric AND u.version=$7::numeric AND u.identifier_version=$8::numeric FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id) WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3),(SELECT count(*) FROM phone_codes.challenges WHERE challenge_id=$9),(SELECT count(*) FROM identity.delivery_intents WHERE command_id=$10)`, string(r.TenantID), string(user), string(id), "+12025550123", oldVersion, verification, userVersion, authority, string(sent.Binding.CommandID), command).Scan(&unchanged, &challenges, &deliveries); err != nil || !unchanged || challenges != 1 || deliveries != 1 {
		t.Fatal("replacement send/replay changed phone or duplicated issuance", unchanged, challenges, deliveries, err)
	}
	var captured string
	captured = capturePhoneChangeSMS(t, ctx, pool, signup, keys, deliveryConfig, sms.Templates, r.TenantID)
	if len(captured) != 6 || strings.Contains(captured, "+") {
		t.Fatal("new-number SMS code missing")
	}
	caller.Request.Action = "identity.phone.update"
	updateProof, err := proofOwner.Verify(ctx, ReauthenticationRequest{TenantID: r.TenantID, Session: auth.NewBearerCredential(bearer), Password: registration.Password, Target: updateTarget, Caller: caller, Network: "192.0.2.10", Device: "phone-browser"})
	if err != nil || updateProof.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("distinct genuine replacement proof", err)
	}
	completionFlow, err := otp.NewSessionSendFlow(original.SessionID, auth.NewBearerCredential(bearer))
	if err != nil {
		t.Fatal(err)
	}
	code, err := auth.NewOneTimeCode(captured)
	if err != nil {
		t.Fatal(err)
	}
	updateKey, err := identity.NewIdempotencyKey([]byte("original-phone-update"))
	if err != nil {
		t.Fatal(err)
	}
	completionSpec := phone.UpdateRequestSpec{TenantID: r.TenantID, UserID: user, Caller: caller, Flow: completionFlow, SendCommandID: sent.Binding.CommandID, Code: code, Proof: updateProof.Proof, CSRFToken: csrf, Reason: "user-requested", IdempotencyKey: updateKey}
	for _, mode := range []string{"foreign-proof-record", "changed-reason", "wrong-csrf"} {
		bad := completionSpec
		if mode == "foreign-proof-record" {
			bad.Proof.Proof.ID = proof.Proof.Proof.ID
		} else if mode == "changed-reason" {
			bad.Reason = "security-policy"
		} else {
			bad.CSRFToken, err = session.NewCSRFToken()
			if err != nil {
				t.Fatal(err)
			}
		}
		request, err := phone.NewUpdateRequest(bad)
		if err != nil {
			t.Fatal("malformed negative fixture", err)
		}
		if result, err := service.Update(ctx, request); err == nil || result.Result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("replacement admitted", mode)
		}
	}
	var used, failed int
	if err = pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM phone_codes.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(r.TenantID), string(sent.Binding.CommandID)).Scan(&used, &failed); err != nil || used != 0 || failed != 0 {
		t.Fatal("unadmitted proof/reason charged original code", err)
	}
	wrong := []byte(captured)
	wrong[0] = '0' + (wrong[0]-'0'+1)%10
	badCode, err := auth.NewOneTimeCode(string(wrong))
	clear(wrong)
	if err != nil {
		t.Fatal(err)
	}
	bad := completionSpec
	bad.Code = badCode
	bad.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("original-wrong-phone-update"))
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest, err := phone.NewUpdateRequest(bad)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := service.Update(ctx, wrongRequest)
	if err == nil || denied.Validate() != nil || denied.Result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("wrong replacement OTP was not a recoverable denial", err)
	}
	// Simulate losing that response. Only original caller input remains; replay
	// must recover its server-owned attempt without another code comparison.
	replayedDenial, replayError := service.Update(ctx, wrongRequest)
	if replayedDenial.Validate() != nil || !replayedDenial.Replayed || replayedDenial.Result.Binding != denied.Result.Binding || replayedDenial.Result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatalf("lost wrong-code response: valid=%t replayed=%t same-binding=%t outcome=%v error=%v", replayedDenial.Validate() == nil, replayedDenial.Replayed, replayedDenial.Result.Binding == denied.Result.Binding, replayedDenial.Result.Outcome, replayError)
	}
	changedInput := bad
	changedInput.Code = code
	changedRequest, err := phone.NewUpdateRequest(changedInput)
	if err != nil {
		t.Fatal(err)
	}
	var conflict identity.ConflictError
	if changed, err := service.Update(ctx, changedRequest); !errors.As(err, &conflict) || changed.Result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("retry key admitted a different submitted code", err)
	}
	var untouched bool
	if err = pool.Raw().QueryRow(ctx, `SELECT c.used_attempts,c.failed_attempts,i.canonical_value=$4 AND i.verified AND i.version=$5::numeric AND p.consumed_command_id IS NULL FROM phone_codes.challenges c JOIN identity.identifiers i ON i.tenant_id=c.tenant_id AND i.identifier_id=$3 JOIN identity_password.reauthentication_records p ON p.proof_id=$6 WHERE c.tenant_id=$1 AND c.challenge_id=$2`, string(r.TenantID), string(sent.Binding.CommandID), string(id), "+12025550123", oldVersion, string(updateProof.Proof.Proof.ID)).Scan(&used, &failed, &untouched); err != nil || used != 1 || failed != 1 || !untouched {
		t.Fatal("wrong-code debit changed phone or consumed fresh update proof", err)
	}
	completion, err := phone.NewUpdateRequest(completionSpec)
	if err != nil {
		t.Fatal(err)
	}
	consumer := service
	var fault *signinCommitFault
	if mode == "before-commit" || mode == "lost-commit" {
		fault = &signinCommitFault{before: mode == "before-commit", marker: "UPDATE identity.identifiers SET kind="}
		faulted, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if faulted.Close(cleanup) != nil {
				t.Error("phone replacement fault-pool cleanup")
			}
		}()
		proofs, err := NewReauthenticationService(faulted, proofConfig)
		if err != nil {
			t.Fatal(err)
		}
		send, err := NewActionPrimarySource(proofs, sendConfig)
		if err != nil {
			t.Fatal(err)
		}
		update, err := NewActionPrimarySource(proofs, updateConfig)
		if err != nil {
			t.Fatal(err)
		}
		signin, err := NewSigninService(faulted, signinConfig)
		if err != nil {
			t.Fatal(err)
		}
		consumer, err = NewPhoneChangeService(send, update, signin, phoneChangeResetOwner(t, faulted, signup, signinConfig, keys), numberPolicy, config, keys)
		if err != nil {
			t.Fatal(err)
		}
	}
	var updated phone.UpdateResult
	if strings.HasPrefix(mode, "concurrent") {
		protectedHook.Store(true)
		type observed struct {
			result phone.UpdateResult
			err    error
		}
		outcomes := make(chan observed, 2)
		for range 2 {
			go func() { result, err := consumer.Update(ctx, completion); outcomes <- observed{result, err} }()
		}
		arrived := 0
		var seenEarly []observed
		for arrived < 2 && len(seenEarly) == 0 {
			select {
			case <-ready:
				arrived++
			case seen := <-outcomes:
				seenEarly = append(seenEarly, seen)
			case <-ctx.Done():
				seenEarly = append(seenEarly, <-outcomes)
			}
		}
		if arrived == 2 {
			// Both invocations observed absence before provider work. Let one
			// finish completely while the other remains paused, forcing the
			// latter through the coordinator's existing-history return path.
			close(firstRelease)
			seenEarly = append(seenEarly, <-outcomes)
			first := seenEarly[0]
			if first.err != nil || first.result.Result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("first replacement did not commit before replay gate", first.err,
					"deadline_exceeded", errors.Is(first.err, context.DeadlineExceeded))
			}
			switch mode {
			case "concurrent-account-withdrawn":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(user))
			case "concurrent-credential-withdrawn":
				_, err = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(r.TenantID), string(user), original.Authentication.CredentialID)
			case "concurrent-query-withdrawn":
				policy, ok := signinConfig.Coordinator.QueryPolicy.Authorization.(*phoneRecoveryDisclosurePolicy)
				if !ok {
					t.Fatal("missing actual current-disclosure policy fixture")
				}
				policy.updateDenied.Store(true)
			}
			if err != nil {
				t.Fatal("withdraw current replacement history authority", err)
			}
		}
		close(release)
		released = true
		winners := 0
		for len(seenEarly) < 2 {
			seenEarly = append(seenEarly, <-outcomes)
		}
		if mode != "concurrent" && len(seenEarly) == 2 {
			loser := seenEarly[1]
			_, recoveryError := loser.result.Recovery.Bindings()
			if loser.err == nil || loser.result.Result.Binding.CommandID != "" || recoveryError == nil {
				t.Fatal("withdrawn authority disclosed racing replacement history")
			}
		}
		for _, seen := range seenEarly {
			if seen.err == nil && seen.result.Result.Outcome == identity.CommitOutcomeCommitted {
				if !seen.result.Replayed {
					updated, winners = seen.result, winners+1
				}
			} else if seen.result.Result.Outcome == identity.CommitOutcomeCommitted {
				t.Error("contending replacement returned contradictory committed denial")
			} else {
				t.Logf("contending replacement denial: outcome=%v error=%v", seen.result.Result.Outcome, seen.err)
			}
		}
		if arrived != 2 || winners != 1 {
			t.Fatalf("contending original proof/code: admitted=%d winners=%d", arrived, winners)
		}
		if mode != "concurrent" {
			if err = pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM phone_codes.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(r.TenantID), string(sent.Binding.CommandID)).Scan(&used, &failed); err != nil || used != 2 || failed != 1 {
				t.Fatal("withdrawn racing recovery repeated OTP debit", err)
			}
			return
		}
		protectedHook.Store(false)
		err = nil
	} else {
		protectedHook.Store(mode == "late-factor" || mode == "risk-unavailable")
		updated, err = consumer.Update(ctx, completion)
	}
	if mode == "late-factor" || mode == "risk-unavailable" {
		if err == nil || updated.Validate() != nil || updated.Result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("withdrawn factor/risk did not preserve denied original custody", err)
		}
		if err = pool.Raw().QueryRow(ctx, `SELECT c.used_attempts,c.failed_attempts,i.canonical_value=$4 AND i.version=$5::numeric AND p.consumed_command_id IS NULL FROM phone_codes.challenges c JOIN identity.identifiers i ON i.tenant_id=c.tenant_id AND i.identifier_id=$3 JOIN identity_password.reauthentication_records p ON p.proof_id=$6 WHERE c.tenant_id=$1 AND c.challenge_id=$2`, string(r.TenantID), string(sent.Binding.CommandID), string(id), "+12025550123", oldVersion, string(updateProof.Proof.Proof.ID)).Scan(&used, &failed, &untouched); err != nil || used != 1 || failed != 1 || !untouched {
			t.Fatal("late factor withdrawal charged code or partially replaced phone", err)
		}
		return
	}
	if fault != nil {
		if err == nil || !fault.hit.Load() || updated.Validate() != nil || updated.Result.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("actual replacement COMMIT interruption lost original unknown custody", err)
		}
		caller.Request.Action = "identity.phone.update.recover"
		recovery, err := phone.NewUpdateRecoveryRequest(phone.UpdateRecoveryRequestSpec{TenantID: r.TenantID, UserID: user, Caller: caller, Flow: completionFlow, Recovery: updated.Recovery, CSRFToken: csrf})
		if err != nil {
			t.Fatal(err)
		}
		expected := identity.CommitOutcomeCommitted
		if mode == "before-commit" {
			expected = identity.CommitOutcomeNotCommitted
		}
		for attempt := range 3 {
			history, err := service.RecoverUpdate(ctx, recovery)
			if attempt == 0 && history.Result.Outcome == identity.CommitOutcomeInProgress && history.Result.RetryAfter > 0 && history.Result.RetryAfter <= time.Second {
				wait := time.NewTimer(history.Result.RetryAfter)
				select {
				case <-wait.C:
				case <-ctx.Done():
					wait.Stop()
					t.Fatal(ctx.Err())
				}
				continue
			}
			if err != nil || history.Validate() != nil || !history.Replayed || history.Result.Binding != updated.Result.Binding || history.Result.Outcome != expected {
				t.Fatalf("original replacement recovery: outcome=%v expected=%v error=%v", history.Result.Outcome, expected, err)
			}
		}
		// A response may be lost before the caller receives Recovery. Its
		// original input/key must still find the same immutable server attempt.
		keyed, err := service.Update(ctx, completion)
		if err != nil || keyed.Validate() != nil || !keyed.Replayed || keyed.Result.Binding != updated.Result.Binding || keyed.Result.Outcome != expected {
			t.Fatal("lost response could not recover by original retry key", err)
		}
		var finalized, successor, consumed bool
		var notices int
		if err = pool.Raw().QueryRow(ctx, `SELECT c.state='finalized',i.canonical_value=$4,p.consumed_command_id IS NOT NULL,(SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=$1 AND purpose='identity.phone.change-notification') FROM phone_codes.challenges c JOIN identity.identifiers i ON i.tenant_id=c.tenant_id AND i.identifier_id=$3 JOIN identity_password.reauthentication_records p ON p.proof_id=$5 WHERE c.tenant_id=$1 AND c.challenge_id=$2`, string(r.TenantID), string(sent.Binding.CommandID), string(id), "+12025550125", string(updateProof.Proof.Proof.ID)).Scan(&finalized, &successor, &consumed, &notices); err != nil || finalized != (mode == "lost-commit") || successor != finalized || consumed != finalized || notices != map[bool]int{false: 0, true: 1}[finalized] {
			t.Fatal("interrupted replacement split OTP/proof/directory/notice effects", err)
		}
		return
	}
	if err != nil || updated.Result.Outcome != identity.CommitOutcomeCommitted || updated.Validate() != nil {
		var invalid identity.InvalidInputError
		if errors.As(err, &invalid) {
			t.Fatalf("genuine replacement rejected at native field %s", invalid.Field)
		}
		t.Fatalf("genuine atomic phone replacement: outcome=%v error=%v", updated.Result.Outcome, err)
	}
	requirePhoneChangeAudit(t, ctx, pool, updated.Result.Binding, "identity.identifier.change")
	if err = pool.Raw().QueryRow(ctx, `SELECT i.canonical_value=$4 AND i.verified AND i.version=$5::numeric AND i.verification_version=$6::numeric AND u.version=$7::numeric AND u.identifier_version=$8::numeric FROM identity.identifiers i JOIN identity.users u USING(tenant_id,user_id) WHERE i.tenant_id=$1 AND i.user_id=$2 AND i.identifier_id=$3`, string(r.TenantID), string(user), string(id), "+12025550125", oldVersion+1, verification+1, userVersion+1, authority+1).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("replacement did not publish exact verified successor", err)
	}
	caller.Request.Action = "identity.phone.update.recover"
	recovery, err := phone.NewUpdateRecoveryRequest(phone.UpdateRecoveryRequestSpec{TenantID: r.TenantID, UserID: user, Caller: caller, Flow: completionFlow, Recovery: updated.Recovery, CSRFToken: csrf})
	if err != nil {
		t.Fatal(err)
	}
	history, err := service.RecoverUpdate(ctx, recovery)
	if err != nil || history.Validate() != nil || !history.Replayed || history.Result.Binding != updated.Result.Binding || history.Result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("code-free replacement recovery did not retain original receipt", err)
	}
	if repeated, err := service.Update(ctx, completion); err != nil || !repeated.Replayed || repeated.Validate() != nil || repeated.Result.Binding != updated.Result.Binding || repeated.Result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("original keyed completion did not recover committed history", err)
	}
	newSubmit := completionSpec
	newSubmit.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("new-submit-after-phone-replacement"))
	if err != nil {
		t.Fatal(err)
	}
	newRequest, err := phone.NewUpdateRequest(newSubmit)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := service.Update(ctx, newRequest); err == nil || result.Result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("new logical submit reused retired session or consumed proof")
	}
	if err = pool.Raw().QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM phone_codes.challenges WHERE tenant_id=$1 AND challenge_id=$2`, string(r.TenantID), string(sent.Binding.CommandID)).Scan(&used, &failed); err != nil || used != 2 || failed != 1 {
		t.Fatal("successful replacement/re-entry did not conserve OTP attempt count", err)
	}
	reader, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: signinConfig.Session, Profile: signinConfig.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: signinConfig.Profile.Audience, Clock: signinConfig.Issuance.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{signinConfig.Issuance.LookupKey}}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := session.ParseToken(bearer)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, parsed)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential}); err != nil || current.Authenticated {
		t.Fatal("replacement left original session authenticated", err)
	}
	if body := capturePhoneChangeMessage(t, ctx, pool, signup, keys, deliveryConfig, config.Notice.Templates, r.TenantID, "+12025550123", "identity.phone.change-notification"); body != "Your phone number was changed." {
		t.Fatal("old-number change notice did not retain required template")
	}
	for _, source := range []migrations.Source{
		PhonePasswordSigninMigrationSource{Base: MigrationSource{}, Version: 90},
		sessionpg.PhonePasswordSigninMigrationSource{Schema: signinConfig.Session.Schema, Version: 90, Predecessor: sessionpg.UsernameSigninAfterPassword},
	} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if step.Version() >= 90 {
				if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
					t.Fatal("phone signin selected history", err)
				}
			}
		}
	}
	phoneSignin := signinConfig
	phoneSignin.Phone = numberPolicy
	testPhoneChangeCurrentSignin(t, ctx, pool, phoneSignin, registration, "+12025550123", false)
	testPhoneChangeCurrentSignin(t, ctx, pool, phoneSignin, registration, "+12025550125", true)
	testPhoneChangeCurrentSignin(t, ctx, pool, signinConfig, registration, "phone-owner@example.test", true)
	resetID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	resetKey, err := identity.NewIdempotencyKey([]byte("independent-reset-after-phone-change"))
	if err != nil {
		t.Fatal(err)
	}
	resetCaller := authorization.DecisionContext{PolicyRevision: 3, CorrelationID: string(resetID), Request: authorization.Request{Tenant: authorization.TenantID(r.TenantID), Action: "identity.password.reset-request", Subject: authorization.Subject{ID: signinTestActor, Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.reset-request"}}}
	resetResult, err := reset.ResetRequest(ctx, password.ResetRequestRequest{TenantID: r.TenantID, CommandID: resetID, Identifier: "phone-owner@example.test", CallbackURL: "https://identity.test/reset", IdempotencyKey: resetKey, Caller: resetCaller, Origin: "https://identity.test", Network: "192.0.2.10", Device: "independent-recovery"})
	if err != nil || resetResult.Validate() != nil || !resetResult.Accepted {
		raw, decode := base64.RawURLEncoding.DecodeString(string(resetResult.CommandID))
		var state string
		var generation uint64
		var output, plan bool
		observation := pool.Raw().QueryRow(ctx, `SELECT state,COALESCE(preparation_started_generation,0),preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL FROM identity.commands WHERE tenant_id=$1 AND purpose='identity.password.reset-request' AND command_id=$2`, string(r.TenantID), raw).Scan(&state, &generation, &output, &plan)
		t.Fatalf("independent reset request: state=%s generation=%d output=%t plan=%t decode=%v observation=%v error=%v", state, generation, output, plan, decode, observation, err)
	}
}

func testPhoneChangeCurrentSignin(t *testing.T, ctx context.Context, pool *database.Pool, config SigninConfig, registration password.SignupRequest, identifier string, allowed bool) {
	t.Helper()
	owner, err := NewSigninService(pool, config)
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, _ := nativeSigninFlow(t)
	r.TenantID, r.Caller.Request.Tenant = registration.TenantID, registration.Caller.Request.Tenant
	r.Identifier, r.Password, r.Device = identifierlib.Input(identifier), registration.Password, "post-replacement-browser"
	action := "identity.password.signin"
	var commitment [32]byte
	if config.Phone != nil {
		action = "identity.phone.password-signin"
		number, err := config.Phone.Canonicalize(ctx, identifier)
		if err != nil {
			t.Fatal(err)
		}
		commitment, err = phone.PasswordSigninIdentifierBinding(number, r.TenantID, config.IdentifierKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	r.Caller.Request.Action, r.Caller.Request.Resource.ID = authorization.Action(action), authorization.ResourceID(action)
	r.PreAuthID, err = identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := session.PreAuthBinding{ID: r.PreAuthID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: action, Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{173}, Remember: r.Remember, PolicyID: config.PolicyID, PolicyVersion: 3, IdentifierBinding: commitment}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	token, err := session.ParseToken(r.Cookie.Token())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.PreAuthDigest(config.FlowKeys[0], b)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, config.Session, flow) != nil {
		t.Fatal("post-replacement genuine browser", err)
	}
	result, err := owner.Signin(ctx, r)
	if !allowed {
		if err != nil || result.Validate() != nil || result.State != auth.SignInStateRejected || result.Issuance.Token != (session.Token{}) {
			t.Fatal("retired phone lost uniform password denial", err)
		}
		return
	}
	if err != nil || result.State != auth.SignInStateAuthenticated {
		t.Fatal("new phone or retained independent email signin denied", err)
	}
	wire, err := result.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	token, err = session.ParseToken(wire)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: config.Session, Profile: config.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: config.Profile.Audience, Clock: config.Issuance.Clock, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{config.Issuance.LookupKey}}})
	if err != nil {
		t.Fatal(err)
	}
	if current, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential}); err != nil || !current.Authenticated {
		t.Fatal("post-replacement signin did not yield a usable session", err)
	}
}

// The independent reset owner is genuinely constructible from supported native
// APIs; the test supplies only configuration/template/key/provider seams.
func phoneChangeResetOwner(t *testing.T, pool *database.Pool, c SignupConfig, signin SigninConfig, keys *keyring.Provider) *ResetService {
	t.Helper()
	signer, err := capability.NewHMACSHA256Signer("phone-change-reset", bytes.Repeat([]byte{164}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{164}, 32))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.test", ID: "phone-change-reset", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	deliveryConfig := c.Delivery
	deliveryConfig.Resolver = resolver
	deliveryConfig.Endpoint = "https://identity.test/reset"
	// Signup's template allowlist is intentionally a different origin. Select
	// the reset template's actual URL policy rather than weakening either one.
	deliveryConfig.TemplateID = "phone-change-reset"
	deliveryConfig.Renderer, err = delivery.NewTemplateRenderer([]delivery.Template{{ID: deliveryConfig.TemplateID, Version: uint64(deliveryConfig.TemplateVersion), Channel: delivery.ChannelEmail, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://identity.test"}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	requestKeys, err := kernel.NewRequestKeyConfig("phone-change-reset", [32]byte{165}, *signin.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	config := ResetConfig{Repository: c.Repository, ConfigurationID: "phone-change-reset-v1", PolicyID: "phone-change-reset", Profile: password.ResetProfileConfig{Issuer: "https://identity.test", Audience: "phone-change-reset", MaximumLifetime: 2 * time.Minute, Callbacks: []string{"https://identity.test/reset"}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {166}}}, Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.test", Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "phone-change-reset", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {167}}, PreparationTimeout: time.Second}, Screening: c.Screening, Risk: c.Risk, Coordinator: signin.Coordinator, Session: signin.Session, GlobalAuthorityID: signin.Profile.GlobalAuthorityID, AuthorizationNamespace: signin.Profile.PolicyNamespace, Origins: c.Origins, ActiveEnvelopeKeyID: c.ActiveEnvelopeKeyID, IdentifierKey: [32]byte{168}, Request: &ResetRequestConfig{Address: c.Address, RequestKeys: requestKeys, Lifetime: time.Minute, IssuanceCustody: issuerpg.IssuancePreparationConfig{Deployment: "phone-change-reset", ActiveEnvelopeKey: "phone-change-reset", EnvelopeKeys: map[string][]byte{"phone-change-reset": bytes.Repeat([]byte{169}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "phone-change-reset", HMAC: bytes.Repeat([]byte{164}, 32)}}, Clock: time.Now}, Delivery: deliveryConfig}}
	owner, err := NewResetService(pool, config, keys)
	if err != nil {
		t.Fatal("real independent reset composition", err)
	}
	return owner
}

func phoneChangeCounterConfig(t *testing.T, ctx context.Context, pool *database.Pool, config risk.AuthenticationAdmissionCustodyConfig, providerBudget time.Duration, before func(context.Context) error) (riskpg.Config, risk.ProtectedProviderAdmissionCustodyConfig) {
	t.Helper()
	history, err := (riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "phone_change_risk", Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range history {
		if _, err = pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	// Match the original counted authentication policy exactly, but keep the
	// protected velocity mutation in its existing native command participant.
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{170}, 32))
	if err != nil {
		t.Fatal(err)
	}
	// Protected facts and transactional counters must share this actual policy
	// owner, not a separately reconstructed but equal policy description.
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: providerBudget, Sources: []risk.Source{
		{Name: "status", Version: "phone-change-policy-v1", Timeout: providerBudget, Read: func(ctx context.Context, c risk.Context) (risk.Signal, error) {
			if err := before(ctx); err != nil {
				return risk.Signal{}, err
			}
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(time.Minute)}, ctx.Err()
		}},
		{Name: "velocity", Version: "native-counter-only", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
			return risk.Signal{}, errors.New("protected velocity must remain native")
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	protected := risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "phone-change-protected-v1", Keys: config.Keys}
	return riskpg.Config{Schema: "phone_change_risk", PolicyVersion: 3, EvidenceKeys: config.Keys, EnvelopeKeys: map[string][]byte{"wrap": bytes.Repeat([]byte{171}, 32)}, CurrentEnvelopeKey: "wrap", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}}, EnforceLockouts: true}, protected
}

func capturePhoneChangeSMS(t *testing.T, ctx context.Context, pool *database.Pool, c SignupConfig, keys *keyring.Provider, custody deliverypg.ContributorConfig, templates []delivery.Template, tenant identity.TenantID) string {
	t.Helper()
	body := capturePhoneChangeMessage(t, ctx, pool, c, keys, custody, templates, tenant, "+12025550125", "otp-phone-verification")
	if !strings.HasPrefix(body, "Code: ") {
		t.Fatal("replacement SMS did not retain code template")
	}
	return strings.TrimPrefix(body, "Code: ")
}

func capturePhoneChangeMessage(t *testing.T, ctx context.Context, pool *database.Pool, c SignupConfig, keys *keyring.Provider, custody deliverypg.ContributorConfig, templates []delivery.Template, tenant identity.TenantID, recipient, purpose string) string {
	t.Helper()
	var intents int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=$1 AND purpose=$2`, string(tenant), purpose).Scan(&intents); err != nil || intents == 0 {
		t.Fatal("actual message intent omitted required purpose", err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	policy := delivery.DefaultConfig()
	policy.Production, policy.DedupeTTL = true, 25*time.Hour
	authorize, err := authorization.NewDecisionService(signupVerificationWorkerPolicy{3})
	if err != nil {
		t.Fatal(err)
	}
	queue, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: custody, Coordinator: c.Coordinator, PolicyID: "phone-worker", PolicyVersion: 3, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{138}, Policies: map[uint64]delivery.Config{1: policy}, StateTracking: true}, crypto, authorize, templates)
	if err != nil {
		t.Fatal(err)
	}
	var body string
	calls := 0
	worker, err := queue.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 3, CorrelationID: "phone-worker", Request: authorization.Request{Tenant: authorization.TenantID(tenant), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "phone-worker", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "phone-worker"}}}, ProviderConfigVersion: 2}, signupVerificationSender(func(_ context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		if a.Recipient != recipient {
			t.Error("replacement SMS changed destination/content")
		}
		calls++
		body = string(a.Body)
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.ProcessOne(ctx)
	if err != nil || !result.Claimed || calls != 1 {
		t.Fatal("actual replacement encrypted SMS worker", err)
	}
	return body
}
