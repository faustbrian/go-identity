//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	"github.com/faustbrian/go-identity/risk"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Actual recovery browser, verified phone, password, enrolled TOTP and committed
// original risk precede this request. All consuming, SMS, canonical capability,
// delivery, audit and outbox effects use real owners and one kernel Work.
func testPhonePasswordRecoveryRequest(t *testing.T, ctx context.Context, pool *database.Pool, config SigninConfig, selected phonePasswordRecoverySelection, input phone.PasswordResetRequestRequestSpec, admission *phonePasswordRecoveryRisk, original risk.PhoneEvidenceRequest, use risk.EvidenceUse, signup SignupConfig, keys *keyring.Provider, rollback, keyed bool, numbers *phone.NumberPolicy, riskConfig phonePasswordRecoveryRiskConfig, complete nativePhoneResetProfile, totpSecret []byte) {
	t.Helper()
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	deliveryCustody := deliverypg.ContributorConfig{Deployment: "phone-reset-request", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {218}}, ActiveEnvelopeKeyID: signup.ActiveEnvelopeKeyID, PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{2: {Provider: "sms", PolicyVersion: 1}}}
	owner, err := deliverypg.NewContributor(deliveryCustody, crypto)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := otppg.NewAttemptCodec(otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"reset-wrap": bytes.Repeat([]byte{219}, 32)}, CurrentWrappingKey: "reset-wrap", AttemptKeys: map[uint32][32]byte{1: {220}}, CodeKeys: map[uint32][32]byte{1: {221}}, CurrentCodeKeyVersion: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposePasswordReset, Alphabet: "0123456789", Length: 6, TTL: time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sms, err := otppg.NewPhonePasswordResetIssuer(otppg.PhonePasswordResetIssuerConfig{Store: otppg.ContributorConfig{Schema: "phone_codes", GlobalAuthorityID: config.Profile.GlobalAuthorityID, UserPolicyNamespace: config.Profile.PolicyNamespace, Codec: codec, LockoutKey: [32]byte{133}, PreAuth: config.Session, PreAuthCookieKeys: map[uint32][]byte{1: bytes.Repeat([]byte{43}, 32)}}, Delivery: owner, Policy: policy, TemplateID: "reset-code", TemplateVersion: 1, ProviderVersion: 2, LocaleChain: []string{"en"}, Templates: []delivery.Template{{ID: "reset-code", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Reset code: {{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 4096}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = sms.Initialize(ctx, pool); err != nil {
		t.Fatal("actual reset SMS startup", err)
	}
	child := testPhoneMFAChallengeConfig(t, config)
	issuer, err := issuerpg.NewIssuer(child.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := issuerpg.NewIssuancePreparationCodec(issuer, child.Custody)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := selected.flow.Bindings()
	resetProfile, err := password.NewPhoneResetProfile(password.ResetProfileConfig{Issuer: "https://identity.test", Audience: config.Profile.Audience, MaximumLifetime: time.Minute, Callbacks: []string{f.Binding.Intent.CallbackURL}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {222}}})
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "reset-link", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://identity.test"}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	link := resetRequestDeliveryPreparation{issuer: issuer, codec: custody, profile: resetProfile, owner: owner, renderer: renderer, resolver: child.Issuer.Crypto.Resolver.(*capability.KeySet), endpoint: f.Binding.Intent.CallbackURL, template: "reset-link", templateVersion: 1, providerVersion: 2, locales: []string{"en"}, scopeKey: [32]byte{223}, timeout: time.Second}
	if keyed {
		primary, err := NewSigninService(pool, config)
		if err != nil {
			t.Fatal("actual native primary", err)
		}
		c := PhonePasswordResetRequestConfig{Enabled: true, AcceptCarrierRisk: true, ConfigurationID: "native-phone-reset-v1", RequestKeys: signup.RequestKeys, IntentKey: [32]byte{224}, ActiveEnvelopeKeyID: signup.ActiveEnvelopeKeyID, NumberBindingKeyVersion: 1, Risk: riskConfig, SMS: sms, Profile: password.ResetProfileConfig{Issuer: "https://identity.test", Audience: config.Profile.Audience, MaximumLifetime: time.Minute, Callbacks: []string{f.Binding.Intent.CallbackURL}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: {222}}}, Issuer: child.Issuer, IssuanceCustody: child.Custody, Delivery: SignupDeliveryConfig{Owner: owner, Renderer: renderer, Resolver: link.resolver, Endpoint: link.endpoint, TemplateID: link.template, TemplateVersion: 1, ProviderVersion: 2, Locales: []string{"en"}, ScopeKey: link.scopeKey, Timeout: time.Second}}
		fresh := func() *PhonePasswordResetRequestService {
			s, err := NewPhonePasswordResetRequestService(primary, numbers, c, keys)
			if err != nil {
				t.Fatal("keyed phone reset request startup", err)
			}
			return s
		}
		// First issuance goes through the owned public Number/Flow entry point,
		// not through a caller-selected UserID or fabricated evidence reference.
		input.CommandID, _ = identity.NewCommandID()
		input.RiskIssuanceCommandID, _ = identity.NewCommandID()
		riskRequest, err := phone.NewPasswordResetInitiationRiskRequest(phone.PasswordResetInitiationRiskRequestSpec{TenantID: input.TenantID, CommandID: input.CommandID, IssuanceCommandID: input.RiskIssuanceCommandID, Number: input.Number, Flow: input.Flow, Caller: input.Caller, Origin: input.Origin, Network: input.Network, Device: input.Device})
		if err != nil {
			t.Fatal(err)
		}
		issued, err := fresh().EvaluatePasswordResetRequestRisk(ctx, riskRequest)
		if err != nil || issued.Outcome != risk.EvidenceCommitted || issued.Evidence.Reference.Reveal() == "" {
			t.Fatal("owned initiation risk could not resolve actual phone authority", err)
		}
		again, err := fresh().EvaluatePasswordResetRequestRisk(ctx, riskRequest)
		if err != nil || again.Evidence.Reference != issued.Evidence.Reference || !again.Evidence.ExpiresAt.Equal(issued.Evidence.ExpiresAt) {
			t.Fatal("owned initiation risk replay changed original evidence", err)
		}
		input.RiskEvidence = issued.Evidence.Reference
		r, err := phone.NewPasswordResetRequestRequest(input)
		if err != nil {
			t.Fatal(err)
		}
		result, err := fresh().RequestPasswordReset(ctx, r)
		if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.CommandID == "" || result.CommandID == input.CommandID || result.CommandID == input.RiskIssuanceCommandID {
			t.Fatal("keyed native request did not commit its server-owned identity", err, result.Outcome)
		}
		replayed, err := fresh().RequestPasswordReset(ctx, r)
		if err != nil || replayed != result {
			t.Fatal("fresh keyed replay changed original receipt", err)
		}
		changed := input
		changed.Device = "different-browser"
		other, _ := phone.NewPasswordResetRequestRequest(changed)
		if _, err = fresh().RequestPasswordReset(ctx, other); err == nil {
			t.Fatal("changed original keyed intent was accepted")
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(result.CommandID))
		var messages, challenges int
		if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM phone_codes.challenges WHERE issue_command_id=$1)`, raw).Scan(&messages, &challenges); err != nil || messages != 2 || challenges != 1 {
			t.Fatal("keyed replay duplicated or lost native request effects", err, messages, challenges)
		}
		// The public native worker decrypts both actually queued intents. Only
		// the external SMS sender is controlled; no private challenge SQL or
		// restored issuer handle supplies either credential to the consumer.
		workerPolicy := delivery.DefaultConfig()
		workerPolicy.Production, workerPolicy.DedupeTTL = true, 25*time.Hour
		authorize, err := authorization.NewDecisionService(signupVerificationWorkerPolicy{3})
		if err != nil {
			t.Fatal(err)
		}
		templates := []delivery.Template{
			{ID: "reset-code", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Reset code: {{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 4096},
			{ID: "reset-link", Version: 1, Channel: delivery.ChannelSMS, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://identity.test"}, MaxRenderedBytes: 4096},
		}
		queue, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: deliveryCustody, Coordinator: config.Coordinator, PolicyID: "phone-reset-worker", PolicyVersion: 3, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{228}, Policies: map[uint64]delivery.Config{1: workerPolicy}, StateTracking: true}, crypto, authorize, templates)
		if err != nil {
			t.Fatal("native reset dispatch startup", err)
		}
		var code, linkWire string
		calls := 0
		worker, err := queue.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 3, CorrelationID: "phone-reset-worker", Request: authorization.Request{Tenant: authorization.TenantID(input.TenantID), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "phone-reset-worker", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "phone-reset-worker"}}}, ProviderConfigVersion: 2}, signupVerificationSender(func(_ context.Context, attempt delivery.Attempt) (delivery.DeliveryResult, error) {
			if attempt.Recipient != "+12025550123" {
				t.Error("reset dispatch changed original recipient")
			}
			body := string(attempt.Body)
			switch {
			case strings.HasPrefix(body, "Reset code: "):
				code = strings.TrimPrefix(body, "Reset code: ")
			case strings.HasPrefix(body, "Reset: "):
				linkWire = strings.TrimPrefix(body, "Reset: ")
			default:
				t.Error("reset worker disclosed an unexpected message profile")
			}
			calls++
			return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			processed, err := worker.ProcessOne(ctx)
			if err != nil || !processed.Claimed {
				t.Fatal("actual reset intent was not delivered", err)
			}
		}
		linkURL, err := url.Parse(linkWire)
		if err != nil || calls != 2 || len(code) != 6 || linkURL.Scheme != "https" || linkURL.Host != "identity.test" || linkURL.Path != "/reset" || linkURL.RawQuery == "" {
			t.Fatal("native dispatch did not produce original SMS and canonical reset link")
		}
		if processed, err := worker.ProcessOne(ctx); err != nil || processed.Claimed {
			t.Fatal("request replay queued another message", err)
		}
		// Completion receives the actual delivered capability and original
		// browser. It must recover committed encrypted request custody through
		// its owner, not invent an SMS continuation from signed scalar caveats.
		proof, err := capability.ParseProof(linkURL.Query().Get("token"), capability.DefaultLimits())
		if err != nil {
			t.Fatal("actual delivered reset capability was invalid")
		}
		defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
		grant, sourceID, _, err := issuer.ReadIssuanceOrigin(ctx, pool, proof, "identity.phone.password-reset-complete")
		if err != nil {
			t.Fatal("actual issued reset provenance unavailable", err)
		}
		origin, err := resetProfile.ResolveOriginal(grant, time.Now().UTC())
		if err != nil || sourceID != result.CommandID || origin.OriginCommandID != sourceID {
			t.Fatal("canonical reset provenance lost original request", err)
		}
		type originalSource interface {
			restoreIssuedRequest(context.Context, password.ResetGrantSpec, authorization.DecisionContext, otp.SendFlow) (*phoneResetIssuedRequest, error)
		}
		restore, exists := any(fresh().read()).(originalSource)
		if !exists {
			t.Fatal("native phone reset cannot restore the actual committed SMS request for completion")
		}
		completionCaller := input.Caller.Clone()
		completionCaller.Request.Action = "identity.phone.password-reset-complete"
		restored, err := restore.restoreIssuedRequest(ctx, origin, completionCaller, input.Flow)
		if err != nil || restored == nil || restored.origin != origin || restored.source.credential != selected.credential {
			t.Fatal("completion did not retain original issued authority", err)
		}
		if _, err = restored.prepared.Plan(); err != nil {
			t.Fatal("completion did not restore real SMS preparation", err)
		}
		testPhoneResetCompletionRateSource(t, ctx, pool, fresh, proof, input.Flow, completionCaller, origin)
		foreign := origin
		foreign.CredentialVersion++
		if _, err = restore.restoreIssuedRequest(ctx, foreign, completionCaller, input.Flow); err == nil {
			t.Fatal("completion adopted changed original credential version")
		}
		kind, flowID, _, err := input.Flow.Bindings()
		if err != nil || kind != otp.FlowAuthorizationPreAuthTransaction {
			t.Fatal("original recovery browser fixture invalid")
		}
		foreignFlow, _ := otp.NewPreAuthSendFlow(identity.PreAuthTransactionID(flowID), authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
		if _, err = restore.restoreIssuedRequest(ctx, origin, completionCaller, foreignFlow); err == nil {
			t.Fatal("completion restored original send for another browser")
		}
		completion, _ := identity.NewCommandID()
		completionIssuance, _ := identity.NewCommandID()
		completionRisk, err := phone.NewPasswordResetCompletionRiskRequest(phone.PasswordResetCompletionRiskRequestSpec{TenantID: input.TenantID, CommandID: completion, IssuanceCommandID: completionIssuance, Flow: input.Flow, ResetCapability: proof, Caller: completionCaller, Origin: input.Origin, Network: input.Network, Device: input.Device})
		if err != nil {
			t.Fatal(err)
		}
		type completionRiskIssuer interface {
			EvaluatePasswordResetCompletionRisk(context.Context, phone.PasswordResetCompletionRiskRequest) (risk.PhoneEvidenceResult, error)
		}
		completionOwner, exists := any(fresh()).(completionRiskIssuer)
		if !exists {
			t.Fatal("native reset cannot issue distinct completion risk from actual original grant/browser")
		}
		completionEvidence, err := completionOwner.EvaluatePasswordResetCompletionRisk(ctx, completionRisk)
		if err != nil || completionEvidence.Outcome != risk.EvidenceCommitted || completionEvidence.Evidence.Reference.Reveal() == "" || completionEvidence.Evidence.Reference == input.RiskEvidence {
			t.Fatal("distinct native completion evidence unavailable", err)
		}
		completionAgain, err := completionOwner.EvaluatePasswordResetCompletionRisk(ctx, completionRisk)
		if err != nil || completionAgain.Evidence.Reference != completionEvidence.Evidence.Reference || !completionAgain.Evidence.ExpiresAt.Equal(completionEvidence.Evidence.ExpiresAt) {
			t.Fatal("completion evidence replay changed original issuance", err)
		}
		if complete >= phoneResetCompleteProfile {
			testNativePhoneResetCompletion(t, ctx, pool, config, selected, fresh, crypto, input, completionCaller, completion, completionIssuance, proof, code, totpSecret, completionEvidence.Evidence.Reference, complete, origin)
			if complete == phoneResetCompleteProfile {
				recovered, err := fresh().EvaluatePasswordResetCompletionRisk(ctx, completionRisk)
				if err != nil || recovered != completionEvidence {
					t.Fatal("matching completion risk retry lost original evidence after its own browser/factor consumption", err)
				}
				for _, name := range []string{"network", "device", "issuance", "new-attempt"} {
					t.Run("risk-terminal-retry-"+name, func(t *testing.T) {
						changed, err := completionRisk.Bindings()
						if err != nil {
							t.Fatal(err)
						}
						switch name {
						case "network":
							changed.Network = "192.0.2.2"
						case "device":
							changed.Device = "different-recovery-browser"
						case "issuance":
							changed.IssuanceCommandID, _ = identity.NewCommandID()
						case "new-attempt":
							changed.CommandID, _ = identity.NewCommandID()
							changed.IssuanceCommandID, _ = identity.NewCommandID()
						}
						other, err := phone.NewPasswordResetCompletionRiskRequest(changed)
						if err != nil {
							t.Fatal(err)
						}
						got, err := fresh().EvaluatePasswordResetCompletionRisk(ctx, other)
						if err == nil && got.Outcome == risk.EvidenceCommitted {
							t.Fatal("changed terminal risk intent accepted")
						}
					})
				}
			}
			return
		}
		metadata, err := selected.factor.Metadata()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3`, string(input.TenantID), string(selected.recipient.User.ID), metadata.FactorID); err != nil {
			t.Fatal("withdraw actual original factor", err)
		}
		reader, err := mfapg.NewTOTPFactorReader(pool, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = reader.ReadForPhoneRecovery(ctx, input.TenantID, selected.recipient.User.ID, metadata.FactorID); err == nil {
			t.Fatal("factor-withdrawal oracle did not deny current custody")
		}
		if _, err = restore.restoreIssuedRequest(ctx, origin, completionCaller, input.Flow); err == nil {
			t.Fatal("completion restored withdrawn factor authority")
		}
		recovered, err := fresh().RequestPasswordReset(ctx, r)
		if err != nil || recovered != result {
			t.Fatal("terminal keyed receipt depended on current factor custody", err)
		}
		return
	}
	phase, err := newPhoneResetRequestPhase(ctx, pool, config, selected, input, admission, original, use, sms, link, crypto, signup.ActiveEnvelopeKeyID)
	if err != nil {
		t.Fatal("actual request composition", err)
	}
	if _, err = phase.plan(false); err != nil {
		t.Fatal("phone request preparation declaration", err)
	}
	if rollback {
		// Fail the real required audit only after the feature has provisionally
		// inserted its SMS/capability/delivery effects. No participant is mocked.
		if _, err := pool.Raw().Exec(ctx, `ALTER TABLE audit.identity_command_bindings ADD CONSTRAINT phone_reset_request_stop CHECK(false) NOT VALID`); err != nil {
			t.Fatal(err)
		}
	}
	result, err := phase.execute(ctx)
	if rollback {
		if err == nil || result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("required audit failure committed request")
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(input.CommandID))
		var messages, challenges int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),(SELECT count(*) FROM phone_codes.challenges WHERE issue_command_id=$1)`, raw).Scan(&messages, &challenges); err != nil || messages != 0 || challenges != 0 {
			t.Fatal("failed request left SMS or delivery effects", err, messages, challenges)
		}
		var state string
		if err := pool.Raw().QueryRow(ctx, `SELECT state FROM phone_reset_risk.issued_evidence WHERE record_id=$1`, string(input.RiskIssuanceCommandID)).Scan(&state); err != nil || state == "finalized" {
			t.Fatal("failed request consumed initiation evidence", err, state)
		}
		return
	}
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		var invalid identity.InvalidInputError
		_ = errors.As(err, &invalid)
		t.Fatal("real atomic phone reset request", err, result.Outcome, invalid.Field)
	}
	var state string
	if err = pool.Raw().QueryRow(ctx, `SELECT state FROM phone_reset_risk.issued_evidence WHERE record_id=$1`, string(input.RiskIssuanceCommandID)).Scan(&state); err != nil || state != "finalized" {
		t.Fatal("request did not consume real original risk", err, state)
	}
	plan, err := phase.prepared.Plan()
	if err != nil || len(plan.Intents) != 1 {
		t.Fatal("actual SMS missing", err)
	}
	grants, err := phase.artifacts.issuance.Plan()
	if err != nil || len(grants.Grants) != 1 || grants.Grants[0].Purpose != "identity.phone.password-reset-complete" {
		t.Fatal("canonical reset grant missing", err)
	}
	replayed, err := phase.execute(ctx)
	if err != nil || replayed.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("exact request replay failed", err)
	}
}
