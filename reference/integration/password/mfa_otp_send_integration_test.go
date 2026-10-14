//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

type otpEnrollmentWorkerPolicy struct{}

func (otpEnrollmentWorkerPolicy) Decide(_ context.Context, _ authorization.Request) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
}

type otpEnrollmentSender func(context.Context, delivery.Attempt) (delivery.DeliveryResult, error)

func (s otpEnrollmentSender) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	return s(ctx, a)
}

type observedOTPEnrollmentIssuer struct {
	*otppg.MFAEnrollmentIssuer
	generations, restorations int
	generated, restored       bool
}

func (s *observedOTPEnrollmentIssuer) GenerateEnrollmentSend(ctx context.Context, c identity.Command, input []byte, generation uint64) ([]byte, error) {
	s.generations++
	wire, err := s.MFAEnrollmentIssuer.GenerateEnrollmentSend(ctx, c, input, generation)
	s.generated = err == nil
	return wire, err
}
func (s *observedOTPEnrollmentIssuer) RestoreEnrollmentSend(ctx context.Context, c identity.Command, input []byte, generation uint64, wire []byte) (mfapg.OTPEnrollmentPreparedSend, error) {
	s.restorations++
	p, err := s.MFAEnrollmentIssuer.RestoreEnrollmentSend(ctx, c, input, generation, wire)
	s.restored = err == nil
	return p, err
}

// Real public pending enrollment -> native MFA send -> durable encrypted queue
// -> actual worker callback. A verified address alone never confirms a factor.
func testPublicOTPEnrollmentSend(t *testing.T, ctx context.Context, pool *database.Pool, enrollment *mfapg.OTPEnrollmentService, cfg mfapg.OTPEnrollmentConfig, source passwordpg.ReauthenticationConfig, enable mfa.EnableRequest, result mfa.EnableResult, keys *keyring.Provider, confirmation string, beforeProvider *func(context.Context)) {
	t.Helper()
	base := mfapg.TOTPActivationMigrationSource{Base: mfapg.URIRevealMigrationSource{Base: mfapg.RecoveryMigrationSource{Base: mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}, Version: 4}, Version: 5}, Version: 6}
	history, err := (mfapg.OTPSendMigrationSource{Base: mfapg.OTPFactorMigrationSource{Base: mfapg.FactorReferenceMigrationSource{Base: base, Version: 13}, Version: 14}, Version: 15}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("MFA send history unavailable", err)
	}
	for _, source := range []migrations.Source{otppg.MigrationSource{Schema: "mfa_otp", Version: 100}, otppg.LockoutMigrationSource{Schema: "mfa_otp", Version: 101}, otppg.SendFamilyMigrationSource{Schema: "mfa_otp", Version: 102}, otppg.IssuanceMigrationSource{Schema: "mfa_otp", Version: 103}, deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 20, WorkerVersion: 23, PolicyVersion: 24, KeyedVersion: 25, StateVersion: 26}} {
		items, e := source.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range items {
			if item.Version() >= 20 {
				if _, e = pool.Raw().Exec(ctx, item.UpSQL()); e != nil {
					t.Fatal("native OTP/delivery history unavailable", e)
				}
			}
		}
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	custody := deliverypg.ContributorConfig{Deployment: "reauth-deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {101}}, ActiveEnvelopeKeyID: "totp-v1", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "otp-mail", PolicyVersion: 1}}}
	deliveryOwner, err := deliverypg.NewContributor(custody, crypto)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := otppg.NewAttemptCodec(otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"otp-wrap": bytes.Repeat([]byte{102}, 32)}, CurrentWrappingKey: "otp-wrap", AttemptKeys: map[uint32][32]byte{1: {103}}, CodeKeys: map[uint32][32]byte{1: {104}}, CurrentCodeKeyVersion: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeMFA, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 5, Attempts: 5, Replacement: otp.ReplacePrevious})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := otp.NewAttemptPolicy(profile, otp.CheckPolicySpec{LockoutAfter: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	templates := []delivery.Template{{ID: "mfa-otp", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Subject: "MFA verification", Body: "{{.code}}", ContentType: "text/plain", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128}}
	issuer, err := otppg.NewMFAEnrollmentIssuer(otppg.MFAEnrollmentIssuerConfig{Store: otppg.ContributorConfig{Schema: "mfa_otp", GlobalAuthorityID: source.Profile.GlobalAuthorityID, UserPolicyNamespace: source.Profile.PolicyNamespace, Codec: codec, LockoutKey: [32]byte{105}}, Session: otppg.SessionAdmissionConfig{Store: source.Session, Profile: source.Profile, RetainedTokenKeys: map[uint32][]byte{1: bytes.Repeat([]byte{37}, 32)}, FreshnessLimit: 5 * time.Minute}, Delivery: deliveryOwner, Policy: policy, TemplateID: "mfa-otp", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: templates})
	if err != nil {
		t.Fatal("native MFA OTP issuer unavailable", err)
	}
	if err = issuer.Initialize(ctx, pool); err != nil {
		t.Fatal("native OTP stable keys unavailable", err)
	}
	primary, ok := cfg.Primary.(mfapg.OTPEnrollmentSendPrimarySource)
	if !ok {
		t.Fatal("actual primary has no OTP send restoration")
	}
	observed := &observedOTPEnrollmentIssuer{MFAEnrollmentIssuer: issuer}
	senderConfig := mfapg.OTPEnrollmentSendConfig{Primary: primary, Issuance: observed, AllowedOrigins: []string{"https://app.test"}}
	sender, err := mfapg.NewOTPEnrollmentSendService(enrollment, senderConfig)
	if err != nil {
		t.Fatal("native MFA sender unavailable", err)
	}
	caller := enable.Caller.Clone()
	caller.Request.Action = "identity.mfa.otp-send"
	request := mfa.OtpSendRequest{TenantID: enable.TenantID, FactorID: mfa.FactorID(result.Enrollment.ID), Channel: delivery.ChannelEmail, Caller: caller, Origin: "https://app.test", Network: enable.Network, Enrollment: &mfa.OTPEnrollmentContext{Session: enable.Session, CSRFToken: enable.CSRFToken}}
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-native-send-rollback"))
	if err := request.Validate(); err != nil {
		t.Fatal("native send request is structurally invalid", err)
	}
	if _, err = pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_mfa_otp_send_fixture() RETURNS trigger LANGUAGE plpgsql AS $fn$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $fn$; CREATE TRIGGER reject_mfa_otp_send_fixture AFTER UPDATE ON identity_mfa.otp_factors FOR EACH ROW EXECUTE FUNCTION public.reject_mfa_otp_send_fixture()`); err != nil {
		t.Fatal(err)
	}
	rolled, sendErr := sender.OtpSend(ctx, request)
	if _, err = pool.Raw().Exec(ctx, `DROP TRIGGER reject_mfa_otp_send_fixture ON identity_mfa.otp_factors; DROP FUNCTION public.reject_mfa_otp_send_fixture()`); err != nil {
		t.Fatal(err)
	}
	if sendErr == nil || rolled.Outcome != identity.CommitOutcomeNotCommitted || rolled.ChallengeID != "" || rolled.DeliveryState != 0 {
		var invalid identity.InvalidInputError
		errors.As(sendErr, &invalid)
		t.Fatalf("failed native send did not roll back: outcome=%d error=%v invalid-field=%s generations=%d generated=%t restored=%t otp-invalid=%t", rolled.Outcome, sendErr, invalid.Field, observed.generations, observed.generated, observed.restored, errors.Is(sendErr, otppg.ErrInvalidCommand))
	}
	var challenges, intents, state int64
	var row string
	if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM mfa_otp.challenges),(SELECT count(*) FROM identity.delivery_intents),state,row_version::text FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND factor_id=$2`, string(enable.TenantID), string(request.FactorID)).Scan(&challenges, &intents, &state, &row); err != nil || challenges != 0 || intents != 0 || state != 1 || row != "1" {
		t.Fatal("OTP/delivery rollback left partial state", err)
	}
	for n, change := range []func(*mfa.OtpSendRequest){
		func(r *mfa.OtpSendRequest) { r.Channel = delivery.ChannelSMS },
		func(r *mfa.OtpSendRequest) { id, _ := identity.NewCommandID(); r.FactorID = mfa.FactorID(id) },
		func(r *mfa.OtpSendRequest) {
			custody := *r.Enrollment
			custody.CSRFToken, _ = session.NewCSRFToken()
			r.Enrollment = &custody
		},
		func(r *mfa.OtpSendRequest) {
			custody := *r.Enrollment
			custody.Session = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			r.Enrollment = &custody
		},
		func(r *mfa.OtpSendRequest) {
			r.Caller = r.Caller.Clone()
			r.Caller.Request.Subject.ID = "foreign-factor-owner"
			r.Caller.Request.Resource.ID = "foreign-factor-owner"
		},
	} {
		candidate := request
		change(&candidate)
		candidate.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte(fmt.Sprintf("otp-native-send-denial-%d", n)))
		if out, err := sender.OtpSend(ctx, candidate); err == nil || out.ChallengeID != "" || out.DeliveryState != 0 {
			t.Fatal("wrong channel/factor/primary/CSRF/account sent a code")
		}
		if observed.generations != 1 {
			t.Fatal("denied OTP send reached generation")
		}
	}
	request.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("otp-native-send-success"))
	if err := request.Validate(); err != nil {
		t.Fatal("fresh native send request invalid", err)
	}
	sent, err := sender.OtpSend(ctx, request)
	if err != nil || sent.Outcome != identity.CommitOutcomeCommitted || sent.CommandID == "" || sent.ChallengeID != string(sent.CommandID) || sent.CommandID == identity.CommandID(request.FactorID) || sent.DeliveryState != delivery.StateQueued {
		var invalid identity.InvalidInputError
		errors.As(err, &invalid)
		t.Fatalf("native MFA send did not queue: outcome=%d error=%v field=%s generations=%d generated=%t restored=%t", sent.Outcome, err, invalid.Field, observed.generations, observed.generated, observed.restored)
	}
	restarted, err := mfapg.NewOTPEnrollmentSendService(enrollment, senderConfig)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := restarted.OtpSend(ctx, request)
	if err != nil || replay != sent {
		t.Fatal("same-key restart replaced OTP/delivery", err)
	}
	query := identity.RecoveryQuery{TenantID: request.TenantID, CommandID: sent.CommandID, UserID: identity.UserID(caller.Request.Subject.ID), ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.mfa.otp-send", RecordID: string(request.FactorID)}
	recovered, err := restarted.RecoverOtpSend(ctx, query, caller)
	if err != nil || recovered != sent {
		t.Fatal("code/proof-free native send recovery failed", err)
	}
	changed := request
	changed.Network = "192.0.2.2"
	if _, err := restarted.OtpSend(ctx, changed); err == nil {
		t.Fatal("same request key adopted different original network")
	} else {
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatal("changed original intent did not report conflict", err)
		}
	}
	if observed.generations != 2 {
		t.Fatal("restart/replay/recovery/changed intent regenerated an OTP")
	}
	if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM mfa_otp.challenges),(SELECT count(*) FROM identity.delivery_intents),state,row_version::text FROM identity_mfa.otp_factors WHERE tenant_id=$1 AND factor_id=$2`, string(enable.TenantID), string(request.FactorID)).Scan(&challenges, &intents, &state, &row); err != nil || challenges != 1 || intents != 1 || state != 1 || row != "2" {
		t.Fatal("native send repeated or confirmed a pending factor", err)
	}
	authz, err := authorization.NewDecisionService(otpEnrollmentWorkerPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	deliveryPolicy := delivery.DefaultConfig()
	deliveryPolicy.Production = true
	deliveryPolicy.DedupeTTL = 25 * time.Hour
	queue, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: custody, Coordinator: cfg.Coordinator, PolicyID: "mfa-worker", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{106}, Policies: map[uint64]delivery.Config{1: deliveryPolicy}, StateTracking: true}, crypto, authz, templates)
	if err != nil {
		t.Fatal("actual delivery worker composition unavailable", err)
	}
	calls := 0
	var captured, wrong auth.OneTimeCode
	var capturedWire string
	worker, err := queue.NewWorker(deliverypg.WorkerConfig{ProviderConfigVersion: 1, Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "otp-worker", Request: authorization.Request{Subject: authorization.Subject{ID: "otp-worker", Kind: authorization.SubjectServiceAccount}, Tenant: authorization.TenantID(enable.TenantID), Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "otp-worker"}}}}, otpEnrollmentSender(func(_ context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		if a.Recipient != "mfa@example.test" || len(a.Body) != 6 {
			return delivery.DeliveryResult{}, delivery.ErrInvalidInput
		}
		for _, c := range a.Body {
			if c < '0' || c > '9' {
				return delivery.DeliveryResult{}, delivery.ErrInvalidInput
			}
		}
		calls++
		capturedWire = strings.Clone(a.Body)
		var err error
		captured, err = auth.NewOneTimeCode(a.Body)
		if err != nil {
			return delivery.DeliveryResult{}, err
		}
		changed := []byte(a.Body)
		changed[0] = '0' + (changed[0]-'0'+1)%10
		wrong, err = auth.NewOneTimeCode(string(changed))
		clear(changed)
		if err != nil {
			return delivery.DeliveryResult{}, err
		}
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.ProcessOne(ctx)
	if err != nil || !processed.Claimed || processed.Completion.State != delivery.StateDelivered || calls != 1 {
		t.Fatal("native OTP did not reach actual worker", err)
	}
	empty, err := worker.ProcessOne(ctx)
	if err != nil || empty.Claimed || calls != 1 {
		t.Fatal("native OTP was delivered twice", err)
	}
	if confirmation != "" {
		testPublicOTPEnrollmentConfirmation(t, ctx, pool, sender, senderConfig, cfg, keys, request, captured, wrong, confirmation, beforeProvider)
	}
	if strings.HasPrefix(confirmation, "login-") {
		testPublicPasswordOTPLoginSend(t, ctx, pool, source, cfg, keys, request, codec, deliveryOwner, policy, templates, worker, func() (auth.OneTimeCode, auth.OneTimeCode, string) { return captured, wrong, capturedWire }, confirmation)
	}
}
