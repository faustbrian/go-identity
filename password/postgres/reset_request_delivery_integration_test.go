//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// The enclosing PostgreSQL journey supplies an actual primary recipient. This
// checks original preparation custody, not public request or sender behavior.
func testResetRequestDelivery(t *testing.T, ctx context.Context, repository *Repository, issuer *issuerpg.Issuer, profile password.ResetProfile, b identity.CommandBinding, origin password.ResetGrantSpec, recipient kernel.RecipientRecord, resolver *capability.KeySet) (resetRequestDelivery, resetRequestDeliveryPreparation) {
	keys, _ := keyring.New(map[string][]byte{"reset-mail": bytes.Repeat([]byte{102}, 32)})
	crypto, _ := envelope.NewService(keys)
	owner, err := deliverypg.NewContributor(deliverypg.ContributorConfig{Deployment: "reset-mail", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {103}}, ActiveEnvelopeKeyID: "reset-mail", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}}, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer([]delivery.Template{{ID: "password-reset", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://identity.test"}, MaxRenderedBytes: 4096}})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(issuer, issuerpg.IssuancePreparationConfig{Deployment: "reset-mail", ActiveEnvelopeKey: "reset-issuer", EnvelopeKeys: map[string][]byte{"reset-issuer": bytes.Repeat([]byte{104}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "public-reset", HMAC: bytes.Repeat([]byte{93}, 32)}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	c := resetRequestDeliveryPreparation{issuer: issuer, codec: codec, profile: profile, owner: owner, renderer: renderer, resolver: resolver, endpoint: "https://identity.test/password/reset", template: "password-reset", templateVersion: 1, providerVersion: 1, locales: []string{"en"}, scopeKey: [32]byte{105}, timeout: time.Second}
	admission := signinTestAdmissionWithConfig(t, ctx, b, signinTestRisk(t))
	prepared, err := repository.generateResetRequestDelivery(ctx, b, origin, recipient, admission, 1, c)
	if err != nil {
		t.Fatal("reset token cannot enter encrypted delivery custody", err)
	}
	issuancePlan, err := prepared.issuance.Plan()
	if err != nil || issuancePlan.ResetRecipientUserID != origin.UserID || len(issuancePlan.Grants) != 1 {
		t.Fatal("reset generation lost original recipient", err)
	}
	deliveryPlan, err := prepared.delivery.Plan()
	if err != nil || len(deliveryPlan.Intents) != 1 || deliveryPlan.Intents[0].ExpiresAt != origin.ExpiresAt {
		t.Fatal("reset delivery renewed original expiry", err)
	}
	if bytes.Contains(prepared.issuanceWire, []byte(recipient.Identifier.CanonicalValue)) || bytes.Contains(prepared.deliveryWire, []byte(recipient.Identifier.CanonicalValue)) {
		t.Fatal("checkpoint exposes mailbox")
	}
	restoredIssue, err := codec.RestorePreparation(ctx, b, 1, issuancePlan, prepared.issuanceWire)
	if err != nil {
		t.Fatal("original issuance restoration", err)
	}
	restoredDelivery, err := owner.RestorePreparation(ctx, b, 1, prepared.deliveryWire)
	if err != nil {
		t.Fatal("original encrypted delivery restoration", err)
	}
	againIssue, _ := restoredIssue.Plan()
	againDelivery, _ := restoredDelivery.Plan()
	if !reflect.DeepEqual(issuancePlan, againIssue) || !reflect.DeepEqual(deliveryPlan, againDelivery) {
		t.Fatal("restoration replaced original token or message intent")
	}
	foreign := b
	foreign.CommandID, _ = identity.NewCommandID()
	if _, err := codec.RestorePreparation(ctx, foreign, 1, issuancePlan, prepared.issuanceWire); err == nil {
		t.Fatal("foreign command restored issuance")
	}
	if _, err := owner.RestorePreparation(ctx, foreign, 1, prepared.deliveryWire); err == nil {
		t.Fatal("foreign command restored delivery")
	}
	if _, err := codec.RestorePreparation(ctx, b, 2, issuancePlan, prepared.issuanceWire); err == nil {
		t.Fatal("foreign generation restored issuance")
	}
	if _, err := owner.RestorePreparation(ctx, b, 2, prepared.deliveryWire); err == nil {
		t.Fatal("foreign generation restored delivery")
	}
	if err := restoredIssue.TransferForDelivery(ctx, 0, func(context.Context, []byte) error { t.Error("restored token disclosed twice"); return nil }); err == nil {
		t.Fatal("restored issuance became revealable")
	}
	for _, mode := range []string{"foreign-origin", "foreign-recipient", "foreign-callback", "foreign-authority", "missing-factor", "bad-endpoint", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			badOrigin, badRecipient, badConfig := origin, recipient, c
			work := ctx
			switch mode {
			case "foreign-origin":
				badOrigin.OriginCommandID, _ = identity.NewCommandID()
			case "foreign-recipient":
				badRecipient.Identifier.CanonicalValue = "foreign@example.test"
			case "foreign-callback":
				badOrigin.CallbackURL = "https://foreign.test/reset"
			case "foreign-authority":
				badOrigin.UserAuthorityVersion++
			case "missing-factor":
				badOrigin.FactorVersion = 0
			case "bad-endpoint":
				badConfig.endpoint = "https://identity.test/reset?token=override"
			case "cancelled":
				var stop context.CancelFunc
				work, stop = context.WithCancel(ctx)
				stop()
			}
			out, err := repository.generateResetRequestDelivery(work, b, badOrigin, badRecipient, admission, 1, badConfig)
			if err == nil || len(out.issuanceWire) != 0 || len(out.deliveryWire) != 0 {
				t.Fatal("invalid reset preparation retained custody", err)
			}
		})
	}
	// The caller stages the original restored custody, not newly issued bytes.
	prepared.issuance, prepared.delivery = restoredIssue, restoredDelivery
	return prepared, c
}

func captureResetDelivery(t *testing.T, ctx context.Context, pool *database.Pool, c resetRequestDeliveryPreparation, coordinator kernel.CoordinatorConfig, recipient string, crypto *envelope.Service) capability.Proof {
	t.Helper()
	history, err := (deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 20, WorkerVersion: 23, PolicyVersion: 24, KeyedVersion: 25, StateVersion: 26}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		var installed bool
		switch m.Version() {
		case 23:
			err = pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.delivery_processing') IS NOT NULL`).Scan(&installed)
		case 24:
			err = pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.delivery_policy_profiles') IS NOT NULL`).Scan(&installed)
		case 25:
			err = pool.Raw().QueryRow(ctx, `SELECT to_regclass('identity.delivery_keyed_commands') IS NOT NULL`).Scan(&installed)
		case 26:
			err = pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='identity' AND table_name='delivery_intents' AND column_name='status_version')`).Scan(&installed)
		default:
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !installed {
			if _, err = pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("reset worker forward history", err)
			}
		}
	}
	authz, _ := authorization.NewDecisionService(signupVerificationWorkerPolicy{3})
	policy := delivery.DefaultConfig()
	policy.Production, policy.DedupeTTL = true, 25*time.Hour
	templates := []delivery.Template{{ID: "password-reset", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "Reset: {{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://identity.test"}, MaxRenderedBytes: 4096}}
	service, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: deliverypg.ContributorConfig{Deployment: "reset-mail", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {103}}, ActiveEnvelopeKeyID: "reset-mail", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "mail", PolicyVersion: 1}}}, Coordinator: coordinator, PolicyID: "reset", PolicyVersion: 3, AuditRetentionVersion: 1, Timeout: 3 * time.Second, NamespaceKey: [32]byte{106}, Policies: map[uint64]delivery.Config{1: policy}, StateTracking: true}, crypto, authz, templates)
	if err != nil {
		t.Fatal("reset delivery worker composition", err)
	}
	var proof capability.Proof
	calls := 0
	worker, err := service.NewWorker(deliverypg.WorkerConfig{Scope: authorization.DecisionContext{PolicyRevision: 3, CorrelationID: "reset-worker", Request: authorization.Request{Tenant: signinTestTenant, Action: "identity.delivery.process", Subject: authorization.Subject{ID: "reset-worker", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "reset-worker"}}}, ProviderConfigVersion: 1}, signupVerificationSender(func(_ context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		if a.Recipient == recipient && strings.HasPrefix(string(a.Body), "Reset: ") {
			calls++
			link, e := url.Parse(strings.TrimPrefix(string(a.Body), "Reset: "))
			if e != nil {
				return delivery.DeliveryResult{}, delivery.ErrInvalidInput
			}
			proof, e = capability.ParseProof(link.Query().Get("token"), capability.DefaultLimits())
			if e != nil {
				return delivery.DeliveryResult{}, delivery.ErrInvalidInput
			}
		}
		return delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 16 && calls == 0; n++ {
		processed, e := worker.ProcessOne(ctx)
		if e != nil || !processed.Claimed || processed.Completion.State != delivery.StateDelivered {
			t.Fatal("reset message processing", e)
		}
	}
	if calls != 1 {
		t.Fatal("original reset not delivered exactly once")
	}
	return proof
}
