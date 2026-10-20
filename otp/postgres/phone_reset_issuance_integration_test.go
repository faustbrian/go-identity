//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
)

// Supplier preparation only: a real enrolled encrypted factor and actual native
// SMS generator/delivery custody. This is not request Work or risk/capability
// authorization, and does not establish the public phone recovery journey.
func TestPhoneResetIssuanceNativePreparation(t *testing.T) {
	ctx, _, _, issuer, root, input := phoneResetIssuanceNativeFixture(t)
	issuedAt, expiresAt, err := input.Timeline()
	if err != nil || expiresAt.Sub(issuedAt) != time.Minute {
		t.Fatal("original native SMS lifetime was not selected once", err)
	}
	wire, err := issuer.Generate(ctx, root, input, 1)
	if err != nil || len(wire) == 0 {
		t.Fatal("original request cannot generate native SMS", err)
	}
	defer clear(wire)
	cookie, _ := root.PreAuthCookie()
	if bytes.Contains(wire, []byte(cookie.Token())) {
		t.Fatal("encrypted retained output contains original bearer")
	}
	prepared, err := issuer.Restore(ctx, root, input, 1, wire)
	if err != nil {
		t.Fatal("native SMS output cannot restore", err)
	}
	plan, err := prepared.Plan()
	if err != nil || len(plan.Intents) != 1 || plan.Intents[0].Purpose != "otp-password-reset" || !plan.Intents[0].ExpiresAt.Equal(expiresAt) {
		t.Fatal("native recovery SMS changed delivery purpose", err)
	}
	again, err := issuer.Restore(ctx, root, input, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	second, err := again.Plan()
	if err != nil || !reflect.DeepEqual(plan, second) {
		t.Fatal("restore generated a new code or delivery", err)
	}
	if _, err := issuer.Restore(ctx, root, input, 2, wire); err == nil {
		t.Fatal("retained original output changed generation")
	}
	spec, _ := root.Feature()
	foreign, _ := identity.NewFeaturePreAuthCommand(spec, auth.NewBearerCredential("wrong-original-cookie"))
	if _, err := issuer.Restore(ctx, foreign, input, 1, wire); err == nil {
		t.Fatal("retained output lost original browser possession")
	}
	if err := prepared.Persist(ctx, kernel.Work{}, nil, root); err == nil {
		t.Fatal("prepared SMS fabricated protected Work")
	}
}

func phoneResetIssuanceNativeFixture(t *testing.T) (context.Context, *pgx.Conn, *database.Pool, *PhonePasswordResetIssuer, identity.Command, PhonePasswordResetSendInput) {
	t.Helper()
	ctx, db, _, _ := admissionDatabase(t)
	directory := kernel.DirectoryAuthorityMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 12}, Version: 13}, Version: 14, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"tenant"}}
	for i, source := range []migrations.Source{directory, mfapg.TOTPFactorMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if i == 0 && m.Version() < 12 {
				continue
			}
			if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant','user','active',1,4,5,6);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant','user','credential',1,'identity/password',1,true);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('tenant','user','phone','phone','+358401234567',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal(err)
	}
	pool, err := database.New(ctx, database.Config{DSN: os.Getenv("IDENTITY_OTP_POSTGRES_TEST_DSN"), Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := pool.Close(c); err != nil {
			t.Error(err)
		}
	})
	var now time.Time
	if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = now.UTC().Truncate(time.Microsecond)
	codec, _, joint, authority, old := phoneRecoveryCommandFixture(t)
	request, binding := phoneResetIssuanceRecordFixture(t)
	cookie, _ := joint.PhonePasswordResetPreAuthCookie()
	original, _ := old.Bindings()
	original.Binding.IssuedAt, original.Binding.ExpiresAt = now.Add(-time.Second), now.Add(4*time.Minute)
	token, _ := session.ParseToken(cookie.Token())
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	original.Cookie, err = token.PreAuthDigest(key, original.Binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(original)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring.New(map[string][]byte{"fixture": bytes.Repeat([]byte{0x72}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := mfapg.NewTOTPEnrollmentPreparer(keys, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	factorID := "AAAAAAAAAAAAAAAAAAAAAQ"
	pending, err := enrollment.Prepare(ctx, mfapg.TOTPEnrollmentPreparation{TenantID: "tenant", UserID: "user", FactorID: factorID, AuthorityVersion: 1, Profile: mfa.TOTPProfile{Algorithm: "SHA1", Digits: 8, Period: 30 * time.Second, AllowedSkewSteps: 1, Issuer: "Example"}, CreatedAt: now.Add(-time.Minute), TTL: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := pending.Envelope()
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	for _, c := range []struct {
		n       byte
		purpose string
	}{{91, "identity.password.signup"}, {92, "identity.mfa.enable"}} {
		id := bytes.Repeat([]byte{c.n}, 16)
		if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant',$2,$3,1,$4)`, id, c.purpose, bytes.Repeat([]byte{c.n}, 32), []byte{1}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant',$2)`, id, c.purpose); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES('tenant','user',1,1,$1,'identity.password.signup')`, bytes.Repeat([]byte{91}, 16)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('tenant','user',$1,2,1,1,'SHA1',8,30,1,'Example',$2,$3,'identity.mfa.enable',$4,$5,$6)`, factorID, wire, bytes.Repeat([]byte{92}, 16), now.Add(-time.Minute), now.Add(4*time.Minute), now); err != nil {
		t.Fatal(err)
	}
	reader, err := mfapg.NewTOTPFactorReader(pool, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := reader.ReadForPhoneRecovery(ctx, "tenant", "user", factorID)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := repo.ResolveRecipient(ctx, request.recipient.Query)
	if err != nil || recipient.Suppressed {
		t.Fatal("actual verified recipient", err)
	}
	templates := preparedSendTemplates("{{.code}}")
	templates[0].Channel, templates[0].Subject = delivery.ChannelSMS, ""
	issuer, err := NewPhonePasswordResetIssuer(PhonePasswordResetIssuerConfig{Store: ContributorConfig{Schema: "otp_store", Codec: codec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}}, Delivery: issuanceDeliveryOwner(t), Policy: request.policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: templates})
	if err != nil {
		t.Fatal(err)
	}
	input, err := issuer.CaptureInput(ctx, binding, flow, recipient, authority, snapshot, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal("capture exact original native inputs", err)
	}
	fields, err := input.Fields()
	if err != nil {
		t.Fatal(err)
	}
	root, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: phoneResetSendOperation(), Fields: fields}, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, db, pool, issuer, root, input
}

// This probe stops at the actual closed coordinator preparation gate. Its
// domain/risk methods are unexecuted tripwires, not runtime authorization peers.
// A passing declaration cannot establish SMS persistence or usable Work.
type phoneResetIssuancePreparationProbe struct{ contributorFeature }

func (*phoneResetIssuancePreparationProbe) ValidateFeaturePreparation(identity.Command, kernel.CommandPlan) error {
	return nil
}
func (*phoneResetIssuancePreparationProbe) AdmitFeaturePreparation(context.Context, kernel.Work, identity.Command) error {
	return errors.New("unexecuted request admission")
}
func (*phoneResetIssuancePreparationProbe) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, errors.New("unexecuted SMS generation")
}
func (*phoneResetIssuancePreparationProbe) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, kernel.CommandPlan, error) {
	return identity.Command{}, kernel.CommandPlan{}, errors.New("unexecuted SMS restore")
}

func TestPhoneResetIssuanceNativeRequestPreparationGate(t *testing.T) {
	_, _, pool, _, root, _ := phoneResetIssuanceNativeFixture(t)
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	domain := &phoneResetIssuancePreparationProbe{contributorFeature: contributorFeature{op: phoneResetSendOperation()}}
	risk := &phoneRecoveryUnexecuted{descriptor: kernel.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{}, &contributorLifecycle{}, domain, risk})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: 3 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := root.Feature()
	declaration := phoneResetIssuanceRequestDeclaration(t, spec, registry, domain.Descriptor())
	if _, err := coordinator.PrepareFeaturePreparationPlan(root, declaration); err != nil {
		t.Fatal("native SMS request cannot enter original preparation", err)
	}
}

func phoneResetIssuanceRequestDeclaration(t *testing.T, spec identity.FeatureCommandSpec, registry *kernel.ContributorRegistry, owner kernel.ContributorDescriptor) kernel.CommandPlan {
	t.Helper()
	b := spec.Binding
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	record, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: "otp.send", Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "otp_challenge", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "aggregate.type": "otp_challenge", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, "otp_challenge", record)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	risk := &kernel.RiskEvidencePlan{IssuanceCommandID: "AwMDAwMDAwMDAwMDAwMDAw", Tenant: string(b.TenantID), Subject: string(b.UserID), IssuerActor: string(b.ActorID), ConsumerCommandID: string(b.CommandID), ConsumerActor: string(b.ActorID), Purpose: "phone-password-reset-initiate", Phase: "phone-reset-initiation", RecoveryOperation: b.OperationID, PolicyVersion: 1, KeyVersion: 1, IntentDigest: [32]byte{2}, EvidenceDigest: [32]byte{3}, ProofDigest: [32]byte{4}, Signature: [32]byte{5}, IssuedAt: now, CheckedAt: now, ExpiresAt: now.Add(time.Minute)}
	return kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "otp_challenge", Feature: &kernel.FeatureRegistration{Contributor: owner, Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: "otp.sent.v1", AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: "otp.send", SchemaVersion: 1, BindingDigest: digest, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected"}}, RiskEvidence: risk}
}
