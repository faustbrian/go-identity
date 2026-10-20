//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

// This component uses real SMS generation, native issuance Work, encrypted
// delivery, the encrypted enrolled factor and the stored challenge. The existing
// named capability/risk peers establish no canonical reset permission. Completion
// mapping neither compares codes nor proves the full protected reset journey.
func TestPhoneResetConfirmationUsesActualOriginalIssuance(t *testing.T) {
	ctx, pool, domain := phoneResetConfirmationFixture(t)
	prepared := domain.prepared
	fields, err := prepared.Fields()
	wantFields, _ := domain.input.Fields()
	if err != nil || !reflect.DeepEqual(fields, wantFields) {
		t.Fatal("completion did not retain original factor selection", err)
	}
	fields[0].Value.Text = "changed"
	fields, err = prepared.Fields()
	if err != nil || !reflect.DeepEqual(fields, wantFields) {
		t.Fatal("caller mutated original factor fields", err)
	}
	factor, err := prepared.OriginalFactor()
	gotFactor, ge := factor.Metadata()
	wantFactor, _ := domain.input.state().factor.Metadata()
	if err != nil || ge != nil || gotFactor != wantFactor {
		t.Fatal("completion adopted another factor snapshot", err, ge)
	}
	at, until, err := prepared.Timeline()
	wantAt, wantUntil, _ := domain.input.Timeline()
	if err != nil || !at.Equal(wantAt) || !until.Equal(wantUntil) {
		t.Fatal("completion renewed original SMS lifetime", err)
	}
	message := persistedSendMessage(t, ctx, domain.db)
	sms, err := auth.NewOneTimeCode(message.Body)
	if err != nil {
		t.Fatal("real encrypted SMS code unavailable")
	}
	input := phoneResetConfirmationInput(t, domain, sms)
	// A later failed attempt advances the stored version. Preparation must read
	// that actual version, not adopt issuance's frozen initial version.
	if _, err := domain.db.Exec(ctx, `UPDATE otp_store.challenges SET failed_attempts=1,used_attempts=1,version=2`); err != nil {
		t.Fatal(err)
	}
	mapped, plan, err := prepared.PrepareConfirmation(ctx, pool, input, 7)
	if err != nil || plan.Mode != kernel.OTPConsume || plan.ExpectedVersion != 2 || plan.ChallengeID != string(domain.input.state().binding.CommandID) {
		t.Fatal("original SMS cannot enter real joint completion mapping", err)
	}
	spec, ok := mapped.PhonePasswordResetInputFeature()
	if !ok {
		t.Fatal("mapping lost joint input custody")
	}
	if _, ok := mapped.Feature(); ok {
		t.Fatal("mapping exposed legacy feature custody")
	}
	authority, err := domain.issuer.state().store.codec.restoreAuthority(spec)
	if err != nil || authority != domain.input.state().record.authority {
		t.Fatal("mapping reconstructed original authority", err)
	}
	attempt, err := domain.issuer.state().store.codec.restoreRecord(spec)
	if err != nil {
		t.Fatal(err)
	}
	wantContinuation, _ := domain.input.state().record.continuation.Bindings()
	gotContinuation, _ := attempt.Attempt.Continuation.Bindings()
	wantFlow, _ := wantContinuation.Authorization.PreAuthTransaction()
	gotFlow, _ := gotContinuation.Authorization.PreAuthTransaction()
	wantOriginal, _ := wantFlow.Bindings()
	gotOriginal, _ := gotFlow.Bindings()
	if gotContinuation.Scope != wantContinuation.Scope || gotOriginal != wantOriginal {
		t.Fatal("mapping replaced original pre-auth or SMS scope")
	}
	password, proof, gotSMS, totp, present := input.PhonePasswordResetInputCustody()
	mappedPassword, mappedProof, mappedSMS, mappedTOTP, retained := mapped.PhonePasswordResetInputCustody()
	if !present || !retained || password.Len() == 0 || password.Len() != mappedPassword.Len() {
		t.Fatal("mapping replaced borrowed password")
	}
	for _, pair := range [][2]auth.OneTimeCode{{gotSMS, mappedSMS}, {totp, mappedTOTP}} {
		a, _ := pair[0].CommandDigest([32]byte{1}, "test")
		b, err := pair[1].CommandDigest([32]byte{1}, "test")
		if err != nil || a != b {
			t.Fatal("mapping changed borrowed independent codes", err)
		}
	}
	a, _ := proof.CommandDigest([32]byte{1}, "test", 4096)
	b, err := mappedProof.CommandDigest([32]byte{1}, "test", 4096)
	if err != nil || a != b {
		t.Fatal("mapping replaced canonical capability custody", err)
	}
	first, err := prepared.NewPhoneRecoveryContributor()
	if err != nil || first.ValidateOTPAttemptCommand(mapped, plan) != nil {
		t.Fatal("actual original owner cannot select joint completion", err)
	}
	second, err := prepared.NewPhoneRecoveryContributor()
	if err != nil || first == second || first.phoneRecovery == second.phoneRecovery || first.send != nil || first.codec != domain.issuer.state().store.codec {
		t.Fatal("invocations share mutable recovery preparation", err)
	}
	if err := domain.issuer.state().store.ValidateOTPAttemptCommand(mapped, plan); err == nil {
		t.Fatal("issuance owner was mutated into a recovery owner")
	}
	if out, p, err := prepared.PrepareConfirmation(ctx, pool, mapped, 7); err == nil || out != (identity.Command{}) || p != (kernel.OTPAttemptPlan{}) {
		t.Fatal("mapped completion was renewed")
	}
	var version string
	var failed int
	if err := domain.db.QueryRow(ctx, `SELECT version::text,failed_attempts FROM otp_store.challenges`).Scan(&version, &failed); err != nil || version != "2" || failed != 1 {
		t.Fatal("mapping compared, consumed or changed original SMS", err)
	}
	password.Destroy()
	if mappedPassword.Len() != 0 {
		t.Fatal("mapping copied borrowed password into independent custody")
	}
}

func TestPhoneResetConfirmationRejectsForeignOriginal(t *testing.T) {
	ctx, pool, domain := phoneResetConfirmationFixture(t)
	wrongCode := "999999"
	if persistedSendMessage(t, ctx, domain.db).Body == wrongCode {
		wrongCode = "000000"
	}
	sms, _ := auth.NewOneTimeCode(wrongCode) // mapping is deliberately not comparison
	input := phoneResetConfirmationInput(t, domain, sms)
	if _, _, err := domain.prepared.PrepareConfirmation(ctx, pool, input, 7); err != nil {
		t.Fatal("bridge compared submitted code instead of preparing exact custody", err)
	}
	spec, _ := input.PhonePasswordResetInputFeature()
	password, proof, _, totp, _ := input.PhonePasswordResetInputCustody()
	cookie, _ := input.PhonePasswordResetPreAuthCookie()
	for name, change := range map[string]func(*identity.FeatureCommandSpec){
		"source-command": func(s *identity.FeatureCommandSpec) { s.Binding.CommandID = domain.input.state().binding.CommandID },
		"tenant":         func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "other" },
		"user":           func(s *identity.FeatureCommandSpec) { s.Binding.UserID = "other" },
		"actor":          func(s *identity.FeatureCommandSpec) { s.Binding.ActorID = "other" },
		"actor-kind":     func(s *identity.FeatureCommandSpec) { s.Binding.ActorKind = "user" },
		"policy":         func(s *identity.FeatureCommandSpec) { s.Binding.PolicyID = "other" },
		"policy-version": func(s *identity.FeatureCommandSpec) { s.Binding.PolicyVersion++ },
		"credential":     func(s *identity.FeatureCommandSpec) { s.Binding.RecordID = "other" },
		"factor": func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "phone.reset.factor-id" {
					s.Fields[i].Value.Text = "other"
				}
			}
		},
		"factor-version": func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "phone.reset.factor-version" {
					s.Fields[i].Value.Uint64++
				}
			}
		},
		"factor-authority": func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "phone.reset.factor-authority-version" {
					s.Fields[i].Value.Uint64++
				}
			}
		},
		"missing-factor": func(s *identity.FeatureCommandSpec) { s.Fields = s.Fields[:2] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := spec
			changed.Fields = append([]identity.FeatureField(nil), spec.Fields...)
			change(&changed)
			command, err := identity.NewFeaturePhonePasswordResetInputCommand(changed, password, proof, sms, totp)
			if err == nil {
				command, err = identity.BindPhonePasswordResetPreAuth(command, cookie)
			}
			if err != nil {
				t.Fatal("invalid denial fixture", err)
			}
			if out, p, err := domain.prepared.PrepareConfirmation(ctx, pool, command, 7); err == nil || out != (identity.Command{}) || p != (kernel.OTPAttemptPlan{}) {
				t.Fatal("different original recovery scope accepted")
			}
		})
	}
	wrong, _ := identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	wrong, err := identity.BindPhonePasswordResetPreAuth(wrong, auth.NewBearerCredential(wrongCookieWire()))
	if err != nil {
		t.Fatal("foreign cookie fixture", err)
	}
	for _, command := range []identity.Command{{}, domain.original, wrong} {
		if out, p, err := domain.prepared.PrepareConfirmation(ctx, pool, command, 7); err == nil || out != (identity.Command{}) || p != (kernel.OTPAttemptPlan{}) {
			t.Fatal("zero, wrong source or foreign cookie accepted")
		}
	}
	for _, key := range []uint32{0, 99} {
		if _, _, err := domain.prepared.PrepareConfirmation(ctx, pool, input, key); err == nil {
			t.Fatal("unknown attempt key accepted")
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, _, err := domain.prepared.PrepareConfirmation(canceled, pool, input, 7); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, _, err := domain.prepared.PrepareConfirmation(ctx, nil, input, 7); err == nil {
		t.Fatal("absent native pool accepted")
	}
	if _, err := (PreparedPhonePasswordResetSend{}).NewPhoneRecoveryContributor(); err == nil {
		t.Fatal("zero acquired consuming owner")
	}
	if _, err := (PreparedPhonePasswordResetSend{}).Fields(); err == nil {
		t.Fatal("zero acquired factor fields")
	}
	if _, err := (PreparedPhonePasswordResetSend{}).OriginalFactor(); err == nil {
		t.Fatal("zero acquired encrypted factor")
	}
	if at, until, err := (PreparedPhonePasswordResetSend{}).Timeline(); err == nil || !at.IsZero() || !until.IsZero() {
		t.Fatal("zero acquired original timeline")
	}
	// The bridge is reachable only through exact authenticated original output.
	id, _ := ownershipID(string(domain.input.state().binding.CommandID))
	var wire []byte
	if err := domain.db.QueryRow(ctx, `SELECT preparation_ciphertext FROM identity.commands WHERE command_id=$1`, id).Scan(&wire); err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	if _, err := domain.issuer.Restore(ctx, domain.original, domain.input, 1, wire); err != nil {
		t.Fatal("committed original cannot restore", err)
	}
	if _, err := domain.issuer.Restore(ctx, domain.original, domain.input, 2, wire); err == nil {
		t.Fatal("other generation acquired confirmation")
	}
	tampered := bytes.Clone(wire)
	tampered[len(tampered)-1] ^= 1
	if _, err := domain.issuer.Restore(ctx, domain.original, domain.input, 1, tampered); err == nil {
		t.Fatal("tampered output acquired confirmation")
	}
	clear(tampered)
	templates := preparedSendTemplates("changed {{.code}}")
	templates[0].Channel, templates[0].Subject = delivery.ChannelSMS, ""
	other, err := NewPhonePasswordResetIssuer(PhonePasswordResetIssuerConfig{Store: ContributorConfig{Schema: "otp_store", Codec: domain.issuer.state().store.codec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}}, Delivery: domain.issuer.DeliveryContributor(), Policy: domain.input.state().record.policy, TemplateID: "otp-code", TemplateVersion: 1, ProviderVersion: 1, LocaleChain: []string{"en"}, Templates: templates})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Restore(ctx, domain.original, domain.input, 1, wire); err == nil {
		t.Fatal("other configuration acquired confirmation")
	}
	// Live borrowed password destruction cannot be converted into retained authority.
	password.Destroy()
	if _, _, err := domain.prepared.PrepareConfirmation(ctx, pool, input, 7); err == nil {
		t.Fatal("destroyed borrowed custody accepted")
	}
}

func phoneResetConfirmationInput(t *testing.T, domain *phoneResetIssuanceComponent, sms auth.OneTimeCode) identity.Command {
	t.Helper()
	_, _, template, _, _ := phoneRecoveryCommandFixture(t)
	_, proof, _, totp, _ := template.PhonePasswordResetInputCustody()
	password, err := primitive.NewSecret([]byte("component reset replacement password"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(password.Destroy)
	spec, _ := domain.original.Feature()
	spec.Operation = identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	spec.Binding.CommandID = "AgICAgICAgICAgICAgICAg"
	spec.Binding.RecordID = string(domain.input.state().record.authority.Credential.ID)
	spec.Fields, err = domain.prepared.Fields()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	cookie, _ := domain.original.PreAuthCookie()
	command, err = identity.BindPhonePasswordResetPreAuth(command, cookie)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func phoneResetConfirmationFixture(t *testing.T) (context.Context, *database.Pool, *phoneResetIssuanceComponent) {
	t.Helper()
	ctx, db, pool, issuer, root, input := phoneResetIssuanceNativeFixture(t)
	for _, source := range []migrations.Source{MigrationSource{Schema: "otp_store", Version: 100}, LockoutMigrationSource{Schema: "otp_store", Version: 101}, SendFamilyMigrationSource{Schema: "otp_store", Version: 102}, IssuanceMigrationSource{Schema: "otp_store", Version: 103}, deliverypg.MigrationSource{Base: kernel.MigrationSource{}, Version: 250}, kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, kernel.AdmissionPreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 11}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range history {
			if m.Version() < 10 {
				continue
			}
			if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
				t.Fatal("existing component migration", err)
			}
		}
	}
	files, err := fs.ReadDir(outboxpg.Migrations(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		wire, err := fs.ReadFile(outboxpg.Migrations(), file.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal(err)
		}
	}
	m, err := authoritypg.AuthoritySchemaMigration(300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, m.Up); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE identity.global_authorities SET version=2; UPDATE identity.tenant_authorities SET version=3;
CREATE TABLE public.native_otp_audits(event_id text PRIMARY KEY,command_id text UNIQUE NOT NULL,outcome text NOT NULL);
CREATE TABLE public.native_otp_lifecycle(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL);
CREATE TABLE public.phone_reset_issuance_component_grants(command_id text PRIMARY KEY,generation numeric NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	tx := admissionBegin(t, ctx, db)
	current, err := authoritypg.InitializeAuthority(ctx, tx.Tx, authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	i := input.state()
	i.record.authority.UserAuthorization.Version = current.Version
	continuation, _ := i.record.continuation.Bindings()
	original, _ := continuation.Authorization.PreAuthTransaction()
	input, err = issuer.CaptureInput(ctx, i.binding, original, *i.record.recipient, i.record.authority, i.factor, i.record.issuedAt, i.record.expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	admissionInsert(t, ctx, db, issuer.state().store.preauth, original)
	if err := issuer.Initialize(ctx, pool); err != nil {
		t.Fatal(err)
	}
	domain := &phoneResetIssuanceComponent{contributorFeature: contributorFeature{op: phoneResetSendOperation()}, issuer: issuer, original: root, input: input, db: db}
	domain.grant = phoneResetIssuanceComponentGrant(t, input.state().binding, input.state().record.expiresAt)
	risk := &phoneResetIssuanceRiskPeer{command: root}
	repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{}, &contributorLifecycle{apply: true}, domain, risk, domain.grant, issuer.DeliveryContributor()})
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := root.Feature()
	declaration := phoneResetIssuanceRequestDeclaration(t, spec, registry, domain.Descriptor())
	declaration.Contributors = nil
	for _, d := range registry.Descriptors() {
		if d != issuer.DeliveryContributor().Descriptor() && d != domain.grant.Descriptor() {
			declaration.Contributors = append(declaration.Contributors, d)
		}
	}
	domain.declaration, risk.plan = declaration, *declaration.RiskEvidence
	coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 3 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.ExecutePreparedFeature(ctx, root, declaration)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual native SMS issuance failed", err)
	}
	return ctx, pool, domain
}
