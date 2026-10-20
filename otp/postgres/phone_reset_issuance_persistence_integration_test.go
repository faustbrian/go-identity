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
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
)

// Deliberate component peer, not risk authenticity/one-use proof. Every handle
// comes from the actual coordinator and is checked against its exact frozen
// request/plan/generation. It owns no SQL, effects, budget or retry mechanism.
type phoneResetIssuanceRiskPeer struct {
	command identity.Command
	plan    kernel.RiskEvidencePlan
}

func (*phoneResetIssuanceRiskPeer) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}
func (p *phoneResetIssuanceRiskPeer) require(b kernel.RiskReservationBinding) error {
	s, _ := p.command.Feature()
	if b.Command != s.Binding || b.Plan != p.plan || b.Fingerprint == ([32]byte{}) || b.Generation == 0 {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneResetIssuanceRiskPeer) ReserveRiskEvidence(ctx context.Context, w kernel.RiskReservationWork) error {
	b, e := w.Binding(p)
	if e != nil {
		return e
	}
	return p.require(b)
}
func (*phoneResetIssuanceRiskPeer) RebindRiskEvidence(context.Context, kernel.RiskReservationWork) error {
	return errors.New("component takeover not selected")
}
func (p *phoneResetIssuanceRiskPeer) ValidateRiskEvidenceCommand(c identity.Command, plan kernel.RiskEvidencePlan) error {
	if c != p.command || plan != p.plan {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneResetIssuanceRiskPeer) CheckRiskEvidence(ctx context.Context, w kernel.RiskApplyWork) error {
	b, e := w.Binding(p)
	if e != nil {
		return e
	}
	return p.require(b)
}
func (p *phoneResetIssuanceRiskPeer) FinalizeRiskEvidence(ctx context.Context, w kernel.RiskFinalizeWork) error {
	b, e := w.Binding(p)
	if e != nil {
		return e
	}
	return p.require(b)
}
func (p *phoneResetIssuanceRiskPeer) ReleaseRiskEvidence(ctx context.Context, w kernel.RiskReleaseWork) error {
	b, e := w.Binding(p)
	if e != nil {
		return e
	}
	return p.require(b)
}
func (*phoneResetIssuanceRiskPeer) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

// Deliberate capability issuance peer, NOT the canonical signed reset service
// or replay store. A core-verified synthetic grant is required by kernel stage
// grammar; this test-owned row proves only same-Work atomic participant effects.
type phoneResetIssuanceGrantPeer struct {
	command identity.CommandBinding
	plan    kernel.CapabilityIssuancePlan
	grant   capability.Grant
}

func (*phoneResetIssuanceGrantPeer) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.issuance", Version: 1}
}
func (p *phoneResetIssuanceGrantPeer) ValidateCapabilityIssuance(b identity.CommandBinding, plan kernel.CapabilityIssuancePlan) error {
	if b != p.command || !reflect.DeepEqual(plan, p.plan) {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneResetIssuanceGrantPeer) PersistCapabilityIssuance(ctx context.Context, w kernel.CapabilityIssuanceWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	if b.Generation == 0 || b.PreviousGeneration != 0 || b.Fingerprint == ([32]byte{}) || p.ValidateCapabilityIssuance(b.Command, b.Plan) != nil {
		return ErrInvalidCommand
	}
	grants, err := w.Grants(p)
	if err != nil || len(grants) != 1 || grants[0].EnvelopeDigest() != p.grant.EnvelopeDigest() {
		return ErrInvalidCommand
	}
	_, err = w.Exec(ctx, `INSERT INTO public.phone_reset_issuance_component_grants(command_id,generation) VALUES($1,$2::numeric)`, string(b.Command.CommandID), b.Generation)
	return err
}
func (*phoneResetIssuanceGrantPeer) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func phoneResetIssuanceComponentGrant(t *testing.T, b identity.CommandBinding, until time.Time) *phoneResetIssuanceGrantPeer {
	t.Helper()
	key := bytes.Repeat([]byte{0x75}, 32)
	signer, err := capability.NewHMACSHA256Signer("component-only", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	payload := capability.Payload{Version: 1, Issuer: "https://component.test", Audiences: []string{"component"}, Subject: string(b.UserID), Resource: "component-only-reset", Operation: "identity.phone.password-reset-complete", IssuedAt: now, NotBefore: now, ExpiresAt: until, ID: string(b.CommandID), Tenant: string(b.TenantID), MaxUses: 1}
	wire, err := capability.Issue(t.Context(), payload, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := capability.Verify(t.Context(), wire, capability.ResolverFunc(func(context.Context, string, capability.Algorithm) (capability.ResolvedKey, error) {
		return capability.ResolvedKey{Issuer: payload.Issuer, Verifier: verifier}, nil
	}), capability.VerifyOptions{Issuer: payload.Issuer, Now: now, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	p := &phoneResetIssuanceGrantPeer{command: b, grant: grant}
	p.plan = kernel.CapabilityIssuancePlan{Contributor: p.Descriptor(), Grants: []kernel.CapabilityPlan{{CapabilityID: payload.ID, Purpose: capability.Purpose(payload.Operation), ReplayKeyVersion: 1, ReplayDigest: [32]byte{1}, ProofFingerprint: grant.EnvelopeDigest(), ExpiresAt: grant.Payload().ExpiresAt, MaxUses: 1}}}
	return p
}

// Invocation-local fixture owner only. Actual SMS/MFA/primary/flow/recipient,
// audit SQL and encrypted delivery run; signed capability/risk/native phone
// orchestration do not. This is not full request or reset journey acceptance.
type phoneResetIssuanceComponent struct {
	contributorFeature
	issuer       *PhonePasswordResetIssuer
	original     identity.Command
	input        PhonePasswordResetSendInput
	declaration  kernel.CommandPlan
	prepared     PreparedPhonePasswordResetSend
	db           *pgx.Conn
	mode         string
	generated    int
	grant        *phoneResetIssuanceGrantPeer
	factorLocked chan pgx.Tx
}

func (p *phoneResetIssuanceComponent) ValidateFeaturePreparation(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.original {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneResetIssuanceComponent) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.original {
		return ErrInvalidCommand
	}
	i := p.input.state()
	a := i.record.authority
	if err := w.RequireActiveDirectoryAuthority(ctx, p, a.Directory); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthority(ctx, p, kernel.UserAuthorityAdmission{UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion}); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, issuanceCredential(a)); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, a.UserAuthorization); err != nil {
		return err
	}
	continuation, _ := i.record.continuation.Bindings()
	original, _ := continuation.Authorization.PreAuthTransaction()
	if err := requireNativeFlow(ctx, w, p.issuer.state().store, nativeFlow{preauth: original}, nil); err != nil {
		return err
	}
	if err := w.RequireRecipient(ctx, p, *i.record.recipient); err != nil {
		return err
	}
	return mfapg.RequirePhoneResetIssuancePreparation(ctx, w, p, c, i.factor, original)
}
func (p *phoneResetIssuanceComponent) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.generated++
	wire, err := p.issuer.Generate(ctx, c, p.input, generation)
	if err != nil {
		return nil, err
	}
	// Fixed test-only withdrawal between acknowledged generation and protected
	// Apply. This runs outside SQL/Work; no production caller hook is introduced.
	changes := map[string]string{"stale-factor": `UPDATE identity_mfa.factor_authorities SET version=2`, "removed-factor": `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL`, "withdrawn-password": `UPDATE identity.credential_references SET enabled=false`, "stale-recipient": `UPDATE identity.identifiers SET version=version+1`}
	if sql := changes[p.mode]; sql != "" {
		if _, err = p.db.Exec(ctx, sql); err != nil {
			clear(wire)
			return nil, err
		}
	}
	if p.mode == "expired-original-sms" {
		if _, err := p.db.Exec(ctx, `SELECT pg_sleep(2.2)`); err != nil {
			clear(wire)
			return nil, err
		}
	}
	if p.mode == "factor-lock-order" {
		blocker, err := p.db.Begin(ctx)
		if err != nil {
			clear(wire)
			return nil, err
		}
		m, _ := p.input.state().factor.Metadata()
		if _, err := blocker.Exec(ctx, `SELECT factor_id FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 FOR UPDATE`, string(m.TenantID), string(m.UserID), m.FactorID); err != nil {
			_ = blocker.Rollback(ctx)
			clear(wire)
			return nil, err
		}
		p.factorLocked <- blocker
	}
	return wire, nil
}
func (p *phoneResetIssuanceComponent) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	prepared, err := p.issuer.Restore(ctx, c, p.input, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	delivery, err := prepared.Plan()
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.prepared = prepared
	final := p.declaration
	final.Delivery = &delivery
	final.CapabilityIssuance = &p.grant.plan
	final.Contributors = append(append([]kernel.ContributorDescriptor(nil), final.Contributors...), p.grant.Descriptor(), delivery.Contributor)
	return c, final, nil
}

type phoneResetIssuanceAdmission struct{ phase *phoneResetIssuanceComponent }

func (a phoneResetIssuanceAdmission) Check(ctx context.Context) error {
	if ctx == nil || a.phase == nil {
		return ErrInvalidCommand
	}
	return ctx.Err()
}
func (a phoneResetIssuanceAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.GenerateFeaturePreparation(ctx, a.phase.original, generation)
}
func (p *phoneResetIssuanceComponent) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.issuer.original(ctx, c, p.input, 1); err != nil {
		return nil, err
	}
	return phoneResetIssuanceAdmission{p}, nil
}
func (p *phoneResetIssuanceComponent) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, err := p.issuer.Restore(ctx, c, p.input, generation, wire); err != nil {
		return nil, err
	}
	return phoneResetIssuanceAdmission{p}, nil
}
func (p *phoneResetIssuanceComponent) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p.mode == "reconstructed-root" {
		spec, _ := c.Feature()
		cookie, _ := c.PreAuthCookie()
		var err error
		c, err = identity.NewFeaturePreAuthCommand(spec, cookie)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := p.prepared.Persist(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := w.StageCapabilityIssuanceFor(p.grant, 0, p.grant.grant); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.mode == "rollback" {
		return identity.FeatureReceipt{}, errors.New("component protected rollback")
	}
	return identity.FeatureReceipt{Operation: phoneResetSendOperation(), AfterVersion: 1}, nil
}
func (p *phoneResetIssuanceComponent) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return p.issuer.Recover(ctx, w, p)
}

func TestPhoneResetIssuanceNativePersistence(t *testing.T) {
	for _, mode := range []string{"committed", "rollback", "stale-factor", "removed-factor", "withdrawn-password", "stale-recipient", "reconstructed-root", "expired-original-sms", "factor-lock-order"} {
		t.Run(mode, func(t *testing.T) {
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
CREATE TABLE public.native_otp_lifecycle(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL)`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `CREATE TABLE public.phone_reset_issuance_component_grants(command_id text PRIMARY KEY,generation numeric NOT NULL)`); err != nil {
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
			if mode == "expired-original-sms" {
				i.record.expiresAt = i.record.issuedAt.Add(2 * time.Second)
			}
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
			domain := &phoneResetIssuanceComponent{contributorFeature: contributorFeature{op: phoneResetSendOperation()}, issuer: issuer, original: root, input: input, db: db, mode: mode, factorLocked: make(chan pgx.Tx, 1)}
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
			domain.declaration = declaration
			risk.plan = *declaration.RiskEvidence
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 3 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			var result identity.CommandResult
			if mode == "factor-lock-order" {
				result, err = phoneResetIssuanceFactorOrder(t, ctx, pool, coordinator, domain)
			} else {
				result, err = coordinator.ExecutePreparedFeature(ctx, root, declaration)
			}
			committed := mode == "committed" || mode == "factor-lock-order"
			if committed && (err != nil || result.Outcome != identity.CommitOutcomeCommitted) || !committed && err == nil {
				t.Fatal("native SMS component classification", result.Outcome, err, "generation", domain.generated, "restored", domain.prepared.state() != nil)
			}
			var challenges, families, effects, audits, events, grants int
			var unused, flowUnconsumed bool
			if err := db.QueryRow(ctx, `SELECT (SELECT count(*) FROM otp_store.challenges),(SELECT coalesce(sum(cardinality(sent_at)),0) FROM otp_store.send_families),(SELECT count(*) FROM identity.delivery_intents),(SELECT count(*) FROM public.native_otp_audits),(SELECT count(*) FROM public.native_otp_lifecycle),(SELECT last_step IS NULL AND row_version=1 FROM identity_mfa.totp_factors),(SELECT count(*) FROM public.phone_reset_issuance_component_grants),(SELECT state='issued' AND version=issued_version FROM session_store.preauth_transactions)`).Scan(&challenges, &families, &effects, &audits, &events, &unused, &grants, &flowUnconsumed); err != nil {
				t.Fatal(err)
			}
			want := 0
			if committed {
				want = 1
			}
			// Native Abort retains one denied audit after protected execution;
			// it does not retain the provisional issuance/delivery/lifecycle.
			if challenges != want || families != want || effects != want || audits != 1 || events != want || grants != want || !unused || !flowUnconsumed || domain.generated != 1 {
				t.Fatalf("component effects not atomic: challenge=%d send=%d delivery=%d audit=%d lifecycle=%d factor-untouched=%t generation=%d", challenges, families, effects, audits, events, unused, domain.generated)
			}
			if committed {
				message := persistedSendMessage(t, ctx, db)
				code, err := auth.NewOneTimeCode(message.Body)
				if err != nil {
					t.Fatal("actual encrypted SMS has no bounded code")
				}
				var digest []byte
				var keyVersion int64
				var challengeID, subject, purpose string
				var issuedAt, expiresAt time.Time
				if err := db.QueryRow(ctx, `SELECT code_digest,digest_key_version,challenge_id,subject_id,purpose,issued_at,expires_at FROM otp_store.challenges`).Scan(&digest, &keyVersion, &challengeID, &subject, &purpose, &issuedAt, &expiresAt); err != nil {
					t.Fatal(err)
				}
				defer clear(digest)
				if len(digest) != 32 || keyVersion < 1 || keyVersion > int64(^uint32(0)) {
					t.Fatal("invalid persisted SMS digest")
				}
				stored := otp.StoredCodeDigest{KeyVersion: uint32(keyVersion)}
				copy(stored.Value[:], digest)
				i := input.state()
				scope, _ := i.record.continuation.DigestScope()
				match, err := issuer.state().store.codec.verifier.Compare(scope, stored, code)
				if err != nil || !match || message.Channel != delivery.ChannelSMS || message.Address != i.record.recipient.Query.CanonicalValue || challengeID != string(i.binding.CommandID) || subject != string(i.binding.UserID) || purpose != "password-reset" || !issuedAt.Equal(i.record.issuedAt) || !expiresAt.Equal(i.record.expiresAt) {
					t.Fatal("stored challenge and actual encrypted original SMS diverged", err)
				}
				replay, err := coordinator.ExecutePreparedFeature(ctx, root, declaration)
				if err != nil || replay.Outcome != identity.CommitOutcomeCommitted || replay.AuditEventID != result.AuditEventID || domain.generated != 1 {
					t.Fatal("terminal request regenerated or changed original SMS", err)
				}
			}
		})
	}
}

// Observe real PostgreSQL relation locks, not callback choreography or invisible
// provisional rows. Generation has ended and its transaction was closed before
// the fixture peer holds the factor; the next blocked factor read is protected
// Apply, which must hold no OTP exclusion/challenge relation locks yet.
func phoneResetIssuanceFactorOrder(t *testing.T, ctx context.Context, pool *database.Pool, coordinator *kernel.Coordinator, domain *phoneResetIssuanceComponent) (identity.CommandResult, error) {
	t.Helper()
	type outcome struct {
		result identity.CommandResult
		err    error
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan outcome, 1)
	joined := false
	var blocker pgx.Tx
	defer func() {
		cancel()
		if blocker != nil {
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			if err := blocker.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				t.Error(err)
			}
			stop()
		}
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("native request goroutine did not stop")
			}
		}
		if blocker == nil {
			select {
			case late := <-domain.factorLocked:
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				if err := late.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
					t.Error(err)
				}
				stop()
			default:
			}
		}
	}()
	go func() {
		result, err := coordinator.ExecutePreparedFeature(runCtx, domain.original, domain.declaration)
		done <- outcome{result, err}
	}()
	select {
	case blocker = <-domain.factorLocked:
	case result := <-done:
		joined = true
		return result.result, result.err
	case <-ctx.Done():
		return identity.CommandResult{}, ctx.Err()
	}
	observe, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var pid int32
		if err := pool.Raw().QueryRow(observe, `SELECT COALESCE((SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM identity_mfa.totp_factors%FOR UPDATE%' LIMIT 1),0)`).Scan(&pid); err != nil {
			t.Fatal("protected factor wait observation", err)
		}
		if pid != 0 {
			var otpLocks bool
			if err := pool.Raw().QueryRow(observe, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE l.pid=$1 AND n.nspname='otp_store' AND c.relname IN('lockouts','send_families','challenges'))`, pid).Scan(&otpLocks); err != nil {
				t.Fatal(err)
			}
			if otpLocks {
				t.Fatal("protected request acquired OTP exclusions before original factor")
			}
			break
		}
		select {
		case result := <-done:
			joined = true
			return result.result, result.err
		case <-observe.Done():
			t.Fatal("protected factor wait was not observed")
		case <-tick.C:
		}
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		joined = true
		return result.result, result.err
	case <-ctx.Done():
		return identity.CommandResult{}, ctx.Err()
	}
}
