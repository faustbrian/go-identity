//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Component proof only: actual coordinator-created OTPAttemptWork, native OTP,
// current pre-auth/password/user/verified-phone and encrypted MFA factor. The
// password-domain input admission and SQL audit persistence are labelled seams;
// capability/risk are UNEXECUTED declaration tripwires, not recovery permission.
// No consuming reset, signed recovery authorization or public service is proved.
type phoneRecoveryCountedDomain struct {
	contributorFeature
	intent     kernel.CredentialResetIntent
	authority  AttemptAuthority
	admissions int
}

func (*phoneRecoveryCountedDomain) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *phoneRecoveryCountedDomain) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	s, ok := c.PhonePasswordResetFeature()
	if !ok || s.Operation != p.op {
		return ErrInvalidCommand
	}
	return nil
}
func (p *phoneRecoveryCountedDomain) CredentialReset(identity.Command) (kernel.CredentialResetIntent, error) {
	return p.intent, nil
}
func (*phoneRecoveryCountedDomain) CheckFeatureCommit(context.Context, kernel.Work, identity.Command) error {
	return errors.New("unexpected reset commit")
}
func (p *phoneRecoveryCountedDomain) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, _ identity.Command) error {
	p.admissions++
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.authority.Directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, p, credentialAdmission(p.authority)); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, p, p.authority.UserAuthorization); err != nil {
		return err
	}
	return w.RequireVerifiedIdentifier(ctx, p, kernel.VerifiedIdentifierAdmission{IdentifierID: "phone", Kind: identity.IdentifierPhone, IdentifierVersion: 1, VerificationVersion: 1, User: kernel.UserAuthorityAdmission{UserAuthorityVersion: p.authority.UserAuthorityVersion, IdentifierAuthorityVersion: p.authority.IdentifierAuthorityVersion, CredentialAuthorityVersion: p.authority.CredentialAuthorityVersion}})
}
func (*phoneRecoveryCountedDomain) ValidateFeaturePreparation(identity.Command, kernel.CommandPlan) error {
	return errors.New("unexpected preparation")
}
func (*phoneRecoveryCountedDomain) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, errors.New("unexpected generation")
}
func (*phoneRecoveryCountedDomain) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, kernel.CommandPlan, error) {
	return identity.Command{}, kernel.CommandPlan{}, errors.New("unexpected restore")
}
func (*phoneRecoveryCountedDomain) PrepareFeatureAdmission(context.Context, identity.Command) (kernel.FeaturePreparationAdmission, error) {
	return nil, errors.New("unexpected admission preparation")
}
func (*phoneRecoveryCountedDomain) RestoreFeatureAdmission(context.Context, identity.Command, uint64, []byte) (kernel.FeaturePreparationAdmission, error) {
	return nil, errors.New("unexpected admission restore")
}

type phoneRecoveryCountedLifecycle struct{ contributorLifecycle }

func (*phoneRecoveryCountedLifecycle) PersistCredentialReset(context.Context, kernel.Work) error {
	return errors.New("unexpected reset lifecycle")
}

type phoneRecoveryUnexecuted struct {
	descriptor kernel.ContributorDescriptor
	calls      int
}

func (p *phoneRecoveryUnexecuted) Descriptor() kernel.ContributorDescriptor { return p.descriptor }
func (p *phoneRecoveryUnexecuted) unexpected() error {
	p.calls++
	return errors.New("unexecuted declaration participant invoked")
}
func (p *phoneRecoveryUnexecuted) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, p.unexpected()
}
func (p *phoneRecoveryUnexecuted) ReserveCapability(context.Context, kernel.CapabilityReservationWork) error {
	return p.unexpected()
}
func (p *phoneRecoveryUnexecuted) RebindCapability(context.Context, kernel.CapabilityReservationWork) error {
	return p.unexpected()
}
func (p *phoneRecoveryUnexecuted) ReleaseCapability(context.Context, kernel.CapabilityReleaseWork) error {
	return p.unexpected()
}
func (p *phoneRecoveryUnexecuted) ApplyCapability(context.Context, kernel.CapabilityApplyWork) error {
	return p.unexpected()
}
func (p *phoneRecoveryUnexecuted) FinalizeCapability(context.Context, kernel.CapabilityFinalizeWork) error {
	return p.unexpected()
}
func (p *phoneRecoveryUnexecuted) ReserveRiskEvidence(context.Context, kernel.RiskReservationWork) error {
	return p.unexpected()
}
func (p *phoneRecoveryUnexecuted) RebindRiskEvidence(context.Context, kernel.RiskReservationWork) error {
	return p.unexpected()
}

func TestPhoneRecoveryNativeCountedConjunction(t *testing.T) {
	for _, mode := range []string{"sms-right-totp-wrong", "sms-wrong-totp-right", "both-wrong", "both-right", "replayed-totp", "stale-factor", "removed-factor", "unavailable-factor", "withdrawn-password", "unverified-phone", "audit-rollback", "commit-unknown", "late-factor-expiry", "destroyed-preparation", "protected-factor-order", "protected-rollback", "protected-expired-receipt", "protected-zero-receipt", "protected-absent-receipt", "protected-apply-only-receipt"} {
		t.Run(mode, func(t *testing.T) {
			ctx, db, peer, preauth := admissionDatabase(t)
			base := kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 12}
			credentials := kernel.CredentialMigrationSource{Base: base, Version: 13}
			directory := kernel.DirectoryAuthorityMigrationSource{Base: credentials, Version: 14, GlobalAuthorityID: "deployment", TenantIDs: []identity.TenantID{"tenant"}}
			for i, source := range []migrations.Source{directory, MigrationSource{Schema: "otp_store", Version: 100}, LockoutMigrationSource{Schema: "otp_store", Version: 101}, mfapg.TOTPFactorMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}} {
				history, err := source.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range history {
					if i == 0 && m.Version() < 12 {
						continue
					}
					if _, err := db.Exec(ctx, m.UpSQL()); err != nil {
						t.Fatal("fixture install", err)
					}
				}
			}
			migration, err := authoritypg.AuthoritySchemaMigration(300)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, migration.Up); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `UPDATE identity.global_authorities SET version=2; UPDATE identity.tenant_authorities SET version=3;
INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('tenant','user','active',1,4,5,6);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('tenant','user','credential',1,'identity/password',1,true);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('tenant','user','phone','phone','+358401234567',true,true,1,2,1,clock_timestamp());
INSERT INTO otp_store.digest_keys VALUES(3,'hmac-sha256-v1');
CREATE TABLE public.native_otp_audits(event_id text PRIMARY KEY,command_id text UNIQUE NOT NULL,outcome text NOT NULL);
CREATE TABLE public.native_otp_domain(command_id text PRIMARY KEY);
CREATE TABLE public.native_otp_lifecycle(command_id text PRIMARY KEY,event_id text UNIQUE NOT NULL);`); err != nil {
				t.Fatal(err)
			}
			tx := admissionBegin(t, ctx, db)
			if _, err := authoritypg.InitializeAuthority(ctx, tx.Tx, authoritypg.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, time.Second); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			pool, err := database.New(ctx, database.Config{DSN: os.Getenv("IDENTITY_OTP_POSTGRES_TEST_DSN"), Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = db.Config().Database; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := pool.Close(cleanup); err != nil {
					t.Error(err)
				}
			})
			var now time.Time
			if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			now = now.UTC().Truncate(time.Microsecond)
			keys, err := keyring.New(map[string][]byte{"fixture": bytes.Repeat([]byte{0x72}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			crypto, err := envelope.NewService(keys)
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
			binding, _ := pending.EncryptionContext()
			wire, err := sealed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: binding})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			for _, entry := range []struct {
				n       byte
				purpose string
			}{{91, "identity.password.signup"}, {92, "identity.mfa.enable"}} {
				id := bytes.Repeat([]byte{entry.n}, 16)
				if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'tenant',$2,$3,1,$4);`, id, entry.purpose, bytes.Repeat([]byte{entry.n}, 32), []byte{1}); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'tenant',$2)`, id, entry.purpose); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := db.Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES('tenant','user',1,1,$1,'identity.password.signup');`, bytes.Repeat([]byte{91}, 16)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('tenant','user',$1,2,1,1,'SHA1',8,30,1,'Example',$2,$3,'identity.mfa.enable',$4,$5,$6)`, factorID, wire, bytes.Repeat([]byte{92}, 16), now.Add(-time.Minute), now.Add(4*time.Minute), now); err != nil {
				t.Fatal(err)
			}
			reader, err := mfapg.NewTOTPFactorReader(pool, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			var originalReplay *string
			if mode == "replayed-totp" {
				if err := db.QueryRow(ctx, `UPDATE identity_mfa.totp_factors SET last_step=$1::numeric RETURNING last_step::text`, fmt.Sprintf("%d", now.Unix()/30)).Scan(&originalReplay); err != nil {
					t.Fatal(err)
				}
			}
			snapshot, err := reader.ReadForPhoneRecovery(ctx, "tenant", "user", factorID)
			if err != nil {
				t.Fatal(err)
			}
			factor, err := mfapg.NewPhoneRecoveryTOTPVerifier(crypto, [32]byte{0x73}, 1)
			if err != nil {
				t.Fatal(err)
			}
			code := phoneRecoveryFixtureCode(plain, now)
			if mode == "sms-right-totp-wrong" || mode == "both-wrong" || mode == "audit-rollback" || mode == "commit-unknown" || mode == "late-factor-expiry" {
				code = "123456"
			} // impossible eight-digit profile match
			sms := "123456"
			if mode == "sms-wrong-totp-right" || mode == "both-wrong" {
				sms = "654321"
			}
			owner, command, attempt, flow, authority := phoneRecoveryCountedCommand(t, now, sms, code, factorID, strings.HasPrefix(mode, "protected-"))
			admissionInsert(t, ctx, db, preauth, flow)
			keyBinding := owner.lockout.binding()
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.lockout_key_binding VALUES(true,$1)`, keyBinding[:]); err != nil {
				t.Fatal(err)
			}
			a, err := owner.codec.restoreAttempt(command, attempt)
			if err != nil {
				t.Fatal(err)
			}
			ab, _ := a.Bindings()
			continuation, _ := ab.Continuation.Bindings()
			tx = admissionBegin(t, ctx, db)
			if err := owner.lockout.initializeLockouts(ctx, sqlChallengeQuery(tx.Tx), sqlChallengeExec(tx.Tx), "otp_store", continuation.Scope); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			scope, _ := ab.Continuation.DigestScope()
			verifier, _ := otp.NewVerifier(3, codecConfig().CodeKeys)
			good, _ := auth.NewOneTimeCode("123456")
			digest, _ := verifier.Digest(scope, good)
			stored := digest.Storage()
			sd, _ := verifier.ScopeDigest(scope, 3)
			issue := otpCommand(t, ctx, db, "tenant", 77)
			if _, err := db.Exec(ctx, `WITH instant AS MATERIALIZED(SELECT clock_timestamp() AS now) UPDATE identity.commands SET state='committed',generation=1,attempt=1,lease_owner=$2,lease_until=instant.now,heartbeat_at=instant.now,created_at=instant.now,updated_at=instant.now,result_version=1,terminal_class='committed',result=$2,terminal_at=instant.now FROM instant WHERE command_id=$1`, issue, bytes.Repeat([]byte{77}, 16)); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(ctx, `INSERT INTO otp_store.challenges(tenant_id,challenge_id,subject_id,purpose,issue_command_id,issue_command_purpose,issue_fingerprint,digest_key_version,code_digest,scope_digest,policy_version,scope_generation,alphabet,code_length,ttl_us,resend_interval_us,maximum_sends,attempt_limit,replacement,checks_enabled,check_limit,lockout_us,issued_at,expires_at,state,version) VALUES('tenant','challenge','user','password-reset',$1,'identity.otp.send',$2,3,$3,$4,11,12,'0123456789',6,60000000,30000000,3,3,'retain',true,2,60000000,$5,$5::timestamptz+interval '60 seconds','issued',1)`, issue, bytes.Repeat([]byte{77}, 32), stored.Value[:], sd.Value[:], now); err != nil {
				t.Fatal(err)
			}
			until := now.Add(time.Minute)
			if mode == "late-factor-expiry" {
				until = now.Add(time.Second)
			}
			if mode == "protected-expired-receipt" {
				until = now.Add(2 * time.Second)
			}
			if mode == "both-right" {
				spec, _ := command.PhonePasswordResetFeature()
				_, proof, sms, totp, _ := command.PhonePasswordResetCustody()
				foreign, _ := identity.NewFeaturePhonePasswordResetCommand(spec, "$fixture$replacement", proof, sms, totp)
				foreign, _ = identity.BindPhonePasswordResetPreAuth(foreign, auth.NewBearerCredential("invalid-original-cookie"))
				if _, err := owner.PreparePhoneRecovery(ctx, foreign, attempt, PhoneRecoveryPreparation{Factor: snapshot, Verifier: factor, ValidUntil: until}); err == nil {
					t.Fatal("foreign browser bearer acquired plaintext preparation")
				}
			}
			custody, err := owner.PreparePhoneRecovery(ctx, command, attempt, PhoneRecoveryPreparation{Factor: snapshot, Verifier: factor, ValidUntil: until})
			if err != nil {
				t.Fatal("outside-lock preparation", err)
			}
			defer custody.Destroy()
			if mode == "both-right" {
				spec, _ := command.PhonePasswordResetFeature()
				_, proof, sms, totp, _ := command.PhonePasswordResetCustody()
				cookie, _ := command.PhonePasswordResetPreAuthCookie()
				clone, _ := identity.NewFeaturePhonePasswordResetCommand(spec, "$fixture$replacement", proof, sms, totp)
				clone, _ = identity.BindPhonePasswordResetPreAuth(clone, cookie)
				if _, _, err := owner.executionOriginal(clone, attempt); err == nil {
					t.Fatal("reconstructed command borrowed final preparation")
				}
				changed := attempt
				changed.ExpectedVersion++
				if _, _, err := owner.executionOriginal(command, changed); err == nil {
					t.Fatal("foreign attempt plan borrowed final preparation")
				}
			}
			if mode == "destroyed-preparation" {
				custody.Destroy()
			}
			for name, sql := range map[string]string{"stale-factor": `UPDATE identity_mfa.factor_authorities SET version=2`, "removed-factor": `UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL`, "unavailable-factor": `ALTER TABLE identity_mfa.totp_factors RENAME COLUMN encrypted_secret TO unavailable_secret`, "withdrawn-password": `UPDATE identity.credential_references SET enabled=false`, "unverified-phone": `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=1,verified_at=NULL`} {
				if mode == name {
					if _, err := db.Exec(ctx, sql); err != nil {
						t.Fatal(err)
					}
				}
			}
			spec, _ := command.PhonePasswordResetFeature()
			intent := kernel.CredentialResetIntent{Replacement: kernel.CredentialReplacementIntent{Credential: authority.Credential, ExpectedUserVersion: 1, ExpectedAuthorityVersion: authority.CredentialAuthorityVersion}, ExpectedEnabled: true}
			domain := &phoneRecoveryCountedDomain{contributorFeature: contributorFeature{op: spec.Operation}, intent: intent, authority: authority}
			if strings.HasPrefix(mode, "protected-") {
				testPhoneRecoveryProtectedFactorOrder(t, ctx, db, peer, pool, directory, owner, command, attempt, custody, domain, now, mode)
				return
			}
			capability := &phoneRecoveryUnexecuted{descriptor: kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}}
			risk := &phoneRecoveryUnexecuted{descriptor: kernel.ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}}
			repo, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repo, &contributorAudit{fail: mode == "audit-rollback"}, &phoneRecoveryCountedLifecycle{}, domain, owner, risk, capability})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			declaration := phoneRecoveryCountedPlan(t, registry, command, attempt, now)
			plan, err := coordinator.PrepareOTPAttemptPlan(spec.Binding, command, declaration)
			if err != nil {
				t.Fatal("closed phone counted plan", err)
			}
			if mode == "commit-unknown" {
				// A real deferred primary constraint fails only at COMMIT. This
				// exercises the coordinator's conservative Unknown return, not a
				// claim of transport-acknowledgement fault injection or rollback
				// permission for the consumer. Never retry/replace it here.
				if _, err := db.Exec(ctx, `CREATE TABLE public.native_otp_audit_commit_guard(command_id text PRIMARY KEY); ALTER TABLE public.native_otp_audits ADD FOREIGN KEY(command_id) REFERENCES public.native_otp_audit_commit_guard(command_id) DEFERRABLE INITIALLY DEFERRED`); err != nil {
					t.Fatal(err)
				}
			}
			var result identity.CommandResult
			if mode == "late-factor-expiry" {
				blocker, blockErr := peer.Begin(ctx)
				if blockErr != nil {
					t.Fatal(blockErr)
				}
				defer blocker.Rollback(context.Background())
				if _, blockErr := blocker.Exec(ctx, `SELECT challenge_id FROM otp_store.challenges FOR UPDATE`); blockErr != nil {
					t.Fatal(blockErr)
				}
				waitConsumingExpiry(t, ctx, db, until, func(run context.Context) error {
					result, err = coordinator.RecordOTPAttemptDenial(run, spec.Binding, command, plan)
					return err
				}, func() error { return blocker.Rollback(ctx) })
			} else {
				result, err = coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan)
			}
			if err == nil {
				t.Fatal("counted conjunction became authorization")
			}
			want := 1
			if mode == "both-right" || mode == "stale-factor" || mode == "removed-factor" || mode == "unavailable-factor" || mode == "withdrawn-password" || mode == "unverified-phone" || mode == "audit-rollback" || mode == "commit-unknown" || mode == "late-factor-expiry" || mode == "destroyed-preparation" {
				want = 0
			}
			var used, failed, audits, domains, events int
			var state, flowState string
			var replay *string
			if err := db.QueryRow(ctx, `SELECT (SELECT used_attempts FROM otp_store.challenges),(SELECT failed_attempts FROM otp_store.challenges),(SELECT state FROM otp_store.challenges),(SELECT state FROM session_store.preauth_transactions),(SELECT last_step::text FROM identity_mfa.totp_factors),(SELECT count(*) FROM public.native_otp_audits),(SELECT count(*) FROM public.native_otp_domain),(SELECT count(*) FROM public.native_otp_lifecycle)`).Scan(&used, &failed, &state, &flowState, &replay, &audits, &domains, &events); err != nil {
				t.Fatal(err)
			}
			replayChanged := replay != nil && originalReplay == nil || replay == nil && originalReplay != nil || replay != nil && originalReplay != nil && *replay != *originalReplay
			if used != want || failed != want || state != "issued" || flowState != "issued" || replayChanged || audits != want || domains != 0 || events != 0 || risk.calls != 0 || capability.calls != 0 {
				t.Fatal("counted atomicity/conjunction fence failed", mode, used, failed, state, flowState, audits, domains, events)
			}
			if mode == "both-right" {
				if result.Outcome != identity.CommitOutcomeConflict {
					t.Fatal("correct conjunction did not roll provisional count back", result.Outcome)
				}
			}
			if mode == "commit-unknown" && result.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("commit failure lost original Unknown outcome", result.Outcome)
			}
			if want == 1 {
				if domain.admissions == 0 || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("real counted owner was not reached", domain.admissions, result.Outcome)
				}
				custody.Destroy() // historical replay must not need prepared plaintext
				originalAdmissions := domain.admissions
				replayed, replayErr := coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, command, plan)
				if replayErr != nil || replayed.Outcome != result.Outcome || replayed.AuditEventID != result.AuditEventID || domain.admissions != originalAdmissions {
					t.Fatal("exact replay reentered counted admission", replayErr)
				}
				_, proof, originalSMS, _, _ := command.PhonePasswordResetCustody()
				changedCode, _ := auth.NewOneTimeCode("99999999")
				changed, _ := identity.NewFeaturePhonePasswordResetCommand(spec, "$fixture$replacement", proof, originalSMS, changedCode)
				cookie, _ := command.PhonePasswordResetPreAuthCookie()
				changed, _ = identity.BindPhonePasswordResetPreAuth(changed, cookie)
				changedPlan, changedErr := coordinator.PrepareOTPAttemptPlan(spec.Binding, changed, declaration)
				if changedErr != nil {
					t.Fatal("changed joint declaration", changedErr)
				}
				changedResult, changedErr := coordinator.RecordOTPAttemptDenial(ctx, spec.Binding, changed, changedPlan)
				if changedErr == nil || changedResult.Outcome != identity.CommitOutcomeConflict || domain.admissions != originalAdmissions {
					t.Fatal("changed joint factor borrowed original replay", changedErr, changedResult.Outcome)
				}
				if err := db.QueryRow(ctx, `SELECT used_attempts,failed_attempts FROM otp_store.challenges`).Scan(&used, &failed); err != nil || used != 1 || failed != 1 {
					t.Fatal("replay charged again", err)
				}
			}
		})
	}
}

func phoneRecoveryFixtureCode(secret []byte, now time.Time) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%08d", value%100000000)
}

func phoneRecoveryCountedCommand(t *testing.T, now time.Time, smsText, totpText, factorID string, consuming bool) (*Contributor, identity.Command, kernel.OTPAttemptPlan, session.PreAuthTransaction, AttemptAuthority) {
	t.Helper()
	codec, _, input, authority, old := phoneRecoveryCommandFixture(t)
	spec, _ := input.PhonePasswordResetInputFeature()
	_, proof, _, _, _ := input.PhonePasswordResetInputCustody()
	cookie, _ := input.PhonePasswordResetPreAuthCookie()
	authority.UserAuthorization.Version = 1
	intent := kernel.CredentialResetIntent{Replacement: kernel.CredentialReplacementIntent{Credential: authority.Credential, ExpectedUserVersion: 1, ExpectedAuthorityVersion: authority.CredentialAuthorityVersion}, ExpectedEnabled: true}
	fields, err := kernel.CredentialResetFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields = append(fields, identity.FeatureField{Name: "phone.reset.factor-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: factorID}}, identity.FeatureField{Name: "phone.reset.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}}, identity.FeatureField{Name: "phone.reset.factor-authority-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}})
	f, _ := old.Bindings()
	if consuming {
		// Consuming pre-auth uses the original issued policy. The older counted
		// fixture never reserved this flow and intentionally has separate policy
		// labels; do not change its existing metering partitions.
		spec.Binding.PolicyID, spec.Binding.PolicyVersion = f.Binding.Intent.PolicyID, f.Binding.Intent.PolicyVersion
	}
	f.Binding.IssuedAt = now.Add(-time.Second)
	f.Binding.ExpiresAt = now.Add(time.Minute)
	token, _ := session.ParseToken(cookie.Token())
	key, _ := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	f.Cookie, err = token.PreAuthDigest(key, f.Binding)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := session.NewPreAuthTransaction(f)
	if err != nil {
		t.Fatal(err)
	}
	authorization, _ := otp.NewBoundPreAuthAuthorization(flow)
	destination, _ := otp.NewDestinationInput("+358401234567")
	continuation, err := otp.NewContinuation(otp.DigestScopeSpec{TenantID: "tenant", SubjectID: "user", Purpose: otp.PurposePasswordReset, Channel: otp.ChannelSMS, Destination: destination, ChallengeID: "challenge", TargetID: "credential", PolicyVersion: 11, Generation: 12}, authorization, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	sms, _ := auth.NewOneTimeCode(smsText)
	totp, _ := auth.NewOneTimeCode(totpText)
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	attempt, err := issuer.PrepareForCommand(t.Context(), spec.Binding, spec.Operation, continuation, otp.AttemptModeConsume, 1, sms)
	if err != nil {
		t.Fatal(err)
	}
	password, _, _, _, _ := input.PhonePasswordResetInputCustody()
	input, err = identity.NewFeaturePhonePasswordResetInputCommand(spec, password, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	input, err = identity.BindPhonePasswordResetPreAuth(input, cookie)
	if err != nil {
		t.Fatal(err)
	}
	mapped, plan, err := codec.MapPhonePasswordResetWithAuthority(t.Context(), attempt, 3, input, authority)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ = mapped.PhonePasswordResetInputFeature()
	generated, err := identity.NewFeaturePhonePasswordResetCommand(spec, "$fixture$replacement", proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	generated, err = identity.BindPhonePasswordResetPreAuth(generated, cookie)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewPhoneRecoveryContributor(ContributorConfig{Schema: "otp_store", Codec: codec, GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: [32]byte{0x61}, PreAuth: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, PreAuthCookieKeys: map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	return owner, generated, plan, flow, authority
}

func phoneRecoveryCountedPlan(t *testing.T, registry *kernel.ContributorRegistry, command identity.Command, attempt kernel.OTPAttemptPlan, now time.Time) kernel.CommandPlan {
	t.Helper()
	spec, _ := command.PhonePasswordResetFeature()
	b := spec.Binding
	builder, _ := audit.NewBuilder(audit.BuilderConfig{})
	actor := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		actor = audit.ActorHuman
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: spec.Operation.OperationID, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: actor, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "credential", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: fmt.Sprintf("%d", b.PolicyVersion)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "aggregate.type": "credential", "aggregate.id": b.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, "credential", record)
	if err != nil {
		t.Fatal(err)
	}
	var feature kernel.FeatureRegistration
	for _, f := range registry.FeatureOperations() {
		if f.Operation == spec.Operation {
			feature = f
		}
	}
	return kernel.CommandPlan{Feature: &feature, SubjectType: "credential", Contributors: registry.Descriptors(), OTP: &attempt, Lifecycle: &kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: spec.Operation.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true, RetentionClass: "protected"}}, Capability: &kernel.CapabilityPlan{CapabilityID: "unexecuted-component-declaration", Purpose: "identity.phone.password-reset-complete", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{4}, ExpiresAt: now.Truncate(time.Second).Add(time.Minute), MaxUses: 1}, RiskEvidence: &kernel.RiskEvidencePlan{IssuanceCommandID: "AgICAgICAgICAgICAgICAg", Tenant: string(b.TenantID), Subject: string(b.UserID), IssuerActor: string(b.ActorID), Purpose: "phone-password-reset-complete", Phase: "phone-reset-completion", RecoveryOperation: b.OperationID, PolicyVersion: 1, KeyVersion: 1, IntentDigest: [32]byte{8}, ConsumerCommandID: string(b.CommandID), ConsumerActor: string(b.ActorID), EvidenceDigest: [32]byte{9}, ProofDigest: [32]byte{10}, Signature: [32]byte{11}, IssuedAt: now, CheckedAt: now, ExpiresAt: now.Add(time.Minute)}}
}
