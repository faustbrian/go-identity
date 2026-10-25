//go:build integration

package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	password "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// Primary/policy admission and audit/lifecycle sinks are fixture seams.
// Native original challenge issuance, encrypted factor verification, capability
// consumption, session/family/evidence persistence and the coordinator are real.
// This proves their transaction composition, not public MFA login.
type mfaSessionFixture struct {
	command        identity.Command
	plan           kernel.CommandPlan
	primary        kernel.CapabilityPlan
	challenge      kernel.MFAContinuationPlan
	continuation   mfa.PartialAuthContinuation
	issuer         *capabilitypg.Issuer
	issuance       capabilitypg.PreparedIssuance
	child          kernel.CapabilityPlan
	completion     kernel.MFACompletionPlan
	effect         *MFATOTPCompletionEffect
	recoveryEffect *MFARecoveryCompletionEffect
	recipient      kernel.RecipientRecord
	snapshot       mfapg.TOTPFactorSnapshot
	secret         password.Secret
	verifier       mfa.TOTPVerifier
	deny           bool
	calls          int
	stage          string
	flow           session.PreAuthTransaction
	cookieKey      session.DigestKey
	primaryOrigin  identity.CommandID
	counters       *riskpg.Repository
	passkey        bool
	passkeyEffect  *MFAPasskeyTOTPCompletionEffect
	finalExpiry    bool
	expiryWaited   bool
	finalDenied    bool
}

// Deliberately wait after Apply's successful credential check, as later audit
// or outbox IO can do. The original database expiry is never renewed.
type mfaCredentialExpiryAudit struct {
	revokeAudit
	entered *bool
	id      string
}

func (a *mfaCredentialExpiryAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	if err := a.revokeAudit.PersistAudits(ctx, w); err != nil {
		return err
	}
	rows, err := w.Query(ctx, `SELECT expires_at FROM identity.credential_references WHERE tenant_id='magic-effect' AND user_id='recipient' AND credential_id=$1`, a.id)
	if err != nil {
		return err
	}
	var expires time.Time
	err = readSessionAdmission(rows, &expires)
	rows.Close()
	if err != nil {
		return err
	}
	*a.entered = true
	timer := time.NewTimer(time.Until(expires) + 10*time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *mfaSessionFixture) Descriptor() kernel.ContributorDescriptor {
	if p.effect == nil {
		if p.passkey {
			return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
		}
		return kernel.ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
	}
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *mfaSessionFixture) FeatureOperations() []identity.FeatureOperation {
	s, _ := p.command.Feature()
	return []identity.FeatureOperation{s.Operation}
}
func (p *mfaSessionFixture) ValidateFeatureCommand(c identity.Command, _ kernel.CommandPlan) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *mfaSessionFixture) ValidateMagicLinkConsumption(c identity.Command, proof kernel.CapabilityPlan) error {
	if c != p.command || proof != p.primary {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *mfaSessionFixture) ValidateMagicLinkMFAChallenge(c identity.Command, scope kernel.MFAContinuationPlan) error {
	if c != p.command || scope != p.challenge {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *mfaSessionFixture) ValidatePasskeyMFAChallenge(c identity.Command, scope kernel.MFAContinuationPlan) error {
	if !p.passkey || c != p.command || scope != p.challenge {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *mfaSessionFixture) ValidateMFACompletion(c identity.Command, child kernel.CapabilityPlan, scope kernel.MFACompletionPlan) error {
	if c != p.command || child != p.child || scope != p.completion {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *mfaSessionFixture) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.calls++
	if p.effect == nil {
		p.stage = "challenge"
		var err error
		if p.passkey {
			err = mfapg.PersistPasskeyContinuation(ctx, w, p, c, p.continuation)
		} else {
			err = mfapg.PersistMagicLinkContinuation(ctx, w, p, c, p.continuation)
		}
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.stage = "child-issuance"
		if err := p.issuer.Stage(ctx, w, p.issuance); err != nil {
			return identity.FeatureReceipt{}, err
		}
		b, fingerprint, generation, err := w.FeatureCommandIdentity(p)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		use := PreAuthUse{Command: b, Fingerprint: fingerprint, Generation: generation}
		p.stage = "browser-reservation"
		if err := ReservePreAuth(ctx, w, Config{Schema: "session_store", MaximumDuration: time.Second}, p.flow, use); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.stage = "browser-finalization"
		if err := FinalizePreAuth(ctx, w, Config{Schema: "session_store", MaximumDuration: time.Second}, p.flow, use); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.stage = "challenge-effects"
		s, _ := c.Feature()
		if p.passkey {
			return identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}, nil
		}
		return identity.FeatureReceipt{Operation: s.Operation}, nil
	}
	p.stage = "browser"
	flow, err := p.flow.Bindings()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	cookie, ok := c.PreAuthCookie()
	if !ok {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	parsed, err := session.ParseToken(cookie.Token())
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	digest, err := parsed.PreAuthDigest(p.cookieKey, flow.Binding)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.flow.Check(now, flow.Binding, digest) != nil {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	var browserErr error
	if p.passkeyEffect != nil {
		browserErr = RequireMFAPasskeyConsumedPreAuth(ctx, w, p, c, p.effect.config, p.flow, p.primaryOrigin)
	} else {
		browserErr = RequireMFAConsumedPreAuth(ctx, w, p, c, p.effect.config, p.flow, p.primaryOrigin)
	}
	if browserErr != nil {
		return identity.FeatureReceipt{}, browserErr
	}
	p.stage = "directory"
	record, err := MFATOTPCompletionSession(c)
	if p.recoveryEffect != nil {
		record, err = MFARecoveryCompletionSession(c)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := record.Bindings()
	a, _ := s.Authority.Bindings()
	q, authority, err := verifiedIdentifierSessionAdmissionWithFactor(OTPAdmissionConfig(p.effect.profile), s, a.Factor)
	var credential kernel.CredentialAdmission
	if p.passkeyEffect != nil {
		feature, _ := p.command.Feature()
		selected := feature.Binding
		selected.UserID, selected.ActorID, selected.ActorKind = s.UserID, identity.ActorID(s.UserID), authorization.SubjectUser
		directory, admitted, policyScope, e := passkeyMFASessionAdmission(p.passkeyEffect.native.passkey.profile, record, selected)
		q, authority, credential, err = directory.Query, policyScope.Scope, admitted, e
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	// Match the production lock order before taking factor/continuation locks.
	if err := w.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{Query: q, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.passkeyEffect != nil {
		if _, err := w.RequireMFAPasskeyCredential(ctx, p, credential); err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := p.passkeyEffect.native.passkey.authority.RequireMFAPasskeySession(ctx, w, p, p.passkeyEffect.native.passkey.profile.RPNamespace, record); err != nil {
			return identity.FeatureReceipt{}, err
		}
	} else {
		if err := w.RequireRecipient(ctx, p, p.recipient); err != nil {
			return identity.FeatureReceipt{}, err
		}
	}
	if err := policy.RequireAuthority(ctx, w, authority, a.Authorization.Version, time.Second); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.stage = "factor"
	if p.recoveryEffect != nil {
		keys, _ := mfapg.NewRecoveryVerificationKeys(map[uint32][32]byte{1: {4}})
		locked, err := mfapg.LockRecoveryCompletion(ctx, w, p, c, keys)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		if err := mfapg.RecordRecoveryCompletion(ctx, w, p, locked); err != nil {
			return identity.FeatureReceipt{}, err
		}
		p.stage = "recovery-session"
		return p.recoveryEffect.Apply(ctx, w, p, c, p.recipient, locked)
	}
	locked, err := mfapg.LockTOTPCompletion(ctx, w, p, c, p.snapshot)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	meta, now, err := locked.VerificationState()
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	code, ok := c.OneTimeCode()
	if !ok {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	step, err := p.verifier.Verify(ctx, p.secret, code, meta.Profile, []byte("fixture/session-completion/v1"), now, meta.Replay)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := mfapg.RecordTOTPCompletion(ctx, w, p, locked, step); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.stage = "session"
	if p.passkeyEffect != nil {
		if p.finalExpiry {
			if _, err := w.Exec(ctx, `UPDATE identity.credential_references SET expires_at=clock_timestamp()+interval '200 milliseconds' WHERE tenant_id=$1 AND user_id=$2 AND credential_id=$3`, string(s.TenantID), string(s.UserID), s.Authentication.CredentialID); err != nil {
				return identity.FeatureReceipt{}, err
			}
		}
		return p.passkeyEffect.Apply(ctx, w, p, c, locked)
	}
	return p.effect.Apply(ctx, w, p, c, p.recipient, locked)
}
func (p *mfaSessionFixture) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command || p.deny {
		return identity.ForbiddenError{}
	}
	if p.effect != nil {
		r, err := MFATOTPCompletionSession(c)
		if p.recoveryEffect != nil {
			r, err = MFARecoveryCompletionSession(c)
		}
		if err != nil {
			return err
		}
		if p.passkeyEffect != nil {
			err := p.passkeyEffect.Check(ctx, w, p, c)
			var denied identity.ForbiddenError
			p.finalDenied = errors.As(err, &denied)
			return err
		}
		return requireMFAIssueTime(ctx, w, r)
	}
	return ctx.Err()
}
func (p *mfaSessionFixture) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p.passkeyEffect != nil {
		return p.passkeyEffect.Recover(ctx, w, p)
	}
	if p.recoveryEffect != nil {
		return p.recoveryEffect.Recover(ctx, w, p)
	}
	if p.effect != nil {
		return p.effect.Recover(ctx, w, p)
	}
	return kernel.RecoveryUnknown, identity.UnavailableError{}
}

func (p *mfaSessionFixture) RecordMFATOTPAttemptDenial(ctx context.Context, w kernel.MFATOTPAttemptWork) (kernel.MFAAttemptDisposition, error) {
	p.calls++
	command, err := w.NativeCommand(p)
	if err != nil {
		return 0, err
	}
	flow, err := p.flow.Bindings()
	if err != nil {
		return 0, err
	}
	cookie, ok := command.PreAuthCookie()
	if !ok {
		return 0, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return 0, err
	}
	digest, err := token.PreAuthDigest(p.cookieKey, flow.Binding)
	if err != nil {
		return 0, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return 0, err
	}
	if p.flow.Check(now, flow.Binding, digest) != nil {
		return 0, identity.ForbiddenError{}
	}
	if err := RequireMFAConsumedPreAuthAttempt(ctx, w, p, p.effect.config, p.flow, p.primaryOrigin); err != nil {
		return 0, err
	}
	if p.counters != nil {
		choice, err := w.ReserveCommandCounters(ctx, p)
		if err != nil {
			return 0, err
		}
		if choice == kernel.CommandCounterDenied {
			return kernel.MFAAttemptDenied, nil
		}
	}
	locked, err := mfapg.LockTOTPAttempt(ctx, w, p, p.snapshot)
	if err != nil {
		return 0, err
	}
	meta, now, err := locked.VerificationState()
	if err != nil {
		return 0, err
	}
	code, ok := command.OneTimeCode()
	if !ok {
		return 0, identity.ForbiddenError{}
	}
	_, err = p.verifier.Verify(ctx, p.secret, code, meta.Profile, []byte("fixture/session-completion/v1"), now, meta.Replay)
	if err == nil {
		return kernel.MFAAttemptUnchanged, nil
	}
	var denied identity.ForbiddenError
	if !errors.As(err, &denied) {
		return 0, err
	}
	if err := mfapg.RecordTOTPAttemptDenial(ctx, w, p, locked); err != nil {
		return 0, err
	}
	return kernel.MFAAttemptDenied, nil
}
func (p *mfaSessionFixture) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}
func (p *mfaSessionFixture) AdmitFeaturePreparation(ctx context.Context, _ kernel.Work, c identity.Command) error {
	p.stage = "admission"
	if c != p.command {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
func (p *mfaSessionFixture) GenerateFeaturePreparation(ctx context.Context, c identity.Command, generation uint64) ([]byte, error) {
	p.stage = "generation"
	if c != p.command || generation == 0 {
		return nil, identity.ForbiddenError{}
	}
	return []byte("session-mfa-native-fixture"), ctx.Err()
}
func (p *mfaSessionFixture) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	p.stage = "restoration"
	if c != p.command || generation == 0 || string(wire) != "session-mfa-native-fixture" {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	return c, p.plan, ctx.Err()
}

type mfaSessionAdmission struct{ p *mfaSessionFixture }

func (a mfaSessionAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (a mfaSessionAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	return a.p.GenerateFeaturePreparation(ctx, a.p.command, generation)
}
func (p *mfaSessionFixture) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	p.stage = "external-admission"
	if c != p.command {
		return nil, identity.ForbiddenError{}
	}
	return mfaSessionAdmission{p}, ctx.Err()
}
func (p *mfaSessionFixture) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	return mfaSessionAdmission{p}, nil
}

func testNativeMFASessionEffect(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	// The parent installs directory/authorization/session and factor roots.
	// Append each owned history exactly once; never replay root CREATEs.
	continuations, err := (mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 3}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	factors, err := (mfapg.TOTPFactorMigrationSource{Base: fixtureSource(continuations), Version: 4}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range factors[1:] {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	recoveryHistory, err := (mfapg.RecoveryMigrationSource{Base: fixtureSource(factors), Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, recoveryHistory[len(recoveryHistory)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	passkeyHistory, err := (mfapg.PasskeyContinuationMigrationSource{Base: fixtureSource(recoveryHistory), Version: 6}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, passkeyHistory[len(passkeyHistory)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	preparation, err := (kernel.PreparationMigrationSource{Base: kernel.MigrationSource{}, Version: 43}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := (kernel.AdmissionPreparationMigrationSource{Base: fixtureSource(preparation), Version: 44}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range admission[len(admission)-2:] {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	protectedPreparation, err := (kernel.CounterPreparationMigrationSource{Base: fixtureSource(admission), Version: 66}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, protectedPreparation[len(protectedPreparation)-1].UpSQL()); err != nil {
		t.Fatal(err)
	}
	for _, source := range []interface {
		Load(context.Context) ([]migrations.Migration, error)
	}{MFAMigrationSource{Schema: "session_store", Version: 45}, MFASigninMigrationSource{Schema: "session_store", Version: 46}, PasswordMFAMigrationSource{Schema: "session_store", Version: 47}, MFARecoveryMigrationSource{Schema: "session_store", Version: 48}, PasskeyMFAMigrationSource{Schema: "session_store", Version: 67, PreviousConstraint: "session_record_binding_v8"}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, migration := range history {
			if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	profile := MagicLinkAdmissionConfig{GlobalAuthorityID: "deployment-issue", PolicyNamespace: "users", Audience: "service-a"}
	effect, err := NewMFATOTPCompletionEffect(config, profile)
	if err != nil {
		t.Fatal(err)
	}
	counters := installMFACounters(t, ctx, pool)
	for _, mode := range []string{"late-denial", "blocked-user", "stale-factor", "changed-remember", "wrong-cookie", "foreign-primary", "released-flow", "foreign-browser-fingerprint", "foreign-browser-generation", "counted-wrong-code", "counted-wrong-cookie", "counted-risk-wrong-code", "counted-risk-correct-code", "counted-risk-wrong-cookie", "counted-risk-audit-failure", "commit", "risk-commit", "recovery-late-denial", "recovery-wrong-cookie", "recovery-commit", "recovery-risk-commit", "stale-policy", "passkey-commit", "passkey-late-denial", "passkey-disabled-credential", "passkey-final-expiry"} {
		t.Run(mode, func(t *testing.T) {
			recovery := strings.HasPrefix(mode, "recovery-")
			passkey := strings.HasPrefix(mode, "passkey-")
			var now time.Time
			if err := pool.Raw().QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
				t.Fatal(err)
			}
			now = now.UTC().Truncate(time.Second)
			// An independent factor per case avoids shared replay-counter pollution.
			factorID, _ := identity.NewCommandID()
			enrollmentID, _ := identity.NewCommandID()
			rootID, _ := identity.NewCommandID()
			primaryID, _ := identity.NewCommandID()
			childID, _ := identity.NewCommandID()
			completeID, _ := identity.NewCommandID()
			seedCommand := func(id identity.CommandID, purpose string) {
				t.Helper()
				raw := mustCommandBytes(t, id)
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,'magic-effect',$2,decode(repeat('01',32),'hex'),1,decode('01','hex'));`, raw, purpose); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,'magic-effect',$2)`, raw, purpose); err != nil {
					t.Fatal(err)
				}
			}
			seedCommand(rootID, "identity.password.signup")
			seedCommand(enrollmentID, "identity.mfa.enable")
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES('magic-effect','recipient',2,1,$1,'identity.password.signup') ON CONFLICT (tenant_id,user_id) DO NOTHING`, mustCommandBytes(t, rootID)); err != nil {
				t.Fatal(err)
			}
			provider, err := keyring.New(map[string][]byte{"factor-v1": bytes.Repeat([]byte{1}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			crypto, err := envelope.NewService(provider)
			if err != nil {
				t.Fatal(err)
			}
			// Pin the encrypted profile's existing persistence representation.
			profileBytes := []byte(`{"Algorithm":"SHA1","Digits":8,"PeriodSeconds":30,"SkewSteps":0,"Issuer":"Example"}`)
			profileDigest := sha256.Sum256(profileBytes)
			binding, err := envelope.NewContext(map[string]string{"service": "identity.mfa", "field": "totp-secret-v1", "tenant": "magic-effect", "user": "recipient", "factor": string(factorID), "enrollment_version": "1", "profile": hex.EncodeToString(profileDigest[:])})
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: []byte("12345678901234567890"), KeyReference: "factor-v1", Context: binding})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := sealed.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			defer clear(wire)
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES('magic-effect','recipient',$1,2,1,1,'SHA1',8,30,0,'Example',$2,$3,'identity.mfa.enable',$4,$5,$4)`, string(factorID), wire, mustCommandBytes(t, enrollmentID), now, now.Add(5*time.Minute)); err != nil {
				t.Fatal(err)
			}
			recoveryCode, _ := auth.NewRecoveryCode("synthetic-recovery-" + string(factorID))
			if recovery {
				binding, _ := json.Marshal(struct {
					Profile, Tenant, User, Factor, Set string
					Epoch                              uint64
				}{"mfa-recovery-code-v1", "magic-effect", "recipient", string(factorID), string(factorID), 1})
				digest, err := recoveryCode.KeyedDigest([32]byte{4}, binding)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.recovery_sets VALUES('magic-effect','recipient',$1,$1,1,1,2,1,1,$2,'identity.mfa.enable',$3)`, string(factorID), mustCommandBytes(t, enrollmentID), now); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.recovery_codes(tenant_id,set_id,code_index,digest) VALUES('magic-effect',$1,0,$2)`, string(factorID), digest[:]); err != nil {
					t.Fatal(err)
				}
			}
			key := []byte("0123456789abcdef0123456789abcdef")
			signer, _ := capability.NewHMACSHA256Signer("sign-v1", key)
			verifier, _ := capability.NewHMACSHA256Verifier(key)
			keys, _ := capability.NewKeySet([]capability.Key{{Issuer: "https://identity.example.test", ID: "sign-v1", Verifier: verifier}})
			issuer, err := capabilitypg.NewIssuer(capabilitypg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://identity.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()}, Audience: "service-a", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {1}}, PreparationTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			b := revokeBinding()
			b.CommandID = primaryID
			b.TenantID = "magic-effect"
			b.UserID = ""
			b.RecordID = ""
			b.AnonymousFlowID = string(primaryID)
			b.OperationID = "identity.magic-link.consume"
			b.SchemaID = "magic-link-consume"
			parent := capability.Payload{Version: 1, Issuer: "https://identity.example.test", Audiences: []string{"service-a"}, Subject: "recipient", Tenant: "magic-effect", ID: "primary-" + string(primaryID), Resource: "identity.magiclink/magic-email", Operation: b.OperationID, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(10 * time.Minute), MaxUses: 1, Caveats: map[string]string{"magiclink.identifier": "magic-email"}}
			parentWire, err := capability.Issue(ctx, parent, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			parentProof, err := capability.ParseProof(parentWire, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer parentProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			parentGrant, err := capability.Verify(ctx, parentWire, keys, capability.VerifyOptions{Issuer: "https://identity.example.test", Now: now, Limits: capability.DefaultLimits()})
			if err != nil {
				t.Fatal(err)
			}
			primary, err := issuer.PrepareMagicLinkConsumption(ctx, b, "recipient", "magic-email", parentProof, parentGrant.EnvelopeDigest(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO public.capability_identity_one_use(tenant_id,purpose,replay_key_version,replay_digest,capability_id,proof_fingerprint,expires_at,max_uses) VALUES('magic-effect',$1,1,$2,$3,$4,$5,1)`, string(primary.Purpose), primary.ReplayDigest[:], primary.CapabilityID, primary.ProofFingerprint[:], primary.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			if passkey {
				b.UserID, b.ActorID, b.ActorKind, b.RecordID, b.AnonymousFlowID = "recipient", "recipient", authorization.SubjectUser, string(primaryID), ""
				b.OperationID, b.SchemaID = "identity.passkey.signin-verify", "identity.passkey.signin-verify.native-v1"
			}
			_, original := magicLinkSigninMappingFixture(t, false)
			s, _ := original.Bindings()
			cookieKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{4}, 32))
			browserToken, _ := session.ParseToken(strings.Repeat("A", 43))
			flowBinding := session.PreAuthBinding{ID: identity.PreAuthTransactionID(primaryID), Intent: session.PreAuthIntent{TenantID: b.TenantID, Action: b.OperationID, Origin: "https://app.example.test", CallbackURL: "https://app.example.test/login", Nonce: [32]byte{1}, Remember: s.Remember, PolicyID: b.PolicyID, PolicyVersion: b.PolicyVersion}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			cookieDigest, err := browserToken.PreAuthDigest(cookieKey, flowBinding)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: flowBinding, Cookie: cookieDigest, Version: 1})
			if err != nil {
				t.Fatal(err)
			}
			flowWire, err := encodePreAuth(flow)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.preauth_transactions(tenant_id,flow_id,record,issued_at,expires_at,digest_version,digest,issued_version,version,state) VALUES($1,$2,$3,$4,$5,1,$6,1,1,'issued')`, string(b.TenantID), string(flowBinding.ID), flowWire, now.Format(storedTimeLayout), flowBinding.ExpiresAt.Format(storedTimeLayout), cookieDigest.Sum[:]); err != nil {
				t.Fatal(err)
			}
			methods := []string{"totp"}
			if recovery {
				methods = append(methods, "recovery-code")
			}
			continuationSpec := mfa.ContinuationSpec{ID: mfa.ContinuationID(childID), PrimaryProofID: auth.ProofID(primary.CapabilityID), PrimaryProofDigest: primary.ProofFingerprint, PrimaryProofExpiresAt: primary.ExpiresAt, TenantID: b.TenantID, SubjectID: "recipient", SourcePreAuthID: flowBinding.ID, Origin: "https://app.example.test", AllowedMethods: methods, PolicyVersion: 1, FactorVersion: 2, RememberPolicy: s.Remember, Purpose: "identity.mfa.complete", Audience: "service-a", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), MaxAttempts: 3, AttemptsRemaining: 3, State: mfa.Pending, Version: 1}
			if passkey {
				// The primary verifier is this component test's explicit seam.
				// No assertion-authentication claim is made by this projection.
				continuationSpec.PrimaryProofID, continuationSpec.PasskeyCommandID = auth.ProofID(primaryID), primaryID
			}
			continuation, err := mfa.NewPartialAuthContinuation(continuationSpec)
			if err != nil {
				t.Fatal(err)
			}
			digest, _ := continuation.ScopeDigest()
			payload, err := continuation.CapabilityPayload(parent.Issuer)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := issuer.PrepareMFAContinuation(ctx, b, payload)
			if passkey {
				payload.CorrelationID = string(primaryID)
				prepared, err = issuer.PreparePasskeyMFAContinuation(ctx, b, payload)
			}
			if err != nil {
				t.Fatal(err)
			}
			issue, _ := prepared.Plan()
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: magicLinkSessionOperation(), Fields: []identity.FeatureField{{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: primary.CapabilityID}}}})
			if passkey {
				op := identity.FeatureOperation{Owner: "passkey", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
				command, err = identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: op}, auth.NewBearerCredential(strings.Repeat("A", 43)))
			}
			if err != nil {
				t.Fatal(err)
			}
			phase := &mfaSessionFixture{command: command, primary: primary, challenge: kernel.MFAContinuationPlan{ID: childID, UserID: "recipient", ScopeDigest: digest, PolicyVersion: 1, FactorVersion: 2, IssuedAt: now, ExpiresAt: payload.ExpiresAt}, continuation: continuation, issuer: issuer, issuance: prepared, flow: flow, passkey: passkey}
			fingerprintVersion := uint32(1)
			newCoordinator := func(p *mfaSessionFixture, issuance bool) *kernel.Coordinator {
				t.Helper()
				var auditing kernel.Contributor = &revokeAudit{fail: !issuance && mode == "counted-risk-audit-failure"}
				if !issuance && mode == "passkey-final-expiry" {
					auditing = &mfaCredentialExpiryAudit{entered: &p.expiryWaited, id: "passkey-completion-" + mode}
				}
				entries := []kernel.Contributor{domain, auditing, &revokeOutbox{}, p}
				if p.counters != nil {
					entries = append(entries, p.counters)
				}
				if !issuance || !p.passkey {
					entries = append(entries, capabilitypg.NewParticipant())
				}
				if issuance {
					entries = append(entries, issuer)
				}
				registry, err := kernel.NewContributorRegistry(entries)
				if err != nil {
					t.Fatal(err)
				}
				observationPolicy := &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 1, Authorization: revokeQueryPolicy{}}
				c, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: fingerprintVersion, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}, 2: {2}}, QueryPolicy: observationPolicy, AdmissionPolicy: observationPolicy})
				if err != nil {
					t.Fatal(err)
				}
				p.plan.Contributors = registry.Descriptors()
				return c
			}
			planFor := func(p *mfaSessionFixture, event string) kernel.CommandPlan {
				t.Helper()
				spec, _ := p.command.Feature()
				subject := spec.Binding.AnonymousFlowID
				after := uint64(0)
				if p.effect == nil && p.passkey {
					subject, after = spec.Binding.RecordID, 1
				}
				builder, _ := audit.NewBuilder(audit.BuilderConfig{})
				seed, err := builder.Build(audit.RecordInput{OccurredAt: now, Action: "authentication.succeeded", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(spec.Binding.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: subject}, Context: audit.ContextInput{TenantID: string(spec.Binding.TenantID), CorrelationID: spec.Binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: spec.Binding.PolicyID, Version: fmt.Sprint(spec.Binding.PolicyVersion)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(spec.Binding.CommandID), "aggregate.type": "authentication_attempt", "aggregate.id": subject, "aggregate.before_version": "0", "aggregate.after_version": fmt.Sprint(after), "retention.class": "protected"}})
				if err != nil {
					t.Fatal(err)
				}
				d, err := kernel.FeatureAuditBindingDigest(spec.Binding, spec.Operation, "authentication_attempt", seed)
				if err != nil {
					t.Fatal(err)
				}
				return kernel.CommandPlan{Contributors: p.plan.Contributors, SubjectType: "authentication_attempt", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: event, AfterVersion: after}, Audits: []kernel.AuditPlan{{EventType: "authentication.succeeded", SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: d}}}
			}
			coordinator := newCoordinator(phase, true)
			phase.plan = planFor(phase, "mfa.challenge.created.v1")
			phase.plan.Capability = &primary
			if passkey {
				phase.plan.Capability = nil
			}
			phase.plan.MFAContinuation = &phase.challenge
			phase.plan.CapabilityIssuance = &issue
			phase.plan, err = coordinator.PrepareCommandPlan(b, command, phase.plan)
			if err != nil {
				t.Fatal("final native challenge declaration", err)
			}
			if passkey {
				reservation, _, err := coordinator.ReserveCommand(ctx, b, command, phase.plan)
				if err != nil {
					t.Fatal("component passkey primary reservation", err)
				}
				work, err := coordinator.Begin(ctx, reservation)
				if err != nil {
					t.Fatal(err)
				}
				defer coordinator.Abort(work, identity.UnavailableError{})
				result, err := coordinator.ApplyFeature(ctx, work, command)
				if err == nil {
					result, err = coordinator.Commit(work, result)
				}
				if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("component passkey primary challenge failed", phase.stage, err)
				}
			} else {
				originalPlan := phase.plan
				originalPlan.CapabilityIssuance = nil
				originalPlan.Contributors = originalPlan.Contributors[:len(originalPlan.Contributors)-1]
				originalPlan, err = coordinator.PrepareFeaturePreparationPlan(command, originalPlan)
				if err != nil {
					t.Fatal(err)
				}
				if result, err := coordinator.ExecutePreparedFeature(ctx, command, originalPlan); err != nil || result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("original challenge failed", phase.stage, err)
				}
			}
			childWire, err := capability.Issue(ctx, payload, signer, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			childProof, err := capability.ParseProof(childWire, capability.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer childProof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			grant, primaryOrigin, replayVersion, err := issuer.ReadIssuanceOrigin(ctx, pool, childProof, "identity.mfa.complete")
			if err != nil {
				t.Fatal(err)
			}
			reader, _ := mfapg.NewTOTPFactorReader(pool, time.Second)
			snapshot, err := reader.Read(ctx, grant, parent.Issuer, string(factorID))
			if err != nil {
				t.Fatal(err)
			}
			sealed, _ = snapshot.Envelope()
			binding, _ = snapshot.EncryptionContext()
			plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: binding})
			if err != nil {
				t.Fatal("encrypted factor unavailable")
			}
			secret, err := password.NewSecret(plain)
			clear(plain)
			if err != nil {
				t.Fatal(err)
			}
			defer secret.Destroy()
			var completeNow time.Time
			if err := pool.Raw().QueryRow(ctx, "SELECT clock_timestamp()").Scan(&completeNow); err != nil {
				t.Fatal(err)
			}
			completeNow = completeNow.UTC()
			untilNext := 30*time.Second - time.Duration(completeNow.UnixNano()%int64(30*time.Second))
			if untilNext < 3*time.Second {
				timer := time.NewTimer(untilNext + 100*time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					t.Fatal(ctx.Err())
				case <-timer.C:
				}
				if err := pool.Raw().QueryRow(ctx, "SELECT clock_timestamp()").Scan(&completeNow); err != nil {
					t.Fatal(err)
				}
				completeNow = completeNow.UTC()
			}
			var moving [8]byte
			binary.BigEndian.PutUint64(moving[:], uint64(completeNow.Unix()/30))
			mac := hmac.New(sha1.New, []byte("12345678901234567890"))
			_, _ = mac.Write(moving[:])
			hash := mac.Sum(nil)
			offset := hash[len(hash)-1] & 15
			code, err := auth.NewOneTimeCode(fmt.Sprintf("%08d", (binary.BigEndian.Uint32(hash[offset:offset+4])&0x7fffffff)%100000000))
			clear(hash)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(mode, "counted-") && mode != "counted-risk-correct-code" {
				code, _ = auth.NewOneTimeCode("123456")
			}
			b.CommandID = completeID
			if passkey {
				b = revokeBinding()
				b.CommandID, b.TenantID, b.UserID, b.RecordID, b.AnonymousFlowID = completeID, "magic-effect", "", "", string(flowBinding.ID)
			}
			b.OperationID = "identity.mfa.totp-verify"
			b.SchemaID = "mfa-totp-verify"
			if recovery {
				b.OperationID, b.SchemaID = "identity.mfa.recovery-use", "mfa-recovery-use"
			}
			child, err := issuer.PrepareMFAConsumption(ctx, b, "recipient", childID, digest, parent.Issuer, childProof, grant.EnvelopeDigest(), replayVersion)
			if err != nil {
				t.Fatal(err)
			}
			s.TenantID = "magic-effect"
			s.UserID = "recipient"
			s.SessionID = "mfa-session-" + mode
			s.FamilyID = "mfa-family-" + mode
			s.IssuedAt = completeNow
			s.LastActivityAt = completeNow
			lookupKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{3}, 32))
			issuedToken, err := session.NewToken(32)
			if err != nil {
				t.Fatal(err)
			}
			s.Lookup, err = issuedToken.Digest(lookupKey, string(s.TenantID))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "changed-remember" {
				changed, _ := s.Remember.Bindings()
				changed.Choice = session.PersistentSession
				s.Remember, err = session.NewRememberPolicy(changed)
				if err != nil {
					t.Fatal(err)
				}
			}
			keysOwned, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: s.TenantID}, s.UserID)
			sessionKeys, _ := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
			policyKey, _ := (policy.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: "users", SubjectID: authorization.SubjectID(s.UserID)}).Key()
			factorKey, _ := mfapg.FactorAuthorityKey(s.TenantID, s.UserID)
			a := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
			s.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: a(keysOwned.Global), Tenant: a(keysOwned.Tenant), User: a(keysOwned.User), Identifier: a(keysOwned.Identifier), Credential: a(keysOwned.Credential), SessionFamily: a(sessionKeys.Family), Session: a(sessionKeys.Session), Authorization: a(policyKey), Factor: session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: factorKey, Version: 2}}})
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: s.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: "magic@example.test", Eligibility: kernel.RecipientVerified})
			if err != nil {
				t.Fatal(err)
			}
			primaryProjection, _ := original.MagicLinkAuthentication().Bindings()
			primaryProjection.CommandID, primaryProjection.CapabilityID = primaryID, primary.CapabilityID
			primaryProjection.IdentifierID, primaryProjection.IdentifierVersion, primaryProjection.VerificationVersion = recipient.Identifier.ID, recipient.Identifier.Version, recipient.Verification.Version
			primaryProjection.AuthenticatedAt, primaryProjection.ValidUntil = now, primary.ExpiresAt
			primaryMeta, err := session.NewMagicLinkAuthentication(primaryProjection)
			if err != nil {
				t.Fatal(err)
			}
			remember, _ := s.Remember.Bindings()
			factorMeta, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: completeID, PrimaryCommandID: primaryID, ContinuationID: childID, ContinuationScopeDigest: digest, Method: "totp", FactorID: string(factorID), EnrollmentVersion: 1, FactorAuthorityVersion: 2, ContinuationVersion: 1, Remember: remember, VerifiedAt: completeNow, ValidUntil: payload.ExpiresAt})
			if err != nil {
				t.Fatal(err)
			}
			if recovery {
				metadata, _ := factorMeta.Bindings()
				metadata.Method, metadata.RecoverySetID, metadata.RecoverySetVersion = "recovery-code", factorID, 1
				factorMeta, err = session.NewMFAAuthentication(metadata)
				if err != nil {
					t.Fatal(err)
				}
			}
			record, err := session.NewSessionWithMagicLinkMFA(s, primaryMeta, factorMeta)
			if passkey {
				credentialID := "passkey-completion-" + mode
				if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,2,'passkey',1,$4)`, string(s.TenantID), string(s.UserID), credentialID, mode != "passkey-disabled-credential"); err != nil {
					t.Fatal(err)
				}
				s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, ProofVersion: 1, CredentialID: credentialID, CredentialVersion: 1, Proof: auth.Proof{ID: auth.ProofID(primaryID), Tenant: string(s.TenantID), Subject: string(s.UserID), Method: "passkey", Assurance: auth.AssurancePhishingResistant, Purpose: session.PasskeyMFAPrimaryPurpose, Audience: s.Audience, IssuedAt: now, ExpiresAt: primary.ExpiresAt}}
				vector, _ := s.Authority.Bindings()
				vector.Passkey = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "passkey:rp-a:completion", Version: 4}}
				s.Authority, err = session.NewAuthoritySnapshot(vector)
				if err != nil {
					t.Fatal(err)
				}
				record, err = session.NewSessionWithPasskeyMFA(s, factorMeta)
			}
			if err != nil {
				t.Fatal(err)
			}
			fields, err := MFATOTPCompletionSessionFields(record)
			if recovery {
				fields, err = MFARecoveryCompletionSessionFields(record)
			}
			if err != nil {
				t.Fatal(err)
			}
			fields = append(fields, identity.FeatureField{Name: "proof-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: child.CapabilityID}})
			browserCookie := strings.Repeat("A", 43)
			if mode == "wrong-cookie" || mode == "counted-wrong-cookie" || mode == "counted-risk-wrong-cookie" || mode == "recovery-wrong-cookie" {
				browserCookie = strings.Repeat("B", 42) + "A"
			}
			command, err = identity.NewFeatureOneTimeCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: mfaTOTPCompletionSessionOperation(), Fields: fields}, code, auth.NewBearerCredential(browserCookie))
			if recovery {
				command, err = identity.NewFeatureRecoveryCodePreAuthCommand(identity.FeatureCommandSpec{Binding: b, Operation: mfaRecoveryCompletionSessionOperation(), Fields: fields}, recoveryCode, auth.NewBearerCredential(browserCookie))
			}
			if err != nil {
				t.Fatal(err)
			}
			totp, _ := mfa.NewTOTPVerifier([32]byte{1})
			completion := kernel.MFACompletionPlan{ID: childID, UserID: "recipient", ScopeDigest: digest, PolicyVersion: 1, FactorVersion: 2, ContinuationVersion: 1}
			phase = &mfaSessionFixture{command: command, child: child, completion: completion, effect: effect, recipient: recipient, snapshot: snapshot, secret: secret, verifier: totp, deny: mode == "late-denial", flow: flow, cookieKey: cookieKey, primaryOrigin: primaryOrigin}
			if passkey {
				selected := MFAPasskeySessionAdmission{Profile: PasskeyAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience, RPNamespace: "rp-a"}, Authority: &mfaPasskeyMappingComponent{version: 4, now: completeNow}}
				phase.passkeyEffect, err = NewMFAPasskeyTOTPCompletionEffect(config, selected)
				if err != nil {
					t.Fatal(err)
				}
				phase.deny = mode == "passkey-late-denial"
				phase.finalExpiry = mode == "passkey-final-expiry"
			}
			if recovery {
				phase.recoveryEffect, err = NewMFARecoveryCompletionEffect(config, profile)
				if err != nil {
					t.Fatal(err)
				}
				phase.deny = mode == "recovery-late-denial"
			}
			var counterPlan kernel.CommandCounterPlan
			originalCommand := command
			if strings.HasPrefix(mode, "counted-risk-") || mode == "risk-commit" || mode == "recovery-risk-commit" {
				phase.counters = counters
				command, counterPlan, err = counters.PrepareMFACompletionCommandCounters(command, risk.Subject{User: "recipient", Network: "127.0.0.1"}, child, completion, time.Now().UTC().Truncate(time.Microsecond))
				if err != nil {
					t.Fatal(err)
				}
				phase.command = command
			}
			if mode == "foreign-primary" {
				phase.primaryOrigin = enrollmentID
			}
			coordinator = newCoordinator(phase, false)
			phase.plan = planFor(phase, "session.created.v1")
			phase.plan.Capability = &child
			phase.plan.MFACompletion = &completion
			if phase.counters != nil {
				phase.plan.CommandCounters = &counterPlan
			}
			if mode == "recovery-risk-commit" {
				phase.plan, err = coordinator.PrepareMFARecoveryFeaturePlanWithOriginal(originalCommand, command, phase.plan)
			} else if mode == "risk-commit" {
				phase.plan, err = coordinator.PrepareMFATOTPFeaturePlanWithOriginal(originalCommand, command, phase.plan)
			} else if phase.counters != nil {
				phase.plan, err = coordinator.PrepareMFATOTPAttemptPlanWithOriginal(originalCommand, command, phase.plan)
			} else if strings.HasPrefix(mode, "counted-") {
				phase.plan, err = coordinator.PrepareMFATOTPAttemptPlan(b, command, phase.plan)
			} else {
				phase.plan, err = coordinator.PrepareFeaturePreparationPlan(command, phase.plan)
			}
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "released-flow":
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.preauth_transactions SET state='released' WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), b.AnonymousFlowID); err != nil {
					t.Fatal(err)
				}
			case "foreign-browser-fingerprint":
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.preauth_transactions SET fingerprint=decode(repeat('02',32),'hex') WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), b.AnonymousFlowID); err != nil {
					t.Fatal(err)
				}
			case "foreign-browser-generation":
				if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.preauth_transactions SET generation=generation+1 WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), b.AnonymousFlowID); err != nil {
					t.Fatal(err)
				}
			case "blocked-user":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id='magic-effect' AND user_id='recipient'`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='magic-effect' AND user_id='recipient'`); err != nil {
						t.Error(err)
					}
				}()
			case "stale-policy":
				// Use the owning policy transition, not a synthetic decision.
				if _, err := policy.AdvanceAuthority(ctx, pool.Raw(), policy.AuthorityScope{TenantID: "magic-effect", PolicyNamespace: "users", SubjectID: "recipient"}, 1, time.Second); err != nil {
					t.Fatal(err)
				}
			case "stale-factor":
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=3 WHERE tenant_id='magic-effect' AND user_id='recipient'`); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id='magic-effect' AND user_id='recipient'`); err != nil {
						t.Error(err)
					}
				}()
			}
			var browserBefore, browserAfter string
			if err := pool.Raw().QueryRow(ctx, `SELECT to_jsonb(f)::text FROM session_store.preauth_transactions f WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), b.AnonymousFlowID).Scan(&browserBefore); err != nil {
				t.Fatal(err)
			}
			var result identity.CommandResult
			var runErr error
			if mode == "recovery-risk-commit" {
				result, runErr = coordinator.ExecutePreparedMFARecoveryFeature(ctx, originalCommand, command, phase.plan)
			} else if mode == "risk-commit" {
				result, runErr = coordinator.ExecutePreparedMFATOTPFeature(ctx, originalCommand, command, phase.plan)
			} else if phase.counters != nil {
				result, runErr = coordinator.RecordMFATOTPAttemptDenialWithOriginal(ctx, originalCommand, command, phase.plan)
			} else if strings.HasPrefix(mode, "counted-") {
				result, runErr = coordinator.RecordMFATOTPAttemptDenial(ctx, b, command, phase.plan)
			} else {
				result, runErr = coordinator.ExecutePreparedFeature(ctx, command, phase.plan)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT to_jsonb(f)::text FROM session_store.preauth_transactions f WHERE tenant_id=$1 AND flow_id=$2`, string(b.TenantID), b.AnonymousFlowID).Scan(&browserAfter); err != nil || browserBefore != browserAfter {
				t.Fatal("MFA completion changed the original consumed browser flow", err)
			}
			var sessions, families, issuances, events int
			var state int16
			var remaining, uses int32
			var last *string
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2),(SELECT count(*) FROM session_store.families WHERE tenant_id=$1 AND family_id=$3),(SELECT count(*) FROM session_store.session_issuances WHERE command_id=$4),(SELECT count(*) FROM public.revoke_outbox WHERE command_id=$5),c.state,c.attempts_remaining,t.last_step::text,k.uses FROM identity_mfa.continuations c JOIN identity_mfa.totp_factors t ON t.tenant_id=c.tenant_id AND t.user_id=c.user_id JOIN public.capability_identity_one_use k ON k.tenant_id=c.tenant_id AND k.capability_id=c.continuation_id WHERE c.tenant_id=$1 AND c.continuation_id=$6 AND t.factor_id=$7`, string(s.TenantID), s.SessionID, s.FamilyID, mustCommandBytes(t, completeID), string(completeID), string(childID), string(factorID)).Scan(&sessions, &families, &issuances, &events, &state, &remaining, &last, &uses); err != nil {
				t.Fatal(err)
			}
			if recovery {
				var burned, bound bool
				if err := pool.Raw().QueryRow(ctx, `SELECT COALESCE(consumed_command_id=$2,false),consumed_at IS NOT NULL FROM identity_mfa.recovery_codes WHERE tenant_id=$1 AND set_id=$3`, string(s.TenantID), mustCommandBytes(t, completeID), string(factorID)).Scan(&bound, &burned); err != nil || burned != bound || burned != (mode == "recovery-commit" || mode == "recovery-risk-commit") {
					t.Fatal("recovery burn split from original outcome", err, burned, runErr, phase.stage)
				}
			}
			if mode != "commit" && mode != "risk-commit" && mode != "recovery-commit" && mode != "recovery-risk-commit" && mode != "passkey-commit" {
				if mode == "passkey-final-expiry" && (!phase.expiryWaited || !phase.finalDenied) {
					t.Fatal("expiry test did not reach final credential denial after audit wait", phase.stage, runErr)
				}
				if mode == "passkey-late-denial" && phase.stage != "session" {
					t.Fatal("passkey rollback never reached recorded factor/session", phase.stage, runErr)
				}
				if mode == "recovery-late-denial" && phase.stage != "recovery-session" {
					t.Fatal("rollback case never reached recorded burn/session", phase.stage, runErr)
				}
				if phase.counters != nil {
					var charges, snapshots int
					if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_mfa.counter_charges WHERE command_id=$1),(SELECT count(*) FROM risk_mfa.counter_snapshots WHERE command_id=$1)`, mustCommandBytes(t, completeID)).Scan(&charges, &snapshots); err != nil {
						t.Fatal(err)
					}
					want := 0
					if mode == "counted-risk-wrong-code" {
						want = 1
					}
					if charges != want || snapshots != 4*want {
						t.Fatal("risk charge split from counted outcome", mode, charges, snapshots)
					}
				}
				wantState, wantRemaining := int16(mfa.Pending), int32(3)
				if mode == "counted-wrong-code" || mode == "counted-risk-wrong-code" {
					wantState, wantRemaining = int16(mfa.Challenged), 2
				}
				if runErr == nil || phase.calls != 1 || sessions != 0 || families != 0 || issuances != 0 || events != 0 || state != wantState || remaining != wantRemaining || last != nil || uses != 0 {
					t.Fatal("late failure split MFA/session transaction", phase.stage, runErr, sessions, families, issuances, events, state, remaining, uses)
				}
				if mode == "counted-wrong-code" || mode == "counted-risk-wrong-code" {
					var replay identity.CommandResult
					var err error
					if phase.counters != nil {
						replay, err = coordinator.RecordMFATOTPAttemptDenialWithOriginal(ctx, originalCommand, command, phase.plan)
					} else {
						replay, err = coordinator.RecordMFATOTPAttemptDenial(ctx, b, command, phase.plan)
					}
					if err != nil || !reflect.DeepEqual(replay, result) || phase.calls != 1 {
						t.Fatal("wrong-code retry charged shared budget twice", err)
					}
					if phase.counters != nil {
						// History belongs to submitted intent, not the current counter
						// preparation or fingerprint key. No live factor callback runs.
						fingerprintVersion = 2
						rotated := newCoordinator(phase, false)
						caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}}}
						history, found, historyErr := rotated.QueryMFATOTPCommand(ctx, originalCommand, caller)
						var denied identity.ForbiddenError
						if !found || !errors.As(historyErr, &denied) || !reflect.DeepEqual(history, result) || phase.calls != 1 {
							t.Fatal("counter preparation replaced original denial history", found, historyErr)
						}
					}
				}
				return
			}
			if runErr != nil || result.Outcome != identity.CommitOutcomeCommitted || phase.calls != 1 || sessions != 1 || families != 1 || issuances != 1 || events != 1 || state != int16(mfa.Completed) || remaining != 2 || last == nil && !recovery || last != nil && recovery || uses != 1 {
				t.Fatal("native MFA/session not atomic", phase.stage, runErr, sessions, families, issuances, events, state, remaining, uses)
			}
			if mode == "risk-commit" || mode == "recovery-risk-commit" {
				var charges, snapshots int
				if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM risk_mfa.counter_charges WHERE command_id=$1),(SELECT count(*) FROM risk_mfa.counter_snapshots WHERE command_id=$1)`, mustCommandBytes(t, completeID)).Scan(&charges, &snapshots); err != nil || charges != 1 || snapshots != 4 {
					t.Fatal("successful native MFA lost original counter charge", charges, snapshots, err)
				}
			}
			native, _ := NewRepository(pool, config)
			stored, err := native.Get(ctx, s.TenantID, s.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			expected, _, _ := encodeRecord(record)
			actual, _, _ := encodeRecord(stored.Session)
			if !bytes.Equal(expected, actual) {
				t.Fatal("native session changed original primary/factor/remember")
			}
			readNow := completeNow.Add(time.Second)
			validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "service-a", Clock: sessionReadClock(func() time.Time { return readNow }), MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookupKey}}
			if passkey {
				selected := phase.passkeyEffect.native.passkey
				service, err := NewMFAPasskeySessionService(pool, MFAPasskeySessionServiceConfig{Repository: config, Profile: selected.profile, Authority: selected.authority, Validation: validation})
				if err != nil {
					t.Fatal(err)
				}
				credential, _ := session.NewCredential(session.CredentialBearer, issuedToken)
				request := session.GetRequest{TenantID: s.TenantID, Credential: credential}
				admitted, err := service.Get(ctx, request)
				actual, _ := admitted.Session.MFAAuthentication().Bindings()
				want, _ := record.MFAAuthentication().Bindings()
				if err != nil || !admitted.Authenticated || actual != want {
					t.Fatal("recorded passkey/TOTP session cannot authenticate", err)
				}
				replay, err := coordinator.ExecutePreparedFeature(ctx, command, phase.plan)
				if err != nil || !reflect.DeepEqual(replay, result) || phase.calls != 1 {
					t.Fatal("passkey completion replay repeated factor/session", err)
				}
				query, caller := revokeRecoveryInput(b)
				query.AnonymousFlowID = b.AnonymousFlowID
				caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}
				if recovered, err := coordinator.RecoverFeatureCommand(ctx, query, caller); err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("passkey TOTP issuance receipt unrecoverable", err)
				}
				testPasskeyMFARevoke(t, ctx, pool, config, profile, validation.Clock, service, admitted, request, selected)
				return
			}
			service, err := NewMFAMagicLinkSessionService(pool, MFAMagicLinkSessionServiceConfig{Repository: config, Profile: profile, Validation: validation})
			if err != nil {
				t.Fatal(err)
			}
			credential, _ := session.NewCredential(session.CredentialBearer, issuedToken)
			request := session.GetRequest{TenantID: s.TenantID, Credential: credential}
			admitted, err := service.Get(ctx, request)
			if err != nil || !admitted.Authenticated {
				t.Fatal("issued MFA session cannot authenticate", err)
			}
			if admitted.Session.MFAAuthentication() == (session.MFAAuthentication{}) {
				t.Fatal("factor metadata lost on public session read")
			}
			if mode == "commit" || mode == "recovery-commit" {
				t.Run("password-origin session reader", func(t *testing.T) {
					testPasswordMFASessionRead(t, ctx, pool, config, profile, validation, record, request)
				})
			}
			if mode == "commit" {
				t.Run("passkey-origin session reader", func(t *testing.T) {
					testPasskeyMFASessionRead(t, ctx, pool, config, profile, validation, record, request)
				})
			}
			combined, err := NewSelectedSessionService(pool, SelectedSessionServiceConfig{Repository: config, Validation: validation, Admission: SelectedSessionAdmissionConfig{SingleFactor: SingleFactorSessionAdmissionConfig{MagicLink: &profile}, MFAMagicLink: &profile}})
			if err != nil {
				t.Fatal(err)
			}
			if current, err := combined.Get(ctx, request); err != nil || !current.Authenticated || current.Session.MFAAuthentication() == (session.MFAAuthentication{}) || !current.ValidUntil().Equal(admitted.ValidUntil()) {
				t.Fatal("combined reader lost MFA authority or renewed its deadline", err)
			}
			cached, err := service.CacheAdmission(admitted, 20*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			single, err := NewMagicLinkSessionService(pool, MagicLinkSessionServiceConfig{Repository: config, Profile: profile, Validation: validation})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := single.Get(ctx, request); err != nil || result.Authenticated {
				t.Fatal("MFA record entered single-factor reader")
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=3 WHERE tenant_id='magic-effect' AND user_id='recipient'`); err != nil {
				t.Fatal(err)
			}
			if result, err := service.Get(ctx, request); err != nil || result.Authenticated {
				t.Fatal("changed MFA generation retained session access")
			}
			if result, err := combined.Get(ctx, request); err != nil || result.Authenticated {
				t.Fatal("combined reader fell back after changed MFA generation", err)
			}
			if result, err := combined.GetCached(ctx, request, cached); err != nil || result.Authenticated {
				t.Fatal("dedicated MFA cache crossed selected owner profile", err)
			}
			// A warm cache retains only its original bounded positive evidence;
			// no invalidation event is needed for the expiry guarantee.
			warm, err := service.GetCached(ctx, request, cached)
			if err != nil || !warm.Authenticated || !warm.ValidUntil().Equal(admitted.ValidUntil()) {
				t.Fatal("MFA cache renewed original evidence", err)
			}
			readNow = admitted.ValidUntil()
			if expired, err := service.GetCached(ctx, request, cached); err != nil || expired.Authenticated {
				t.Fatal("expired MFA cache bypassed changed generation", err)
			}
			if result, err := single.GetCached(ctx, request, cached); err != nil || result.Authenticated {
				t.Fatal(err)
			}
			// Deliberately unavailable owned authority: expired evidence cannot
			// become a stale-positive fallback. Rename is restored in this fixture.
			if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity_mfa.factor_authorities RENAME TO unavailable_factor_authorities`); err != nil {
				t.Fatal(err)
			}
			outage, outageErr := service.GetCached(ctx, request, cached)
			if _, err := pool.Raw().Exec(ctx, `ALTER TABLE identity_mfa.unavailable_factor_authorities RENAME TO factor_authorities`); err != nil {
				t.Fatal(err)
			}
			if outageErr == nil || outage.Authenticated {
				t.Fatal("expired MFA evidence survived failed refresh")
			}
			if _, err := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id='magic-effect' AND user_id='recipient'`); err != nil {
				t.Fatal(err)
			}
			// Completed child expiry remains history. Original session lifetime
			// and fresh current authority, not a renewed MFA proof, govern Get.
			readNow = completeNow.Add(6 * time.Minute)
			later, err := service.Get(ctx, request)
			if err != nil || !later.Authenticated {
				t.Fatal("expired original child incorrectly ended issued session", err)
			}
			originalPrimary, _ := later.Session.MagicLinkAuthentication().Bindings()
			if !originalPrimary.AuthenticatedAt.Equal(now) {
				t.Fatal("later session read renewed primary authentication")
			}
			var replay identity.CommandResult
			if mode == "recovery-risk-commit" {
				replay, err = coordinator.ExecutePreparedMFARecoveryFeature(ctx, originalCommand, command, phase.plan)
			} else if mode == "risk-commit" {
				replay, err = coordinator.ExecutePreparedMFATOTPFeature(ctx, originalCommand, command, phase.plan)
			} else {
				replay, err = coordinator.ExecutePreparedFeature(ctx, command, phase.plan)
			}
			if err != nil || !reflect.DeepEqual(replay, result) || phase.calls != 1 {
				t.Fatal("completion retry repeated session/factor", err)
			}
			query, caller := revokeRecoveryInput(b)
			query.AnonymousFlowID = b.AnonymousFlowID
			caller.Request.Resource = authorization.Resource{Type: "identity.anonymous-flow", ID: authorization.ResourceID(b.AnonymousFlowID)}
			if mode == "risk-commit" {
				fingerprintVersion = 2
				rotated := newCoordinator(phase, false)
				history, found, historyErr := rotated.QueryMFATOTPCommand(ctx, originalCommand, caller)
				if !found || historyErr != nil || !reflect.DeepEqual(history, result) || phase.calls != 1 {
					t.Fatal("committed original MFA history lost after key rotation", found, historyErr)
				}
			}
			recovered, err := coordinator.RecoverFeatureCommand(ctx, query, caller)
			if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original MFA session receipt unrecoverable", err)
			}
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(s.TenantID), s.SessionID); err != nil {
				t.Fatal(err)
			}
			issuanceDigest := mfaTOTPIssuanceDigest
			if recovery {
				issuanceDigest = mfaRecoveryIssuanceDigest
			}
			retained, status, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, issuanceDigest)
			if err != nil || status != kernel.RecoveryCommitted || retained.SessionID != s.SessionID {
				t.Fatal("pruning lost original MFA issuance", err)
			}
			if recovery {
				_, wrong, err := readNativeIssuanceIdentity(ctx, pool.Raw(), `"session_store"`, b, kernel.LifecyclePlan{}, mfaTOTPIssuanceDigest)
				if err != nil || wrong != kernel.RecoveryUnknown {
					t.Fatal("recovery borrowed TOTP issuance evidence", err)
				}
			}
		})
	}
}

// Real protected counter policy/store, not an allow-all velocity fixture.
// Provider admission remains a separate public-composition obligation.
func installMFACounters(t *testing.T, ctx context.Context, pool *database.Pool) *riskpg.Repository {
	t.Helper()
	history, err := (riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "risk_mfa", Version: 60}, Version: 61}, Version: 62}, Version: 63}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := (riskpg.VerificationCounterMigrationSource{Schema: "risk_mfa", Version: 64}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := (riskpg.MFACompletionCounterMigrationSource{Schema: "risk_mfa", Version: 65}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history = append(history, verification...)
	history = append(history, completion...)
	recovery, err := (riskpg.MFARecoveryCounterMigrationSource{Schema: "risk_mfa", Version: 67}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	history = append(history, recovery...)
	for _, migration := range history {
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("native risk history", err)
		}
	}
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}
	for i := range profiles {
		profiles[i].RequiredSignals = []string{"velocity"}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{83}, 32))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{84}, 32), bytes.Repeat([]byte{85}, 32))
	if err != nil {
		t.Fatal(err)
	}
	repository, err := riskpg.NewRepository(riskpg.Config{Schema: "risk_mfa", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"mfa-test": bytes.Repeat([]byte{86}, 32)}, CurrentEnvelopeKey: "mfa-test", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}}})
	if err != nil {
		t.Fatal(err)
	}
	return repository
}
