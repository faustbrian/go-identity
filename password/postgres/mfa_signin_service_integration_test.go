//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"io/fs"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
)

func testPublicPasswordMFAChallenge(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, crypto *primitive.Service, hash primitive.EncodedHash, storage sessionpg.Config, profile sessionpg.IdentifierAdmissionConfig) {
	t.Helper()
	_, c := publicSigninFixture(t, pool, policy, crypto, hash, storage, profile)
	base := mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}
	factors := mfapg.TOTPFactorMigrationSource{Base: base, Version: 3}
	history, err := (mfapg.PasswordContinuationMigrationSource{Base: factors, Version: 4}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history[1:] {
		if _, err := pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal(err)
		}
	}
	files, err := fs.ReadDir(issuerpg.Migrations(), ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		wire, err := fs.ReadFile(issuerpg.Migrations(), f.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
			t.Fatal(err)
		}
	}
	seedCommand := func(purpose string) []byte {
		id, _ := identity.NewCommandID()
		raw, _ := base64.RawURLEncoding.DecodeString(string(id))
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,decode('01','hex'))`, raw, signinTestTenant, purpose, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, raw, signinTestTenant, purpose); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities VALUES($1,$2,1,1,$3,'identity.password.signup')`, signinTestTenant, signinTestUser, seedCommand("identity.password.signup")); err != nil {
		t.Fatal(err)
	}
	factorID, _ := identity.NewCommandID()
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.totp_factors(tenant_id,user_id,factor_id,state,enrollment_version,row_version,algorithm,digits,period_seconds,skew_steps,issuer,encrypted_secret,created_command_id,created_purpose,created_at,enrollment_expires_at,confirmed_at) VALUES($1,$2,$3,2,1,1,'SHA1',6,30,1,'test',decode('01','hex'),$4,'identity.mfa.enable',clock_timestamp(),clock_timestamp()+interval '5 minutes',clock_timestamp())`, signinTestTenant, signinTestUser, string(factorID), seedCommand("identity.mfa.enable")); err != nil {
		t.Fatal(err)
	}
	signing := bytes.Repeat([]byte{91}, 32)
	signer, _ := capability.NewHMACSHA256Signer("mfa-signing", signing)
	verifier, _ := capability.NewHMACSHA256Verifier(signing)
	keys, _ := capability.NewKeySet([]capability.Key{{ID: "mfa-signing", Verifier: verifier}})
	mc := MFAChallengeConfig{Lifetime: time.Minute, MaxAttempts: 3, IssuerURL: "https://identity.test", Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Signer: signer, Resolver: keys, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: profile.Audience, CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {92}}, PreparationTimeout: time.Second}, Custody: issuerpg.IssuancePreparationConfig{Deployment: "password-mfa-test", ActiveEnvelopeKey: "mfa-envelope", EnvelopeKeys: map[string][]byte{"mfa-envelope": bytes.Repeat([]byte{93}, 32)}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "mfa-signing", HMAC: signing}}, Clock: time.Now}}
	service, err := NewMFASigninService(pool, c, mc)
	if err != nil {
		t.Fatal("native MFA composition denied", err)
	}
	r, _, _, _ := nativeSigninFlow(t)
	r.TenantID, r.Caller.Request.Tenant, r.Caller.Request.Subject.ID = signinTestTenant, signinTestTenant, signinTestActor
	r.Device = "synthetic-device"
	r.PreAuthID, _ = identity.NewPreAuthTransactionID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := session.PreAuthBinding{ID: r.PreAuthID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{2}, Remember: r.Remember, PolicyID: c.PolicyID, PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	token, _ := session.ParseToken(r.Cookie.Token())
	digest, _ := token.PreAuthDigest(c.FlowKeys[0], b)
	flow, err := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
		t.Fatal("browser fixture rejected", err)
	}
	wrong := r
	wrong.Password, err = primitive.NewSecret([]byte("synthetic-wrong-password"))
	if err != nil {
		t.Fatal(err)
	}
	rejected, rejectionErr := service.Signin(ctx, wrong)
	wrong.Password.Destroy()
	if rejectionErr != nil || rejected.State != auth.SignInStateRejected || rejected.Validate() != nil || rejected.Challenge != (password.MFAChallengeResult{}) {
		t.Fatal("wrong password acquired continuation", rejectionErr)
	}
	var pending string
	if err := pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)).Scan(&pending); err != nil || pending != "issued" {
		t.Fatal("wrong password consumed original browser", err)
	}
	result, err := service.Signin(ctx, r)
	if err != nil || result.State != auth.SignInStateChallengeRequired || result.Validate() != nil || result.SessionID != "" || result.Issuance.Token != (session.Token{}) || result.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("password did not commit challenge-only outcome", err)
	}
	var sessions, primary, final, continuations, children int
	var flowState string
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM signin_sessions.sessions),(SELECT count(*) FROM identity_password.mfa_primary_records),(SELECT count(*) FROM identity_password.signin_records),(SELECT count(*) FROM identity_mfa.continuations),(SELECT count(*) FROM public.capability_identity_one_use),state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(r.PreAuthID)).Scan(&sessions, &primary, &final, &continuations, &children, &flowState); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || final != 0 || primary != 1 || continuations != 1 || children != 1 || flowState != "consumed" {
		t.Fatal("challenge split from protected effects", sessions, primary, final, continuations, children, flowState)
	}
	if result.Challenge.Proof == (capability.Proof{}) {
		t.Fatal("original commit lost challenge custody")
	}
	child, err := capability.NewService(mc.Issuer.Crypto)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := child.Verify(ctx, result.Challenge.Proof, "identity.mfa.complete", profile.Audience)
	if err != nil {
		t.Fatal("actual signed child denied", err)
	}
	reader, _ := mfapg.NewContinuationReader(pool, time.Second)
	continuation, err := reader.Read(ctx, grant, mc.IssuerURL)
	if err != nil {
		t.Fatal("committed continuation not publicly readable", err)
	}
	scope, _ := continuation.Bindings()
	if scope.PrimaryProofID != auth.ProofID(result.Issuance.CommandID) || scope.SubjectID != identity.SubjectID(signinTestUser) || scope.SourcePreAuthID != r.PreAuthID {
		t.Fatal("primary/browser scope changed")
	}
	boundPrimary, err := service.ReadMFAPasswordPrimary(ctx, result.Challenge.Proof, continuation, flow, r.Caller)
	if err != nil || boundPrimary.Authentication.Proof.ID != scope.PrimaryProofID || boundPrimary.Authentication.Proof.Purpose != session.PasswordMFAPrimaryPurpose || boundPrimary.Authentication.CredentialVersion != 7 {
		t.Fatal("genuine password primary cannot reach completion", err)
	}
	if boundPrimary.Recipient.Validate() != nil || boundPrimary.Recipient.Suppressed || boundPrimary.Recipient.User.ID != signinTestUser || boundPrimary.Recipient.Identifier.Kind != identity.IdentifierEmail {
		t.Fatal("original signin recipient lost")
	}
	changedScope := scope
	changedScope.PrimaryProofDigest[0] ^= 1
	changedContinuation, err := mfa.NewPartialAuthContinuation(changedScope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadMFAPasswordPrimary(ctx, result.Challenge.Proof, changedContinuation, flow, r.Caller); err == nil {
		t.Fatal("retargeted primary scope admitted completion")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id=$3`, string(r.TenantID), c.Profile.PolicyNamespace, string(signinTestUser)); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReadMFAPasswordPrimary(ctx, result.Challenge.Proof, continuation, flow, r.Caller); err == nil {
		t.Fatal("original signed authorization epoch renewed")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE authorization_subject_authorities SET version=version-1 WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id=$3`, string(r.TenantID), c.Profile.PolicyNamespace, string(signinTestUser)); err != nil {
		t.Fatal(err)
	}
	recovery := password.SigninRecoveryRequest{Recovery: result.Recovery, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
	restarted, err := NewMFASigninService(pool, c, mc)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.RecoverSignin(ctx, recovery)
	if err != nil || recovered.State != auth.SignInStateChallengeRequired || recovered.Validate() != nil || recovered.Challenge.ID != result.Challenge.ID || recovered.Challenge.ExpiresAt != result.Challenge.ExpiresAt || recovered.Challenge.Proof != (capability.Proof{}) || recovered.SessionID != "" {
		t.Fatal("password-free challenge restart recovery failed", err)
	}
	foreign := recovery
	foreign.Cookie = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{94}, 32)))
	if denied, err := restarted.RecoverSignin(ctx, foreign); err == nil || denied.Challenge != (password.MFAChallengeResult{}) {
		t.Fatal("foreign browser acquired challenge history")
	}
	fault := &signinCommitFault{marker: "identity_password.mfa_primary_records("}
	faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(pc *database.PoolConfig) error { pc.ConnConfig.DialFunc = fault.dial; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := faultPool.Close(cleanup); err != nil {
			t.Error("fault pool cleanup failed")
		}
	}()
	faultService, err := NewMFASigninService(faultPool, c, mc)
	if err != nil {
		t.Fatal(err)
	}
	r.PreAuthID, _ = identity.NewPreAuthTransactionID()
	b.ID = r.PreAuthID
	b.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
	b.ExpiresAt = b.IssuedAt.Add(5 * time.Minute)
	digest, _ = token.PreAuthDigest(c.FlowKeys[0], b)
	flow, err = session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
		t.Fatal(err)
	}
	ambiguous, ambiguousErr := faultService.Signin(ctx, r)
	if !fault.hit.Load() || ambiguousErr == nil || ambiguous.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || ambiguous.Challenge.Proof != (capability.Proof{}) {
		t.Fatal("commit disconnect disclosed or lost ambiguity", ambiguousErr)
	}
	faultRecovery := password.SigninRecoveryRequest{Recovery: ambiguous.Recovery, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
	settled, err := restarted.RecoverSignin(ctx, faultRecovery)
	if err != nil || settled.State != auth.SignInStateChallengeRequired || settled.Validate() != nil || settled.Challenge.Proof != (capability.Proof{}) || settled.Issuance.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("ambiguous committed challenge cannot recover", err)
	}
	beforeFault := &signinCommitFault{before: true, marker: "identity_password.mfa_primary_records("}
	beforePool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(pc *database.PoolConfig) error { pc.ConnConfig.DialFunc = beforeFault.dial; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := beforePool.Close(cleanup); err != nil {
			t.Error("precommit fault pool cleanup failed")
		}
	}()
	beforeService, err := NewMFASigninService(beforePool, c, mc)
	if err != nil {
		t.Fatal(err)
	}
	r.PreAuthID, _ = identity.NewPreAuthTransactionID()
	b.ID = r.PreAuthID
	b.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
	b.ExpiresAt = b.IssuedAt.Add(5 * time.Minute)
	digest, _ = token.PreAuthDigest(c.FlowKeys[0], b)
	flow, err = session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
		t.Fatal(err)
	}
	unsettled, unsettledErr := beforeService.Signin(ctx, r)
	if !beforeFault.hit.Load() || unsettledErr == nil || unsettled.Issuance.CommitOutcome != identity.CommitOutcomeUnknown || unsettled.Challenge.Proof != (capability.Proof{}) {
		t.Fatal("precommit disconnect lost ambiguity", unsettledErr)
	}
	unsettledRecovery := password.SigninRecoveryRequest{Recovery: unsettled.Recovery, Cookie: r.Cookie, Caller: r.Caller, Origin: r.Origin, Network: r.Network, Device: r.Device}
	waiting, err := restarted.RecoverSignin(ctx, unsettledRecovery)
	if err != nil || waiting.Issuance.CommitOutcome != identity.CommitOutcomeInProgress || waiting.Challenge != (password.MFAChallengeResult{}) || waiting.Validate() != nil {
		t.Fatal("live original lease was reexecuted or declared rollback", err)
	}
	// Simulate passage of the original lease in this disposable primary; do not
	// alter the outcome or any domain effect. Real recovery must reconcile owners.
	original, _ := base64.RawURLEncoding.DecodeString(string(unsettled.Issuance.CommandID))
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1 AND state='pending'`, original); err != nil {
		t.Fatal(err)
	}
	aborted, abortErr := restarted.RecoverSignin(ctx, unsettledRecovery)
	if aborted.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || aborted.Validate() != nil || aborted.Challenge != (password.MFAChallengeResult{}) {
		t.Fatal("expired uncommitted challenge did not reconcile", abortErr)
	}
	repeated, repeatedErr := restarted.RecoverSignin(ctx, unsettledRecovery)
	if repeated.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || repeated.Validate() != nil || repeated.Challenge != (password.MFAChallengeResult{}) {
		t.Fatal("terminal failed challenge history lost on repeat", repeatedErr)
	}
	parameters := policy.Argon2idParameters()
	parameters.Time++
	strong, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: parameters, Limits: policy.Limits()})
	if err != nil {
		t.Fatal(err)
	}
	strongCrypto, err := primitive.New(strong)
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := strongCrypto.Hash(ctx, []byte("synthetic-dummy-only"))
	if err != nil {
		t.Fatal(err)
	}
	c.Repository.HashPolicy, c.Verifier.Primitive, c.Verifier.DummyHash = strong, strongCrypto, dummy
	upgrading, err := NewMFASigninService(pool, c, mc)
	if err != nil {
		t.Fatal(err)
	}
	r.PreAuthID, _ = identity.NewPreAuthTransactionID()
	b.ID = r.PreAuthID
	b.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
	b.ExpiresAt = b.IssuedAt.Add(5 * time.Minute)
	digest, _ = token.PreAuthDigest(c.FlowKeys[0], b)
	flow, err = session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
		t.Fatal("upgrade flow rejected", err)
	}
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE public.outbox_messages ADD CONSTRAINT password_mfa_rollback_fixture CHECK(false) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	denied, deniedErr := upgrading.Signin(ctx, r)
	if deniedErr == nil || denied.Issuance.CommitOutcome != identity.CommitOutcomeNotCommitted || denied.Challenge.Proof != (capability.Proof{}) {
		t.Fatal("late failure did not withhold challenge", deniedErr)
	}
	var rolledBackVersion, rolledBackFlow string
	var retainedPrimaries int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT version::text FROM identity_password.credentials WHERE tenant_id=$1 AND user_id=$2),(SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$3),(SELECT count(*) FROM identity_password.mfa_primary_records)`, signinTestTenant, signinTestUser, string(r.PreAuthID)).Scan(&rolledBackVersion, &rolledBackFlow, &retainedPrimaries); err != nil {
		t.Fatal(err)
	}
	if rolledBackVersion != "7" || rolledBackFlow != "issued" || retainedPrimaries != 2 {
		t.Fatal("late failure split rehash, browser or primary persistence")
	}
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE public.outbox_messages DROP CONSTRAINT password_mfa_rollback_fixture`); err != nil {
		t.Fatal(err)
	}
	upgraded, err := upgrading.Signin(ctx, r)
	if err != nil || upgraded.State != auth.SignInStateChallengeRequired || upgraded.Validate() != nil {
		t.Fatal("hash upgrade lost MFA challenge", err)
	}
	var materialVersion, referenceVersion, primaryVersion string
	if err := pool.Raw().QueryRow(ctx, `SELECT p.version::text,r.version::text,(convert_from(m.record,'UTF8')::jsonb)->>'CredentialVersion' FROM identity_password.credentials p JOIN identity.credential_references r ON r.tenant_id=p.tenant_id AND r.user_id=p.user_id AND r.credential_id=p.credential_id JOIN identity_password.mfa_primary_records m ON m.tenant_id=p.tenant_id AND m.user_id=p.user_id WHERE p.tenant_id=$1 AND m.proof_id=$2`, signinTestTenant, string(upgraded.Issuance.CommandID)).Scan(&materialVersion, &referenceVersion, &primaryVersion); err != nil {
		t.Fatal(err)
	}
	if materialVersion != "8" || referenceVersion != "8" || primaryVersion != "8" {
		t.Fatal("challenge did not bind protected credential successor")
	}
	// An explicit known-empty successor may select ordinary password signin;
	// an absent row must never stand in for this authoritative transition.
	if _, err := pool.Raw().Exec(ctx, `WITH removed AS (UPDATE identity_mfa.factor_authorities SET version=2,active_factors=0 WHERE tenant_id=$1 AND user_id=$2 RETURNING tenant_id,user_id) UPDATE identity_mfa.totp_factors SET state=3,encrypted_secret=NULL,last_step=NULL WHERE (tenant_id,user_id) IN (SELECT tenant_id,user_id FROM removed)`, signinTestTenant, signinTestUser); err != nil {
		t.Fatal(err)
	}
	r.PreAuthID, _ = identity.NewPreAuthTransactionID()
	b.ID = r.PreAuthID
	b.IssuedAt = time.Now().UTC().Truncate(time.Microsecond)
	b.ExpiresAt = b.IssuedAt.Add(5 * time.Minute)
	digest, _ = token.PreAuthDigest(c.FlowKeys[0], b)
	flow, err = session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: b, Cookie: digest, Version: 1})
	if err != nil || sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, storage, flow) != nil {
		t.Fatal(err)
	}
	ordinary, err := upgrading.Signin(ctx, r)
	if err != nil || ordinary.State != auth.SignInStateAuthenticated || ordinary.Challenge != (password.MFAChallengeResult{}) || ordinary.Validate() != nil {
		t.Fatal("known-empty native MFA selection lost SFA compatibility", err)
	}
}
