//go:build integration

package anonymouspostgres_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password/v2"
)

const upgradeTargetID identity.UserID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
const upgradeProofAudience = "anonymous-upgrade"
const upgradeFixturePassword = "synthetic anonymous upgrade target password"

type anonymousUpgradeTarget struct {
	record  session.Session
	bearer  auth.BearerCredential
	csrf    session.CSRFToken
	profile sessionpg.IdentifierAdmissionConfig
	proofs  *passwordpg.ReauthenticationService
	primary *passwordpg.ActionPrimarySource
}

func installUpgradeTargetHistory(t *testing.T, f publicAnonymousFixture) {
	t.Helper()
	passwordHistory := passwordpg.AnonymousUpgradeReauthenticationMigrationSource{Base: passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.UsernameSigninMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	for _, source := range []migrations.Source{passwordHistory, mfapg.MigrationSource{Version: 1}} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if _, err := f.pool.Raw().Exec(f.ctx, step.UpSQL()); err != nil {
				t.Fatal("actual target proof/factor history", err)
			}
		}
	}
}

// Seed a pre-existing permanent account, not a replacement authentication
// implementation. The native session reader must authenticate these rows; only
// the real password service verifies the candidate and commits a signed proof.
// These fixtures deliberately preserve a canonical ULID target beside opaque
// guest identifiers. They do not claim to exercise registration or signin.
func newAnonymousUpgradeTarget(t *testing.T, f publicAnonymousFixture, remember session.RememberPolicy) anonymousUpgradeTarget {
	t.Helper()
	installUpgradeTargetHistory(t, f)
	const tenant identity.TenantID = "AAAAAAAAAAAAAAAAAAAAAQ"
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: f.config.Profile.GlobalAuthorityID, PolicyNamespace: "users", Audience: f.config.Profile.Audience, AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(tenant), string(upgradeTargetID)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',1,true)`, string(tenant), string(upgradeTargetID)); err != nil {
		t.Fatal(err)
	}
	// Existing initialized factor authority is explicit, with its real command
	// foreign key. Missing rows must never be interpreted as no enrolled factors.
	for _, sql := range []string{
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(md5($1::text||':'||$2::text),'hex'),$1::text,'identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'))`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(md5($1::text||':'||$2::text),'hex'),$1::text,'identity.password.signup')`,
		`INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1::text,$2::text,1,0,decode(md5($1::text||':'||$2::text),'hex'),'identity.password.signup')`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, string(tenant), string(upgradeTargetID)); err != nil {
			t.Fatal("explicit existing factor authority", err)
		}
	}
	policyScope := authority.AuthorityScope{TenantID: authorization.TenantID(tenant), PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(upgradeTargetID)}
	if _, err := authority.InitializeAuthority(f.ctx, f.pool.Raw(), policyScope, time.Second); err != nil {
		t.Fatal(err)
	}
	keys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: tenant}, upgradeTargetID)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID, familyID = "permanent-target-session", "permanent-target-family"
	sk, err := sessionpg.SessionAuthorityKeys(tenant, upgradeTargetID, familyID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := policyScope.Key()
	if err != nil {
		t.Fatal(err)
	}
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	vectorSpec := session.AuthoritySnapshotSpec{Global: bind(keys.Global), Tenant: bind(keys.Tenant), User: bind(keys.User), Identifier: bind(keys.Identifier), Credential: bind(keys.Credential), Session: bind(sk.Session), SessionFamily: bind(sk.Family), Authorization: bind(pk)}
	vector, err := session.NewAuthoritySnapshot(vectorSpec)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(f.lookupKey, string(tenant))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	csrfState, err := csrf.Digest(f.csrfKey, session.CSRFBinding{TenantID: tenant, SessionID: sessionID, SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	metadata := session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: string(tenant), Subject: string(upgradeTargetID), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: profile.Audience, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}, CredentialID: "password", CredentialVersion: 1, ProofVersion: 1}
	record, err := session.NewSessionWithCSRF(session.SessionSpec{SessionID: sessionID, FamilyID: familyID, TenantID: tenant, UserID: upgradeTargetID, Audience: profile.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: digest, Authentication: metadata, IssuedAt: now, LastActivityAt: now}, csrfState)
	if err != nil {
		t.Fatal(err)
	}
	resolved, _ := remember.Bindings()
	csrfSpec, _ := csrfState.Bindings()
	payload, err := json.Marshal(map[string]any{"Schema": 2, "SessionID": sessionID, "FamilyID": familyID, "TenantID": tenant, "UserID": upgradeTargetID, "Audience": profile.Audience, "Version": uint64(1), "FamilyVersion": uint64(1), "Remember": resolved, "Authority": vectorSpec, "Lookup": digest, "Authentication": metadata, "IssuedAt": now, "LastActivityAt": now, "CSRF": csrfSpec})
	if err != nil {
		t.Fatal(err)
	}
	lifetime, err := record.Lifetime(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(tenant), familyID, string(upgradeTargetID), now.Format("2006-01-02T15:04:05.000000000Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',1,$5,$6,$7)`, string(tenant), sessionID, string(upgradeTargetID), familyID, digest.Sum[:], lifetime.ExpiresAt.Format("2006-01-02T15:04:05.000000000Z"), payload); err != nil {
		t.Fatal(err)
	}
	crypto, err := primitive.New(primitive.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.Hash(f.ctx, []byte(upgradeFixturePassword))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES($1,$2,'password',1,'argon2id',$3)`, string(tenant), string(upgradeTargetID), hash.String()); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	signer, err := passwordpg.NewReauthenticationSigningKey("upgrade-proof", private)
	if err != nil {
		t.Fatal(err)
	}
	custody := f.config.Risk
	custody.ConfigurationID = "anonymous-upgrade-target-proof"
	proofs, err := passwordpg.NewReauthenticationService(f.pool, passwordpg.ReauthenticationConfig{Repository: passwordpg.Config{MaximumDuration: 3 * time.Second, HashPolicy: primitive.DefaultPolicy()}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: 2 * time.Second, DummyHash: hash, Now: time.Now}, Session: f.config.Sessions, Profile: profile, LookupKeys: []session.DigestKey{f.lookupKey}, Risk: custody, Coordinator: f.config.Coordinator, SigningKey: signer, VerificationKeys: map[string]ed25519.PublicKey{"upgrade-proof": private.Public().(ed25519.PublicKey)}, Issuer: "anonymous-native-test", Environment: "isolated", Targets: []passwordpg.ReauthenticationTarget{{Purpose: "identity.password.verify", Action: "identity.anonymous.upgrade", Audience: upgradeProofAudience}}, TTL: 5 * time.Minute, IdentifierKey: bytes.Repeat([]byte{91}, 32)})
	if err != nil {
		t.Fatal("actual native target proof owner", err)
	}
	primary, err := passwordpg.NewActionPrimarySource(proofs, passwordpg.ActionPrimaryConfig{Action: "identity.anonymous.upgrade", Audience: upgradeProofAudience, MaximumAge: 15 * time.Minute, Transport: session.CredentialCookie, CSRFKeys: []session.CSRFKey{f.csrfKey}})
	if err != nil {
		t.Fatal(err)
	}
	return anonymousUpgradeTarget{record: record, bearer: auth.NewBearerCredential(wire), csrf: csrf, profile: profile, proofs: proofs, primary: primary}
}

func (a anonymousUpgradeTarget) verify(t *testing.T, f publicAnonymousFixture) auth.ReauthenticationProof {
	t.Helper()
	secret, err := primitive.NewSecret([]byte(upgradeFixturePassword))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	b, _ := a.record.Bindings()
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(b.UserID)}, Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	out, err := a.proofs.Verify(f.ctx, passwordpg.ReauthenticationRequest{TenantID: b.TenantID, Session: a.bearer, Password: secret, Target: passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.anonymous.upgrade", Audience: upgradeProofAudience}, Caller: caller, Network: "192.0.2.1", Device: "upgrade-target"})
	if err != nil || out.Outcome != identity.CommitOutcomeCommitted || out.Proof == (auth.ReauthenticationProof{}) {
		t.Fatal("real target password verification", err, out.Outcome)
	}
	return out.Proof
}

func TestNativeAnonymousUpgradeAuthenticatesActualPermanentTarget(t *testing.T) {
	f := newPublicAnonymousFixture(t)
	r := f.fresh()
	issued, err := f.service.Signin(f.ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	guest, _ := issued.Session.Session.Bindings()
	target := newAnonymousUpgradeTarget(t, f, guest.Remember)
	proof := target.verify(t, f)
	id, _ := identity.NewCommandID()
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: authorization.TenantID(guest.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(upgradeTargetID)}, Action: "identity.anonymous.upgrade", Resource: authorization.Resource{Type: "anonymous", ID: authorization.ResourceID(guest.UserID)}}}
	request := passwordpg.ActionPrimaryRequest{TenantID: guest.TenantID, CommandID: id, RecordID: string(guest.UserID), Session: target.bearer, Proof: proof, Caller: caller, CSRFToken: target.csrf}
	admitted, err := target.primary.Prepare(f.ctx, request)
	if err != nil {
		t.Fatal("actual signed target proof cannot prepare native upgrade", err)
	}
	original, err := admitted.Original()
	b, _ := original.Bindings()
	if err != nil || b.UserID != upgradeTargetID || b.UserID == guest.UserID || b.SessionID != "permanent-target-session" {
		t.Fatal("guest possession substituted for permanent authentication", err)
	}
	wrong := request
	guestWire, err := issued.Session.Token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	wrong.Session = auth.NewBearerCredential(guestWire)
	if _, err := target.primary.Prepare(f.ctx, wrong); err == nil {
		t.Fatal("guest bearer impersonated actual permanent target")
	}
	wrong = request
	wrong.CSRFToken = session.CSRFToken{}
	if _, err := target.primary.Prepare(f.ctx, wrong); err == nil {
		t.Fatal("target action proof omitted actual target cookie CSRF")
	}
	var recorded, consumed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*),count(consumed_command_id) FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND proof_id=$3`, string(guest.TenantID), string(upgradeTargetID), string(proof.Proof.ID)).Scan(&recorded, &consumed); err != nil || recorded != 1 || consumed != 0 {
		t.Fatal("preparation did not retain one real unconsumed signed proof", err, recorded, consumed)
	}
}
