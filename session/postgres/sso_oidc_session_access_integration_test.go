//go:build integration

package postgres

import (
	"bytes"
	"context"
	"io/fs"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
)

// This component proves native session access/logout, not protocol validation
// or issuance. Only the existing SQL-backed organization-owner port is a fixture;
// kernel, factor, linked-account, opaque-token and revocation persistence are real.
type ssoSessionAccessFixture struct {
	ctx          context.Context
	pool         *database.Pool
	profile      IdentifierAdmissionConfig
	selection    SSOOIDCSessionAdmission
	oauth2       SSOOAuth2SessionAdmission
	repository   Config
	validation   session.ServiceConfig
	reader       *session.SessionService
	bothSelected bool
	csrfKey      session.CSRFKey
	request      session.GetRequest
	csrf         session.CSRFToken
	record       session.Session
}

func newSSOSessionAccessFixture(t *testing.T, method string) ssoSessionAccessFixture {
	t.Helper()
	if method != "sso-oidc" && method != "sso-oauth2" {
		t.Fatal("fixture requires an explicit enterprise authentication method")
	}
	ctx, pool, _ := anonymousSessionDatabase(t)
	accountHistory, err := (kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 30}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range accountHistory {
		if step.Version() >= 30 {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("actual linked account history", err)
			}
		}
	}
	for _, source := range []migrations.Source{mfapg.MigrationSource{Version: 34}, CSRFMigrationSource{Schema: "session_store", Version: 38}} {
		history, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range history {
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("factor and synchronizer-token history", err)
			}
		}
	}
	history, err := (RevokeOneMigrationSource{Base: RevocationMigrationSource{Base: MigrationSource{Schema: "session_store", Version: 20}, Version: 21}, Version: 39}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("terminal self-logout history", err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('guest-tenant','enterprise-user','active',1);
INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES(decode(repeat('01',16),'hex'),'guest-tenant','identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex'));
INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES(decode(repeat('01',16),'hex'),'guest-tenant','identity.password.signup');
INSERT INTO identity_mfa.factor_authorities VALUES('guest-tenant','enterprise-user',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('guest-tenant','enterprise-user','enterprise-credential',3,'sso',1,true);
WITH a AS (SELECT 'oidc'::text AS provider,'https://issuer.example'::text AS issuer,'enterprise-subject'::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT 'guest-tenant','enterprise-user','enterprise-account',provider,issuer,subject,sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a;
INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('guest-tenant','enterprise-user','enterprise-credential','enterprise-account');
CREATE TABLE public.sso_session_membership(tenant_id text NOT NULL,user_id text NOT NULL,organization_id text NOT NULL,authority_key text NOT NULL,version bigint NOT NULL CHECK(version>0),active boolean NOT NULL,PRIMARY KEY(tenant_id,user_id,organization_id));
INSERT INTO public.sso_session_membership VALUES('guest-tenant','enterprise-user','selected-org','organization:guest-tenant:selected-org',7,true)`); err != nil {
		t.Fatal("real identity/factor/link and controlled membership rows", err)
	}
	profile := IdentifierAdmissionConfig{GlobalAuthorityID: "guest-deployment", PolicyNamespace: "users", Audience: "service-a", AuthenticationMethod: method, CredentialKind: identity.CredentialProvider, CredentialOwner: "sso"}
	scope := policy.AuthorityScope{TenantID: "guest-tenant", PolicyNamespace: "users", SubjectID: "enterprise-user"}
	if _, err := policy.InitializeAuthority(ctx, pool.Raw(), scope, time.Second); err != nil {
		t.Fatal(err)
	}
	installSSOOIDCSessionAccessEffects(t, ctx, pool)
	key, err := session.NewDigestKey(1, bytes.Repeat([]byte{83}, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(7, bytes.Repeat([]byte{84}, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	rawToken, tokenErr := token.Reveal()
	rawCSRF, csrfErr := csrf.Reveal()
	if tokenErr != nil || csrfErr != nil || rawToken == "" || rawCSRF == "" || rawToken == rawCSRF {
		t.Fatal("real independent token primitives did not produce opaque custody")
	}
	proofID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	spec, _ := testSession(t).Bindings()
	spec.TenantID, spec.UserID, spec.SessionID, spec.FamilyID = "guest-tenant", "enterprise-user", "enterprise-access", "enterprise-family"
	spec.Version, spec.FamilyVersion, spec.IssuedAt, spec.LastActivityAt = 1, 1, now, now
	spec.Audience = profile.Audience
	spec.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: auth.ProofID(proofID), Tenant: string(spec.TenantID), Subject: string(spec.UserID), Method: method, Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: profile.Audience, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "enterprise-credential", CredentialVersion: 1}
	spec.Lookup, err = token.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	kernelKeys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: spec.TenantID}, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	sessionKeys, err := SessionAuthorityKeys(spec.TenantID, spec.UserID, spec.FamilyID, spec.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	policyKey, err := scope.Key()
	if err != nil {
		t.Fatal(err)
	}
	factorKey, err := mfapg.FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil {
		t.Fatal(err)
	}
	bind := func(key string, version uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: key, Version: version}
	}
	spec.Authority, err = session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: bind(kernelKeys.Global, 1), Tenant: bind(kernelKeys.Tenant, 1), User: bind(kernelKeys.User, 1), Identifier: bind(kernelKeys.Identifier, 1), Credential: bind(kernelKeys.Credential, 1), Session: bind(sessionKeys.Session, 1), SessionFamily: bind(sessionKeys.Family, 1), Authorization: bind(policyKey, 1), Factor: session.OptionalAuthorityBinding{Present: true, Binding: bind(factorKey, 1)}, ActiveOrganizationID: "selected-org", Organization: session.OptionalAuthorityBinding{Present: true, Binding: bind("organization:guest-tenant:selected-org", 7)}})
	if err != nil {
		t.Fatal(err)
	}
	csrfState, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(spec, csrfState)
	if err != nil {
		t.Fatal(err)
	}
	wire, expiry, err := encodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(spec.TenantID), spec.FamilyID, string(spec.UserID), now.Format(storedTimeLayout)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8::jsonb)`, string(spec.TenantID), spec.SessionID, string(spec.UserID), spec.FamilyID, int64(spec.Lookup.KeyVersion), spec.Lookup.Sum[:], expiry, wire); err != nil {
		t.Fatal("actual opaque session persistence", err)
	}
	organization := &ssoOIDCSessionOrganizationFixture{pool: pool}
	oidcProfile, oauth2Profile := profile, profile
	oidcProfile.AuthenticationMethod, oauth2Profile.AuthenticationMethod = "sso-oidc", "sso-oauth2"
	selection := SSOOIDCSessionAdmission{Profile: oidcProfile, Authority: organization}
	oauth2 := SSOOAuth2SessionAdmission{Profile: oauth2Profile, Authority: organization}
	config := Config{Schema: "session_store", MaximumDuration: time.Second}
	validation := session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, Clock: clock.System{}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}}
	readerConfig := SelectedSessionServiceConfig{Repository: config, Validation: validation}
	var reader *session.SessionService
	if method == "sso-oidc" {
		readerConfig.Admission.SSOOIDC = &selection
		reader, err = NewSelectedSessionService(pool, readerConfig)
	} else {
		reader, err = NewSelectedSessionServiceWithSSOOAuth2(pool, readerConfig, oauth2)
	}
	if err != nil {
		t.Fatal("explicit enterprise session reader", err)
	}
	credential, err := session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		t.Fatal(err)
	}
	return ssoSessionAccessFixture{ctx: ctx, pool: pool, profile: profile, selection: selection, oauth2: oauth2, repository: config, validation: validation, reader: reader, csrfKey: csrfKey, request: session.GetRequest{TenantID: spec.TenantID, Credential: credential}, csrf: csrf, record: record}
}

func installSSOOIDCSessionAccessEffects(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL search_path=public,pg_catalog`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
		t.Fatal(err)
	}
	for _, source := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations()} {
		entries, err := fs.ReadDir(source, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			wire, err := fs.ReadFile(source, entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
				t.Fatal("actual audit/lifecycle history", err)
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// FreshInstallPreflightSQL establishes that this transaction alone reserved
	// these cluster-wide roles; the disposable database does not remove them.
	t.Cleanup(func() {
		bounded, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := pool.Raw().Exec(bounded, `DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention`); err != nil {
			t.Error("owned audit-role cleanup", err)
		}
	})
}

func TestSSOOIDCSessionAccessAndStrictCookieLogoutPostgres(t *testing.T) {
	assertSSOSessionAccessAndStrictCookieLogout(t, newSSOSessionAccessFixture(t, "sso-oidc"))
}

func assertSSOSessionAccessAndStrictCookieLogout(t *testing.T, f ssoSessionAccessFixture) {
	t.Helper()
	accepted, err := f.reader.Get(f.ctx, f.request)
	if err != nil || !accepted.Authenticated || accepted.ValidateAt(time.Now().UTC()) != nil {
		t.Fatal("real enterprise opaque session did not authenticate", err)
	}
	spec, _ := accepted.Session.Bindings()
	vector, _ := spec.Authority.Bindings()
	original, _ := f.record.Bindings()
	originalVector, _ := original.Authority.Bindings()
	if spec.Authentication.Proof.Method != f.profile.AuthenticationMethod || spec.Authentication.CredentialID != "enterprise-credential" || vector.ActiveOrganizationID != "selected-org" || !vector.Organization.Present || !vector.Factor.Present {
		t.Fatal("enterprise reader erased original ownership or selected authority")
	}
	if spec.Authentication != original.Authentication || vector != originalVector || spec.TenantID != original.TenantID || spec.UserID != original.UserID || spec.SessionID != original.SessionID || spec.FamilyID != original.FamilyID {
		t.Fatal("enterprise reader substituted the original credential, proof or exact authority bindings")
	}
	execution := IssueExecutorConfig{Repository: f.repository, Profile: IssueAdmissionConfig(f.profile), Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}}, Authorization: revokeQueryPolicy{}, Clock: clock.System{}, PolicyID: "session-policy", PolicyVersion: 1, AuditRetentionVersion: 1}
	executorConfig := RevokeOneExecutorConfig{Execution: execution, Sessions: f.reader}
	if f.bothSelected {
		executorConfig.SSOOIDC = &f.selection
	}
	var executor *CookieRevokeOneExecutor
	if f.profile.AuthenticationMethod == "sso-oidc" && !f.bothSelected {
		executorConfig.SSOOIDC = &f.selection
		executor, err = NewCookieRevokeOneExecutor(f.pool, executorConfig, []session.CSRFKey{f.csrfKey})
	} else {
		executor, err = NewCookieRevokeOneExecutorWithSSOOAuth2(f.pool, executorConfig, []session.CSRFKey{f.csrfKey}, f.oauth2)
	}
	if err != nil {
		t.Fatal("native enterprise CSRF executor", err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	if err != nil {
		t.Fatal(err)
	}
	base, err := session.NewSignOutService(f.reader, executor, session.SignOutConfig{Cookie: cookie, PolicyID: execution.PolicyID, PolicyVersion: execution.PolicyVersion, MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	logout, err := session.NewCookieSignOutService(base, []session.CSRFKey{f.csrfKey})
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	request := session.SignOutRequest{TenantID: spec.TenantID, CommandID: id, CorrelationID: "enterprise-cookie-logout", Transport: session.CredentialCookie, Credential: f.request.Credential}
	wrong, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		token session.CSRFToken
	}{
		{name: "missing CSRF", token: session.CSRFToken{}},
		{name: "foreign CSRF", token: wrong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denied, err := logout.SignOut(f.ctx, request, tc.token)
			if err == nil || denied.SignedOut || denied.ClearCookie || denied.CommitOutcome == identity.CommitOutcomeCommitted {
				t.Fatal("enterprise logout accepted absent or foreign synchronizer custody")
			}
			if got, err := f.reader.Get(f.ctx, f.request); err != nil || !got.Authenticated {
				t.Fatal("CSRF rejection revoked the original session", err)
			}
		})
	}
	for _, tc := range []struct{ name, change, restore string }{
		{"membership withdrawal after authenticated read", `UPDATE public.sso_session_membership SET active=false`, `UPDATE public.sso_session_membership SET active=true`},
		{"factor requirement after authenticated read", `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id='guest-tenant'`, `UPDATE identity_mfa.factor_authorities SET active_factors=0 WHERE tenant_id='guest-tenant'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller, err := f.reader.Get(f.ctx, f.request)
			if err != nil || !caller.Authenticated {
				t.Fatal(err)
			}
			binding := revokeBinding()
			op := session.RevokeOneOperation()
			binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			binding.TenantID, binding.UserID, binding.ActorID, binding.RecordID = spec.TenantID, spec.UserID, identity.ActorID(spec.UserID), spec.SessionID
			binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
			command, err := session.NewRevokeOneCommand(binding, caller.Session)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := f.reader.PrepareRevokeOneWithCSRF(caller, command, f.csrf, f.csrfKey)
			if err != nil {
				t.Fatal("retain original cookie/CSRF custody before withdrawal", err)
			}
			if _, err := f.pool.Raw().Exec(f.ctx, tc.change); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := f.pool.Raw().Exec(f.ctx, tc.restore); err != nil {
					t.Error("restore isolated current authority", err)
				}
			}()
			if denied, err := executor.ExecuteRevokeOneWithCSRF(f.ctx, prepared); err == nil || denied.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("native logout reused withdrawn source authority", err)
			}
			var transitions, events int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, binding.CommandID)).Scan(&transitions, &events); err != nil || transitions != 0 || events != 0 {
				t.Fatal("denied enterprise logout retained protected effects", err)
			}
		})
		if got, err := f.reader.Get(f.ctx, f.request); err != nil || !got.Authenticated {
			t.Fatal("withdrawal denial changed the original session", err)
		}
	}
	result, err := logout.SignOut(f.ctx, request, f.csrf)
	if err != nil || !result.SignedOut || !result.ClearCookie || result.CommitOutcome != identity.CommitOutcomeCommitted || result.Cookie.Value != "" || result.Cookie.MaxAge != -1 {
		t.Fatal("enterprise logout did not atomically revoke and clear the cookie", err)
	}
	if got, err := f.reader.Get(f.ctx, f.request); err != nil || got.Authenticated || got.Session != (session.Session{}) {
		t.Fatal("revoked enterprise cookie still authenticates", err)
	}
	if repeated, err := logout.SignOut(f.ctx, request, f.csrf); err != nil || !repeated.SignedOut || !repeated.ClearCookie {
		t.Fatal("repeated enterprise logout did not preserve removal", err)
	}
	var transitions, audits, events int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.session_revocations WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.outcome=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, mustCommandBytes(t, id), int64(audit.OutcomeSucceeded)).Scan(&transitions, &audits, &events); err != nil || transitions != 1 || audits != 1 || events != 1 {
		t.Fatal("enterprise logout duplicated or omitted durable effects", transitions, audits, events, err)
	}
}

func TestSSOOIDCSessionAccessRequiresExplicitSelectionAndCurrentAuthorityPostgres(t *testing.T) {
	assertSSOSessionAccessRequiresExplicitSelectionAndCurrentAuthority(t, newSSOSessionAccessFixture(t, "sso-oidc"))
}

func assertSSOSessionAccessRequiresExplicitSelectionAndCurrentAuthority(t *testing.T, f ssoSessionAccessFixture) {
	t.Helper()
	if got, err := f.reader.Get(f.ctx, f.request); err != nil || !got.Authenticated {
		t.Fatal("current enterprise fixture did not authenticate", err)
	}
	password := f.profile
	password.AuthenticationMethod, password.CredentialKind, password.CredentialOwner = "password", identity.CredentialPassword, "identity/password"
	social := f.profile
	social.AuthenticationMethod, social.CredentialOwner = "oauth", "identity/oauth"
	defaultReader, err := NewSessionService(f.pool, SessionServiceConfig{Repository: f.repository, Validation: f.validation, Profile: password})
	if err != nil {
		t.Fatal(err)
	}
	withoutEnterprise, err := NewSelectedSessionService(f.pool, SelectedSessionServiceConfig{Repository: f.repository, Validation: f.validation, Admission: SelectedSessionAdmissionConfig{SingleFactor: SingleFactorSessionAdmissionConfig{Verified: &password, OAuth: &social}}})
	if err != nil {
		t.Fatal(err)
	}
	enterpriseConfig := SelectedSessionServiceConfig{Repository: f.repository, Validation: f.validation}
	var otherEnterprise *session.SessionService
	if f.profile.AuthenticationMethod == "sso-oauth2" {
		enterpriseConfig.Admission.SSOOIDC = &f.selection
		otherEnterprise, err = NewSelectedSessionService(f.pool, enterpriseConfig)
	} else {
		otherEnterprise, err = NewSelectedSessionServiceWithSSOOAuth2(f.pool, enterpriseConfig, f.oauth2)
	}
	if err != nil {
		t.Fatal("independently selected other enterprise method", err)
	}
	for name, reader := range map[string]*session.SessionService{"default password": defaultReader, "selected social and password": withoutEnterprise, "only other enterprise method selected": otherEnterprise} {
		t.Run(name, func(t *testing.T) {
			if got, err := reader.Get(f.ctx, f.request); got.Authenticated || got.Session != (session.Session{}) {
				t.Fatal("unselected enterprise session fell back to another credential owner", err)
			}
		})
	}
	enterpriseConfig.Admission.SingleFactor = SingleFactorSessionAdmissionConfig{Verified: &password, OAuth: &social}
	enterpriseConfig.Admission.SSOOIDC = &f.selection
	bothEnterprise, err := NewSelectedSessionServiceWithSSOOAuth2(f.pool, enterpriseConfig, f.oauth2)
	if err != nil {
		t.Fatal("explicit independent OIDC and OAuth2 selection", err)
	}
	accepted, err := bothEnterprise.Get(f.ctx, f.request)
	if err != nil || !accepted.Authenticated {
		t.Fatal("selecting both enterprise methods lost the original owner", err)
	}
	spec, _ := accepted.Session.Bindings()
	original, _ := f.record.Bindings()
	if spec.Authentication != original.Authentication || spec.Authority.CompareCurrent(original.Authority) != nil {
		t.Fatal("combined enterprise selection changed the original proof or authority")
	}
	f.reader = bothEnterprise
	foreign := f.request
	foreign.TenantID = "different-tenant"
	if got, err := f.reader.Get(f.ctx, foreign); got.Authenticated || got.Session != (session.Session{}) {
		t.Fatal("enterprise opaque cookie crossed tenant scope", err)
	}
	for _, tc := range []struct{ name, change, restore string }{
		{"unlinked account", `UPDATE identity.accounts SET linked=false WHERE tenant_id='guest-tenant' AND account_id='enterprise-account'`, `UPDATE identity.accounts SET linked=true WHERE tenant_id='guest-tenant' AND account_id='enterprise-account'`},
		{"missing credential association", `DELETE FROM identity.account_credentials WHERE tenant_id='guest-tenant' AND user_id='enterprise-user' AND credential_id='enterprise-credential'`, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES('guest-tenant','enterprise-user','enterprise-credential','enterprise-account')`},
		{"disabled credential", `UPDATE identity.credential_references SET enabled=false WHERE tenant_id='guest-tenant' AND credential_id='enterprise-credential'`, `UPDATE identity.credential_references SET enabled=true WHERE tenant_id='guest-tenant' AND credential_id='enterprise-credential'`},
		{"social credential substitution", `UPDATE identity.credential_references SET owner='identity/oauth' WHERE tenant_id='guest-tenant' AND credential_id='enterprise-credential'`, `UPDATE identity.credential_references SET owner='sso' WHERE tenant_id='guest-tenant' AND credential_id='enterprise-credential'`},
		{"removed member", `UPDATE public.sso_session_membership SET active=false`, `UPDATE public.sso_session_membership SET active=true`},
		{"changed organization epoch", `UPDATE public.sso_session_membership SET version=8`, `UPDATE public.sso_session_membership SET version=7`},
		{"changed factor epoch", `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id='guest-tenant'`, `UPDATE identity_mfa.factor_authorities SET version=1 WHERE tenant_id='guest-tenant'`},
		{"newly required second factor", `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id='guest-tenant'`, `UPDATE identity_mfa.factor_authorities SET active_factors=0 WHERE tenant_id='guest-tenant'`},
		{"changed authorization policy", `UPDATE authorization_subject_authorities SET version=2 WHERE tenant_id='guest-tenant'`, `UPDATE authorization_subject_authorities SET version=1 WHERE tenant_id='guest-tenant'`},
		{"suspended user", `UPDATE identity.users SET status='suspended' WHERE tenant_id='guest-tenant' AND user_id='enterprise-user'`, `UPDATE identity.users SET status='active' WHERE tenant_id='guest-tenant' AND user_id='enterprise-user'`},
		{"disabled tenant", `UPDATE identity.tenant_authorities SET enabled=false WHERE tenant_id='guest-tenant'`, `UPDATE identity.tenant_authorities SET enabled=true WHERE tenant_id='guest-tenant'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.pool.Raw().Exec(f.ctx, tc.change); err != nil {
				t.Fatal("change isolated authority", err)
			}
			defer func() {
				if _, err := f.pool.Raw().Exec(f.ctx, tc.restore); err != nil {
					t.Error("restore isolated authority", err)
				}
			}()
			if got, err := f.reader.Get(f.ctx, f.request); got.Authenticated || got.Session != (session.Session{}) {
				t.Fatal("enterprise session ignored changed current authority", err)
			}
		})
		if got, err := f.reader.Get(f.ctx, f.request); err != nil || !got.Authenticated {
			t.Fatal("partition did not restore its original current-authority fixture", err)
		}
	}
}
