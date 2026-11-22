//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

type enterpriseProvisioned struct {
	user         identity.UserID
	organization organization.ID
	provider     sso.ProviderID
	bearer       auth.BearerCredential
}

// Provision through the native admin owner. Test-only SQL supplies the
// pre-existing human, domain proof and link; installing a provider must still
// use the same checked/encrypted PostgreSQL transitions as a deployment.
func provisionReferenceEnterprise(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, browser *http.Client, origin string, provider *referenceEnterpriseIssuer) enterpriseProvisioned {
	t.Helper()
	pool := deps.PostgreSQL
	user, bearer := seedEnterpriseAdministrator(t, ctx, pool, c)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/v1/organization/create", bytes.NewBufferString(`{"name":"Enterprise test","slug":"enterprise-fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer.Token())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "enterprise-create-organization")
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var created organizationhttp.MutationResponse
	err = json.NewDecoder(response.Body).Decode(&created)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !created.Committed || created.OrganizationID == "" {
		t.Fatal("native organization creation did not commit", response.StatusCode, err)
	}
	profile := c.EnterpriseOIDC.Login.Profiles[0]
	organizations, err := organizationpg.NewRepository(pool, c.Organization.Repository)
	if err != nil {
		t.Fatal(err)
	}
	validation := c.Session.Native.Validation
	validation.Clock = c.Session.Native.Execution.Clock
	sessions, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: c.Session.Native.Execution.Repository,
		Profile: c.PasswordSignin.Native.Profile, Validation: validation})
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(c.Organization.Counters)
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(deps.EnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	execution, login := c.Session.Native.Execution, c.EnterpriseOIDC.Login
	setup, err := ssopg.NewProviderService(pool, ssopg.ProviderServiceConfig{Clock: execution.Clock, MaximumDuration: 4 * time.Second,
		Sessions: sessions, Session: execution.Repository, Profile: c.PasswordSignin.Native.Profile, LookupKeys: map[uint32]session.DigestKey{
			enterpriseLookupVersion(t, validation.LookupKeys[0]): validation.LookupKeys[0],
		}, Organizations: organizations, Authorization: execution.Authorization, PolicyID: login.PolicyID, PolicyVersion: execution.PolicyVersion,
		Counters: counters, RequestKeys: login.RequestKeys, Coordinator: login.Coordinator, Envelope: crypto, KeyReference: login.KeyReference,
	}, organization.Authentication{TenantID: otpTenant, Bearer: bearer}, "127.0.0.1")
	if err != nil {
		t.Fatal("compose native provider setup", err)
	}
	metadata, err := sso.NewOIDCStaticMetadata(provider.metadata())
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 1, SubjectClaim: "sub"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := setup.ProviderRegisterOidc(ctx, sso.ProviderRegisterOidcRequest{OrganizationID: string(created.OrganizationID), CommandID: enterpriseCommand(t),
		Issuer: provider.server.URL, StaticMetadata: metadata, Mapping: mapping, Domains: []string{profile.Domain}, IdempotencyKey: enterpriseKey(t, "enterprise-register")})
	if err != nil || registered.Provider.ID == "" || registered.Provider.Version != 1 || registered.Provider.Enabled {
		t.Fatal("native provider registration did not commit disabled version", err)
	}
	providerID := registered.Provider.ID
	setup, err = setup.ForOrganization(string(created.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	policy := referenceEnterpriseOIDCPolicy{}
	credentials, err := ssopg.NewProviderCredentialsService(setup, ssopg.ProviderCredentialsConfig{Authorization: policy, IngressKeyID: login.KeyReference, MaximumReferenceLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	binding := sso.CredentialReferenceContext{TenantID: otpTenant, OrganizationID: string(created.OrganizationID), ProviderID: providerID, Protocol: "oidc", Purpose: "client-secret",
		Generation: 1, ProviderVersion: 1, Audience: "identity.sso.provider.credentials-rotate", EnvelopeKeyID: login.KeyReference, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: provider.secret, KeyReference: login.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	credential, err := sso.NewEncryptedCredentialReference(ctx, crypto, wire, binding)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := credentials.ProviderCredentialsRotate(ctx, sso.ProviderCredentialsRotateRequest{CommandID: enterpriseCommand(t), ProviderID: providerID,
		ExpectedVersion: 1, CredentialReference: credential, OverlapPolicy: sso.NewNoCredentialOverlapPolicy()})
	if err != nil || rotated.Version != 2 {
		t.Fatal("native provider credential installation did not commit", err)
	}
	setup, err = setup.WithProviderEnableAuthorization(policy)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := setup.ObserveProviderCredentialCheckpoint(ctx, providerID, 2)
	if err != nil {
		t.Fatal("native installed credential not observable", err)
	}
	domain := organization.DomainProof{TenantID: otpTenant, OrganizationID: created.OrganizationID, ClaimID: "reference-enterprise-domain", Domain: profile.Domain,
		ClaimVersion: 1, ProofVersion: 1, Method: organization.DomainDNS, ObservedAt: now, ExpiresAt: now.Add(15 * time.Minute)}
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO organization.domain_claims(tenant_id,organization_id,claim_id,canonical_domain,state,version) VALUES($1,$2,$3,$4,'requested',1)`, otpTenant, string(domain.OrganizationID), string(domain.ClaimID), domain.Domain)
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO organization.domain_evidence(tenant_id,organization_id,claim_id,canonical_domain,claim_version,proof_version,method,observed_at,expires_at,revoked,command_id)
VALUES($1,$2,$3,$4,1,1,'dns-txt',$5,$6,false,$7)`, otpTenant, string(domain.OrganizationID), string(domain.ClaimID), domain.Domain, domain.ObservedAt, domain.ExpiresAt, string(enterpriseCommand(t)))
	enabled, err := setup.ProviderEnable(ctx, sso.ProviderEnableRequest{ProviderID: providerID, ExpectedVersion: 2,
		DomainProofCheckpoint: sso.DomainProofCheckpoint{Key: organization.DomainProofKey(domain), ProofVersion: domain.ProofVersion}, CredentialCheckpoint: checkpoint,
		IdempotencyKey: enterpriseKey(t, "enterprise-enable")})
	if err != nil || !enabled.Provider.Enabled || enabled.Provider.Version != 3 {
		t.Fatal("native provider enable did not commit from current proof", err)
	}
	selected := enterpriseProvisioned{user: user, organization: created.OrganizationID, provider: sso.ProviderID(providerID), bearer: bearer}
	seedEnterpriseLink(t, ctx, pool, selected, provider.server.URL)
	return selected
}

func seedEnterpriseAdministrator(t *testing.T, ctx context.Context, pool *database.Pool, c reference.StoreConfiguration) (identity.UserID, auth.BearerCredential) {
	t.Helper()
	value, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	user := identity.UserID(value)
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, otpTenant, string(user))
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'enterprise-fixture-password',1,'identity/password',1,true)`, otpTenant, string(user))
	profile := c.PasswordSignin.Native.Profile
	policy := authority.AuthorityScope{TenantID: authorization.TenantID(otpTenant), PolicyNamespace: profile.PolicyNamespace, SubjectID: authorization.SubjectID(user)}
	if _, err := authority.InitializeAuthority(ctx, pool.Raw(), policy, time.Second); err != nil {
		t.Fatal("initialize pre-existing human authorization", err)
	}
	policyKey, err := policy.Key()
	if err != nil {
		t.Fatal(err)
	}
	directoryKeys, err := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: otpTenant}, user)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID, familyID = "enterprise-fixture-admin", "enterprise-fixture-admin-family"
	keys, err := sessionpg.SessionAuthorityKeys(otpTenant, user, familyID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	bind := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	vectorSpec := session.AuthoritySnapshotSpec{Global: bind(directoryKeys.Global), Tenant: bind(directoryKeys.Tenant), User: bind(directoryKeys.User), Identifier: bind(directoryKeys.Identifier),
		Credential: bind(directoryKeys.Credential), SessionFamily: bind(keys.Family), Session: bind(keys.Session), Authorization: bind(policyKey)}
	vector, err := session.NewAuthoritySnapshot(vectorSpec)
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, c.HTTPPreAuth.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(c.Session.Native.Validation.LookupKeys[0], otpTenant)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	metadata := session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: otpTenant, Subject: string(user),
		Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: profile.Audience, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)},
		ProofVersion: 1, CredentialID: "enterprise-fixture-password", CredentialVersion: 1}
	if _, err := session.NewSession(session.SessionSpec{SessionID: sessionID, FamilyID: familyID, TenantID: otpTenant, UserID: user, Audience: profile.Audience,
		Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: digest, Authentication: metadata, IssuedAt: now, LastActivityAt: now}); err != nil {
		t.Fatal("invalid synthetic existing administrator session", err)
	}
	lifetime, _ := remember.Bindings()
	wire, err := json.Marshal(map[string]any{"Schema": 1, "SessionID": sessionID, "FamilyID": familyID, "TenantID": otpTenant, "UserID": user, "Audience": profile.Audience,
		"Version": 1, "FamilyVersion": 1, "Remember": lifetime, "Authority": vectorSpec, "Lookup": digest, "Authentication": metadata, "IssuedAt": now, "LastActivityAt": now})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	// The retained Reference fixture explicitly selects `session_store`.
	const instant = "2006-01-02T15:04:05.000000000Z"
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, otpTenant, familyID, string(user), now.Format(instant))
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record)
VALUES($1,$2,$3,$4,1,1,'active',$5,$6,$7,$8)`, otpTenant, sessionID, string(user), familyID, int64(digest.KeyVersion), digest.Sum[:], now.Add(lifetime.IdleTTL).Format(instant), wire)
	plain, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	return user, auth.NewBearerCredential(plain)
}

func seedEnterpriseLink(t *testing.T, ctx context.Context, pool *database.Pool, selected enterpriseProvisioned, issuer string) {
	t.Helper()
	provider, err := ssopg.SSOOIDCAccountProviderNamespace(selected.organization, selected.provider)
	if err != nil {
		t.Fatal(err)
	}
	user := string(selected.user)
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'enterprise-fixture-provider',3,'sso',1,true)`, otpTenant, user)
	execEnterpriseFixture(t, ctx, pool, `WITH a AS (SELECT $3::text AS provider,$4::text AS issuer,$5::text AS subject)
INSERT INTO identity.accounts(tenant_id,user_id,account_id,provider,issuer,subject,subject_key,version,social_link_version,linked)
SELECT $1,$2,'enterprise-fixture-link',provider,issuer,subject,
sha256(convert_to(octet_length(provider)::text||':'||provider||octet_length(issuer)::text||':'||issuer||octet_length(subject)::text||':'||subject,'UTF8')),1,1,true FROM a`, otpTenant, user, provider, issuer, enterpriseProviderSubject)
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO identity.account_credentials(tenant_id,user_id,credential_id,account_id) VALUES($1,$2,'enterprise-fixture-provider','enterprise-fixture-link')`, otpTenant, user)
	command, err := base64.RawURLEncoding.DecodeString(string(enterpriseCommand(t)))
	if err != nil {
		t.Fatal(err)
	}
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.password.signup',$3,1,$4)`, command, otpTenant, bytes.Repeat([]byte{0xA5}, 32), []byte{1})
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.password.signup')`, command, otpTenant)
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,$2,1,0,$3,'identity.password.signup')`, otpTenant, user, command)
}

func execEnterpriseFixture(t *testing.T, ctx context.Context, pool *database.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Raw().Exec(ctx, sql, args...); err != nil {
		t.Fatal("prepare retained enterprise fixture", err)
	}
}

func enterpriseCommand(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func enterpriseKey(t *testing.T, value string) identity.IdempotencyKey {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func enterpriseLookupVersion(t *testing.T, key session.DigestKey) uint32 {
	t.Helper()
	probe, err := session.ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := probe.Digest(key, otpTenant)
	if err != nil {
		t.Fatal(err)
	}
	return digest.KeyVersion
}
