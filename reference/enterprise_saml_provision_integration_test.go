//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

const referenceSAMLIdPEntity = "urn:example:reference-saml-idp"

// Provisioning uses the native organization/provider owners and the released
// go-sso/postgres SAML registration, signing-custody and activation contracts.
func provisionReferenceEnterpriseSAML(t *testing.T, ctx context.Context, c reference.StoreConfiguration, deps reference.ReferenceDependencies, browser *http.Client, origin string, idp referenceSAMLIdPFixture, replacement ...referenceSAMLIdPFixture) enterpriseProvisioned {
	t.Helper()
	if len(replacement) > 1 {
		t.Fatal("SAML provisioning accepts at most one IdP pin replacement")
	}
	pool := deps.PostgreSQL
	user, bearer := seedEnterpriseAdministrator(t, ctx, pool, c)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/v1/organization/create", bytes.NewBufferString(`{"name":"Enterprise SAML test","slug":"enterprise-saml-fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+bearer.Token())
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "enterprise-saml-create-organization")
	response, err := browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var created organizationhttp.MutationResponse
	err = json.NewDecoder(response.Body).Decode(&created)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !created.Committed || created.OrganizationID == "" {
		t.Fatal("native SAML organization creation did not commit", response.StatusCode, err)
	}

	login := c.EnterpriseSAML.Login
	providerDomain := c.EnterpriseSAML.Profile.Domain
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
	execution := c.Session.Native.Execution
	setup, err := ssopg.NewProviderService(pool, ssopg.ProviderServiceConfig{Clock: execution.Clock, MaximumDuration: 4 * time.Second,
		Sessions: sessions, Session: execution.Repository, Profile: c.PasswordSignin.Native.Profile, LookupKeys: map[uint32]session.DigestKey{
			enterpriseLookupVersion(t, validation.LookupKeys[0]): validation.LookupKeys[0],
		}, Organizations: organizations, Authorization: execution.Authorization, PolicyID: login.PolicyID, PolicyVersion: execution.PolicyVersion,
		Counters: counters, RequestKeys: c.PasswordSignup.Native.RequestKeys, Coordinator: login.Coordinator, Envelope: crypto, KeyReference: login.KeyReference,
	}, organization.Authentication{TenantID: otpTenant, Bearer: bearer}, "127.0.0.1")
	if err != nil {
		t.Fatal("compose native SAML provider setup", err)
	}
	setup, err = setup.WithSAMLRegistration(origin, saml.ValidateRegistration)
	if err != nil {
		t.Fatal("select native SAML registration", err)
	}
	// The controlled IdP fixture supplies the exact document and independently
	// approved binding that the operator would configure for real imports.
	document, approvedSHA256 := referenceSAMLApprovedIDPMetadata(idp.certificateDER)
	imported, err := saml.ImportIDPMetadata(ctx, document, referenceSAMLIdPEntity, approvedSHA256, execution.Clock.Now())
	if err != nil || imported.RedirectEndpoint != c.HTTPEnterpriseSAML.AuthorizationEndpoint {
		t.Fatal("approved IdP metadata did not select the installed SAML Redirect binding", err)
	}
	configuration, err := sso.NewSAMLConfiguration(sso.SAMLConfigurationSpec{
		EntityID: imported.EntityID, RedirectEndpoint: imported.RedirectEndpoint, SigningCertificates: imported.SigningCertificates,
	})
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := sso.NewAttributeMapping(sso.AttributeMappingSpec{Version: 1, SubjectClaim: "name_id"})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := setup.ProviderRegisterSaml(ctx, sso.ProviderRegisterSamlRequest{
		OrganizationID: string(created.OrganizationID), CommandID: enterpriseCommand(t), Configuration: configuration,
		Mapping: mapping, Domains: []string{providerDomain}, IdempotencyKey: enterpriseKey(t, "enterprise-saml-register"),
	})
	if err != nil || registered.Completion.Outcome != identity.CommitOutcomeCommitted || registered.Provider.ID == "" || registered.Provider.Protocol != "saml" || registered.Provider.Version != 1 || registered.Provider.Enabled {
		t.Fatal("native SAML registration did not commit disabled version", err)
	}
	providerID := registered.Provider.ID
	setup, err = setup.WithSAMLSigningCredentialValidator(saml.ValidateSPSigningCredential)
	if err != nil {
		t.Fatal("select native SP signing validation", err)
	}
	setup, err = setup.ForOrganization(string(created.OrganizationID))
	if err != nil {
		t.Fatal(err)
	}
	policy := referenceEnterpriseOIDCPolicy{allowSAML: true}
	credentials, err := ssopg.NewProviderCredentialsService(setup, ssopg.ProviderCredentialsConfig{
		Authorization: policy, IngressKeyID: login.KeyReference, MaximumReferenceLifetime: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := execution.Clock.Now().UTC().Truncate(time.Microsecond)
	bundle := referenceSAMLSPCredential(t, ctx, now)
	defer clear(bundle)
	binding := sso.CredentialReferenceContext{
		TenantID: otpTenant, OrganizationID: string(created.OrganizationID), ProviderID: providerID,
		Protocol: "saml", Purpose: "sp-signing-key", Generation: 1, ProviderVersion: 1,
		Audience: "identity.sso.provider.credentials-rotate", EnvelopeKeyID: login.KeyReference,
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: bundle, KeyReference: login.KeyReference, Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	clear(bundle)
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	credential, err := sso.NewEncryptedCredentialReference(ctx, crypto, wire, binding)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := credentials.ProviderCredentialsRotate(ctx, sso.ProviderCredentialsRotateRequest{
		CommandID: enterpriseCommand(t), ProviderID: providerID, ExpectedVersion: 1,
		CredentialReference: credential, OverlapPolicy: sso.NewNoCredentialOverlapPolicy(),
	})
	if err != nil || rotated.Completion.Outcome != identity.CommitOutcomeCommitted || rotated.Version != 2 || !rotated.Active {
		t.Fatal("native SP signing installation did not commit", err)
	}
	providerVersion := rotated.Version
	if len(replacement) == 1 {
		providerVersion = rotateReferenceSAMLIDPPins(t, ctx, credentials, crypto, binding, replacement[0])
	}
	setup, err = setup.WithProviderEnableAuthorization(policy)
	if err != nil {
		t.Fatal(err)
	}
	setup, err = setup.WithProviderDisableAuthorization(policy)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := setup.ObserveSAMLProviderCredentialCheckpoint(ctx, providerID, providerVersion)
	if err != nil || checkpoint.Protocol() != "saml" {
		t.Fatal("native SAML signing credential not observable", err)
	}
	checkpointBinding, err := checkpoint.Bindings()
	if err != nil || checkpointBinding.ProviderID != providerID || checkpointBinding.ProviderVersion != providerVersion || checkpointBinding.Generation != 1 {
		t.Fatal("native SAML checkpoint lost the installed signer generation", err)
	}
	domain := organization.DomainProof{
		TenantID: otpTenant, OrganizationID: created.OrganizationID, ClaimID: "reference-enterprise-saml-domain", Domain: providerDomain,
		ClaimVersion: 1, ProofVersion: 1, Method: organization.DomainDNS, ObservedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO organization.domain_claims(tenant_id,organization_id,claim_id,canonical_domain,state,version) VALUES($1,$2,$3,$4,'requested',1)`,
		otpTenant, string(domain.OrganizationID), string(domain.ClaimID), domain.Domain)
	execEnterpriseFixture(t, ctx, pool, `INSERT INTO organization.domain_evidence(tenant_id,organization_id,claim_id,canonical_domain,claim_version,proof_version,method,observed_at,expires_at,revoked,command_id)
VALUES($1,$2,$3,$4,1,1,'dns-txt',$5,$6,false,$7)`, otpTenant, string(domain.OrganizationID), string(domain.ClaimID), domain.Domain, domain.ObservedAt, domain.ExpiresAt, string(enterpriseCommand(t)))
	enabled, err := setup.ProviderEnable(ctx, sso.ProviderEnableRequest{
		ProviderID: providerID, ExpectedVersion: providerVersion, CredentialCheckpoint: checkpoint,
		DomainProofCheckpoint: sso.DomainProofCheckpoint{Key: organization.DomainProofKey(domain), ProofVersion: domain.ProofVersion},
		IdempotencyKey:        enterpriseKey(t, "enterprise-saml-enable"),
	})
	if err != nil || enabled.Completion.Outcome != identity.CommitOutcomeCommitted || !enabled.Provider.Enabled || enabled.Provider.Version != providerVersion+1 || enabled.Provider.Protocol != "saml" {
		t.Fatal("native SAML enable did not commit from current domain and signer proof", err)
	}
	selected := enterpriseProvisioned{user: user, organization: created.OrganizationID, provider: sso.ProviderID(providerID), bearer: bearer}
	seedReferenceSAMLLink(t, ctx, pool, selected, referenceSAMLIdPEntity)
	return selected
}

func referenceSAMLApprovedIDPMetadata(certificate []byte) ([]byte, [32]byte) {
	document := []byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="` + referenceSAMLIdPEntity + `">
<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(certificate) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/login"/>
</md:IDPSSODescriptor></md:EntityDescriptor>`)
	return document, sha256.Sum256(document)
}

func referenceSAMLSPCredential(t *testing.T, ctx context.Context, now time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("generate ephemeral SP signing key:", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode ephemeral SP signing key:", err)
	}
	defer clear(privateDER)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create ephemeral SP signing certificate:", err)
	}
	bundle, err := saml.EncodeSPSigningCredential(ctx, privateDER, certificate, now)
	if err != nil {
		t.Fatal("encode native SP signing credential:", err)
	}
	return bundle
}
