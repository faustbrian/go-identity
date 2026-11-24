//go:build integration

package reference_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	ssopg "github.com/faustbrian/go-sso/postgres"
	"github.com/faustbrian/go-sso/saml"
)

func TestReferencePostgresEnterpriseSAMLJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, organization: true, enterpriseSAML: true})
}

func TestReferencePostgresEnterpriseSAMLSPLogoutJourney(t *testing.T) {
	for _, profile := range []string{"local-only", "redirect"} {
		t.Run(profile, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
				postgresBaseline: true, organization: true, enterpriseSAML: true, enterpriseSAMLSPLogout: profile,
			})
		})
	}
}

func configureReferenceEnterpriseSAML(t *testing.T, c *reference.StoreConfiguration, origin string) referenceSAMLIdPFixture {
	t.Helper()
	previous, err := c.Session.Native.Cookie.DeletionAttributes()
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: previous.Name, SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c.Session.Native.Cookie, c.OTP.Signin.Issuer.Cookie, c.PasswordSignin.Native.Issuance.Cookie = cookie, cookie, cookie
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	signal, err := session.NewDigestKey(13, bytes.Repeat([]byte{0x73}, 32))
	if err != nil {
		t.Fatal(err)
	}
	issuer := c.PasswordSignin.Native.Issuance
	issuer.Clock = nil
	grant := c.PasswordSignup.Issuer
	grant.Audience = "reference-enterprise"
	requestKeys, err := kernel.NewRequestKeyConfig("reference-enterprise-saml-start", [32]byte{0xe6}, c.PasswordSignup.Native.RequestKeys.Policy)
	if err != nil {
		t.Fatal(err)
	}
	success, failure := origin+"/enterprise/complete", origin+"/enterprise/error"
	c.EnterpriseSAML = &reference.EnterpriseSAMLConfiguration{
		Routing: ssopg.ProviderRouterConfig{MaximumDuration: time.Second, Lifetime: 8 * time.Second, PolicyVersion: 9, MaximumProviders: 4},
		Login: ssopg.ProviderLoginConfig{TenantID: otpTenant, ActorID: c.PasswordSignup.PreAuth.ActorID, PolicyID: "reference-enterprise", Origin: origin,
			ConfigurationID: "reference-enterprise-saml-v1", CallbackAllowlist: []string{success, failure},
			FlowKeys: c.PasswordSignin.Native.FlowKeys, Coordinator: c.PasswordSignup.Native.Coordinator, RequestKeys: requestKeys,
			Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "reference-enterprise-saml-risk"}, Capability: grant, CapabilityPreparation: c.PasswordSignup.Preparation,
			KeyReference: "issue-envelope", StateKeys: map[uint32][32]byte{1: {0xe5}}, CurrentStateKey: 1, StateLifetime: 5 * time.Minute},
		Profile: ssopg.StaticSAMLLoginProfile{OrganizationID: "EnterpriseOrganization", ProviderID: "Enterprise_SAML-01", Domain: "enterprise.example",
			TrustedOrigin: origin, ProviderVersion: 3, CredentialGeneration: 1, MappingVersion: 1},
		Completion: ssopg.ProviderSAMLLoginCompletionConfig{Audience: c.Session.Native.Validation.Audience, PolicyNamespace: c.PasswordSignin.Native.Profile.PolicyNamespace,
			Issuer: issuer, CSRFKey: c.PasswordSignin.Native.CSRFKey},
	}
	c.HTTPEnterpriseSAML = &reference.HTTPEnterpriseSAMLConfiguration{FlowSignalKey: signal, IdentityProviderOrigin: identityhttp.Origin("https://idp.example"),
		AuthorizationEndpoint: "https://idp.example/login", SuccessCallback: success, ErrorCallback: failure, CSRFCookie: csrf, Lifetime: c.HTTPPreAuth.Lifetime, Metadata: true}
	return newReferenceSAMLIdPFixture(t, time.Now().UTC())
}

func proveReferenceEnterpriseSAMLJourney(t *testing.T, ctx context.Context, base *http.Client, origin string, features reference.FeatureSet, deps reference.ReferenceDependencies,
	policy *reference.HTTPEnterpriseSAMLConfiguration, selected enterpriseProvisioned, idp referenceSAMLIdPFixture, logoutStart *reference.EnterpriseSAMLLogoutStartConfiguration) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *base
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	providerPath := "/saml2/" + string(selected.provider)
	startPath, acsPath := providerPath+"/login", providerPath+"/acs"
	do := func(method, path string, body io.Reader, decorate func(*http.Request)) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, origin+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if decorate != nil {
			decorate(request)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("SAML Reference HTTPS request failed", err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	metadataPath := providerPath + "/metadata"
	publicMetadata := do(http.MethodGet, metadataPath, nil, nil)
	var selectedSLO string
	if policy.Logout {
		selectedSLO = origin + providerPath + "/slo"
	}
	certificate := referenceSAMLMetadataCertificate(t, publicMetadata, origin+metadataPath, origin+acsPath, selectedSLO, idp.certificateDER)
	start := do(http.MethodGet, startPath, nil, func(r *http.Request) {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
	})
	location := start.Header.Get("Location")
	if start.StatusCode != http.StatusSeeOther || !strings.HasPrefix(location, policy.AuthorizationEndpoint+"?") {
		var flow, mapping, login int
		checkErr := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE purpose='identity.session.preauth-issue'),
 (SELECT count(*) FROM identity.request_key_mappings WHERE route_id='identity.sso.saml-start'),
 (SELECT count(*) FROM sso_providers.login_transactions WHERE protocol='saml')`).Scan(&flow, &mapping, &login)
		t.Fatalf("SAML start did not disclose the installed signed Redirect: status %d, durable flow/mapping/login %d/%d/%d, diagnostic %v", start.StatusCode, flow, mapping, login, checkErr)
	}
	cookies := start.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Secure-identity_frontchannel" || cookies[0].Path != acsPath ||
		cookies[0].SameSite != http.SameSiteNoneMode || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].MaxAge > 300 {
		t.Fatal("SAML start did not set the dedicated exact-path correlation cookie")
	}
	correlation := cookies[0]
	requestID, spEntity, relay := originalReferenceSAMLRequest(t, location, origin+acsPath)
	if spEntity != origin+metadataPath {
		t.Fatal("AuthnRequest issuer differs from the published metadata entity")
	}
	verifyReferenceSAMLRedirectSignature(t, certificate, location)
	encoded := idp.signedPOSTResponse(t, referenceSAMLResponseInput{RequestID: requestID, Issuer: referenceSAMLIdPEntity, Audience: spEntity, ACS: origin + acsPath,
		NameID: enterpriseProviderSubject, ResponseID: "_reference_response", AssertionID: "_reference_assertion", Now: time.Now().UTC()})
	form := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}.Encode()
	acs := func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", string(policy.IdentityProviderOrigin))
	}
	foreign := do(http.MethodPost, acsPath, strings.NewReader(form), func(r *http.Request) {
		acs(r)
		r.Header.Set("Origin", "https://unconfigured.example")
	})
	if foreign.StatusCode != http.StatusForbidden || foreign.Header.Get("Location") != "" || len(foreign.Cookies()) != 0 {
		t.Fatal("a foreign origin reached the signed callback", foreign.StatusCode)
	}
	callback := do(http.MethodPost, acsPath, strings.NewReader(form), acs)
	if callback.StatusCode != http.StatusSeeOther || callback.Header.Get("Location") != policy.SuccessCallback || callback.Header.Get("Access-Control-Allow-Origin") != "" || len(callback.Cookies()) != 3 {
		t.Fatal("signed POST did not deliver one Reference browser session", callback.StatusCode)
	}
	var credential *http.Cookie
	var csrf string
	for _, cookie := range callback.Cookies() {
		if cookie.Name == correlation.Name {
			if cookie.Path != acsPath || cookie.MaxAge >= 0 {
				t.Fatal("ACS did not delete the original correlation cookie")
			}
			continue
		}
		if !cookie.Secure || cookie.Path != "/" || cookie.SameSite != http.SameSiteLaxMode || cookie.Value == "" {
			t.Fatal("ACS relaxed the normal session/CSRF cookie policy")
		}
		if cookie.HttpOnly {
			credential = cookie
		} else if cookie.Name == "__Host-identity_csrf" {
			csrf = cookie.Value
		}
	}
	if credential == nil || csrf == "" {
		t.Fatal("signed POST omitted separate session/CSRF credentials")
	}
	read := func(want bool) sessionhttp.GetResponse {
		t.Helper()
		r := do(http.MethodGet, "/v1/session/get", nil, nil)
		defer r.Body.Close()
		var result sessionhttp.GetResponse
		if r.StatusCode != http.StatusOK || json.NewDecoder(r.Body).Decode(&result) != nil || result.Authenticated != want {
			t.Fatal("common session route did not report expected SAML session state", r.StatusCode)
		}
		if want && (result.Session == nil || result.Principal == nil || result.Principal.UserID != selected.user || result.Principal.TenantID != otpTenant) {
			t.Fatal("SAML did not authenticate the exact linked tenant user")
		}
		return result
	}
	public := read(true)
	checkReferenceEnterpriseOrganization(t, ctx, features, credential.Value, public.Session.ID, "sso-saml", selected)
	appURL, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(appURL, []*http.Cookie{correlation})
	replay := do(http.MethodPost, acsPath, strings.NewReader(form), acs)
	if replay.StatusCode != http.StatusForbidden || replay.Header.Get("Location") != "" || len(replay.Cookies()) != 0 {
		t.Fatal("the original assertion could be delivered again", replay.StatusCode)
	}
	if policy.LogoutStart {
		proveReferenceSAMLSPLogout(t, ctx, base, origin, providerPath, string(policy.IdentityProviderOrigin), logoutStart.RedirectEndpoint,
			logoutStart.FinalRedirectAllowlist[0], csrf, &client, certificate, idp)
		return
	}
	signout := func(token string) *http.Response {
		return do(http.MethodPost, "/v1/session/signout", strings.NewReader(`{}`), func(r *http.Request) {
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-CSRF-Token", token)
		})
	}
	if wrong := signout("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); wrong.StatusCode != http.StatusForbidden || len(wrong.Cookies()) != 0 {
		t.Fatal("incorrect synchronizer modified the SAML session", wrong.StatusCode)
	}
	read(true)
	logout := signout(csrf)
	if logout.StatusCode != http.StatusOK || len(logout.Cookies()) != 2 {
		t.Fatal("strict SAML logout did not clear the normal cookies", logout.StatusCode)
	}
	for _, removed := range logout.Cookies() {
		if removed.MaxAge >= 0 || removed.Name != credential.Name && removed.Name != "__Host-identity_csrf" {
			t.Fatal("strict logout did not delete both delivered cookies")
		}
	}
	jar.SetCookies(appURL, []*http.Cookie{credential})
	read(false)
}

func referenceSAMLMetadataCertificate(t *testing.T, response *http.Response, entity, acs, slo string, idpDER []byte) *rsa.PublicKey {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/samlmetadata+xml" ||
		response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 {
		t.Fatal("signed profile did not expose uncached, cookie-free SP metadata", response.StatusCode)
	}
	var document struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
		Entity  string   `xml:"entityID,attr"`
		SP      []struct {
			SignsRequests  bool `xml:"AuthnRequestsSigned,attr"`
			WantsSignature bool `xml:"WantAssertionsSigned,attr"`
			Keys           []struct {
				Use string `xml:"use,attr"`
				DER string `xml:"KeyInfo>X509Data>X509Certificate"`
			} `xml:"KeyDescriptor"`
			ACS []struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
				Index    string `xml:"index,attr"`
				Default  bool   `xml:"isDefault,attr"`
			} `xml:"AssertionConsumerService"`
			Logout []struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
			} `xml:"SingleLogoutService"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	}
	if err := xml.NewDecoder(io.LimitReader(response.Body, 96<<10)).Decode(&document); err != nil || document.Entity != entity || len(document.SP) != 1 {
		t.Fatal("invalid or foreign SP metadata", err)
	}
	p := document.SP[0]
	if !p.SignsRequests || !p.WantsSignature || len(p.Keys) != 1 || p.Keys[0].Use != "signing" || len(p.ACS) != 1 {
		t.Fatal("SP metadata advertised the wrong signed profile")
	}
	if slo == "" && len(p.Logout) != 0 || slo != "" && (len(p.Logout) != 1 ||
		p.Logout[0].Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" || p.Logout[0].Location != slo) {
		t.Fatal("SP metadata advertised the wrong logout binding")
	}
	endpoint := p.ACS[0]
	if endpoint.Binding != "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" || endpoint.Location != acs || endpoint.Index != "0" || !endpoint.Default {
		t.Fatal("SP metadata did not advertise the exact default ACS")
	}
	der, err := base64.StdEncoding.DecodeString(p.Keys[0].DER)
	if err != nil || bytes.Equal(der, idpDER) {
		t.Fatal("SP metadata exposed missing or foreign signing material")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("invalid published SP certificate", err)
	}
	key, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("published certificate does not match the selected RSA profile")
	}
	return key
}

func verifyReferenceSAMLRedirectSignature(t *testing.T, key *rsa.PublicKey, location string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal("invalid signed redirect", err)
	}
	signed, _, hasSignature := strings.Cut(u.RawQuery, "&Signature=")
	signature, err := base64.StdEncoding.DecodeString(u.Query().Get("Signature"))
	if !hasSignature || err != nil {
		t.Fatal("the actual redirect omitted its signed binding", err)
	}
	digest := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}); err != nil {
		t.Fatal("published SP certificate cannot verify the actual AuthnRequest", err)
	}
}

func originalReferenceSAMLRequest(t *testing.T, location, acs string) (requestID, issuer, relay string) {
	t.Helper()
	redirect, err := url.Parse(location)
	if err != nil {
		t.Fatal("invalid IdP Redirect")
	}
	query := redirect.Query()
	compressed, err := base64.StdEncoding.DecodeString(query.Get("SAMLRequest"))
	if err != nil || len(query.Get("RelayState")) != 43 || query.Get("SigAlg") != saml.SignatureAlgorithmRSAPSSSHA256 || query.Get("Signature") == "" {
		t.Fatal("missing signed SAML binding fields")
	}
	inflated := flate.NewReader(bytes.NewReader(compressed))
	defer inflated.Close()
	var request struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		ID      string   `xml:"ID,attr"`
		ACS     string   `xml:"AssertionConsumerServiceURL,attr"`
		Issuer  string   `xml:"Issuer"`
	}
	if err := xml.NewDecoder(io.LimitReader(inflated, 16<<10)).Decode(&request); err != nil || request.ID == "" || request.ACS != acs || request.Issuer == "" {
		t.Fatal("AuthnRequest did not bind the selected SP and original ACS", err)
	}
	return request.ID, request.Issuer, query.Get("RelayState")
}

func TestReferenceSAMLIdPFixtureProducesTheOriginalSignedResponse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	idp := newReferenceSAMLIdPFixture(t, now)
	const spEntity = "https://identity.example/saml2"
	const acs = "https://identity.example/saml2/installed/acs"
	const issuer = "urn:example:reference-saml-idp"
	const requestID = "_original_request"
	const subject = "reference-linked-subject"
	p, err := saml.NewPOSTResponseProfile(saml.POSTResponseConfig{SPEntityID: spEntity, AssertionConsumerURL: acs,
		IdentityProviderEntityID: issuer, SigningCertificates: [][]byte{idp.certificateDER}})
	if err != nil {
		t.Fatal("compose real SAML verifier", err)
	}
	encoded := idp.signedPOSTResponse(t, referenceSAMLResponseInput{RequestID: requestID, Issuer: issuer, Audience: spEntity, ACS: acs,
		NameID: subject, ResponseID: "_response", AssertionID: "_assertion", Now: now})
	verified, err := p.Validate(t.Context(), saml.POSTResponseInput{SAMLResponse: encoded, RequestID: requestID, IssuedAt: now.Add(-time.Second),
		ExpiresAt: now.Add(5 * time.Minute), Now: now})
	if err != nil {
		t.Fatal("real pinned verifier denied the independently signed fixture", err)
	}
	evidence, err := verified.Evidence()
	if err != nil || evidence.ProviderSubject != subject || evidence.ResponseID != "_response" || evidence.AssertionID != "_assertion" ||
		!evidence.AssertionExpiresAt.Equal(now.Add(4*time.Minute)) || !evidence.ValidUntil.Equal(now.Add(3*time.Minute)) {
		t.Fatal("verified evidence changed original replay identity or validity", err)
	}
}
