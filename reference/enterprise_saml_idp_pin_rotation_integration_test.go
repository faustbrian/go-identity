//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-sso"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func TestReferencePostgresEnterpriseSAMLIDPPinRotationJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, enterpriseSAML: true, enterpriseSAMLIDPPins: true,
	})
}

func rotateReferenceSAMLIDPPins(t *testing.T, ctx context.Context, credentials *ssopg.ProviderCredentialsService,
	crypto *envelope.Service, binding sso.CredentialReferenceContext, replacement referenceSAMLIdPFixture) uint64 {
	t.Helper()
	bundle, err := sso.EncodeSAMLIDPSigningCertificates([][]byte{replacement.certificateDER})
	if err != nil {
		t.Fatal("encode replacement IdP signing pin", err)
	}
	defer clear(bundle)
	binding.Purpose = sso.SAMLIDPSigningCertificatesPurpose
	binding.ProviderVersion, binding.Generation = 2, 3
	aad, err := binding.EncryptionContext()
	if err != nil {
		t.Fatal("bind replacement IdP pin to the disabled provider successor", err)
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: bundle, KeyReference: binding.EnvelopeKeyID, Context: aad})
	if err != nil {
		t.Fatal("seal replacement IdP signing pin", err)
	}
	clear(bundle)
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	credential, err := sso.NewEncryptedCredentialReference(ctx, crypto, wire, binding)
	if err != nil {
		t.Fatal("authenticate replacement IdP signing pin", err)
	}
	rotated, err := credentials.ProviderCredentialsRotate(ctx, sso.ProviderCredentialsRotateRequest{
		CommandID: enterpriseCommand(t), ProviderID: binding.ProviderID, ExpectedVersion: binding.ProviderVersion,
		CredentialReference: credential, OverlapPolicy: sso.NewNoCredentialOverlapPolicy(),
	})
	if err != nil || rotated.Completion.Outcome != identity.CommitOutcomeCommitted || rotated.ProviderID != binding.ProviderID ||
		rotated.Version != 3 || !rotated.Active || rotated.ReconciliationRequired {
		t.Fatal("replace only the disabled installed provider's IdP pins", err)
	}
	return rotated.Version
}

func proveReferenceEnterpriseSAMLIDPPinRotation(t *testing.T, ctx context.Context, base *http.Client, origin string,
	features reference.FeatureSet, deps reference.ReferenceDependencies, policy *reference.HTTPEnterpriseSAMLConfiguration,
	selected enterpriseProvisioned, retired, replacement referenceSAMLIdPFixture) {
	t.Helper()
	providerPath := "/saml2/" + string(selected.provider)
	acsPath, metadataPath := providerPath+"/acs", providerPath+"/metadata"
	appURL, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	request := func(client *http.Client, method, path string, body io.Reader) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, origin+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", string(policy.IdentityProviderOrigin))
		} else if path == providerPath+"/login" {
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("IdP pin replacement HTTPS request failed", err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	type issuanceCounts struct{ sessions, issuances int }
	counts := func() issuanceCounts {
		t.Helper()
		var result issuanceCounts
		err := deps.PostgreSQL.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM session_store.sessions WHERE tenant_id=$1::text),
 (SELECT count(*) FROM session_store.session_issuances WHERE tenant_id=$1::text)`, otpTenant).
			Scan(&result.sessions, &result.issuances)
		if err != nil {
			t.Fatal("read exact fixture session issuance counts", err)
		}
		return result
	}
	readSession := func(client *http.Client, authenticated bool) sessionhttp.GetResponse {
		t.Helper()
		response := request(client, http.MethodGet, "/v1/session/get", nil)
		defer response.Body.Close()
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil || result.Authenticated != authenticated {
			t.Fatal("rotated IdP pin did not preserve the expected browser session state", response.StatusCode)
		}
		if authenticated && (result.Session == nil || result.Principal == nil || result.Principal.UserID != selected.user || result.Principal.TenantID != otpTenant) {
			t.Fatal("replacement IdP signer did not authenticate the exact linked tenant user")
		}
		return result
	}
	metadata := request(base, http.MethodGet, metadataPath, nil)
	spCertificate := referenceSAMLMetadataCertificate(t, metadata, origin+metadataPath, origin+acsPath, "", replacement.certificateDER)
	var retiredRequestID string
	for _, signer := range []struct {
		name     string
		fixture  referenceSAMLIdPFixture
		accepted bool
	}{{"retired", retired, false}, {"replacement", replacement, true}} {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		client := *base
		client.Jar = jar
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		start := request(&client, http.MethodGet, providerPath+"/login", nil)
		location, cookies := start.Header.Get("Location"), start.Cookies()
		_ = start.Body.Close()
		if start.StatusCode != http.StatusSeeOther || !strings.HasPrefix(location, policy.AuthorizationEndpoint+"?") || len(cookies) != 1 {
			t.Fatal("IdP pin replacement did not issue a separate signed browser start", signer.name, start.StatusCode)
		}
		correlation := cookies[0]
		if correlation.Name != "__Secure-identity_frontchannel" || correlation.Path != acsPath || !correlation.Secure || !correlation.HttpOnly || correlation.SameSite != http.SameSiteNoneMode {
			t.Fatal("IdP pin replacement lost exact browser correlation custody")
		}
		requestID, entity, relay := originalReferenceSAMLRequest(t, location, origin+acsPath)
		if entity != origin+metadataPath {
			t.Fatal("IdP pin replacement changed the installed SP entity")
		}
		if signer.accepted && requestID == retiredRequestID {
			t.Fatal("replacement IdP signer reused the retired signer's browser start")
		}
		if !signer.accepted {
			retiredRequestID = requestID
		}
		verifyReferenceSAMLRedirectSignature(t, spCertificate, location)
		encoded := signer.fixture.signedPOSTResponse(t, referenceSAMLResponseInput{
			RequestID: requestID, Issuer: referenceSAMLIdPEntity, Audience: entity, ACS: origin + acsPath,
			NameID: enterpriseProviderSubject, ResponseID: "_pin_response_" + signer.name, AssertionID: "_pin_assertion_" + signer.name,
			Now: time.Now().UTC(),
		})
		form := url.Values{"SAMLResponse": {encoded}, "RelayState": {relay}}.Encode()
		before := counts()
		callback := request(&client, http.MethodPost, acsPath, strings.NewReader(form))
		_ = callback.Body.Close()
		if !signer.accepted {
			if callback.StatusCode != http.StatusForbidden || callback.Header.Get("Location") != "" || len(callback.Cookies()) != 0 {
				t.Fatal("retired installed IdP signer was not rejected without browser issuance", callback.StatusCode)
			}
			readSession(&client, false)
			if counts() != before {
				t.Fatal("retired IdP signer created a durable session or issuance")
			}
			continue
		}
		if callback.StatusCode != http.StatusSeeOther || callback.Header.Get("Location") != policy.SuccessCallback || len(callback.Cookies()) != 3 {
			t.Fatal("replacement installed IdP signer did not deliver one linked session", callback.StatusCode)
		}
		public := readSession(&client, true)
		var credential *http.Cookie
		for _, cookie := range callback.Cookies() {
			if cookie.Name != correlation.Name && cookie.HttpOnly {
				credential = cookie
			}
		}
		if credential == nil {
			t.Fatal("replacement IdP signer omitted the browser session credential")
		}
		checkReferenceEnterpriseOrganization(t, ctx, features, credential.Value, public.Session.ID, "sso-saml", selected)
		want := issuanceCounts{sessions: before.sessions + 1, issuances: before.issuances + 1}
		if counts() != want {
			t.Fatal("replacement IdP signer did not create exactly one durable session and issuance")
		}
		jar.SetCookies(appURL, []*http.Cookie{correlation})
		replay := request(&client, http.MethodPost, acsPath, strings.NewReader(form))
		_ = replay.Body.Close()
		if replay.StatusCode != http.StatusForbidden || replay.Header.Get("Location") != "" || len(replay.Cookies()) != 0 || counts() != want {
			t.Fatal("replacement IdP assertion replay issued another browser or durable session", replay.StatusCode)
		}
		if readSession(&client, true).Session.ID != public.Session.ID {
			t.Fatal("replacement IdP assertion replay changed the original linked session")
		}
	}
}
