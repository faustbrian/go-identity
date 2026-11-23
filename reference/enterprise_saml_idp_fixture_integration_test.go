//go:build integration

package reference_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xml/v2/xdm"
)

type referenceSAMLIdPFixture struct {
	key            *ecdsa.PrivateKey
	certificateDER []byte
}

func newReferenceSAMLIdPFixture(t *testing.T, now time.Time) referenceSAMLIdPFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate ephemeral IdP signing key:", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal("generate ephemeral IdP certificate serial:", err)
	}
	serial.Add(serial, big.NewInt(1))
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create ephemeral IdP signing certificate:", err)
	}
	return referenceSAMLIdPFixture{key: key, certificateDER: certificate}
}

type referenceSAMLResponseInput struct {
	RequestID, Issuer, Audience, ACS string
	NameID, ResponseID, AssertionID  string
	Now                              time.Time
}

// signedPOSTResponse follows go-sso/saml's released POST response fixture:
// OASIS Core §§2.4.1.2, 2.5.1.2, 3.2.2 and Profiles §4.1.4.3. Signing is
// independent of the SP verifier; no verification or identity policy runs here.
func (f referenceSAMLIdPFixture) signedPOSTResponse(t *testing.T, input referenceSAMLResponseInput) string {
	t.Helper()
	if !xdm.IsNCName(input.RequestID) {
		t.Fatal("SAML fixture requires the original request ID")
	}
	return f.signPOSTResponse(t, input)
}

// Both omissions are part of the signed XML, not edits to a signed message.
func (f referenceSAMLIdPFixture) signedUnsolicitedPOSTResponse(t *testing.T, input referenceSAMLResponseInput) string {
	t.Helper()
	if input.RequestID != "" {
		t.Fatal("unsolicited SAML fixture requires no request ID")
	}
	return f.signPOSTResponse(t, input)
}

func (f referenceSAMLIdPFixture) signPOSTResponse(t *testing.T, input referenceSAMLResponseInput) string {
	t.Helper()
	if f.key == nil || input.Now.IsZero() || input.Issuer == "" || input.Audience == "" || input.NameID == "" {
		t.Fatal("SAML fixture requires a signing key, timestamp, issuer, audience and NameID")
	}
	if !xdm.IsNCName(input.ResponseID) || !xdm.IsNCName(input.AssertionID) || input.ResponseID == input.AssertionID {
		t.Fatal("SAML fixture requires distinct response and assertion IDs")
	}
	acs, err := url.Parse(input.ACS)
	if err != nil || acs.Scheme != "https" || acs.Host == "" {
		t.Fatal("SAML fixture requires an HTTPS assertion consumer URL")
	}

	escape := func(value string) string {
		var out bytes.Buffer
		if err := xml.EscapeText(&out, []byte(value)); err != nil {
			t.Fatal("escape SAML fixture value:", err)
		}
		return out.String()
	}
	correlation := ""
	if input.RequestID != "" {
		correlation = fmt.Sprintf(` InResponseTo="%s"`, escape(input.RequestID))
	}
	now := input.Now.UTC()
	issued := now.Format(time.RFC3339Nano)
	confirmationExpiry := now.Add(3 * time.Minute).Format(time.RFC3339Nano)
	assertionExpiry := now.Add(4 * time.Minute).Format(time.RFC3339Nano)
	issuer := `<a:Issuer>` + escape(input.Issuer) + `</a:Issuer>`
	assertionOpen := fmt.Sprintf(`<a:Assertion xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" IssueInstant="%s" Version="2.0">`, escape(input.AssertionID), issued)
	subject := `<a:Subject><a:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` + escape(input.NameID) + `</a:NameID>` +
		`<a:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
		fmt.Sprintf(`<a:SubjectConfirmationData%s NotOnOrAfter="%s" Recipient="%s"></a:SubjectConfirmationData>`, correlation, confirmationExpiry, escape(input.ACS)) +
		`</a:SubjectConfirmation></a:Subject>`
	conditions := fmt.Sprintf(`<a:Conditions NotBefore="%s" NotOnOrAfter="%s"><a:AudienceRestriction><a:Audience>%s</a:Audience></a:AudienceRestriction></a:Conditions>`, issued, assertionExpiry, escape(input.Audience))
	authentication := fmt.Sprintf(`<a:AuthnStatement AuthnInstant="%s" SessionIndex="%s">`, issued, escape(input.AssertionID)) +
		`<a:AuthnContext><a:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>`
	assertionContent := subject + conditions + authentication + `</a:Assertion>`
	assertionSignature := f.signXML(t, input.AssertionID, assertionOpen+issuer+assertionContent)
	assertion := assertionOpen + issuer + assertionSignature + assertionContent

	responseOpen := fmt.Sprintf(`<p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="%s" ID="%s"%s IssueInstant="%s" Version="2.0">`, escape(input.ACS), escape(input.ResponseID), correlation, issued)
	responseIssuer := `<a:Issuer xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion">` + escape(input.Issuer) + `</a:Issuer>`
	status := `<p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"></p:StatusCode></p:Status>`
	responseContent := status + assertion + `</p:Response>`
	// XML Signature §6.6.4: the response's enveloped signature covers the
	// already-signed assertion, excluding only the response's own signature.
	responseSignature := f.signXML(t, input.ResponseID, responseOpen+responseIssuer+responseContent)
	response := responseOpen + responseIssuer + responseSignature + responseContent
	return base64.StdEncoding.EncodeToString([]byte(response))
}

func (f referenceSAMLIdPFixture) signXML(t *testing.T, id, unsignedXML string) string {
	t.Helper()
	const namespace = `xmlns:ds="http://www.w3.org/2000/09/xmldsig#"`
	digest := base64.StdEncoding.EncodeToString(referenceSAMLCanonicalDigest(t, unsignedXML))
	signedInfoContent := `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>` +
		`<ds:Reference URI="#` + id + `"><ds:Transforms>` +
		`<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>` +
		`<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
		`<ds:DigestValue>` + digest + `</ds:DigestValue></ds:Reference>`
	signedInfo := `<ds:SignedInfo ` + namespace + `>` + signedInfoContent + `</ds:SignedInfo>`
	signedDigest := referenceSAMLCanonicalDigest(t, signedInfo)
	r, s, err := ecdsa.Sign(rand.Reader, f.key, signedDigest)
	if err != nil {
		t.Fatal("sign SAML fixture node:", err)
	}
	// XML Signature 1.1 §6.4.3 uses fixed-width R || S, not ASN.1 DER.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return `<ds:Signature ` + namespace + `><ds:SignedInfo>` + signedInfoContent + `</ds:SignedInfo>` +
		`<ds:SignatureValue>` + base64.StdEncoding.EncodeToString(signature) + `</ds:SignatureValue></ds:Signature>`
}

func referenceSAMLCanonicalDigest(t *testing.T, source string) []byte {
	t.Helper()
	tree, err := xdm.Parse(strings.NewReader(source), xdm.ParseOptions{MaxBytes: 64 << 10, MaxDepth: 24, MaxNodes: 256})
	if err != nil {
		t.Fatal("parse generated SAML signing input:", err)
	}
	digest, err := c14n.Digest(sha256.New(), tree.Root.FirstChild(), c14n.Options{Algorithm: c14n.Exclusive10})
	if err != nil {
		t.Fatal("canonicalize generated SAML signing input:", err)
	}
	return digest
}
