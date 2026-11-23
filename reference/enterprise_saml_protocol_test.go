package reference

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	ssopg "github.com/faustbrian/go-sso/postgres"
	saml "github.com/faustbrian/go-sso/saml"
)

func TestEnterpriseSAMLProtocolSignsWithInstalledCredential(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), KeyUsage: x509.KeyUsageDigitalSignature,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	certDER, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	bundle, err := saml.EncodeSPSigningCredential(t.Context(), keyDER, certDER, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(bundle)
	const idp = "https://idp.example/login"
	input := ssopg.SAMLAuthnRedirectInput{SPEntityID: "https://identity.example/saml2", AssertionConsumerURL: "https://identity.example/saml2/installed/acs",
		IdentityProviderURL: idp, RequestID: "_request", RelayState: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), IssuedAt: now}
	destination, until, err := enterpriseSAMLSignRedirect(t.Context(), input, bundle, now)
	if err != nil || !until.Equal(certificate.NotAfter) || destination.Scheme+"://"+destination.Host+destination.Path != idp {
		t.Fatal("signing did not preserve the installed destination and original certificate cutoff", err)
	}
	signed, _, present := strings.Cut(destination.RawQuery, "&Signature=")
	query, parseErr := url.ParseQuery(destination.RawQuery)
	signature, decodeErr := base64.StdEncoding.DecodeString(query.Get("Signature"))
	digest := sha256.Sum256([]byte(signed))
	if !present || parseErr != nil || decodeErr != nil || query.Get("RelayState") != input.RelayState || query.Get("SigAlg") != saml.SignatureAlgorithmRSAPSSSHA256 ||
		rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256}) != nil {
		t.Fatal("redirect does not verify with the installed public key")
	}
	if expired, cutoff, err := enterpriseSAMLSignRedirect(t.Context(), input, bundle, certificate.NotAfter); err == nil || expired != (url.URL{}) || !cutoff.IsZero() {
		t.Fatal("an expired signer disclosed a redirect")
	}
}
