//go:build integration

package reference_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-identity/session"
	webauthn "github.com/faustbrian/go-webauthn"
)

func TestReferencePostgresPasskeySelectedAlgorithmsHTTP(t *testing.T) {
	for _, profile := range []struct {
		name       string
		algorithms []webauthn.Algorithm
	}{
		{"Ed25519", []webauthn.Algorithm{webauthn.EdDSA}},
		{"mixed-Ed-first", []webauthn.Algorithm{webauthn.EdDSA, webauthn.ES256}},
		{"mixed-ES-first", []webauthn.Algorithm{webauthn.ES256, webauthn.EdDSA}},
	} {
		t.Run(profile.name, func(t *testing.T) {
			for _, upgrade := range []bool{false, true} {
				t.Run(map[bool]string{false: "fresh", true: "populated-kernel-upgrade"}[upgrade], func(t *testing.T) {
					proveReferencePasskeyStandalone(t, upgrade, standalonePasskeyJourney{algorithms: profile.algorithms, management: true, httpManagement: true, enrollment: true, enrollmentTransport: session.CredentialCookie, sessionDeletion: true, httpEnrollment: true, httpDeletion: true})
				})
			}
		})
	}
}

// This owns only an external authenticator key. All protocol verification and
// application authority remain in the actual public Reference graph.
func referencePasskeyTestSigner(t *testing.T, algorithms []webauthn.Algorithm, index int) crypto.Signer {
	t.Helper()
	algorithm := webauthn.ES256
	if len(algorithms) != 0 {
		algorithm = algorithms[index%len(algorithms)]
	}
	switch algorithm {
	case webauthn.ES256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	case webauthn.EdDSA:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	default:
		t.Fatal("unsupported test authenticator algorithm")
		return nil
	}
}

func referencePasskeyAlgorithmParameters(t *testing.T, raw []byte, selected []webauthn.Algorithm) {
	t.Helper()
	var wire struct {
		PublicKey struct {
			Parameters []struct {
				Type      string             `json:"type"`
				Algorithm webauthn.Algorithm `json:"alg"`
			} `json:"pubKeyCredParams"`
		} `json:"publicKey"`
	}
	if json.Unmarshal(raw, &wire) != nil {
		t.Fatal("invalid registration algorithm options")
	}
	if selected == nil {
		selected = []webauthn.Algorithm{webauthn.ES256}
	}
	if len(wire.PublicKey.Parameters) != len(selected) {
		t.Fatal("registration changed selected algorithm count")
	}
	for i, parameter := range wire.PublicKey.Parameters {
		if parameter.Type != "public-key" || parameter.Algorithm != selected[i] {
			t.Fatal("registration changed selected algorithm order")
		}
	}
}
