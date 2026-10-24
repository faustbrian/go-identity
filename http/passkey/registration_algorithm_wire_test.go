package passkeyhttp

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestRegistrationOptionsWireBoundsSupportedAlgorithmLists(t *testing.T) {
	for _, profile := range []string{"password-enrollment", "signup", "session-enrollment", "password-and-signup", "session-and-signup"} {
		t.Run(profile, func(t *testing.T) {
			var selection FeatureConfig
			switch profile {
			case "password-enrollment", "password-and-signup":
				c, _, _, _, _, _ := registrationFixture(t)
				selection.Registration = &c
			case "session-enrollment", "session-and-signup":
				c, _, _, _, _ := sessionEnrollmentFixture(t)
				selection.SessionEnrollment = &c
			}
			if strings.Contains(profile, "signup") {
				c, _, _, _ := signupFixture(t)
				if selection.Registration != nil {
					c.OptionsRate, c.VerificationRate = selection.Registration.OptionsRate, selection.Registration.VerificationRate
				}
				if selection.SessionEnrollment != nil {
					c.OptionsRate, c.VerificationRate = selection.SessionEnrollment.OptionsRate, selection.SessionEnrollment.VerificationRate
				}
				selection.Signup = &c
			}
			feature, err := NewFeature(selection)
			if err != nil {
				t.Fatal(err)
			}
			_, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Registration algorithms", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, part := range []string{"paths", "/v1/passkey/register-options", "post", "responses", "200", "content", "application/json", "schema"} {
				var ok bool
				node, ok = node.Lookup(part)
				if !ok {
					t.Fatal("missing selected registration response schema", part)
				}
			}
			// These are response instances, not synthetic native credentials or
			// authorization. Reference's PostgreSQL journeys prove native issuance.
			for _, candidate := range []struct {
				name, parameters string
				valid            bool
			}{
				{"default-es256", `[{"type":"public-key","alg":-7}]`, true},
				{"ed25519", `[{"type":"public-key","alg":-8}]`, true},
				{"es256-first", `[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8}]`, true},
				{"ed25519-first", `[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7}]`, true},
				{"empty", `[]`, false},
				{"null", `null`, false},
				{"duplicate-es256", `[{"type":"public-key","alg":-7},{"alg":-7,"type":"public-key"}]`, false},
				{"duplicate-ed25519", `[{"type":"public-key","alg":-8},{"type":"public-key","alg":-8}]`, false},
				{"rs256", `[{"type":"public-key","alg":-257}]`, false},
				{"unknown", `[{"type":"public-key","alg":0}]`, false},
				{"mixed-rs256", `[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}]`, false},
				{"excess", `[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8},{"type":"public-key","alg":-7}]`, false},
				{"wrong-type", `[{"type":"other","alg":-8}]`, false},
				{"missing-algorithm", `[{"type":"public-key"}]`, false},
				{"string-algorithm", `[{"type":"public-key","alg":"-8"}]`, false},
				{"extra-field", `[{"type":"public-key","alg":-8,"curve":"Ed25519"}]`, false},
			} {
				t.Run(candidate.name, func(t *testing.T) {
					wire := fmt.Sprintf(`{"commandID":"AAAAAAAAAAAAAAAAAAAAAQ","commitOutcome":"committed","replayed":false,"options":{"publicKey":{"challenge":"%s","timeout":300000,"userVerification":"required","rp":{"id":"tenant.example","name":"Tenant"},"user":{"id":"%s","name":"%s","displayName":"%s"},"pubKeyCredParams":%s,"attestation":"none","authenticatorSelection":{"userVerification":"required","residentKey":"required","requireResidentKey":true}}}}`, strings.Repeat("A", 43), strings.Repeat("A", 43), strings.Repeat("A", 43), strings.Repeat("A", 43), candidate.parameters)
					instance, err := parse.JSON(t.Context(), strings.NewReader(wire), parse.DefaultLimits())
					if err != nil {
						t.Fatal(err)
					}
					report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
					if err != nil || report.Valid() != candidate.valid {
						t.Fatalf("selected registration response valid=%v, want %v: %v", report.Valid(), candidate.valid, err)
					}
				})
			}
		})
	}
}
