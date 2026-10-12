package postgres

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestMFARecordRetainsExactFactorAndPrimaryProvenance(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		t.Run(fmt.Sprint(csrf), func(t *testing.T) {
			original := magicLinkRecordFixture(t, csrf)
			s, _ := original.Bindings()
			primary := original.MagicLinkAuthentication()
			p, _ := primary.Bindings()
			a, _ := s.Authority.Bindings()
			a.Factor = session.OptionalAuthorityBinding{Present: true, Binding: session.AuthorityBinding{ScopeKey: "factor/user", Version: 7}}
			s.Authority, _ = session.NewAuthoritySnapshot(a)
			remember, _ := s.Remember.Bindings()
			factor, err := session.NewMFAAuthentication(session.MFAAuthenticationSpec{CommandID: "BAQEBAQEBAQEBAQEBAQEBA", PrimaryCommandID: p.CommandID, ContinuationID: "BQUFBQUFBQUFBQUFBQUFBQ", ContinuationScopeDigest: [32]byte{1}, Method: "totp", FactorID: "BgYGBgYGBgYGBgYGBgYGBg", EnrollmentVersion: 1, FactorAuthorityVersion: 7, ContinuationVersion: 1, Remember: remember, VerifiedAt: s.IssuedAt, ValidUntil: p.ValidUntil})
			if err != nil {
				t.Fatal(err)
			}
			if csrf {
				original, err = session.NewSessionWithMagicLinkMFAAndCSRF(s, primary, factor, original.CSRFState())
			} else {
				original, err = session.NewSessionWithMagicLinkMFA(s, primary, factor)
			}
			if err != nil {
				t.Fatal(err)
			}
			fields, err := OriginalSessionFields(original)
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := OriginalSessionFromFields(s.TenantID, s.UserID, fields)
			if err != nil {
				t.Fatal("native mapping dropped factor provenance", err)
			}
			mappedFactor, _ := mapped.MFAAuthentication().Bindings()
			expectedFactor, _ := factor.Bindings()
			if mappedFactor != expectedFactor {
				t.Fatal("native mapping substituted factor")
			}
			for i, field := range fields {
				if field.Name != "source-session.mfa.scope" {
					continue
				}
				partial := append(fields[:i:i], fields[i+1:]...)
				if _, err := OriginalSessionFromFields(s.TenantID, s.UserID, partial); err == nil {
					t.Fatal("partial factor mapping accepted")
				}
			}
			wire, expiry, err := encodeRecord(original)
			if err != nil {
				t.Fatal(err)
			}
			var top map[string]json.RawMessage
			if json.Unmarshal(wire, &top) != nil || len(top["MFA"]) == 0 {
				t.Fatal("durable record dropped MFA provenance")
			}
			// JSONB reorders object keys, so complete semantic decoding must
			// retain the exact projections without relying on wire key order.
			reordered, _ := json.Marshal(top)
			loaded, err := decodeRecord(reordered)
			if err != nil {
				t.Fatal("complete MFA record could not be restored", err)
			}
			got, _ := loaded.MFAAuthentication().Bindings()
			want, _ := factor.Bindings()
			before, _ := primary.Bindings()
			after, _ := loaded.MagicLinkAuthentication().Bindings()
			_, restoredExpiry, err := encodeRecord(loaded)
			if err != nil || got != want || before != after || restoredExpiry != expiry {
				t.Fatal("durable restore substituted factor, primary or expiry")
			}
			var object map[string]json.RawMessage
			if json.Unmarshal(top["MFA"], &object) != nil {
				t.Fatal("factor projection malformed")
			}
			for _, badDigest := range []string{"[1]", "null", "[null]"} {
				object["ContinuationScopeDigest"] = json.RawMessage(badDigest)
				top["MFA"], _ = json.Marshal(object)
				bad, _ := json.Marshal(top)
				if _, err := decodeRecord(bad); err == nil {
					t.Fatal("malformed factor digest accepted")
				}
			}
			delete(top, "MFA")
			lossy, _ := json.Marshal(top)
			if _, err := decodeRecord(lossy); err == nil {
				t.Fatal("missing factor metadata degraded to single-factor")
			}
		})
	}
}
