package postgres

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func magicLinkRecordFixture(t testing.TB, csrf bool) session.Session {
	t.Helper()
	otp := otpRecordFixture(t, csrf)
	s, _ := otp.Bindings()
	p, _ := otp.OTPAuthentication().Bindings()
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationMagicLink}
	m, err := session.NewMagicLinkAuthentication(session.MagicLinkAuthenticationSpec{CommandID: p.CommandID, RequestCommandID: p.SendCommandID, CapabilityID: "original-grant", IdentifierID: p.IdentifierID, IdentifierVersion: p.IdentifierVersion, VerificationVersion: p.VerificationVersion, AuthenticatedAt: p.AuthenticatedAt, ValidUntil: p.ValidUntil})
	if err != nil {
		t.Fatal(err)
	}
	var r session.Session
	if csrf {
		r, err = session.NewSessionWithMagicLinkAndCSRF(s, m, otp.CSRFState())
	} else {
		r, err = session.NewSessionWithMagicLink(s, m)
	}
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMagicLinkStoredRecordPreservesExactGrantAndVersions(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		t.Run(fmt.Sprint(csrf), func(t *testing.T) {
			original := magicLinkRecordFixture(t, csrf)
			wire, expiry, err := encodeRecord(original)
			if err != nil {
				t.Fatal(err)
			}
			var top map[string]json.RawMessage
			if json.Unmarshal(wire, &top) != nil {
				t.Fatal("invalid record")
			}
			schema := "7"
			if csrf {
				schema = "8"
			}
			if string(top["Schema"]) != schema || len(top["MagicLink"]) == 0 {
				t.Fatal("wrong method storage profile")
			}
			// jsonb may reorder objects, never round uint64 authority versions.
			reordered, _ := json.Marshal(top)
			restored, err := decodeRecord(reordered)
			if err != nil {
				t.Fatal("durable restart lost provenance", err)
			}
			before, _ := original.MagicLinkAuthentication().Bindings()
			after, _ := restored.MagicLinkAuthentication().Bindings()
			if before != after {
				t.Fatal("changed grant/identifier provenance")
			}
			again, restoredExpiry, err := encodeRecord(restored)
			if err != nil || !bytes.Equal(wire, again) || expiry != restoredExpiry {
				t.Fatal("changed bytes/expiry", err)
			}
			for _, bad := range [][]byte{
				bytes.Replace(wire, []byte(`"MagicLink":{`), []byte(`"MagicLink":null,"MagicLink":{`), 1),
				bytes.Replace(wire, []byte(`"CapabilityID":"original-grant"`), []byte(`"CapabilityID":null`), 1),
				bytes.Replace(wire, []byte(`"VerificationVersion":18446744073709551615`), []byte(`"VerificationVersion":0`), 1),
				bytes.Replace(wire, []byte(`"Kind":4`), []byte(`"Kind":3`), 1),
				bytes.Replace(wire, []byte(`"Schema":`+schema), []byte(`"Schema":1`), 1),
			} {
				if bytes.Equal(bad, wire) {
					t.Fatal("mutation did not change fixture")
				}
				if _, err := decodeRecord(bad); err == nil {
					t.Fatal("corrupt stored grant accepted")
				}
			}
		})
	}
}
