package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func otpRecordFixture(t testing.TB, csrf bool) session.Session {
	t.Helper()
	s, _ := testSession(t).Bindings()
	v, _ := s.Authority.Bindings()
	v.ActiveOrganizationID = ""
	v.Organization, v.Factor, v.Passkey = session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}, session.OptionalAuthorityBinding{}
	var err error
	s.Authority, err = session.NewAuthoritySnapshot(v)
	if err != nil {
		t.Fatal(err)
	}
	s.Authentication = session.AuthenticationMetadata{Kind: session.AuthenticationOTP}
	p, err := session.NewOTPAuthentication(session.OTPAuthenticationSpec{
		CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", SendCommandID: "AgICAgICAgICAgICAgICAg",
		ChallengeID: "original-challenge", AttemptID: "AwMDAwMDAwMDAwMDAwMDAw",
		IdentifierID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", IdentifierKind: identity.IdentifierPhone,
		IdentifierVersion: math.MaxUint64, VerificationVersion: math.MaxUint64,
		AuthenticatedAt: s.IssuedAt.Add(-time.Second), ValidUntil: s.IssuedAt.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	var record session.Session
	if csrf {
		state, e := session.NewCSRFState(session.CSRFStateSpec{Binding: session.CSRFBinding{TenantID: s.TenantID, SessionID: s.SessionID, SessionVersion: s.Version}, KeyVersion: 7, Digest: [32]byte{9}})
		if e != nil {
			t.Fatal(e)
		}
		record, err = session.NewSessionWithOTPAndCSRF(s, p, state)
	} else {
		record, err = session.NewSessionWithOTP(s, p)
	}
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestOTPStoredRecordPreservesOriginalProvenance(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		t.Run(fmt.Sprint(csrf), func(t *testing.T) {
			original := otpRecordFixture(t, csrf)
			payload, expiry, err := encodeRecord(original)
			if err != nil {
				t.Fatal(err)
			}
			// PostgreSQL jsonb reorders object keys. Its projection must still
			// preserve uint64 precision and the complete original method state.
			var top map[string]json.RawMessage
			if err := json.Unmarshal(payload, &top); err != nil {
				t.Fatal(err)
			}
			schema := "3"
			if csrf {
				schema = "4"
			}
			if string(top["Schema"]) != schema || len(top["OTP"]) == 0 {
				t.Fatal("wrong stored method profile")
			}
			canonical, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := decodeRecord(canonical)
			if err != nil {
				t.Fatal("OTP record cannot survive durable reconstruction", err)
			}
			before, _ := original.OTPAuthentication().Bindings()
			after, err := restored.OTPAuthentication().Bindings()
			if err != nil || before != after {
				t.Fatal("OTP provenance changed", err)
			}
			beforeCSRF, _ := original.CSRFState().Bindings()
			afterCSRF, _ := restored.CSRFState().Bindings()
			if beforeCSRF != afterCSRF {
				t.Fatal("synchronizer state changed")
			}
			again, restoredExpiry, err := encodeRecord(restored)
			if err != nil || !bytes.Equal(payload, again) || expiry != restoredExpiry {
				t.Fatal("record or expiry changed during restart", err)
			}
			base, _ := restored.Bindings()
			// Challenge expiry is historical; it must not erase an otherwise
			// live session or renew its original authentication freshness.
			life, err := restored.Lifetime(after.ValidUntil.Add(time.Second))
			want, _ := original.Lifetime(after.ValidUntil.Add(time.Second))
			if err != nil || life != want || base.Authentication.Kind != session.AuthenticationOTP {
				t.Fatal("challenge history replaced session lifetime", err)
			}
		})
	}
}

func TestOTPStoredRecordRejectsIncompleteAndMixedProfiles(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		payload, _, err := encodeRecord(otpRecordFixture(t, csrf))
		if err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(map[string]json.RawMessage){
			func(v map[string]json.RawMessage) { delete(v, "OTP") },
			func(v map[string]json.RawMessage) { v["OTP"] = json.RawMessage(`null`) },
			func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`1`) },
			func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`2`) },
			func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`5`) },
			func(v map[string]json.RawMessage) {
				v["OTP"] = bytes.Replace(v["OTP"], []byte(`"IdentifierKind":"phone"`), []byte(`"IdentifierKind":"username"`), 1)
			},
			func(v map[string]json.RawMessage) {
				v["OTP"] = bytes.Replace(v["OTP"], []byte(`"VerificationVersion":18446744073709551615`), []byte(`"VerificationVersion":0`), 1)
			},
			func(v map[string]json.RawMessage) {
				v["OTP"] = bytes.Replace(v["OTP"], []byte(`"AttemptID":`), []byte(`"Unknown":`), 1)
			},
			func(v map[string]json.RawMessage) {
				v["OTP"] = bytes.Replace(v["OTP"], []byte(`"ChallengeID":`), []byte(`"ChallengeID":null,"ChallengeID":`), 1)
			},
			func(v map[string]json.RawMessage) {
				v["Authentication"] = bytes.Replace(v["Authentication"], []byte(`"Kind":3`), []byte(`"Kind":1`), 1)
			},
		} {
			var top map[string]json.RawMessage
			if err := json.Unmarshal(payload, &top); err != nil {
				t.Fatal(err)
			}
			unchanged, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			mutate(top)
			bad, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(bad, unchanged) {
				t.Fatal("invalid fixture unchanged")
			}
			if got, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) || got != (session.Session{}) {
				t.Fatal("incomplete or mixed OTP record accepted", err)
			}
		}
	}
}

func TestOTPStoredRecordRequiresEveryOriginalField(t *testing.T) {
	payload, _, err := encodeRecord(otpRecordFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CommandID", "SendCommandID", "ChallengeID", "AttemptID", "IdentifierID", "IdentifierKind", "IdentifierVersion", "VerificationVersion", "AuthenticatedAt", "ValidUntil"} {
		for _, null := range []bool{false, true} {
			var top, metadata map[string]json.RawMessage
			if err := json.Unmarshal(payload, &top); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(top["OTP"], &metadata); err != nil {
				t.Fatal(err)
			}
			delete(metadata, name)
			if null {
				metadata[name] = json.RawMessage(`null`)
			}
			top["OTP"], err = json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			bad, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) || got != (session.Session{}) {
				t.Fatalf("incomplete original %s accepted", name)
			}
		}
	}
	// Absence is meaningful: an OTP projection, including explicit null,
	// cannot be smuggled into either historical schema.
	for _, legacy := range []session.Session{testSession(t), csrfSessionFixture(t)} {
		b, _, err := encodeRecord(legacy)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []json.RawMessage{json.RawMessage(`null`), json.RawMessage(`{}`)} {
			var top map[string]json.RawMessage
			if err := json.Unmarshal(b, &top); err != nil {
				t.Fatal(err)
			}
			top["OTP"] = value
			bad, err := json.Marshal(top)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) || got != (session.Session{}) {
				t.Fatal("legacy record acquired an OTP projection", err)
			}
		}
	}
}
