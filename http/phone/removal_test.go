package phonehttp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-identity/phone"
)

func TestRemovalSelectionRequiresActualCustody(t *testing.T) {
	if h, err := NewRemovalHandler(RemovalConfig{}); err == nil || h != nil {
		t.Fatal("unconfigured removal handler accepted")
	}
	if _, err := NewRemovalFeature(RemovalConfig{}); err == nil {
		t.Fatal("unconfigured removal advertised")
	}
}

func TestRemovalBodyHasOneClosedNonOTPScope(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	valid := map[string]json.RawMessage{"number": json.RawMessage(`"+12025550123"`), "identifierID": json.RawMessage(`"AAAAAAAAAAAAAAAAAAAAAQ"`), "expectedIdentifierVersion": json.RawMessage(`"2"`), "expectedVerificationVersion": json.RawMessage(`"2"`), "proofID": json.RawMessage(`"AAAAAAAAAAAAAAAAAAAAAg"`), "reason": json.RawMessage(`"user-requested"`)}
	proof, spec, err := decodeRemovalBody(context.Background(), policy, valid)
	if err != nil || proof != "AAAAAAAAAAAAAAAAAAAAAg" || spec.IdentifierID != "AAAAAAAAAAAAAAAAAAAAAQ" || spec.ExpectedIdentifierVersion != 2 || spec.ExpectedVerificationVersion != 2 {
		t.Fatal("valid closed original removal body", err)
	}
	for _, field := range []string{"code", "flowID", "tenantID", "userID", "targetSubjectID", "commandID", "idempotencyKey", "skipNotification"} {
		bad := make(map[string]json.RawMessage, len(valid)+1)
		for k, v := range valid {
			bad[k] = v
		}
		bad[field] = json.RawMessage(`"override"`)
		if _, _, err := decodeRemovalBody(context.Background(), policy, bad); err == nil {
			t.Fatal("authority/OTP/body-key override accepted", field)
		}
	}
	for _, value := range []string{`2`, `"0"`, `"02"`, `"18446744073709551615"`, `"18446744073709551616"`, `null`} {
		bad := make(map[string]json.RawMessage, len(valid))
		for k, v := range valid {
			bad[k] = v
		}
		bad["expectedIdentifierVersion"] = json.RawMessage(value)
		if _, _, err := decodeRemovalBody(context.Background(), policy, bad); err == nil {
			t.Fatal("noncanonical/unbounded version accepted")
		}
	}
}

func FuzzPhoneRemovalBody(f *testing.F) {
	f.Add([]byte(`{"number":"+12025550123","identifierID":"AAAAAAAAAAAAAAAAAAAAAQ","expectedIdentifierVersion":"2","expectedVerificationVersion":"2","proofID":"AAAAAAAAAAAAAAAAAAAAAg","reason":"user-requested"}`))
	f.Add([]byte(`{"expectedIdentifierVersion":18446744073709551616,"code":"000000"}`))
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return
		}
		_, _, _ = decodeRemovalBody(context.Background(), policy, fields)
	})
}
