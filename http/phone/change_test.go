package phonehttp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/faustbrian/go-identity/phone"
)

func TestChangeBodyRetainsExactPredecessorAndFreshUpdateProof(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(raw string) map[string]json.RawMessage {
		t.Helper()
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &fields) != nil {
			t.Fatal("invalid parser fixture")
		}
		return fields
	}
	const send = `{"flowID":"original-session","number":"+12025550125","previousNumber":"+12025550123","identifierID":"AAAAAAAAAAAAAAAAAAAAAQ","expectedIdentifierVersion":"2","expectedVerificationVersion":"3","proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`
	parsed, err := decodeChangeBody(context.Background(), policy, 0, decode(send))
	if err != nil || parsed.flowID != "original-session" || parsed.proofID != "AAAAAAAAAAAAAAAAAAAAAg" || parsed.change.IdentifierID != "AAAAAAAAAAAAAAAAAAAAAQ" || parsed.change.ExpectedIdentifierVersion != 2 || parsed.change.ExpectedVerificationVersion != 3 {
		t.Fatal("replacement lost the exact original predecessor", err)
	}
	previous, _ := parsed.change.PreviousNumber.Record()
	next, _ := parsed.change.Enrollment.Number.Record()
	if previous.E164 != "+12025550123" || next.E164 != "+12025550125" {
		t.Fatal("old and new replacement destinations collapsed")
	}
	const update = `{"flowID":"original-session","sendCommandID":"AAAAAAAAAAAAAAAAAAAAAw","code":"123456","proofID":"AAAAAAAAAAAAAAAAAAAABA","reason":"user-requested"}`
	completion, err := decodeChangeBody(context.Background(), policy, 1, decode(update))
	if err != nil || completion.proofID != "AAAAAAAAAAAAAAAAAAAABA" || completion.update.SendCommandID != "AAAAAAAAAAAAAAAAAAAAAw" || completion.update.Reason != "user-requested" {
		t.Fatal("completion did not retain distinct update proof and original send", err)
	}
	for _, mode := range []int{0, 1} {
		base := send
		if mode == 1 {
			base = update
		}
		for _, extra := range []string{"tenantID", "userID", "commandID", "idempotencyKey", "skipNotification", "remember", "targetSubjectID"} {
			bad := decode(base)
			bad[extra] = json.RawMessage(`"override"`)
			if _, err := decodeChangeBody(context.Background(), policy, mode, bad); err == nil {
				t.Fatal("authority/body-key override accepted", extra)
			}
		}
	}
	for _, value := range []string{`2`, `"0"`, `"02"`, `"18446744073709551615"`, `"18446744073709551616"`, `null`} {
		bad := decode(send)
		bad["expectedIdentifierVersion"] = json.RawMessage(value)
		if _, err := decodeChangeBody(context.Background(), policy, 0, bad); err == nil {
			t.Fatal("lossy or unbounded predecessor version accepted")
		}
	}
}

func FuzzPhoneChangeBody(f *testing.F) {
	f.Add(uint8(0), []byte(`{"flowID":"session","number":"+12025550125","previousNumber":"+12025550123","identifierID":"AAAAAAAAAAAAAAAAAAAAAQ","expectedIdentifierVersion":"2","expectedVerificationVersion":"3","proofID":"AAAAAAAAAAAAAAAAAAAAAg"}`))
	f.Add(uint8(1), []byte(`{"flowID":"session","sendCommandID":"AAAAAAAAAAAAAAAAAAAAAw","code":"123456","proofID":"AAAAAAAAAAAAAAAAAAAABA","reason":"user-requested"}`))
	f.Add(uint8(2), []byte(`{"flowID":"session","recovery":{"scopeDigest":null}}`))
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, mode uint8, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return
		}
		_, _ = decodeChangeBody(context.Background(), policy, int(mode), fields)
	})
}

func TestChangeBodyRejectsFlowOutsideClosedWireProfile(t *testing.T) {
	policy, err := phone.NewNumberPolicy(phone.NumberPolicySpec{Profile: phone.CurrentNumberProfile(), MaximumInputBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range []string{"original session", "original\nflow", "identity-\u00e9", "original\u007fflow"} {
		wire, err := json.Marshal(flow)
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]json.RawMessage{"flowID": wire, "sendCommandID": json.RawMessage(`"AAAAAAAAAAAAAAAAAAAAAw"`), "code": json.RawMessage(`"123456"`), "proofID": json.RawMessage(`"AAAAAAAAAAAAAAAAAAAABA"`), "reason": json.RawMessage(`"user-requested"`)}
		if _, err := decodeChangeBody(t.Context(), policy, 1, fields); err == nil {
			t.Fatal("replacement accepted a flow outside its advertised ASCII grammar")
		}
	}
}
