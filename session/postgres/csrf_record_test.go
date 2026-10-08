package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func csrfSessionFixture(t testing.TB) session.Session {
	return withCSRFState(t, testSession(t), 9)
}

func withCSRFState(t testing.TB, original session.Session, digest byte) session.Session {
	t.Helper()
	base, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	state, err := session.NewCSRFState(session.CSRFStateSpec{
		Binding:    session.CSRFBinding{TenantID: base.TenantID, SessionID: base.SessionID, SessionVersion: base.Version},
		KeyVersion: 7, Digest: [32]byte{digest},
	})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(base, state)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestCSRFNativeCommandPreservesCompleteSession(t *testing.T) {
	for _, record := range []session.Session{testSession(t), csrfSessionFixture(t)} {
		binding := revokeBinding()
		operation := session.RevokeOneOperation()
		binding.OperationID, binding.SchemaID, binding.RecordID = operation.OperationID, operation.SchemaID, "session-a"
		mapped, err := mapSessionRecord(binding, session.RevokeOneOperation(), record)
		if err != nil {
			t.Fatal(err)
		}
		_, restored, err := nativeSessionRecord(mapped, session.RevokeOneOperation())
		if err != nil {
			t.Fatal(err)
		}
		want, wantErr := record.CSRFState().Bindings()
		got, gotErr := restored.CSRFState().Bindings()
		if (wantErr == nil) != (gotErr == nil) || want != got {
			t.Fatal("native command lost synchronizer state")
		}
		projection, _ := mapped.Feature()
		for _, field := range projection.Fields {
			if field.Name == "csrf.key-version" {
				for _, bad := range []identity.FeatureValue{{Kind: identity.FeatureUint64}, {Kind: identity.FeatureUint64, Uint64: 1 << 32}, {Kind: identity.FeatureText, Text: "7"}} {
					mutated, _ := mapped.Feature()
					for i := range mutated.Fields {
						if mutated.Fields[i].Name == field.Name {
							mutated.Fields[i].Value = bad
						}
					}
					command, err := identity.NewFeatureCommand(mutated)
					if err == nil {
						if _, _, err = nativeSessionRecord(command, session.RevokeOneOperation()); err == nil {
							t.Fatal("malformed CSRF command accepted")
						}
					}
				}
			}
		}
	}
}

func TestCSRFRotationIntentPreservesSourceAndSuccessor(t *testing.T) {
	for _, successorCSRF := range []bool{false, true} {
		request := rotationMappingCSRFFixture(t, true, successorCSRF)
		command, _ := request.Command()
		want, _ := command.Rotation()
		mapped, err := MapRotationRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		restored, _, _, err := nativeRotationIntent(mapped)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := restored.Rotation()
		for _, pair := range [][2]session.Session{{want.Source, got.Source}, {want.Successor, got.Successor}} {
			a, _, _ := encodeRecord(pair[0])
			b, _, _ := encodeRecord(pair[1])
			if !bytes.Equal(a, b) {
				t.Fatal("rotation intent lost synchronizer state")
			}
		}
	}
}

func TestCSRFStoredRecordRejectsIncompleteAndForeignState(t *testing.T) {
	payload, _, err := encodeRecord(csrfSessionFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]json.RawMessage){
		func(v map[string]json.RawMessage) { delete(v, "CSRF") },
		func(v map[string]json.RawMessage) { v["CSRF"] = json.RawMessage(`null`) },
		func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`1`) },
		func(v map[string]json.RawMessage) { v["Schema"] = json.RawMessage(`3`) },
	} {
		var top map[string]json.RawMessage
		if err := json.Unmarshal(payload, &top); err != nil {
			t.Fatal(err)
		}
		mutate(top)
		bad, err := json.Marshal(top)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) {
			t.Fatal("invalid schema/state accepted", err)
		}
	}
	for _, field := range []string{"Binding", "KeyVersion", "Digest"} {
		var top map[string]json.RawMessage
		json.Unmarshal(payload, &top)
		var state map[string]json.RawMessage
		json.Unmarshal(top["CSRF"], &state)
		delete(state, field)
		top["CSRF"], _ = json.Marshal(state)
		bad, _ := json.Marshal(top)
		if _, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) {
			t.Fatal("partial state accepted")
		}
	}
	for _, change := range []func(*session.CSRFStateSpec){
		func(s *session.CSRFStateSpec) { s.Binding.TenantID = "foreign" },
		func(s *session.CSRFStateSpec) { s.Binding.SessionID = "foreign" },
		func(s *session.CSRFStateSpec) { s.Binding.SessionVersion-- },
		func(s *session.CSRFStateSpec) { s.KeyVersion = 0 },
		func(s *session.CSRFStateSpec) { s.Digest = [32]byte{} },
	} {
		var top map[string]json.RawMessage
		json.Unmarshal(payload, &top)
		var state session.CSRFStateSpec
		json.Unmarshal(top["CSRF"], &state)
		change(&state)
		top["CSRF"], _ = json.Marshal(state)
		bad, _ := json.Marshal(top)
		if _, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) {
			t.Fatal("foreign/zero state accepted")
		}
	}
	for _, raw := range []string{`[]`, `[9]`, `[null]`, `null`} {
		var top map[string]json.RawMessage
		json.Unmarshal(payload, &top)
		var state map[string]json.RawMessage
		json.Unmarshal(top["CSRF"], &state)
		state["Digest"] = json.RawMessage(raw)
		top["CSRF"], _ = json.Marshal(state)
		bad, _ := json.Marshal(top)
		if _, err := decodeRecord(bad); !errors.Is(err, ErrInvalidRecord) {
			t.Fatal("incomplete digest accepted")
		}
	}
	duplicate := bytes.Replace(payload, []byte(`"KeyVersion":7`), []byte(`"KeyVersion":7,"KeyVersion":7`), 1)
	if _, err := decodeRecord(duplicate); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("duplicate state field accepted")
	}
}

// A restart must preserve the separately stored synchronizer state, not only
// Session.Bindings, which intentionally retains its original public shape.
func TestCSRFStoredRecordSurvivesRestart(t *testing.T) {
	original := csrfSessionFixture(t)
	payload, expiry, err := encodeRecord(original)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := decodeRecord(payload)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := original.CSRFState().Bindings()
	got, err := restored.CSRFState().Bindings()
	if err != nil || got != want {
		t.Fatal("restart lost complete CSRF state", err)
	}
	again, restoredExpiry, err := encodeRecord(restored)
	if err != nil || !bytes.Equal(payload, again) || expiry != restoredExpiry {
		t.Fatal("restart changed exact record or original expiry", err)
	}
	legacy, _, err := encodeRecord(testSession(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(legacy, []byte(`"Schema":1`)) || bytes.Contains(legacy, []byte(`"CSRF"`)) {
		t.Fatal("legacy stored projection changed")
	}
	old, err := decodeRecord(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.CSRFState().Bindings(); err == nil {
		t.Fatal("legacy record acquired CSRF state")
	}
}
