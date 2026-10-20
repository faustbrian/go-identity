package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func phoneRecoveryPreAuth(t testing.TB) session.PreAuthTransaction {
	t.Helper()
	s, _ := testPreAuth(t, time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)).Bindings()
	s.Binding.Intent.Purpose = session.PreAuthPhonePasswordRecovery
	s.Binding.Intent.Action = "identity.phone.password-reset-request"
	s.Binding.Intent.Remember = session.RememberPolicy{}
	s.Binding.Intent.IdentifierBinding = [32]byte{1}
	record, err := session.NewPreAuthTransaction(s)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestPhoneRecoveryPreAuthNativeStoragePreservesAbsentSessionChoice(t *testing.T) {
	record := phoneRecoveryPreAuth(t)
	wire, err := encodePreAuth(record)
	if err != nil {
		t.Fatal("native record cannot store sessionless recovery", err)
	}
	if bytes.Contains(wire, []byte(`"Remember"`)) || !bytes.Contains(wire, []byte(`"Purpose":1`)) {
		t.Fatal("native record invented or omitted purpose/session choice")
	}
	restored, err := decodePreAuth(wire)
	want, _ := record.Bindings()
	got, getErr := restored.Bindings()
	if err != nil || getErr != nil || got != want {
		t.Fatal("recovery original scope changed", err, getErr)
	}
	for _, bad := range [][]byte{
		bytes.Replace(wire, []byte(`"Purpose":1`), []byte(`"Purpose":0`), 1),
		bytes.Replace(wire, []byte(`"Purpose":1`), []byte(`"Purpose":2`), 1),
		bytes.Replace(wire, []byte(`"Purpose":1`), []byte(`"Purpose":1,"Remember":{}`), 1),
		bytes.Replace(wire, []byte(`"Purpose":1`), []byte(`"Purpose":1,"Purpose":1`), 1),
	} {
		if bytes.Equal(bad, wire) {
			t.Fatal("fixture did not alter native record")
		}
		if _, err := decodePreAuth(bad); err == nil {
			t.Fatal("purpose/session substitution admitted")
		}
	}
	legacy, err := encodePreAuth(testPreAuth(t, want.Binding.IssuedAt))
	if err != nil || bytes.Contains(legacy, []byte(`"Purpose"`)) || !bytes.Contains(legacy, []byte(`"Remember"`)) {
		t.Fatal("legacy storage profile changed", err)
	}
}

func TestPhoneRecoveryPreAuthNativeMappingCannotInventRemember(t *testing.T) {
	record := phoneRecoveryPreAuth(t)
	binding := preAuthIssueBinding(record)
	command, err := mapPreAuthIssue(binding, record)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := command.Feature()
	for _, field := range spec.Fields {
		if len(field.Name) >= len("remember.") && field.Name[:len("remember.")] == "remember." {
			t.Fatal("typed recovery command carried a session choice")
		}
	}
	_, restored, err := nativePreAuthIssue(command)
	want, _ := record.Bindings()
	got, getErr := restored.Bindings()
	if err != nil || getErr != nil || got != want {
		t.Fatal("native recovery typed map cannot round trip", err, getErr)
	}
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "remember.choice", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(session.BrowserSession)}})
	mixed, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := nativePreAuthIssue(mixed); err == nil {
		t.Fatal("recovery mapping accepted a login session choice")
	}
}
