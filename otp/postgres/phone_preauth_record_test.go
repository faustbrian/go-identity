package postgres

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/faustbrian/go-identity/session"
)

func TestOTPPreAuthCustodyPreservesFixedLegacyBytes(t *testing.T) {
	// Independent Ruby pack("n"/"Q>"/"N") framing of issuanceRecordSeed's
	// explicit fields under pre-change source 8cbca6b. Do not derive this oracle
	// from either codec: matching encode/decode changes must not hide drift.
	const originalHex = "001641674943416749434167494341674943416749434167000674656e616e7400136964656e746974792e6f74702e73" +
		"69676e696e001568747470733a2f2f6964656e746974792e74657374000000056c6f67696e0014323032362d31302d30" +
		"375431323a30303a30305a0014323032362d31302d30375431323a30353a30305a010000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000b010000034630b8a000000001a3185c50000000000df847" +
		"5800000000d18c2e28000000000301000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000001"
	wire, err := hex.DecodeString(originalHex)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := issuanceRecordSeed(t).Bindings()
	continuation, _ := seed.Continuation.Bindings()
	original, ok := continuation.Authorization.PreAuthTransaction()
	if !ok {
		t.Fatal("legacy seed has no original pre-auth")
	}
	want, _ := original.Bindings()
	reader := recordReader{data: wire, ok: true}
	restored, err := readPreAuthRecord(&reader)
	if err != nil {
		t.Fatal("pre-change unbound custody cannot restore", err)
	}
	got, err := restored.Bindings()
	if err != nil || got != want || len(reader.data) != 0 {
		t.Fatal("pre-change custody changed original fields or gained a target binding", err)
	}
	if !bytes.Equal(appendPreAuthRecord(nil, original), wire) {
		t.Fatal("legacy unbound custody no longer emits its original bytes")
	}
}

func TestOTPPreAuthCustodyRetainsOriginalIdentifierBinding(t *testing.T) {
	_, challenge, _, _, _ := issuanceCustodyFixture(t, false)
	issued, _ := challenge.Bindings()
	continuation, _ := issued.Continuation.Bindings()
	original, _ := continuation.Authorization.PreAuthTransaction()
	spec, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.Intent.IdentifierBinding = [32]byte{77}
	bound, err := session.NewPreAuthTransaction(spec)
	if err != nil {
		t.Fatal(err)
	}
	wire := appendPreAuthRecord(nil, bound)
	reader := recordReader{data: wire, ok: true}
	restored, err := readPreAuthRecord(&reader)
	if err != nil {
		t.Fatal("bound original pre-auth cannot restore", err)
	}
	got, err := restored.Bindings()
	if err != nil || got != spec || len(reader.data) != 0 {
		t.Fatal("OTP custody dropped original identifier target", err)
	}
	if !bytes.Equal(wire, appendPreAuthRecord(nil, restored)) {
		t.Fatal("bound pre-auth bytes were renewed or reinterpreted")
	}
}

func FuzzPhonePreAuthCustody(f *testing.F) {
	seed, _ := issuanceRecordSeed(f).Bindings()
	continuation, _ := seed.Continuation.Bindings()
	original, _ := continuation.Authorization.PreAuthTransaction()
	spec, _ := original.Bindings()
	f.Add(appendPreAuthRecord(nil, original))
	spec.Binding.Intent.IdentifierBinding = [32]byte{77}
	bound, err := session.NewPreAuthTransaction(spec)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(appendPreAuthRecord(nil, bound))
	f.Add([]byte(identifierBoundPreAuthRecordPrefix))
	f.Add(append([]byte(identifierBoundPreAuthRecordPrefix), make([]byte, 32)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		reader := recordReader{data: data, ok: true}
		record, err := readPreAuthRecord(&reader)
		if err == nil && len(reader.data) == 0 && !bytes.Equal(appendPreAuthRecord(nil, record), data) {
			t.Fatal("pre-auth custody parser admitted noncanonical target framing")
		}
	})
}
