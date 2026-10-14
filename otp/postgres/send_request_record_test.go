package postgres

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

func TestSendRequestRecordIsCodeFreeAndCanonical(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		_, challenge, spec, bearer, authority := issuanceCustodyFixture(t, authenticated)
		s, _ := challenge.Bindings()
		request := sendRequestRecord{continuation: s.Continuation, policy: s.Policy,
			issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt, authority: authority}
		wire, err := encodeSendRequestRecord(request, spec.Binding)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(wire, s.Digest.Value[:]) || bytes.Contains(wire, []byte(bearer.Token())) {
			t.Fatal("original request retained generated digest or submitted bearer")
		}
		decoded, err := decodeSendRequestRecord(wire, spec.Binding)
		if err != nil {
			t.Fatal(err)
		}
		again, err := encodeSendRequestRecord(decoded, spec.Binding)
		if err != nil || !bytes.Equal(wire, again) {
			t.Fatal("original request changed on restoration")
		}
		want, _ := request.continuation.Bindings()
		got, _ := decoded.continuation.Bindings()
		if got.Scope != want.Scope || got.RememberPolicy != want.RememberPolicy || decoded.policy != request.policy ||
			decoded.authority != authority || !decoded.issuedAt.Equal(s.IssuedAt) || !decoded.expiresAt.Equal(s.ExpiresAt) {
			t.Fatal("request scope, policy, primary expectations or original time changed")
		}
		for n := range len(wire) {
			if _, err := decodeSendRequestRecord(wire[:n], spec.Binding); err == nil {
				t.Fatal("truncated request accepted")
			}
		}
		if _, err := decodeSendRequestRecord(append(bytes.Clone(wire), 0), spec.Binding); err == nil {
			t.Fatal("trailing request bytes accepted")
		}
		if _, err := decodeIssuanceRecord(wire); err == nil {
			t.Fatal("code-free request became generated issuance")
		}
		if _, _, err := decodeBoundAuthorityRecord(wire, spec.Binding, true); err == nil {
			t.Fatal("original request entered generated authority profile")
		}
		if _, _, err := decodeAuthorityRecord(wire, spec.Binding); err == nil {
			t.Fatal("original request entered submitted attempt profile")
		}
		changed := spec.Binding
		changed.TenantID = "other"
		if _, err := decodeSendRequestRecord(wire, changed); err == nil {
			t.Fatal("cross-tenant request accepted")
		}
	}
}

func TestSendRequestRejectsInvalidOriginalDeclaration(t *testing.T) {
	_, challenge, spec, _, authority := issuanceCustodyFixture(t, false)
	s, _ := challenge.Bindings()
	base := sendRequestRecord{continuation: s.Continuation, policy: s.Policy, authority: authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt}
	for name, change := range map[string]func(*sendRequestRecord, *identity.CommandBinding){
		"zero continuation":   func(s *sendRequestRecord, _ *identity.CommandBinding) { s.continuation = otp.Continuation{} },
		"zero policy":         func(s *sendRequestRecord, _ *identity.CommandBinding) { s.policy = otp.AttemptPolicy{} },
		"zero authority":      func(s *sendRequestRecord, _ *identity.CommandBinding) { s.authority = AttemptAuthority{} },
		"zero time":           func(s *sendRequestRecord, _ *identity.CommandBinding) { s.issuedAt = time.Time{} },
		"fractional time":     func(s *sendRequestRecord, _ *identity.CommandBinding) { s.expiresAt = s.expiresAt.Add(time.Nanosecond) },
		"expired interval":    func(s *sendRequestRecord, _ *identity.CommandBinding) { s.expiresAt = s.issuedAt },
		"extended expiry":     func(s *sendRequestRecord, _ *identity.CommandBinding) { s.expiresAt = s.expiresAt.Add(time.Second) },
		"different challenge": func(_ *sendRequestRecord, b *identity.CommandBinding) { b.RecordID = "other" },
		"different tenant":    func(_ *sendRequestRecord, b *identity.CommandBinding) { b.TenantID = "other" },
		"wrong operation":     func(_ *sendRequestRecord, b *identity.CommandBinding) { b.OperationID = "identity.otp.check" },
	} {
		t.Run(name, func(t *testing.T) {
			r, binding := base, spec.Binding
			change(&r, &binding)
			if wire, err := encodeSendRequestRecord(r, binding); err == nil || wire != nil {
				t.Fatal("invalid original declaration encoded")
			}
		})
	}
	if _, err := decodeSendRequestRecord(bytes.Repeat([]byte{0}, 8193), spec.Binding); err == nil {
		t.Fatal("oversized request accepted")
	}
	if got := fmt.Sprintf("%#v", base); got != "otp.postgres.sendRequest(redacted)" {
		t.Fatal("request diagnostic disclosed custody")
	}
	if _, err := base.MarshalJSON(); err == nil {
		t.Fatal("request serialization allowed")
	}
	if _, err := base.MarshalText(); err == nil {
		t.Fatal("request text export allowed")
	}
}

func FuzzSendRequestRecord(f *testing.F) {
	challenge := issuanceRecordSeed(f)
	s, _ := challenge.Bindings()
	flow, _ := s.Continuation.Bindings()
	original, _ := flow.Authorization.PreAuthTransaction()
	p, _ := original.Bindings()
	op := issuanceOperation(identity.FeatureSubjectAnonymousFlow)
	binding := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", ActorID: "actor", ActorKind: "service-account", AnonymousFlowID: string(p.Binding.ID), RecordID: "challenge", OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "login", PolicyVersion: 11, CorrelationID: "correlation"}
	authority := AttemptAuthority{}
	authority.Directory.Query.GlobalAuthorityID, authority.Directory.Query.TenantID = "deployment", "tenant"
	authority.Directory.GlobalVersion, authority.Directory.TenantVersion = 1, 1
	request := sendRequestRecord{continuation: s.Continuation, policy: s.Policy, authority: authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt}
	wire, err := encodeSendRequestRecord(request, binding)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte(sendRequestRecordPrefix))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8193 {
			return
		}
		s, err := decodeSendRequestRecord(data, binding)
		if err != nil {
			return
		}
		got, err := encodeSendRequestRecord(s, binding)
		if err != nil || !bytes.Equal(data, got) {
			t.Fatal("noncanonical original request accepted")
		}
	})
}
