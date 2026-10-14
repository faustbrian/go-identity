package otp_test

import (
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

func preAuthID() identity.PreAuthTransactionID {
	return identity.PreAuthTransactionID("AQEBAQEBAQEBAQEBAQEBAQ")
}

func TestContinuationExactAuthorizationAndPolicyConservation(t *testing.T) {
	s := digestScopeSpec(t)
	s.AuthorizationBinding = [32]byte{}
	a, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: preAuthID()})
	p := rememberPolicy(t)
	c, e := otp.NewContinuation(s, a, p)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := c.Bindings()
	wire := []byte("identity-otp-authorization-v1\x00\x02\x00\x00\x00\x16AQEBAQEBAQEBAQEBAQEBAQ\x01")
	for _, n := range []uint64{uint64(24 * time.Hour), uint64(time.Hour), uint64(30 * time.Minute), uint64(15 * time.Minute)} {
		wire = binary.BigEndian.AppendUint64(wire, n)
	}
	if b.Scope.AuthorizationBinding != sha256.Sum256(wire) {
		t.Fatal("authorization framing changed")
	}
	base, _ := p.Bindings()
	for _, change := range []func(*session.RememberPolicySpec){
		func(s *session.RememberPolicySpec) { s.Choice = session.PersistentSession },
		func(s *session.RememberPolicySpec) { s.AbsoluteTTL -= time.Nanosecond },
		func(s *session.RememberPolicySpec) { s.IdleTTL -= time.Nanosecond },
		func(s *session.RememberPolicySpec) { s.RefreshAfter -= time.Nanosecond },
		func(s *session.RememberPolicySpec) { s.FreshFor += time.Nanosecond },
	} {
		policy := base
		change(&policy)
		remember, e := session.NewRememberPolicy(policy)
		if e != nil {
			t.Fatal(e)
		}
		other, e := otp.NewContinuation(s, a, remember)
		if e != nil {
			t.Fatal(e)
		}
		got, _ := other.Bindings()
		if got.RememberPolicy != remember || got.Scope.AuthorizationBinding == b.Scope.AuthorizationBinding {
			t.Fatal("remember changed or binding collapsed")
		}
	}
	// Changing a returned scalar projection does not mutate frozen continuation.
	b.Scope.TenantID = "changed"
	again, _ := c.Bindings()
	if again.Scope.TenantID != "tenant" {
		t.Fatal("projection mutation retained")
	}
	for _, purpose := range []otp.Purpose{otp.PurposeMFA, otp.PurposeSignin} {
		copy := s
		copy.Purpose = purpose
		if _, e := otp.NewContinuation(copy, a, p); e != nil {
			t.Fatal("preauth signin policy lost")
		}
	}
	if _, e := otp.NewContinuation(s, otp.FlowAuthorization{}, p); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("zero flow accepted")
	}
	copy := s
	copy.AuthorizationBinding = [32]byte{1}
	if _, e := otp.NewContinuation(copy, a, p); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("caller binding accepted")
	}
	copy = s
	copy.TenantID = ""
	if _, e := otp.NewContinuation(copy, a, p); !errors.Is(e, otp.ErrInvalidDigest) {
		t.Fatal("invalid scope accepted")
	}
	if _, e := (otp.Continuation{}).Bindings(); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("zero continuation projection")
	}
	if _, e := (otp.Continuation{}).DigestScope(); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("zero continuation scope")
	}
	spec, _ := a.Bindings()
	projection, _ := c.Bindings()
	for _, value := range []any{a, spec, c, projection} {
		for _, format := range []string{"%v", "%+v", "%#v", "%q", "%x"} {
			if !strings.Contains(fmt.Sprintf(format, value), "redacted") {
				t.Fatal("authorization formatting disclosed")
			}
		}
		if _, e := json.Marshal(value); e == nil {
			t.Fatal("authorization JSON allowed")
		}
		if _, e := value.(encoding.TextMarshaler).MarshalText(); !errors.Is(e, otp.ErrSensitiveSerialization) {
			t.Fatal("authorization text allowed")
		}
	}
}

func FuzzFlowAuthorization(f *testing.F) {
	f.Add(uint8(1), "session", "")
	f.Add(uint8(2), "", string(preAuthID()))
	f.Add(uint8(0), "session", string(preAuthID()))
	f.Fuzz(func(t *testing.T, kind uint8, sid, pid string) {
		validSession := len(sid) > 0 && len(sid) <= 128
		for _, r := range sid {
			validSession = validSession && r >= 33 && r <= 126
		}
		validPreAuth := false
		if len(pid) == 22 {
			raw, e := base64.RawURLEncoding.Strict().DecodeString(pid)
			validPreAuth = e == nil && len(raw) == 16 && base64.RawURLEncoding.EncodeToString(raw) == pid && string(raw) != strings.Repeat("\x00", 16)
		}
		want := (kind == 1 && validSession && pid == "") || (kind == 2 && validPreAuth && sid == "")
		s := otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationKind(kind), AuthenticatedSessionID: sid, PreAuthTransactionID: identity.PreAuthTransactionID(pid)}
		a, e := otp.NewFlowAuthorization(s)
		if (e == nil) != want {
			t.Fatal("closed union validity differs")
		}
		if want {
			b, e := a.Bindings()
			if e != nil || b != s {
				t.Fatal("accepted authority changed")
			}
		}
	})
}

func rememberPolicy(t *testing.T) session.RememberPolicy {
	t.Helper()
	p, e := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: 30 * time.Minute, FreshFor: 15 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	return p
}

func TestFlowAuthorizationRequiresExplicitDisjointVariant(t *testing.T) {
	for _, s := range []otp.FlowAuthorizationSpec{
		{}, {AuthenticatedSessionID: "session"}, {PreAuthTransactionID: preAuthID()},
		{Kind: 99, AuthenticatedSessionID: "session"},
		{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session", PreAuthTransactionID: preAuthID()},
		{Kind: otp.FlowAuthorizationPreAuthTransaction, AuthenticatedSessionID: "session", PreAuthTransactionID: preAuthID()},
		{Kind: otp.FlowAuthorizationAuthenticatedSession}, {Kind: otp.FlowAuthorizationPreAuthTransaction},
		{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: "forged"},
		{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "bad\n"},
	} {
		if _, e := otp.NewFlowAuthorization(s); !errors.Is(e, otp.ErrInvalidAuthorization) {
			t.Fatal("ambiguous authority accepted")
		}
	}
	for _, s := range []otp.FlowAuthorizationSpec{
		{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session"},
		{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: preAuthID()},
	} {
		a, e := otp.NewFlowAuthorization(s)
		if e != nil {
			t.Fatal(e)
		}
		got, e := a.Bindings()
		if e != nil || got != s {
			t.Fatal("variant changed")
		}
	}
	if _, e := (otp.FlowAuthorization{}).Bindings(); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("zero authority accepted")
	}
}

func TestContinuationBindsRememberWithoutInferringAuthority(t *testing.T) {
	s := digestScopeSpec(t)
	s.AuthorizationBinding = [32]byte{}
	a, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationPreAuthTransaction, PreAuthTransactionID: preAuthID()})
	p := rememberPolicy(t)
	c, e := otp.NewContinuation(s, a, p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Bindings()
	if e != nil || b.RememberPolicy != p || b.Scope.AuthorizationBinding == ([32]byte{}) {
		t.Fatal("policy lost")
	}
	if scope, e := c.DigestScope(); e != nil || scope == (otp.DigestScope{}) {
		t.Fatal("scope absent")
	}
	if _, e := otp.NewContinuation(s, a, session.RememberPolicy{}); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("signin remembered policy omitted")
	}
	authenticated, _ := otp.NewFlowAuthorization(otp.FlowAuthorizationSpec{Kind: otp.FlowAuthorizationAuthenticatedSession, AuthenticatedSessionID: "session"})
	if _, e := otp.NewContinuation(s, authenticated, p); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("authenticated authority used for signin")
	}
	s.Purpose = otp.PurposeEmailVerification
	if _, e := otp.NewContinuation(s, a, p); !errors.Is(e, otp.ErrInvalidAuthorization) {
		t.Fatal("non-signin policy smuggled")
	}
	if _, e := otp.NewContinuation(s, a, session.RememberPolicy{}); e != nil {
		t.Fatal(e)
	}
}
