package postgres

import (
	"encoding/base64"
	"math"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

func TestProtectedPasswordChangeCountersPreserveOriginalCustody(t *testing.T) {
	r, err := NewRepository(protectedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := protectedCommand(t, "counter-tenant").Feature()
	s.Operation.SchemaID, s.Binding.SchemaID = "password-change", "password-change"
	at := time.Date(2026, 10, 9, 20, 0, 0, 123456000, time.UTC)
	proof := auth.ReauthenticationProof{Proof: auth.Proof{
		ID: auth.ProofID(strings.Repeat("p", 22)), Tenant: string(s.Binding.TenantID), Subject: string(s.Binding.UserID),
		Method: "password", Assurance: 1, Purpose: "identity.password.verify", Audience: "identity-platform",
		IssuedAt: at.Add(-time.Second), ExpiresAt: at.Add(time.Minute),
	}, SessionID: "original-session", SessionVersion: math.MaxUint64, Action: s.Operation.OperationID}
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	hash := "$synthetic$original-verifier"
	original, err := identity.NewFeaturePasswordChangeCommand(s, hash, bearer, proof)
	if err != nil {
		t.Fatal(err)
	}
	subject := risk.Subject{User: "subject", Session: "original-session", Network: "2001:db8::1"}
	mapped, plan, err := r.PrepareCommandCounters(original, subject, at)
	if err != nil {
		t.Fatal("authenticated password change rejected", err)
	}
	h, b, p, ok := mapped.PasswordChangeCustody()
	if !ok || h != hash || b.Token() != bearer.Token() || p != proof {
		t.Fatal("original custody lost or renewed")
	}
	metadata, ok := mapped.PasswordChangeFeature()
	if !ok || metadata.Binding != s.Binding || len(metadata.Fields) != len(s.Fields)+4 {
		t.Fatal("bound metadata lost")
	}
	if _, ok := mapped.Feature(); ok {
		t.Fatal("generic borrower admitted")
	}
	if _, ok := mapped.PasswordHashFeature(); ok {
		t.Fatal("hash-only borrower admitted")
	}
	if err := r.ValidateCommandCounters(mapped, plan); err != nil {
		t.Fatal("counter restoration rejected authenticated custody", err)
	}
	restored, err := r.restoreCounter(mapped, plan)
	if err != nil || !restored.command.Bindings().PreparedAt.Equal(at) {
		t.Fatal("original counter preparation time renewed", err)
	}
	if err := r.ValidateCommandCounters(original, plan); err == nil {
		t.Fatal("unprepared command admitted")
	}
	if _, _, err := r.PrepareCommandCounters(mapped, subject, at); err == nil {
		t.Fatal("reserved fields admitted twice")
	}
	wrong := subject
	wrong.User = "other"
	if _, _, err := r.PrepareCommandCounters(original, wrong, at); err == nil {
		t.Fatal("wrong subject admitted")
	}
	foreign := plan
	foreign.Fingerprint[0] ^= 1
	if err := r.ValidateCommandCounters(mapped, foreign); err == nil {
		t.Fatal("foreign plan admitted")
	}
	for _, name := range []string{"counter.network", "counter.session", "counter.key-versions"} {
		changed, _ := mapped.PasswordChangeFeature()
		for i := range changed.Fields {
			f := &changed.Fields[i]
			if f.Name != name {
				continue
			}
			switch name {
			case "counter.network":
				f.Value.Text = "192.0.2.1"
			case "counter.session":
				f.Value.Text = "other-session"
			case "counter.key-versions":
				f.Value.Bytes[3]++
			}
		}
		altered, err := identity.NewFeaturePasswordChangeCommand(changed, hash, bearer, proof)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.ValidateCommandCounters(altered, plan); err == nil {
			t.Fatalf("changed %s admitted", name)
		}
	}
	legacy, err := identity.NewFeaturePasswordHashCommand(s, hash)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.PrepareCommandCounters(legacy, subject, at); err == nil {
		t.Fatal("hash-only custody admitted")
	}
}
