package identity_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

func passwordChangeProof(s identity.FeatureCommandSpec) auth.ReauthenticationProof {
	now := time.Date(2026, 10, 9, 20, 0, 0, 123456789, time.UTC)
	return auth.ReauthenticationProof{Proof: auth.Proof{
		ID: auth.ProofID(strings.Repeat("p", 22)), Tenant: string(s.Binding.TenantID), Subject: string(s.Binding.UserID),
		Method: "password", Assurance: 1, Purpose: "identity.password.verify", Audience: "identity-platform",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}, SessionID: "original-session", SessionVersion: math.MaxUint64, Action: s.Operation.OperationID}
}

func TestFeaturePasswordChangeRetainsAllCustodyAndClosesLegacyPaths(t *testing.T) {
	s := passwordHashFeatureSpec()
	p := passwordChangeProof(s)
	original := p
	hash := "$synthetic$private-verifier"
	needle := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32)))
	bearer := auth.NewBearerCredential(needle)
	c, err := identity.NewFeaturePasswordChangeCommand(s, hash, bearer, p)
	if err != nil {
		t.Fatal(err)
	}
	p.SessionID, s.Fields[0].Name = "mutated", "mutated"
	gotHash, gotBearer, gotProof, ok := c.PasswordChangeCustody()
	if !ok || gotHash != hash || gotBearer.Token() != needle || gotProof != original {
		t.Fatal("original custody changed")
	}
	metadata, ok := c.PasswordChangeFeature()
	if !ok || metadata.Binding != passwordHashFeatureSpec().Binding {
		t.Fatal("scope lost")
	}
	metadata.Fields[0].Name = "projection-mutation"
	metadata, _ = c.PasswordChangeFeature()
	if metadata.Fields[0].Name == "projection-mutation" {
		t.Fatal("projection aliases custody")
	}
	if _, ok := c.Feature(); ok {
		t.Fatal("legacy feature could discard authentication custody")
	}
	if _, ok := c.PasswordHashFeature(); ok {
		t.Fatal("hash-only path could discard authentication custody")
	}
	if _, ok := c.PasswordHash(); ok {
		t.Fatal("hash-only borrower admitted")
	}
	if _, ok := c.SessionToken(); ok {
		t.Fatal("session-only borrower admitted")
	}
	if _, ok := c.OneTimeCode(); ok {
		t.Fatal("OTP borrower admitted")
	}
	if _, ok := c.PreAuthCookie(); ok {
		t.Fatal("cookie borrower admitted")
	}
	type wrapper struct{ command identity.Command }
	for _, value := range []any{c, &c, wrapper{c}, &wrapper{c}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, hash) || strings.Contains(text, needle) || strings.Contains(text, original.SessionID) {
				t.Fatal("diagnostics disclosed custody")
			}
		}
	}
	if b, err := json.Marshal(c); err == nil || strings.Contains(string(b), needle) {
		t.Fatal("command serialized")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			h, b, p, ok := c.PasswordChangeCustody()
			if !ok || h != hash || b.Token() != needle || p != original {
				t.Error("concurrent custody changed")
			}
		})
	}
	wg.Wait()
}

func TestFeaturePasswordChangeRejectsWrongScopeAndMalformedCustody(t *testing.T) {
	s := passwordHashFeatureSpec()
	bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32))))
	for _, mutate := range []func(*identity.FeatureCommandSpec, *auth.ReauthenticationProof, *string, *auth.BearerCredential){
		func(s *identity.FeatureCommandSpec, _ *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			s.Operation.SchemaVersion = 2
			s.Binding.SchemaVersion = 2
		},
		func(s *identity.FeatureCommandSpec, _ *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			s.Operation.SchemaID = "other"
			s.Binding.SchemaID = "other"
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.Proof.Tenant = "foreign"
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.Proof.Subject = "foreign"
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.Action = "identity.password.reset-complete"
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.Proof.Purpose = "other"
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.SessionVersion = 0
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.SessionID = strings.Repeat("s", 129)
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.Proof.ID = ""
		},
		func(_ *identity.FeatureCommandSpec, p *auth.ReauthenticationProof, _ *string, _ *auth.BearerCredential) {
			p.Proof.ExpiresAt = p.Proof.IssuedAt
		},
		func(_ *identity.FeatureCommandSpec, _ *auth.ReauthenticationProof, h *string, _ *auth.BearerCredential) {
			*h = strings.Repeat("h", 16385)
		},
		func(_ *identity.FeatureCommandSpec, _ *auth.ReauthenticationProof, h *string, _ *auth.BearerCredential) {
			*h = "not\ncanonical"
		},
		func(_ *identity.FeatureCommandSpec, _ *auth.ReauthenticationProof, _ *string, b *auth.BearerCredential) {
			*b = auth.NewBearerCredential("malformed")
		},
	} {
		copy, p, h, b := s, passwordChangeProof(s), "synthetic", bearer
		mutate(&copy, &p, &h, &b)
		c, err := identity.NewFeaturePasswordChangeCommand(copy, h, b, p)
		if err == nil {
			t.Fatal("invalid command accepted")
		}
		if h, b, p, ok := c.PasswordChangeCustody(); ok || h != "" || b.Token() != "" || p != (auth.ReauthenticationProof{}) {
			t.Fatal("rejected command retained custody")
		}
	}
	plain, _ := identity.NewFeatureCommand(s)
	hashOnly, _ := identity.NewFeaturePasswordHashCommand(s, "synthetic")
	for _, c := range []identity.Command{{}, plain, hashOnly} {
		if _, ok := c.PasswordChangeFeature(); ok {
			t.Fatal("other variant admitted")
		}
		if _, _, _, ok := c.PasswordChangeCustody(); ok {
			t.Fatal("other variant borrowed")
		}
	}
}

func FuzzFeaturePasswordChangeTransport(f *testing.F) {
	f.Add("synthetic", strings.Repeat("b", 32), "original-session", uint64(1))
	f.Add("not\ncanonical", "", "", uint64(0))
	f.Fuzz(func(t *testing.T, hash, raw, session string, version uint64) {
		if len(hash) > 16385 || len(raw) > 65 || len(session) > 129 {
			return
		}
		s := passwordHashFeatureSpec()
		p := passwordChangeProof(s)
		p.SessionID, p.SessionVersion = session, version
		bearer := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString([]byte(raw)))
		c, err := identity.NewFeaturePasswordChangeCommand(s, hash, bearer, p)
		h, b, got, ok := c.PasswordChangeCustody()
		if err != nil {
			if ok || h != "" || b.Token() != "" || got != (auth.ReauthenticationProof{}) {
				t.Fatal("invalid transport retained custody")
			}
			return
		}
		if !ok || h != hash || b.Token() != bearer.Token() || got != p {
			t.Fatal("accepted transport changed")
		}
		if _, ok := c.Feature(); ok {
			t.Fatal("legacy feature admitted")
		}
		if _, ok := c.PasswordHashFeature(); ok {
			t.Fatal("legacy hash admitted")
		}
	})
}
