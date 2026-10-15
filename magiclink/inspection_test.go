package magiclink_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	memory "github.com/faustbrian/go-capability/v2/adapters/memory"
	"github.com/faustbrian/go-identity/magiclink"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func inspectionFixture(t testing.TB) (capability.Service, capability.Payload, magiclink.InspectionConfig, *time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	key := []byte("0123456789abcdef0123456789abcdef")
	signer, err := capability.NewHMACSHA256Signer("test-key", key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "https://issuer.example.test", ID: "test-key", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := capability.NewService(capability.ServiceConfig{Issuer: "https://issuer.example.test", Signer: signer, Resolver: keys, Clock: func() time.Time { return now }, Limits: capability.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	p := capability.Payload{Version: 1, ID: "link-one", Issuer: "https://issuer.example.test", Audiences: []string{"identity"}, Subject: "user-one", Tenant: "tenant-one", Resource: "identity.magiclink/email-one", Operation: "identity.magic-link.consume", CorrelationID: "request-one", IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Minute), MaxUses: 1, Caveats: map[string]string{"magiclink.identifier": "email-one", "magiclink.callback": "https://app.example.test/finish", "magiclink.intent": "signin-only"}}
	c := magiclink.InspectionConfig{Verifier: s, Tenant: "tenant-one", Issuer: p.Issuer, Audience: "identity", Callbacks: []string{p.Caveats["magiclink.callback"]}, MaximumLifetime: time.Minute, Timeout: time.Second}
	return s, p, c, &now
}

func TestScannerInspectionDoesNotConsumeOrTransferProof(t *testing.T) {
	s, p, c, now := inspectionFixture(t)
	proof, _, err := s.Issue(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := magiclink.NewInspector(c)
	if err != nil {
		t.Fatal(err)
	}
	// Construction snapshots callback policy rather than borrowing a mutable slice.
	c.Callbacks[0] = "https://foreign.example.test/finish"
	for range 3 {
		out, err := inspector.Inspect(context.Background(), magiclink.InspectionRequest{Token: proof, Callback: p.Caveats["magiclink.callback"]})
		if err != nil || !out.SignatureValid || out.Intent != magiclink.SignInOnly {
			t.Fatal("scanner inspection rejected signed scope", err)
		}
	}
	grant, err := s.Verify(context.Background(), proof, "identity.magic-link.consume", "identity")
	if err != nil {
		t.Fatal("inspection transferred or destroyed proof", err)
	}
	store, err := memory.NewConsumptionStore(fixedClock{*now})
	if err != nil {
		t.Fatal(err)
	}
	use, err := grant.Consume(context.Background(), store)
	if err != nil || use.Use != 1 || use.Remaining != 0 {
		t.Fatal("explicit first consumption unavailable", err)
	}
	if _, err = grant.Consume(context.Background(), store); !errors.Is(err, capability.ErrReplayExhausted) {
		t.Fatal("one-use control failed")
	}
	// Inspection deliberately makes no remaining-use or current-login claim.
	if _, err := inspector.Inspect(context.Background(), magiclink.InspectionRequest{Token: proof, Callback: p.Caveats["magiclink.callback"]}); err != nil {
		t.Fatal("inspection acquired consumption semantics", err)
	}
}

func TestInspectionRejectsForeignSignedAuthority(t *testing.T) {
	s, base, c, now := inspectionFixture(t)
	i, err := magiclink.NewInspector(c)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*capability.Payload){
		"tenant":             func(p *capability.Payload) { p.Tenant = "foreign" },
		"issuer":             func(p *capability.Payload) { p.Issuer = "https://foreign.example.test" },
		"purpose":            func(p *capability.Payload) { p.Operation = "identity.password.reset-complete" },
		"audience":           func(p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"multiple audiences": func(p *capability.Payload) { p.Audiences = []string{"identity", "foreign"} },
		"reusable":           func(p *capability.Payload) { p.MaxUses = 0 },
		"multiple uses":      func(p *capability.Payload) { p.MaxUses = 2 },
		"bearer":             func(p *capability.Payload) { p.Subject = ""; p.Bearer = true },
		"resource":           func(p *capability.Payload) { p.Resource = "identity.magiclink/foreign" },
		"callback":           func(p *capability.Payload) { p.Caveats["magiclink.callback"] = "https://foreign.example.test/finish" },
		"intent":             func(p *capability.Payload) { p.Caveats["magiclink.intent"] = "unknown" },
		"missing intent":     func(p *capability.Payload) { delete(p.Caveats, "magiclink.intent") },
		"lifetime":           func(p *capability.Payload) { p.ExpiresAt = p.IssuedAt.Add(2 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			p.Caveats = make(map[string]string)
			for k, v := range base.Caveats {
				p.Caveats[k] = v
			}
			change(&p)
			var proof capability.Proof
			var err error
			if name == "issuer" {
				signer, _ := capability.NewHMACSHA256Signer("test-key", []byte("0123456789abcdef0123456789abcdef"))
				wire, e := capability.Issue(context.Background(), p, signer, capability.DefaultLimits())
				if e != nil {
					t.Fatal(e)
				}
				proof, err = capability.ParseProof(wire, capability.DefaultLimits())
			} else {
				proof, _, err = s.Issue(context.Background(), p)
			}
			if err != nil {
				t.Fatal(err)
			}
			out, err := i.Inspect(context.Background(), magiclink.InspectionRequest{Token: proof, Callback: base.Caveats["magiclink.callback"]})
			if err == nil || out != (magiclink.InspectionResult{}) {
				t.Fatal("foreign signed scope inspected")
			}
		})
	}
	proof, _, err := s.Issue(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	*now = base.ExpiresAt.Add(time.Second)
	if out, err := i.Inspect(context.Background(), magiclink.InspectionRequest{Token: proof, Callback: base.Caveats["magiclink.callback"]}); err == nil || out != (magiclink.InspectionResult{}) {
		t.Fatal("expired proof inspected")
	}
}

type failingVerifier struct {
	err        error
	panicValue bool
}

func (f failingVerifier) Verify(context.Context, capability.Proof, capability.Purpose, string) (capability.Grant, error) {
	if f.panicValue {
		panic("must not enter diagnostics")
	}
	return capability.Grant{}, f.err
}

func TestInspectionFailureIsBoundedRedactedAndNonAuthoritative(t *testing.T) {
	s, p, c, _ := inspectionFixture(t)
	proof, _, err := s.Issue(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	r := magiclink.InspectionRequest{Token: proof, Callback: p.Caveats["magiclink.callback"]}
	for name, v := range map[string]failingVerifier{
		"panic":             {panicValue: true},
		"outage":            {err: errors.New("sensitive upstream failure")},
		"revocation outage": {err: capability.ErrRevocationUnknown},
		"revoked":           {err: capability.ErrRevoked},
	} {
		t.Run(name, func(t *testing.T) {
			cc := c
			cc.Verifier = v
			i, e := magiclink.NewInspector(cc)
			if e != nil {
				t.Fatal(e)
			}
			out, e := i.Inspect(context.Background(), r)
			var classified magiclink.InspectionError
			if out != (magiclink.InspectionResult{}) || !errors.As(e, &classified) {
				t.Fatal("failure exposed result", e)
			}
			want := magiclink.InspectionUnavailable
			if name == "revoked" {
				want = magiclink.InspectionDenied
			}
			if classified.Code != want {
				t.Fatal("failure misclassified")
			}
			if strings.Contains(fmt.Sprintf("%+v", e), "sensitive") || strings.Contains(e.Error(), "diagnostics") {
				t.Fatal("upstream diagnostics leaked")
			}
		})
	}
	i, err := magiclink.NewInspector(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if out, e := i.Inspect(ctx, r); !errors.Is(e, context.Canceled) || out != (magiclink.InspectionResult{}) {
		t.Fatal("cancellation lost", e)
	}
	for _, callback := range []string{r.Callback + "#", r.Callback + "#token", "https://app.example.test.evil/finish", r.Callback + "?token=not-the-original-callback", "https://user@app.example.test/finish"} {
		if out, e := i.Inspect(context.Background(), magiclink.InspectionRequest{Token: proof, Callback: callback}); e == nil || out != (magiclink.InspectionResult{}) {
			t.Fatal("unbound callback accepted")
		}
	}
	if _, e := json.Marshal(r); e == nil {
		t.Fatal("request serialized")
	}
	if _, e := r.MarshalText(); e == nil {
		t.Fatal("request text serialized")
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "app.example.test") {
		t.Fatal("callback logged")
	}
	// Structural parsing must never turn an altered signature into authority.
	var wire string
	if err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error { wire = string(b); return nil }); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(wire, ".")
	signature, e := base64.RawURLEncoding.DecodeString(parts[3])
	if e != nil {
		t.Fatal(e)
	}
	signature[0] ^= 0x80
	parts[3] = base64.RawURLEncoding.EncodeToString(signature)
	forged, e := capability.ParseProof(strings.Join(parts, "."), capability.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	if out, e := i.Inspect(context.Background(), magiclink.InspectionRequest{Token: forged, Callback: r.Callback}); e == nil || out != (magiclink.InspectionResult{}) {
		t.Fatal("forged signature inspected")
	}
	if out, e := i.Inspect(context.Background(), r); e == nil || out != (magiclink.InspectionResult{}) {
		t.Fatal("transferred proof inspected")
	}
}

func TestInspectionRejectsInvalidComposition(t *testing.T) {
	_, _, c, _ := inspectionFixture(t)
	for name, change := range map[string]func(*magiclink.InspectionConfig){
		"nil verifier":       func(c *magiclink.InspectionConfig) { c.Verifier = nil },
		"zero tenant":        func(c *magiclink.InspectionConfig) { c.Tenant = "" },
		"insecure issuer":    func(c *magiclink.InspectionConfig) { c.Issuer = "http://issuer.example.test" },
		"zero audience":      func(c *magiclink.InspectionConfig) { c.Audience = "" },
		"zero callbacks":     func(c *magiclink.InspectionConfig) { c.Callbacks = nil },
		"fragment":           func(c *magiclink.InspectionConfig) { c.Callbacks = []string{"https://app.example.test/finish#"} },
		"zero timeout":       func(c *magiclink.InspectionConfig) { c.Timeout = 0 },
		"unbounded timeout":  func(c *magiclink.InspectionConfig) { c.Timeout = 2 * time.Minute },
		"zero lifetime":      func(c *magiclink.InspectionConfig) { c.MaximumLifetime = 0 },
		"unbounded lifetime": func(c *magiclink.InspectionConfig) { c.MaximumLifetime = 25 * time.Hour },
	} {
		t.Run(name, func(t *testing.T) {
			cc := c
			change(&cc)
			if i, e := magiclink.NewInspector(cc); e == nil || i != nil {
				t.Fatal("invalid configuration constructed")
			}
		})
	}
}

func FuzzInspectionInput(f *testing.F) {
	f.Add("", "https://app.example.test/finish")
	f.Add("not-a-proof", "https://app.example.test/finish#")
	s, p, _, _ := inspectionFixture(f)
	proof, _, err := s.Issue(context.Background(), p)
	if err != nil {
		f.Fatal(err)
	}
	if err := proof.Transfer(context.Background(), func(_ context.Context, b []byte) error { f.Add(string(b), p.Caveats["magiclink.callback"]); return nil }); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, token, callback string) {
		if len(token) > 8192 || len(callback) > 4096 {
			t.Skip()
		}
		s, _, c, _ := inspectionFixture(t)
		i, err := magiclink.NewInspector(c)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := capability.ParseProof(token, capability.DefaultLimits())
		if err != nil {
			return
		}
		out, err := i.Inspect(context.Background(), magiclink.InspectionRequest{Token: proof, Callback: callback})
		if err != nil && out != (magiclink.InspectionResult{}) {
			t.Fatal("denied input acquired inspection result")
		}
		if err == nil {
			grant, e := s.Verify(context.Background(), proof, "identity.magic-link.consume", "identity")
			if e != nil || !out.SignatureValid || grant.Payload().Caveats["magiclink.callback"] != callback {
				t.Fatal("inspection acquired unsigned scope")
			}
		}
	})
}
