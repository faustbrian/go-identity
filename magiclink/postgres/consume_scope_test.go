package magiclinkpostgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
)

// These tests authenticate actual signed grants, not manufactured metadata.
// Durable origin lookup, browser possession and atomic session effects remain
// separate native integration obligations; this pure scope check proves none.
func TestConsumptionScopeMatchesSignedOriginal(t *testing.T) {
	p, selected := signedRequestScopeFixture(t)
	spec, _ := p.original.Feature()
	id, _ := identity.NewCommandID()
	r := magiclink.ConsumeRequest{TenantID: spec.Binding.TenantID, CommandID: id, PreAuthID: identity.PreAuthTransactionID(spec.Binding.AnonymousFlowID), Callback: p.request.Callback, Origin: "https://app.test", Caller: authorization.DecisionContext{Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "ingress"}}}}
	payload, err := p.payload(selected)
	if err != nil {
		t.Fatal(err)
	}
	payload.ID = string(spec.Binding.CommandID)
	grant := signConsumptionScope(t, payload, selected.issued)
	got, err := p.service.validateConsumptionScope(r, p.flow, grant, spec.Binding.CommandID, selected.recipient, selected.issued)
	if err != nil || got.factor != selected.factor || got.recipient != selected.recipient || !got.issued.Equal(selected.issued) || !got.expires.Equal(selected.expires) {
		t.Fatal("consumption lost original signed recipient/factor/timeline", err)
	}
	for name, change := range map[string]func(*capability.Payload){
		"issuer":               func(p *capability.Payload) { p.Issuer = "https://foreign.test" },
		"audience":             func(p *capability.Payload) { p.Audiences = []string{"foreign"} },
		"tenant":               func(p *capability.Payload) { p.Tenant = "foreign" },
		"recipient":            func(p *capability.Payload) { p.Subject = "foreign" },
		"resource":             func(p *capability.Payload) { p.Resource = "identity.magiclink/foreign" },
		"origin-command":       func(p *capability.Payload) { p.CorrelationID = string(id) },
		"multiple-uses":        func(p *capability.Payload) { p.MaxUses = 2 },
		"different-purpose":    func(p *capability.Payload) { p.Operation = "identity.identifier.verify" },
		"missing-factor":       func(p *capability.Payload) { delete(p.Caveats, "magiclink.factor-version") },
		"zero-factor":          func(p *capability.Payload) { p.Caveats["magiclink.factor-version"] = "0" },
		"noncanonical-factor":  func(p *capability.Payload) { p.Caveats["magiclink.factor-version"] = "07" },
		"overflow-factor":      func(p *capability.Payload) { p.Caveats["magiclink.factor-version"] = "18446744073709551616" },
		"identifier":           func(p *capability.Payload) { p.Caveats["magiclink.identifier"] = "foreign" },
		"identifier-version":   func(p *capability.Payload) { p.Caveats["magiclink.identifier-version"] = "1" },
		"verification-version": func(p *capability.Payload) { p.Caveats["magiclink.verification-version"] = "1" },
		"user-authority":       func(p *capability.Payload) { p.Caveats["magiclink.user-authority-version"] = "1" },
		"identifier-authority": func(p *capability.Payload) { p.Caveats["magiclink.identifier-authority-version"] = "1" },
		"credential-authority": func(p *capability.Payload) { p.Caveats["magiclink.credential-authority-version"] = "1" },
		"mailbox":              func(p *capability.Payload) { p.Caveats["magiclink.canonical-email"] = "foreign@example.test" },
		"callback":             func(p *capability.Payload) { p.Caveats["magiclink.callback"] = "https://foreign.test" },
		"signup-upgrade":       func(p *capability.Payload) { p.Caveats["magiclink.intent"] = "signup-if-allowed" },
		"foreign-flow":         func(p *capability.Payload) { p.Caveats["magiclink.flow"] = string(id) },
		"changed-flow":         func(p *capability.Payload) { p.Caveats["magiclink.flow-binding"] = strings.Repeat("0", 64) },
		"different-profile":    func(p *capability.Payload) { p.Caveats["magiclink.profile"] = strings.Repeat("0", 64) },
		"unknown-caveat":       func(p *capability.Payload) { p.Caveats["magiclink.override"] = "allow" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := grant.Payload()
			change(&changed)
			foreign := signConsumptionScope(t, changed, selected.issued)
			if _, err := p.service.validateConsumptionScope(r, p.flow, foreign, spec.Binding.CommandID, selected.recipient, selected.issued); err == nil {
				t.Fatal("signed foreign grant became login authority")
			}
		})
	}
	if _, err := p.service.validateConsumptionScope(r, p.flow, grant, spec.Binding.CommandID, selected.recipient, selected.expires); err == nil {
		t.Fatal("original exclusive expiry renewed")
	}
	selected.recipient.UserAuthorityVersion++
	if _, err := p.service.validateConsumptionScope(r, p.flow, grant, spec.Binding.CommandID, selected.recipient, selected.issued); err == nil {
		t.Fatal("changed current recipient authority accepted")
	}
}

func signConsumptionScope(t *testing.T, payload capability.Payload, now time.Time, configured ...capability.Limits) capability.Grant {
	t.Helper()
	signer, _ := capability.NewHMACSHA256Signer("test", []byte(strings.Repeat("x", 32)))
	verifier, _ := capability.NewHMACSHA256Verifier([]byte(strings.Repeat("x", 32)))
	keys, _ := capability.NewKeySet([]capability.Key{{ID: "test", Verifier: verifier}})
	limits := capability.DefaultLimits()
	if len(configured) != 0 {
		limits = configured[0]
	}
	token, err := capability.Issue(context.Background(), payload, signer, limits)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := capability.Verify(context.Background(), token, keys, capability.VerifyOptions{Now: now, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}
