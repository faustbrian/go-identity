package postgres

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func TestProxyPreviewCallbackGrantPinsOnlyItsOriginalBrowser(t *testing.T) {
	_, production, _ := proxyBindingFixture(t)
	issued := production.IssuedAt.Truncate(time.Second)
	l := proxyPreviewBindingLocator{Tenant: production.Tenant, Flow: production.Transaction, OriginCommand: production.OriginCommand,
		CallbackCommand: production.CallbackCommand, IssuedAt: issued, ExpiresAt: issued.Add(4 * time.Minute)}
	digest := [32]byte{47}
	p := proxyPreviewGrantPayload(l, "https://preview.example", "browser", digest)
	if p.Operation != "identity.oauth.callback" || p.Bearer || p.MaxUses != 1 || p.Subject != string(l.Flow) || p.Resource != string(l.Flow) ||
		p.CorrelationID != string(l.OriginCommand) || p.Tenant != string(l.Tenant) || p.ExpiresAt != l.ExpiresAt || p.IssuedAt != issued || p.NotBefore != issued ||
		len(p.Caveats) != 1 || p.Caveats[proxyPreviewBindingCaveat] != base64.RawURLEncoding.EncodeToString(digest[:]) ||
		!matchesProxyPreviewGrant(l, "https://preview.example", "browser", digest, p) {
		t.Fatal("preview grant does not bind its exact original browser and deadline")
	}
	for name, change := range map[string]func(*capability.Payload){
		"ordinary RP": func(p *capability.Payload) {
			p.Caveats = map[string]string{"identity.oauth.rp.binding": base64.RawURLEncoding.EncodeToString(digest[:])}
		},
		"bearer":        func(p *capability.Payload) { p.Bearer = true },
		"scope":         func(p *capability.Payload) { p.Resource = string(l.OriginCommand) },
		"origin":        func(p *capability.Payload) { p.CorrelationID = string(l.CallbackCommand) },
		"later expiry":  func(p *capability.Payload) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
		"renewed issue": func(p *capability.Payload) { p.IssuedAt = p.IssuedAt.Add(time.Second) },
		"audiences":     func(p *capability.Payload) { p.Audiences = []string{"browser", "foreign"} },
		"other tenant":  func(p *capability.Payload) { p.Tenant = "foreign" },
		"extra caveat":  func(p *capability.Payload) { p.Caveats["other"] = "value" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proxyPreviewGrantPayload(l, "https://preview.example", "browser", digest)
			change(&candidate)
			if matchesProxyPreviewGrant(l, "https://preview.example", "browser", digest, candidate) {
				t.Fatal("preview selected a substituted grant")
			}
		})
	}
}
