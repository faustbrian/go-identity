package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
)

// Reuse only the existing real signing/envelope fixture. No password session or
// LinkService is used by the new production owner, nor is zero risk custody
// presented here as permission to execute a native authentication workflow.
func signinOutputFixture(t *testing.T) *signinStartPhase {
	t.Helper()
	legacy, clock, _ := rpOutputFixture(t)
	r, flow, _, now := signinBrowserFixture(t)
	*clock = now
	config := legacy.service.config()
	profile := legacy.service.profiles[legacy.input.Provider]
	r.Provider = oauth.ProviderID(profile.ID)
	r.Scopes, _ = oauth.NewScopeSet(profile.Scopes)
	s := &SigninService{issuer: legacy.service.issuer, checkpoint: legacy.service.checkpoint, envelopes: legacy.service.envelopes, verifiers: legacy.service.verifiers, profiles: map[string]oauth.ProviderProfile{profile.ID: profile}, profile: [32]byte{91}, config: SigninServiceConfig{StateLifetime: 10 * time.Minute, Capability: config.Capability, CurrentEnvelopeKey: config.CurrentEnvelopeKey, EnvelopeKeys: config.EnvelopeKeys, CurrentStateKeyVersion: config.CurrentStateKeyVersion, StateKeys: config.StateKeys}}
	flowSum, err := signinFlowDigest(flow)
	if err != nil {
		t.Fatal(err)
	}
	b := legacy.input.Binding
	op := rpSigninStartOperation()
	b.UserID, b.AnonymousFlowID, b.ActorID, b.ActorKind = "", string(r.FlowID), "oauth-login", r.Caller.Request.Subject.Kind
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	callback, failure := r.Callback.URL(), r.ErrorCallback.URL()
	input := &signinStartInput{Binding: b, Profile: s.profile, Flow: flowSum, Provider: profile.ID, Network: r.Network, Device: r.Device, Callback: callback.String(), ErrorCallback: failure.String(), Started: now, ValidUntil: now.Add(20 * time.Second), GlobalVersion: 1, TenantVersion: 1}
	return &signinStartPhase{service: s, request: r, flow: flow, flowSum: flowSum, input: input}
}

func TestSigninStartOutputRetainsAnonymousFlowAndOriginalLifetime(t *testing.T) {
	p := signinOutputFixture(t)
	wire, err := p.generateOutput(context.Background(), 1, risk.AuthenticationAdmission{})
	if err != nil {
		t.Fatal("local original state generation", err)
	}
	out, _, plan, err := p.restoreOutput(context.Background(), 1, wire)
	if err != nil || len(plan.Grants) != 1 {
		t.Fatal("original generated output restoration", err)
	}
	flow, _ := p.flow.Bindings()
	if out.Binding.Input.Binding.UserID != "" || out.Binding.Input.Binding.AnonymousFlowID != string(flow.Binding.ID) || out.Binding.Input.Flow != p.flowSum || !out.Binding.ExpiresAt.Equal(flow.Binding.ExpiresAt) || !plan.Grants[0].ExpiresAt.Equal(out.Binding.ExpiresAt) {
		t.Fatal("state generation selected a user, changed browser, or renewed expiry")
	}
	if _, _, _, err := p.restoreOutput(context.Background(), 2, wire); err == nil {
		t.Fatal("output adopted a different generation")
	}
	corrupt := bytes.Clone(wire)
	corrupt[len(corrupt)-1] ^= 1
	if _, _, _, err := p.restoreOutput(context.Background(), 1, corrupt); err == nil {
		t.Fatal("corrupt output admitted")
	}
	changed := *p
	input := *p.input
	input.Flow[0] ^= 1
	changed.input = &input
	if _, _, _, err := changed.restoreOutput(context.Background(), 1, wire); err == nil {
		t.Fatal("different original browser adopted generated state")
	}
	if _, _, _, err := p.restoreOutput(context.Background(), 1, nil); err == nil {
		t.Fatal("empty output admitted")
	}
}
