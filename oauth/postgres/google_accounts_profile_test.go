package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
)

func nativeGoogleProfile() oauth.ProviderProfile {
	p := verifierProfile()
	p.Issuer = "https://accounts.google.com"
	p.AuthorizationEndpoint, p.TokenEndpoint = "https://accounts.google.com/authorize", "https://token.example/token"
	p.ClientAuthentication, p.Scopes, p.Algorithms = oauth.PublicClient, []string{"openid"}, []string{"ES256"}
	p.Timeout, p.ClockSkew = time.Second, time.Minute
	p.MaxResponseBytes, p.MaxTokenBytes, p.MaxCodeBytes = 65536, 16384, 4096
	return p
}

func TestGoogleAccountsNativeProfileSnapshotAndExistingAAD(t *testing.T) {
	profile := nativeGoogleProfile()
	b := verifierBinding(t)
	b.provider = profile
	strict, err := b.aad()
	if err != nil {
		t.Fatal(err)
	}
	profile.GoogleAccounts = true
	selected, err := newRPVerifierBinding(b.tenant, profile, b.transactionID, b.stateDigest, b.operation)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := selected.aad()
	if err != nil || !reflect.DeepEqual(strict, aad) {
		t.Fatal("Google policy invented a second AAD authority", err)
	}
	profile.GoogleAccounts = false
	profile.Scopes[0] = "changed"
	copy := selected.profile()
	copy.GoogleAccounts = false
	copy.Scopes[0] = "changed-again"
	if !selected.profile().GoogleAccounts || selected.profile().Scopes[0] != "openid" {
		t.Fatal("caller changed native immutable selected policy")
	}
	invalid := nativeGoogleProfile()
	invalid.GoogleAccounts = true
	invalid.Issuer = "https://other.example"
	if _, err := newRPVerifierBinding(b.tenant, invalid, b.transactionID, b.stateDigest, b.operation); err == nil {
		t.Fatal("native Google profile admitted a different issuer")
	}
}

// The real signed-token/account/session journey is a separate integration
// consumer. These tests isolate retained canonical state/profile authentication,
// not primary admission, provider exchange or session issuance.
func TestGoogleAccountsNativeLinkPolicySwitchRejectsRetainedCallback(t *testing.T) {
	for name, selected := range map[string]bool{"Google to strict": true, "strict to Google": false} {
		t.Run(name, func(t *testing.T) { proveNativeLinkPolicySwitch(t, selected) })
	}
}

func proveNativeLinkPolicySwitch(t *testing.T, selected bool) {
	t.Helper()
	p, _, request, now := rpCallbackInputFixture(t)
	profile := nativeGoogleProfile()
	profile.GoogleAccounts = selected
	p.service.profiles[profile.ID] = profile
	wire, err := p.generateOutput(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"code": {"original-provider-code"}, "state": {out.Binding.State}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	request.Callback = parsed
	flow, err := p.service.authenticateRPCallback(context.Background(), request, out.Binding, out.StateProofCiphertext, *now)
	if err != nil {
		t.Fatal("retained selected link callback rejected", err)
	}
	flow.destroy()
	retained := bytes.Clone(out.BindingCiphertext)
	bound, err := json.Marshal(out.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bound, []byte(`"GoogleAccounts":true`)) != selected {
		t.Fatal("encrypted native state changed selected or legacy profile bytes")
	}
	digest := sha256.Sum256(bound)
	if flow.stateGrant.Payload().Caveats["identity.oauth.rp.binding"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("canonical native state fingerprint did not bind selected policy")
	}
	changedBinding := out.Binding
	changedBinding.Provider.GoogleAccounts = !selected
	changed, err := p.service.authenticateRPCallback(context.Background(), request, changedBinding, out.StateProofCiphertext, *now)
	changed.destroy()
	if err == nil {
		t.Fatal("retained state proof accepted a rewritten selection")
	}
	profile.GoogleAccounts = !selected
	p.service.profiles[profile.ID] = profile
	flow, err = p.service.authenticateRPCallback(context.Background(), request, out.Binding, out.StateProofCiphertext, *now)
	flow.destroy()
	if err == nil || !bytes.Equal(retained, out.BindingCiphertext) {
		t.Fatal("same-version link policy switch reinterpreted retained state")
	}
	if _, _, _, err := p.restoreOutput(context.Background(), 1, wire); err == nil {
		t.Fatal("link initiation replay adopted a different issuer policy")
	}
}

func TestGoogleAccountsNativeSigninPolicySwitchRejectsRetainedCallback(t *testing.T) {
	for name, selected := range map[string]bool{"Google to strict": true, "strict to Google": false} {
		t.Run(name, func(t *testing.T) { proveNativeSigninPolicySwitch(t, selected) })
	}
}

func proveNativeSigninPolicySwitch(t *testing.T, selected bool) {
	t.Helper()
	p, _, request, now := signinCallbackInputFixture(t)
	profile := nativeGoogleProfile()
	profile.GoogleAccounts = selected
	p.service.profiles[profile.ID] = profile
	wire, err := p.generateOutput(context.Background(), 1, risk.AuthenticationAdmission{})
	if err != nil {
		t.Fatal(err)
	}
	out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := p.openTransaction(context.Background(), out.Binding, out.BindingCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"code": {"original-provider-code"}, "state": {out.Binding.State}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	request.Callback = parsed
	flow, err := p.service.authenticateSigninCallback(context.Background(), request, stored, p.flow, out.StateProofCiphertext, now)
	if err != nil {
		t.Fatal("retained selected signin callback rejected", err)
	}
	flow.destroy()
	profile.GoogleAccounts = !selected
	p.service.profiles[profile.ID] = profile
	flow, err = p.service.authenticateSigninCallback(context.Background(), request, stored, p.flow, out.StateProofCiphertext, now)
	flow.destroy()
	if err == nil {
		t.Fatal("same-version signin policy switch reinterpreted retained state")
	}
	if _, _, _, err := p.restoreOutput(context.Background(), 1, wire); err == nil {
		t.Fatal("signin initiation replay adopted a different issuer policy")
	}
}
