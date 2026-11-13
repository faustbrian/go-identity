package postgres

import (
	"context"
	"net/url"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
)

func TestSigninCallbackCommandBindsExactCodeWithoutRetargetingAnonymousScope(t *testing.T) {
	p, out, r, now := signinCallbackInputFixture(t)
	p.service.config.IntentKey = [32]byte{99}
	stored, err := p.openTransaction(context.Background(), out.Binding, out.BindingCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := p.service.authenticateSigninCallback(context.Background(), r, stored, p.flow, out.StateProofCiphertext, now)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.destroy()
	command, err := p.service.signinCallbackCommand(context.Background(), r, flow)
	if err != nil {
		t.Fatal(err)
	}
	feature, ok := command.Feature()
	b := feature.Binding
	if !ok || b.CommandID != out.Binding.CallbackCommandID || b.CommandID == out.Binding.Input.Binding.CommandID || b.UserID != "" || b.AnonymousFlowID != out.Binding.Input.Binding.AnonymousFlowID || b.ActorID != out.Binding.Input.Binding.ActorID || b.RecordID != "" {
		t.Fatal("callback selected identity or replaced original command/actor custody")
	}
	if _, cookie := command.PreAuthCookie(); !cookie {
		t.Fatal("callback command lost original browser")
	}
	if _, bearer := command.SessionToken(); bearer {
		t.Fatal("callback borrowed session authority")
	}
	if len(feature.Fields) != 1 || feature.Fields[0].Name != "oauth.signin.input" || len(feature.Fields[0].Value.Bytes) != 32 {
		t.Fatal("callback retained plaintext code/state or omitted original input commitment")
	}
	replayed, err := p.service.signinCallbackCommand(context.Background(), r, flow)
	again, _ := replayed.Feature()
	if err != nil || again.Binding != feature.Binding || !sameRPFields(again.Fields, feature.Fields) {
		t.Fatal("same callback changed replay identity", err)
	}
	changed, err := oauth.ParseQueryCallback(context.Background(), (url.Values{"code": {"another-provider-code"}, "state": {out.Binding.State}, "iss": {out.Binding.Provider.Issuer}}).Encode(), out.Binding.Provider)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Destroy()
	other := r
	other.Callback = changed
	different, err := p.service.signinCallbackCommand(context.Background(), other, flow)
	variant, _ := different.Feature()
	if err != nil || variant.Binding != feature.Binding || sameRPFields(variant.Fields, feature.Fields) {
		t.Fatal("different code could adopt original callback claim", err)
	}
	r.Callback.Destroy()
	if _, err := p.service.signinCallbackCommand(context.Background(), r, flow); err == nil {
		t.Fatal("destroyed original input reconstructed exchange custody")
	}
}
