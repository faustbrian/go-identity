package oauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/oauth"
)

func TestCallbackIdentityIsResolvedFromNativeState(t *testing.T) {
	start := linkStartRequest(t)
	parsed, err := oauth.ParseQueryCallback(context.Background(), queryResponse("code=original"), queryProfile())
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	request := oauth.CallbackRequest{Callback: parsed, TenantID: start.TenantID, Session: start.Session, Origin: start.Origin, Network: start.Network}
	if err := request.Validate(); err != nil {
		t.Fatal("callback requires transport-selected user instead of authenticating native state", err)
	}
}

func TestAuthenticatedLinkCallbackRetainsOriginalInputAndRejectsOtherActors(t *testing.T) {
	start := linkStartRequest(t)
	parsed, err := oauth.ParseQueryCallback(context.Background(), queryResponse("code=original%2Bprovider%3Dcode"), queryProfile())
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	request := oauth.CallbackRequest{Callback: parsed, TenantID: start.TenantID, Session: start.Session,
		Origin: start.Origin, Network: start.Network}
	if err := request.Validate(); err != nil {
		t.Fatal("original authenticated-link callback shape rejected", err)
	}
	for name, mutate := range map[string]func(*oauth.CallbackRequest){
		"missing callback":         func(r *oauth.CallbackRequest) { r.Callback = oauth.Callback{} },
		"missing tenant":           func(r *oauth.CallbackRequest) { r.TenantID = "" },
		"missing original browser": func(r *oauth.CallbackRequest) { r.Session = auth.BearerCredential{} },
		"noncanonical browser":     func(r *oauth.CallbackRequest) { r.Session = auth.NewBearerCredential(r.Session.Token() + "=") },
		"origin path":              func(r *oauth.CallbackRequest) { r.Origin += "/" },
		"network normalization":    func(r *oauth.CallbackRequest) { r.Network = "2001:0db8::12" },
	} {
		t.Run(name, func(t *testing.T) {
			other := request
			mutate(&other)
			if err := other.Validate(); err == nil {
				t.Fatal("unsupported callback entered authenticated linking")
			}
		})
	}
	if _, err := json.Marshal(request); err == nil {
		t.Fatal("original callback input serialized")
	}
	if diagnostics := fmt.Sprintf("%#v %s %v", request, request, request); strings.Contains(diagnostics, "original+provider=code") || strings.Contains(diagnostics, start.Session.Token()) || strings.Contains(diagnostics, testNonce) {
		t.Fatal("callback input leaked through diagnostics")
	}
	input, ok := request.Callback.Input()
	if !ok {
		t.Fatal("original callback success variant changed")
	}
	if err := input.Use(context.Background(), func(_ context.Context, code, state []byte) error {
		if string(code) != "original+provider=code" || string(state) != testNonce {
			t.Fatal("callback request replaced original exchange bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request.Callback.Destroy()
	if err := input.Use(context.Background(), func(context.Context, []byte, []byte) error {
		t.Fatal("request destruction did not retain original shared lifetime")
		return nil
	}); err == nil {
		t.Fatal("destroyed callback regained exchange custody")
	}
}
