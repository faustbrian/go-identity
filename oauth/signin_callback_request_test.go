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

func TestSigninCallbackRetainsOriginalPreauthWithoutSelectingUser(t *testing.T) {
	start := signinStartRequest(t)
	for _, response := range []string{"code=original", "error=access_denied"} {
		t.Run(response, func(t *testing.T) {
			parsed, err := oauth.ParseQueryCallback(context.Background(), queryResponse(response), queryProfile())
			if err != nil {
				t.Fatal(err)
			}
			defer parsed.Destroy()
			request := oauth.SigninCallbackRequest{Callback: parsed, TenantID: start.TenantID, FlowCookie: start.FlowCookie, Origin: start.Origin, Network: start.Network, Device: start.Device}
			if err := request.Validate(); err != nil {
				t.Fatal("callback should resolve original flow and Remember natively", err)
			}
			for name, change := range map[string]func(*oauth.SigninCallbackRequest){
				"missing parsed response": func(r *oauth.SigninCallbackRequest) { r.Callback = oauth.Callback{} },
				"missing browser":         func(r *oauth.SigninCallbackRequest) { r.FlowCookie = auth.BearerCredential{} },
				"padded browser": func(r *oauth.SigninCallbackRequest) {
					r.FlowCookie = auth.NewBearerCredential(r.FlowCookie.Token() + "=")
				},
				"missing device":   func(r *oauth.SigninCallbackRequest) { r.Device = "" },
				"unbounded device": func(r *oauth.SigninCallbackRequest) { r.Device = strings.Repeat("d", 129) },
				"origin path":      func(r *oauth.SigninCallbackRequest) { r.Origin += "/" },
				"network port":     func(r *oauth.SigninCallbackRequest) { r.Network += ":443" },
			} {
				t.Run(name, func(t *testing.T) {
					changed := request
					change(&changed)
					if changed.Validate() == nil {
						t.Fatal("unsupported callback/browser shape admitted")
					}
				})
			}
			if _, err := json.Marshal(request); err == nil {
				t.Fatal("callback custody serialized")
			}
			if text := fmt.Sprintf("%#v %s", request, request); strings.Contains(text, start.FlowCookie.Token()) || strings.Contains(text, testNonce) {
				t.Fatal("callback custody disclosed")
			}
		})
	}
}
