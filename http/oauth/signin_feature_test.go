package oauthhttp_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
)

func TestSigninFeatureAdvertisesOnlySelectedExecutableRoutes(t *testing.T) {
	start, native, _, device, _ := signinStartFixture(t)
	callback, _, _, _, _, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
	callback.Rate = start.Rate
	for _, enabled := range []bool{false, true} {
		c := oauthhttp.FeatureConfig{Callback: &callback}
		if enabled {
			c.SigninStart = &start
		} else {
			legacy := callback
			legacy.Signin = nil
			c.Callback = &legacy
		}
		feature, err := oauthhttp.NewFeature(c)
		if err != nil {
			t.Fatal(err)
		}
		h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Selected social authentication", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		var wire struct {
			Paths map[string]map[string]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(document.JSON(), &wire); err != nil {
			t.Fatal(err)
		}
		_, advertised := wire.Paths["/v1/oauth/signin-start"]["post"]
		if advertised != enabled {
			t.Fatal("signin capability advertisement did not match selection")
		}
		response := httptest.NewRecorder()
		h.ServeHTTP(response, signinStartRequest(signinStartBody, device))
		if enabled {
			if response.Code != 200 || native.calls != 1 {
				t.Fatal("selected public route did not reach actual configured native boundary", response.Code)
			}
		} else if response.Code != 404 || native.calls != 0 {
			t.Fatal("unselected public signin route was executable", response.Code)
		}
	}
}
