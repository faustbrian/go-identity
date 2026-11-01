package oauthserverhttp

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzWorkloadHTTPAdmission(f *testing.F) {
	f.Add("grant_type=client_credentials", "valid")
	f.Add("grant_type=client_credentials&grant_type=refresh_token", "valid")
	f.Add("grant_type=client_credentials&client_id=machine", "valid")
	f.Add("grant_type=client_credentials&scope=%ff", "Basic malformed")
	f.Add("grant_type=client_credentials&resource=https%3A%2F%2Fforeign.example", "valid")
	f.Fuzz(func(t *testing.T, form, header string) {
		if len(form) > 32768 || len(header) > 2048 {
			return
		}
		c, store, basic := featureFixture(t)
		if header == "valid" {
			header = basic
		}
		w := httptest.NewRecorder()
		operationHandler(t, c, "token").ServeHTTP(w, wireRequest("token", form, header))
		if len(w.Body.Bytes()) > 16384 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), basic) {
			t.Fatal("hostile input escaped output/custody bounds")
		}
		if w.Code >= 400 && store.calls != 0 {
			t.Fatal("rejected transport/core input reached native effects")
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("hostile response became cacheable")
		}
	})
}
