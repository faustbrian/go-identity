package sessionhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sessionhttp "github.com/faustbrian/go-identity/http/session"
)

func FuzzAdminUserStatusJSON(f *testing.F) {
	f.Add(true, `{"userID":"target","reason":"security"}`)
	f.Add(true, `{"userID":"target","reason":"security","expiresAt":"2026-11-28T10:00:00.123456Z"}`)
	f.Add(true, `{"userID":"target","reason":"security","expiresAt":"2026-11-28T10:00:00.1234560001Z"}`)
	f.Add(true, `{"userID":"target","userID":"other","reason":"security"}`)
	f.Add(false, `{"userID":"target","expectedVersion":2}`)
	f.Add(false, `{"userID":"target","expectedVersion":18446744073709551615}`)
	f.Fuzz(func(t *testing.T, ban bool, body string) {
		if len(body) > 4096 {
			return
		}
		native, rate, config := adminStatusFixture(t)
		config.Ban, config.Unban = ban, !ban
		feature, err := sessionhttp.NewAdminUserStatusFeature(config)
		if err != nil {
			t.Fatal(err)
		}
		operations := feature.Operations()
		if len(operations) != 1 {
			t.Fatal("wrong number of selected operations")
		}
		out := httptest.NewRecorder()
		operations[0].Handler.ServeHTTP(out, adminStatusRequest(ban, body))
		if len(out.Result().Cookies()) != 0 || out.Header().Get("X-CSRF-Token") != "" || native.calls > 1 || rate.calls != native.calls {
			t.Fatal("status parser escaped credential or single-admission custody")
		}
		switch out.Code {
		case http.StatusBadRequest:
			if native.calls != 0 {
				t.Fatal("rejected status input reached the native owner")
			}
		case http.StatusOK:
			if native.calls != 1 || native.input.UserID == "" || (ban && native.input.Reason == "") || (!ban && native.input.ExpectedVersion != 2) {
				t.Fatal("accepted status input lost its effect binding")
			}
		}
	})
}
