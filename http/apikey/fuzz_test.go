package apikeyhttp

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/apikey"
)

func FuzzManagementBody(f *testing.F) {
	f.Add(uint8(0), `{"name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`)
	f.Add(uint8(1), `{"keyID":"key-a","expectedVersion":1}`)
	f.Add(uint8(2), `{"keyID":"key-a","keyID":"key-b","expectedVersion":1}`)
	f.Add(uint8(0), `{"name":"key","permissions":null,"expiresAt":"2026-10-29T12:00:00Z"}`)
	f.Add(uint8(1), `{"keyID":"key-a","expectedVersion":18446744073709551616}`)
	f.Add(uint8(12), `{"organizationID":"org-a","name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`)
	f.Add(uint8(12), `{"organizationID":null,"name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`)
	f.Fuzz(func(t *testing.T, selector uint8, body string) {
		if len(body) > 65536 {
			return
		}
		fixture := newFixture(t)
		organization := &organizationWireOwner{err: apikey.ErrDenied}
		if selector&4 != 0 {
			fixture.config.OrganizationOwned, fixture.config.OrganizationCreator = true, organization
		}
		action := []string{"create", "rotate", "delete"}[selector%3]
		w := httptest.NewRecorder()
		fixtureHandler(t, fixture).ServeHTTP(w, fixture.request(action, body))
		if w.Code != 400 && w.Code != 403 {
			t.Fatal("denying native port became success or leaked unexpected outcome", w.Code)
		}
		if fixture.native.calls+organization.calls > 1 || fixture.sessions.calls > 1 || fixture.rate.calls > 1 || strings.Contains(w.Body.String(), fixture.token) || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("input repeated work or disclosed credential custody")
		}
	})
}
