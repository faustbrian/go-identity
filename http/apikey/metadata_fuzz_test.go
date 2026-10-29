package apikeyhttp

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func FuzzMetadataReadQuery(f *testing.F) {
	f.Add(false, "keyID=key-a")
	f.Add(true, "limit=1")
	f.Add(true, "limit=201")
	f.Add(true, "limit=1&configurationIDs=%5B%22automation%22%5D")
	f.Add(false, "keyID=key-a&keyID=other")
	f.Add(true, "limit=1&cursor=%FF")
	f.Fuzz(func(t *testing.T, list bool, query string) {
		if len(query) > 8192 {
			return
		}
		fixture, owner := metadataFixture(t)
		action := "get"
		if list {
			action = "list"
		}
		r := metadataRequest(fixture, action)
		r.URL.RawQuery, r.RequestURI = query, ""
		w := httptest.NewRecorder()
		fixtureHandler(t, fixture).ServeHTTP(w, r)
		if w.Code != 200 && w.Code != 400 && w.Code != 503 {
			t.Fatal("unexpected metadata parser outcome", w.Code)
		}
		if owner.calls > 1 || fixture.sessions.calls > 1 || fixture.native.calls != 0 || fixture.rate.calls != 0 || strings.Contains(w.Body.String(), fixture.token) || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("metadata query repeated owner work or disclosed credential custody")
		}
		if owner.calls != 0 {
			if list && owner.list.Validate() != nil || !list && owner.get.Validate() != nil {
				t.Fatal("unbounded/invalid query reached native read owner")
			}
		}
		if w.Code != 200 {
			var body map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &body) != nil || body["key"] != nil || body["keys"] != nil {
				t.Fatal("failed query disclosed a partial metadata result")
			}
		}
	})
}
