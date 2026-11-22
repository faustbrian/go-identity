package oauth

import (
	"slices"
	"testing"
)

func TestGitHubTokenResponseAbsentExpiryAndCommaScopesAreSelectedOnly(t *testing.T) {
	c := OIDCConfig{Scopes: []string{"read:user", "user:email"}, MaxResponseBytes: 4096, MaxTokenBytes: 256}
	valid := `{"access_token":"test-only-access","token_type":"bearer","scope":"read:user,user:email"}`
	for _, tc := range []struct {
		name, body string
		policy     OAuth2TokenPolicy
		want       ErrorKind
		expires    int64
	}{
		{"default-strict", valid, "", Unknown, 0},
		{"ordinary-non-expiring", valid, OAuth2GitHubOAuthAppPolicy, "", 0},
		{"real-positive-expiry", `{"access_token":"test-only-access","token_type":"Bearer","scope":"read:user,user:email","expires_in":60}`, OAuth2GitHubOAuthAppPolicy, "", 60},
		{"null-is-not-absent", `{"access_token":"test-only-access","token_type":"Bearer","expires_in":null}`, OAuth2GitHubOAuthAppPolicy, Unknown, 0},
		{"zero-is-not-absent", `{"access_token":"test-only-access","token_type":"Bearer","expires_in":0}`, OAuth2GitHubOAuthAppPolicy, Unknown, 0},
		{"space-is-not-comma", `{"access_token":"test-only-access","token_type":"Bearer","scope":"read:user user:email"}`, OAuth2GitHubOAuthAppPolicy, Unknown, 0},
		{"scope-expansion", `{"access_token":"test-only-access","token_type":"Bearer","scope":"read:user,user:email,repo"}`, OAuth2GitHubOAuthAppPolicy, Unknown, 0},
		{"empty-scope-member", `{"access_token":"test-only-access","token_type":"Bearer","scope":"read:user,,user:email"}`, OAuth2GitHubOAuthAppPolicy, Unknown, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, kind := parseTokenResponseWithPolicy(200, "application/json", []byte(tc.body), c, false, false, tc.policy)
			defer got.clear()
			if kind != tc.want || kind == "" && (got.expires != tc.expires || !slices.Equal(got.scopes, c.Scopes) || !got.scopeReported) {
				t.Fatal("token response changed selected expiry/scopes or certainty")
			}
		})
	}
}
