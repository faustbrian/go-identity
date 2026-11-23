//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
)

// Focused filter: ^TestReferencePostgresEnterpriseOIDCLogoutJourney$
// The existing harness installs actual migration plans and provisions a linked
// member before this browser crosses the TLS application and provider routes.
func TestReferencePostgresEnterpriseOIDCLogoutJourney(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, enterpriseOIDC: true, enterpriseOIDCLogout: true,
	})
}

func interruptReferenceLogoutValidation(t *testing.T, ctx context.Context, d reference.ReferenceDependencies) {
	t.Helper()
	if _, err := d.PostgreSQL.Raw().Exec(ctx, `CREATE FUNCTION public.interrupt_logout_validation_test() RETURNS event_trigger LANGUAGE plpgsql AS $$
BEGIN
 IF position('VALIDATE CONSTRAINT session_revocations_purpose_sso_oidc_v1' IN current_query()) > 0 THEN
  RAISE EXCEPTION 'test: interrupt logout constraint validation';
 END IF;
END $$;
CREATE EVENT TRIGGER interrupt_logout_validation_test ON ddl_command_start WHEN TAG IN ('ALTER TABLE') EXECUTE FUNCTION public.interrupt_logout_validation_test()`); err != nil {
		t.Fatal("install the isolated validation interruption", err)
	}
}

func verifyReferenceLogoutValidationCanResume(t *testing.T, ctx context.Context, stores reference.StoreSet, d reference.ReferenceDependencies) {
	t.Helper()
	if _, err := d.PostgreSQL.Raw().Exec(ctx, `DROP EVENT TRIGGER interrupt_logout_validation_test; DROP FUNCTION public.interrupt_logout_validation_test()`); err != nil {
		t.Fatal("remove the isolated validation interruption", err)
	}
	var validated bool
	if err := d.PostgreSQL.Raw().QueryRow(ctx, `SELECT convalidated FROM pg_catalog.pg_constraint
 WHERE conrelid='session_store.session_revocations'::regclass AND conname='session_revocations_purpose_sso_oidc_v1'`).Scan(&validated); err != nil || validated {
		t.Fatal("the new constraint was not committed in its unvalidated expansion state", err)
	}
	modules := []reference.ModuleID{"identity/session/postgres"}
	check, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: modules})
	if err != nil || len(check.Statuses) != 1 || check.Statuses[0].Compatibility != reference.MigrationRequired {
		t.Fatal("Reference treated its own recorded logout expansion as unmanaged", err)
	}
	plan, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil || len(plan.Plan.Steps) == 0 {
		t.Fatal("Reference could not plan outstanding validation", err)
	}
}

type referenceEnterpriseOIDCLogoutPolicy struct{ referenceEnterpriseOIDCPolicy }

func (p referenceEnterpriseOIDCLogoutPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(c.Request.Tenant) == otpTenant && c.PolicyRevision == 9 {
		resource := c.Request.Resource
		subject := c.Request.Subject
		switch {
		case c.Request.Action == "identity.sso.oidc-logout-complete" && subject.Kind == authorization.SubjectServiceAccount &&
			subject.ID == "AAAAAAAAAAAAAAAAAAAAAw" && resource.Type == "identity.user" && resource.ID != "":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		case (c.Request.Action == "identity.sso.oidc-logout" || c.Request.Action == "identity.sso.oidc-logout.recover") && subject.Kind == authorization.SubjectUser:
			self := resource.Type == "identity.user" && string(resource.ID) == string(subject.ID)
			admission := resource.Type == "identity.request-admission" && resource.ID == "identity.sso.oidc-logout"
			if self || admission {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	return p.referenceEnterpriseOIDCPolicy.Decide(ctx, c)
}

func configureReferenceEnterpriseOIDCLogout(t *testing.T, c *reference.StoreConfiguration, provider *referenceEnterpriseIssuer, origin string) *atomic.Int32 {
	t.Helper()
	c.EnterpriseOIDC.Logout = &reference.EnterpriseOIDCLogoutConfiguration{
		EndSessionEndpoint: provider.server.URL + "/logout", FinalRedirectAllowlist: []string{origin + "/enterprise/logged-out"},
	}
	c.HTTPEnterpriseOIDC.ProviderLogout = true
	var calls atomic.Int32
	previous := provider.server.Config.Handler
	// Install before the harness sends the provider's first request. Existing
	// authorization, token and metadata behavior remains with its original owner.
	provider.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/logout" {
			previous.ServeHTTP(w, r)
			return
		}
		calls.Add(1)
		query, err := url.ParseQuery(r.URL.RawQuery)
		callback := query.Get("post_logout_redirect_uri")
		if err != nil || r.Method != http.MethodGet || len(query) != 3 || query.Get("client_id") != enterpriseProviderClient || len(query["state"]) != 1 || len(query.Get("state")) != 43 ||
			!strings.HasPrefix(callback, origin+"/sso/oidc/") || !strings.HasSuffix(callback, "/logout/callback") {
			t.Error("enterprise provider did not receive the configured client-ID logout profile")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, callback+"?"+url.Values{"state": {query.Get("state")}}.Encode(), http.StatusSeeOther)
	})
	return &calls
}

func proveReferenceEnterpriseOIDCLogoutJourney(t *testing.T, ctx context.Context, base *http.Client, origin string, features reference.FeatureSet,
	provider *referenceEnterpriseIssuer, selected enterpriseProvisioned, providerLogouts *atomic.Int32,
) {
	t.Helper()
	first, originalCookies, csrf := referenceEnterpriseLogoutSignin(t, ctx, base, origin, provider, selected, "provider-logout")
	sibling, _, siblingCSRF := referenceEnterpriseLogoutSignin(t, ctx, base, origin, provider, selected, "ordinary-signout")
	firstState := referenceEnterpriseLogoutRead(t, ctx, first, origin, true)
	siblingState := referenceEnterpriseLogoutRead(t, ctx, sibling, origin, true)
	if firstState.Session.ID == siblingState.Session.ID {
		t.Fatal("two actual enterprise logins did not issue distinct local sessions")
	}
	var originalToken string
	for _, cookie := range originalCookies {
		if cookie.HttpOnly {
			originalToken = cookie.Value
		}
	}
	checkReferenceEnterpriseOrganization(t, ctx, features, originalToken, firstState.Session.ID, "sso-oidc", selected)
	path := "/sso/oidc/" + string(selected.provider) + "/logout"
	final := origin + "/enterprise/logged-out"
	body, err := json.Marshal(map[string]string{"finalRedirect": final})
	if err != nil {
		t.Fatal(err)
	}
	started := referenceEnterpriseLogoutRequest(t, ctx, first, http.MethodPost, origin+path, body, origin, "enterprise-provider-logout", csrf)
	_ = started.Body.Close()
	if started.StatusCode != http.StatusSeeOther || !strings.Contains(started.Header.Get("Cache-Control"), "no-store") || len(started.Cookies()) != 2 {
		t.Fatal("enterprise provider logout did not commit and delete the session and CSRF cookies", started.StatusCode)
	}
	for _, removed := range started.Cookies() {
		if removed.MaxAge >= 0 || !removed.Secure || removed.Path != "/" || removed.Domain != "" {
			t.Fatal("enterprise provider logout did not delete the original host-scoped cookies")
		}
	}
	redirect, err := url.Parse(started.Header.Get("Location"))
	if err != nil || redirect.Scheme+"://"+redirect.Host+redirect.Path != provider.server.URL+"/logout" {
		t.Fatal("enterprise logout did not select its exact configured provider endpoint")
	}
	query := redirect.Query()
	callback := origin + path + "/callback"
	if len(query) != 3 || query.Get("client_id") != enterpriseProviderClient || query.Get("post_logout_redirect_uri") != callback || len(query.Get("state")) != 43 {
		t.Fatal("enterprise logout did not bind the client, exact return route and opaque state")
	}
	// Restore captured custody to distinguish durable native revocation from
	// merely removing the browser cookies in the HTTP response.
	application, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	first.Jar.SetCookies(application, originalCookies)
	referenceEnterpriseLogoutRead(t, ctx, first, origin, false)
	referenceEnterpriseLogoutRead(t, ctx, sibling, origin, true)
	first.Jar.SetCookies(application, originalCookies)
	changed := referenceEnterpriseLogoutRequest(t, ctx, first, http.MethodPost, origin+path, body, origin, "another-provider-logout", csrf)
	_ = changed.Body.Close()
	if changed.StatusCode != http.StatusForbidden || changed.Header.Get("Location") != "" || len(changed.Cookies()) != 0 {
		t.Fatal("a revoked cookie authorized a second provider logout key", changed.StatusCode)
	}
	first.Jar.SetCookies(application, originalCookies)
	repeated := referenceEnterpriseLogoutRequest(t, ctx, first, http.MethodPost, origin+path, body, origin, "enterprise-provider-logout", csrf)
	_ = repeated.Body.Close()
	if repeated.StatusCode != http.StatusSeeOther || repeated.Header.Get("Location") != started.Header.Get("Location") || providerLogouts.Load() != 0 {
		t.Fatal("the original keyed retry did not recover the same state without contacting the provider", repeated.StatusCode)
	}

	external := *provider.server.Client()
	external.CheckRedirect = first.CheckRedirect
	returned := referenceEnterpriseLogoutRequest(t, ctx, &external, http.MethodGet, redirect.String(), nil, "", "", "")
	_ = returned.Body.Close()
	expectedReturn := callback + "?" + url.Values{"state": {query.Get("state")}}.Encode()
	if returned.StatusCode != http.StatusSeeOther || returned.Header.Get("Location") != expectedReturn || providerLogouts.Load() != 1 {
		t.Fatal("enterprise provider did not return the exact original logout state", returned.StatusCode)
	}
	// A fresh client carries neither the revoked session nor a replacement
	// cookie: only the original one-time provider state authorizes completion.
	withoutCookies := *base
	withoutCookies.Jar = nil
	withoutCookies.CheckRedirect = first.CheckRedirect
	completed := referenceEnterpriseLogoutRequest(t, ctx, &withoutCookies, http.MethodGet, returned.Header.Get("Location"), nil, "", "", "")
	_ = completed.Body.Close()
	if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Location") != final || len(completed.Cookies()) != 0 || !strings.Contains(completed.Header.Get("Cache-Control"), "no-store") {
		t.Fatal("one-time enterprise logout return did not redirect without cookie authority", completed.StatusCode)
	}
	replay := referenceEnterpriseLogoutRequest(t, ctx, &withoutCookies, http.MethodGet, returned.Header.Get("Location"), nil, "", "", "")
	_ = replay.Body.Close()
	if replay.StatusCode != http.StatusForbidden || replay.Header.Get("Location") != "" || len(replay.Cookies()) != 0 {
		t.Fatal("consumed enterprise logout state disclosed another redirect or credential", replay.StatusCode)
	}
	first.Jar.SetCookies(application, originalCookies)
	referenceEnterpriseLogoutRead(t, ctx, first, origin, false)
	referenceEnterpriseLogoutRead(t, ctx, sibling, origin, true)
	ordinary := referenceEnterpriseLogoutRequest(t, ctx, sibling, http.MethodPost, origin+"/v1/session/signout", []byte(`{}`), origin, "", siblingCSRF)
	_ = ordinary.Body.Close()
	if ordinary.StatusCode != http.StatusOK || ordinary.Header.Get("Location") != "" || len(ordinary.Cookies()) != 2 || providerLogouts.Load() != 1 {
		t.Fatal("ordinary enterprise session signout unexpectedly became provider logout", ordinary.StatusCode)
	}
	referenceEnterpriseLogoutRead(t, ctx, sibling, origin, false)
}

func referenceEnterpriseLogoutSignin(t *testing.T, ctx context.Context, base *http.Client, origin string, provider *referenceEnterpriseIssuer,
	selected enterpriseProvisioned, key string,
) (*http.Client, []*http.Cookie, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := *base
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	flowResponse := referenceEnterpriseLogoutRequest(t, ctx, &client, http.MethodPost, origin+"/v1/session/preauth-issue", []byte(`{"method":"sso-oidc"}`), origin, "", "")
	var flow struct{ FlowID string }
	err = json.NewDecoder(flowResponse.Body).Decode(&flow)
	_ = flowResponse.Body.Close()
	if err != nil || flowResponse.StatusCode != http.StatusOK || flow.FlowID == "" {
		t.Fatal("enterprise logout fixture did not obtain an actual browser login flow", flowResponse.StatusCode)
	}
	body, err := json.Marshal(map[string]string{"flowID": flow.FlowID, "commandID": string(enterpriseCommand(t)), "providerID": string(selected.provider),
		"callback": origin + "/enterprise/complete", "errorCallback": origin + "/enterprise/error"})
	if err != nil {
		t.Fatal(err)
	}
	started := referenceEnterpriseLogoutRequest(t, ctx, &client, http.MethodPost, origin+"/v1/sso/signin-start", body, origin, key, "")
	var start struct{ AuthorizationURL string }
	err = json.NewDecoder(started.Body).Decode(&start)
	_ = started.Body.Close()
	if err != nil || started.StatusCode != http.StatusOK || start.AuthorizationURL == "" {
		t.Fatal("enterprise logout fixture did not commit its linked-member login start", started.StatusCode)
	}
	external := *provider.server.Client()
	external.CheckRedirect = client.CheckRedirect
	authorized := referenceEnterpriseLogoutRequest(t, ctx, &external, http.MethodGet, start.AuthorizationURL, nil, "", "", "")
	_ = authorized.Body.Close()
	if authorized.StatusCode != http.StatusSeeOther || !strings.HasPrefix(authorized.Header.Get("Location"), origin+"/sso/oidc/callback?") {
		t.Fatal("enterprise logout fixture provider did not return to the actual login route", authorized.StatusCode)
	}
	completed := referenceEnterpriseLogoutRequest(t, ctx, &client, http.MethodGet, authorized.Header.Get("Location"), nil, "", "", "")
	_ = completed.Body.Close()
	if completed.StatusCode != http.StatusSeeOther || completed.Header.Get("Location") != origin+"/enterprise/complete" || len(completed.Cookies()) != 2 {
		t.Fatal("enterprise logout fixture did not issue an actual linked-member cookie", completed.StatusCode)
	}
	var csrf string
	for _, cookie := range completed.Cookies() {
		if cookie.Name == "__Host-identity_csrf" && !cookie.HttpOnly {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("enterprise logout fixture lost the issued synchronizer token")
	}
	state := referenceEnterpriseLogoutRead(t, ctx, &client, origin, true)
	if state.Principal.UserID != selected.user || state.Principal.TenantID != otpTenant {
		t.Fatal("enterprise logout fixture authenticated a different linked member")
	}
	return &client, completed.Cookies(), csrf
}

func referenceEnterpriseLogoutRead(t *testing.T, ctx context.Context, client *http.Client, origin string, authenticated bool) sessionhttp.GetResponse {
	t.Helper()
	response := referenceEnterpriseLogoutRequest(t, ctx, client, http.MethodGet, origin+"/v1/session/get", nil, "", "", "")
	defer response.Body.Close()
	var state sessionhttp.GetResponse
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&state) != nil || state.Authenticated != authenticated ||
		authenticated && (state.Principal == nil || state.Session == nil) || !authenticated && (state.Principal != nil || state.Session != nil) {
		t.Fatal("enterprise logout did not retain its exact durable session disposition", response.StatusCode, state.Authenticated)
	}
	return state
}

func referenceEnterpriseLogoutRequest(t *testing.T, ctx context.Context, client *http.Client, method, target string, body []byte, origin, key, csrf string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal("construct enterprise logout journey request")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("enterprise logout journey HTTPS request failed")
	}
	return response
}
