//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
)

func TestReferencePostgresImpersonationStartStopHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, mfaEnrollment: true, passwordMFA: true, impersonation: true,
	}, true)
}

func configureReferenceImpersonation(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	policy, err := impersonation.NewPolicy("reference-support-v1", c.OTP.RequestKeys.Policy.PolicyVersion)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := session.NewDigestKey(8, bytes.Repeat([]byte{0xc9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.Impersonation = &reference.ImpersonationConfiguration{
		Policy: policy, Activation: impersonationpg.ActivationConfig{LookupKey: lookup}, EnvelopeKey: "issue-envelope",
	}
	c.HTTPImpersonation = &reference.HTTPImpersonationConfiguration{
		TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)},
		KeyedStart: impersonationpg.KeyedStartCustody{
			ConfigurationID: "reference-impersonation-v1", ActiveKey: "support-intent",
			Keys: map[string][]byte{"support-intent": bytes.Repeat([]byte{0xcb}, 32)},
		},
	}
}

// This fixture authorizes only the selected test scope and supported actions.
// Native actor/target, approval, session and proof checks remain real.
type referenceImpersonationPolicy struct{}

func (referenceImpersonationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	r := c.Request
	if ctx.Err() == nil && r.Tenant == otpTenant && c.PolicyRevision == 9 && r.Subject.Kind == authorization.SubjectUser {
		scopes, _ := r.Attributes["impersonation.scope"].StringSet()
		profile := len(scopes) == 1 && scopes[0] == "profile.read"
		recovery, _ := r.Resource.Attributes["identity.command.recovery"].Bool()
		admission, _ := r.Resource.Attributes["identity.request.admission"].Bool()
		switch r.Action {
		case "identity.impersonation.request", "identity.impersonation.approve", "identity.impersonation.start":
			if r.Resource.Type == "identity.user" && (profile || recovery) ||
				r.Action == "identity.impersonation.start" && r.Resource.Type == "identity.request-admission" && r.Resource.ID == "identity.impersonation.start" && admission {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.impersonation.stop", "profile.read":
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

// The caller owns the real PostgreSQL/TLS graph and obtains both ordinary
// administrator sessions through password and TOTP, not seeded session rows.
func proveReferenceImpersonationHTTP(t *testing.T, ctx context.Context, native *reference.ImpersonationService, client *http.Client, base, origin string, requesterCookies, approverCookies []*http.Cookie, requesterCSRF, approverCSRF string, target identity.UserID) {
	t.Helper()
	if native == nil || client == nil || !strings.HasPrefix(base, "https://") {
		t.Fatal("impersonation acceptance requires the real native owner and TLS client")
	}
	ordinary := func(cookies []*http.Cookie, csrf string) impersonationpg.Authentication {
		t.Helper()
		var bearer string
		for _, cookie := range cookies {
			if cookie != nil && cookie.HttpOnly && cookie.Name != impersonationhttp.ChildCookieName && cookie.Name != impersonationhttp.ChildCSRFCookieName {
				if bearer != "" || !strings.HasPrefix(cookie.Name, "__Host-") {
					t.Fatal("administrator bundle must contain one ordinary host credential")
				}
				bearer = cookie.Value
			}
		}
		if _, err := session.ParseToken(bearer); err != nil {
			t.Fatal("administrator bundle lacks an original session token")
		}
		synchronizer, err := session.ParseCSRFToken(csrf)
		if err != nil {
			t.Fatal("administrator lacks an original CSRF synchronizer")
		}
		return impersonationpg.Authentication{Tenant: otpTenant, Bearer: authentication.NewBearerCredential(bearer), CSRF: synchronizer}
	}
	requester := ordinary(requesterCookies, requesterCSRF)
	approver := ordinary(approverCookies, approverCSRF)
	if requester.Bearer.Token() == approver.Bearer.Token() || requesterCSRF == approverCSRF {
		t.Fatal("impersonation requires distinct original administrator credentials")
	}

	// Explicit cookie bundles, not ambient jar state, distinguish the parent
	// session from the child navigation context throughout this acceptance.
	transport := *client
	transport.Jar = nil
	invoke := func(method, path string, body any, cookies []*http.Cookie, csrf, requestOrigin, key string) (*http.Response, []byte) {
		t.Helper()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal("cannot encode impersonation acceptance request")
			}
			defer clear(payload)
		}
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal("cannot construct impersonation acceptance request")
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		if csrf != "" {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		if requestOrigin != "" {
			request.Header.Set("Origin", requestOrigin)
		}
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("impersonation HTTPS transport unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("unbounded or cacheable impersonation response")
		}
		return response, data
	}
	readOriginal := func() sessionhttp.GetResponse {
		t.Helper()
		response, data := invoke(http.MethodGet, "/v1/session/get", nil, requesterCookies, "", "", "")
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.Unmarshal(data, &result) != nil || !result.Authenticated || result.Session == nil || result.Principal == nil || result.Principal.TenantID != otpTenant || len(response.Header.Values("Set-Cookie")) != 0 {
			t.Fatal("original ordinary administrator session is not readable without cookie mutation")
		}
		return result
	}
	original := readOriginal()

	requestID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("cannot generate impersonation request identity")
	}
	scope, err := impersonation.NewScope([]string{"profile.read"})
	if err != nil {
		t.Fatal("cannot construct approved application scope")
	}
	reason, err := impersonation.NewReason("synthetic reference support request")
	if err != nil {
		t.Fatal("cannot construct impersonation request reason")
	}
	prepared, err := native.PrepareRequest(ctx, impersonationpg.RequestInput{Authentication: requester, CommandID: requestID, Target: target, Scope: scope, Reason: reason, Duration: 10 * time.Minute, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal("real password/TOTP requester could not prepare a grant")
	}
	requestBinding, err := prepared.Binding()
	if err != nil || requestBinding.TenantID != otpTenant || identity.UserID(requestBinding.ActorID) != original.Principal.UserID || requestBinding.UserID != target {
		t.Fatal("request binding lost original actor, target or tenant")
	}
	pending, err := native.Execute(ctx, prepared)
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted || pending.Binding != requestBinding || pending.Feature == nil || pending.Feature.AfterVersion != 1 {
		t.Fatal("real grant request did not commit exact pending metadata")
	}
	approvalID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("cannot generate independent approval identity")
	}
	approvalReason, err := impersonation.NewReason("synthetic independent administrator approval")
	if err != nil {
		t.Fatal("cannot construct independent approval reason")
	}
	approval, err := native.PrepareApproval(ctx, impersonationpg.ApproveInput{Authentication: approver, CommandID: approvalID, GrantID: impersonation.GrantID(requestID), ExpectedVersion: 1, Reason: approvalReason, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal("distinct real password/TOTP administrator could not prepare approval")
	}
	approvalBinding, err := approval.Binding()
	if err != nil || approvalBinding.ActorID == requestBinding.ActorID || approvalBinding.UserID != target || approvalBinding.TenantID != otpTenant {
		t.Fatal("approval did not preserve a distinct actual administrator")
	}
	approved, err := native.Execute(ctx, approval)
	if err != nil || approved.Outcome != identity.CommitOutcomeCommitted || approved.Binding != approvalBinding || approved.Feature == nil || approved.Feature.BeforeVersion != 1 || approved.Feature.AfterVersion != 2 {
		t.Fatal("distinct administrator approval did not commit exact approved metadata")
	}
	recovered, err := native.Recover(ctx, approver, approvalBinding)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != approvalBinding || recovered.Feature == nil || recovered.Feature.AfterVersion != 2 {
		t.Fatal("original approver could not reconcile the committed approval")
	}
	if _, err := native.Recover(ctx, requester, approvalBinding); !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("requester unexpectedly recovered the independent approval")
	}

	body := map[string]any{"grantID": requestID, "expectedVersion": uint64(2)}
	key := "reference-impersonation-" + string(requestID)
	assertDenied := func(path string, cookies []*http.Cookie, csrf, requestOrigin, requestKey string, input any) {
		t.Helper()
		response, _ := invoke(http.MethodPost, path, input, cookies, csrf, requestOrigin, requestKey)
		if response.StatusCode != http.StatusForbidden || len(response.Header.Values("Set-Cookie")) != 0 {
			t.Fatal("wrong Origin or exchanged synchronizer did not deny without cookie mutation", path, response.StatusCode)
		}
	}
	assertDenied("/v1/impersonation/start", requesterCookies, requesterCSRF, "https://foreign.example.invalid", key, body)
	assertDenied("/v1/impersonation/start", requesterCookies, approverCSRF, origin, key, body)

	response, data := invoke(http.MethodPost, "/v1/impersonation/start", body, requesterCookies, requesterCSRF, origin, key)
	type startMetadata struct {
		Started          bool                  `json:"started"`
		CredentialIssued bool                  `json:"credentialIssued"`
		CommitOutcome    string                `json:"commitOutcome"`
		CommandID        identity.CommandID    `json:"commandID"`
		GrantID          impersonation.GrantID `json:"grantID"`
		ActorID          identity.ActorID      `json:"actorID"`
		TargetID         identity.UserID       `json:"targetID"`
		Error            string                `json:"error"`
	}
	var started startMetadata
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &started) != nil || !started.Started || !started.CredentialIssued || started.CommitOutcome != "committed" || started.Error != "" || started.CommandID == "" || started.CommandID == requestID || started.GrantID != impersonation.GrantID(requestID) || started.ActorID != requestBinding.ActorID || started.TargetID != target {
		t.Fatal("HTTP Start lost exact approved grant, original actor or target metadata", response.StatusCode)
	}
	childCookies := response.Cookies()
	if len(response.Header.Values("Set-Cookie")) != 2 || len(childCookies) != 2 {
		t.Fatal("HTTP Start must issue only one child cookie pair")
	}
	children := make(map[string]*http.Cookie, 2)
	for _, cookie := range childCookies {
		if cookie.Name != impersonationhttp.ChildCookieName && cookie.Name != impersonationhttp.ChildCSRFCookieName || children[cookie.Name] != nil || cookie.Value == "" || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 900 || cookie.HttpOnly != (cookie.Name == impersonationhttp.ChildCookieName) {
			t.Fatal("HTTP Start child cookie profile is not exact and separate")
		}
		children[cookie.Name] = cookie
	}
	childBearer := children[impersonationhttp.ChildCookieName].Value
	childCSRF := children[impersonationhttp.ChildCSRFCookieName].Value
	if childBearer == childCSRF || childBearer == requester.Bearer.Token() || childBearer == approver.Bearer.Token() || childCSRF == requesterCSRF || childCSRF == approverCSRF {
		t.Fatal("child credentials reuse ordinary authentication or synchronizer")
	}
	assertSecretFree := func(payload []byte) {
		t.Helper()
		for _, secret := range []string{requester.Bearer.Token(), approver.Bearer.Token(), requesterCSRF, approverCSRF, childBearer, childCSRF} {
			if bytes.Contains(payload, []byte(secret)) {
				t.Fatal("impersonation response exposed credential material")
			}
		}
	}
	assertSecretFree(data)
	use := impersonationpg.UseInput{Tenant: otpTenant, Bearer: childBearer, Permission: "profile.read"}
	assertActiveUse := func() {
		t.Helper()
		used, err := native.ValidateUse(ctx, use)
		if err != nil || used.TenantID != otpTenant || used.ActorID != original.Principal.UserID || used.TargetID != target || used.GrantID != started.GrantID || used.GrantVersion != 3 || used.Permission != "profile.read" {
			t.Fatal("real child credential did not authorize exact approved application use")
		}
	}
	assertActiveUse()

	response, data = invoke(http.MethodPost, "/v1/impersonation/start", body, requesterCookies, requesterCSRF, origin, key)
	var replay startMetadata
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &replay) != nil || len(response.Header.Values("Set-Cookie")) != 0 || replay.CredentialIssued {
		t.Fatal("same-key HTTP Start retry did not remain metadata-only")
	}
	expectedReplay := started
	expectedReplay.CredentialIssued = false
	if replay != expectedReplay {
		t.Fatal("same-key HTTP Start retry changed original committed metadata")
	}
	assertSecretFree(data)
	assertDenied("/v1/impersonation/start", requesterCookies, childCSRF, origin, key, body)
	combinedCookies := append(append([]*http.Cookie(nil), requesterCookies...), childCookies...)
	assertDenied("/v1/impersonation/stop", combinedCookies, childCSRF, "https://foreign.example.invalid", "", struct{}{})
	assertDenied("/v1/impersonation/stop", combinedCookies, requesterCSRF, origin, "", struct{}{})
	assertActiveUse()

	response, data = invoke(http.MethodPost, "/v1/impersonation/stop", struct{}{}, combinedCookies, childCSRF, origin, "")
	var stopped struct {
		Stopped       bool               `json:"stopped"`
		ParentResumed bool               `json:"parentResumed"`
		CommitOutcome string             `json:"commitOutcome"`
		CommandID     identity.CommandID `json:"commandID"`
		Error         string             `json:"error"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &stopped) != nil || !stopped.Stopped || !stopped.ParentResumed || stopped.CommitOutcome != "committed" || stopped.CommandID == "" || stopped.Error != "" {
		t.Fatal("HTTP Stop did not commit exact child stop and original parent resumption", response.StatusCode)
	}
	assertSecretFree(data)
	deletions := response.Cookies()
	if len(response.Header.Values("Set-Cookie")) != 2 || len(deletions) != 2 {
		t.Fatal("HTTP Stop must delete exactly the two child cookies")
	}
	for _, cookie := range deletions {
		if children[cookie.Name] == nil || cookie.Value != "" || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.HttpOnly != (cookie.Name == impersonationhttp.ChildCookieName) || cookie.MaxAge != -1 || !cookie.Expires.Equal(time.Unix(1, 0).UTC()) {
			t.Fatal("HTTP Stop mutated ordinary cookies or failed exact child deletion")
		}
		delete(children, cookie.Name)
	}
	if len(children) != 0 {
		t.Fatal("HTTP Stop failed to delete both distinct child cookies")
	}
	if _, err := native.ValidateUse(ctx, use); !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("stopped child credential remained authorized")
	}
	resumed := readOriginal()
	if resumed.Session.ID != original.Session.ID || *resumed.Principal != *original.Principal {
		t.Fatal("HTTP Stop replaced the original ordinary administrator session")
	}
}
