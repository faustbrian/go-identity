//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresImpersonationDenialHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, mfaEnrollment: true, passwordMFA: true, impersonationDenial: true,
	}, true)
}

func configureReferenceImpersonationDenial(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	configureReferenceImpersonation(t, c, origin)
	c.Impersonation.Denial = true
	c.HTTPImpersonation = nil
	c.HTTPImpersonationDenial = &reference.HTTPImpersonationDenialConfiguration{
		TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)},
		AdminNamespace: "reference-impersonation-denial", AdminKey: [32]byte{0xd1},
		Denied: func(ctx context.Context, _ organizationhttp.AdminRateEvent) error {
			t.Error("unexpected administrative denial rate rejection")
			return ctx.Err()
		},
	}
}

// Denial authority is restricted to the real independent administrator and the
// exact frozen grant, target and scope; the existing enrollment policy is shared.
type referenceImpersonationDenialPolicy struct {
	mu      sync.RWMutex
	actor   identity.UserID
	target  identity.UserID
	grantID impersonation.GrantID
}

func (p *referenceImpersonationDenialPolicy) selectGrant(actor, target identity.UserID, grantID impersonation.GrantID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.actor, p.target, p.grantID = actor, target, grantID
}

func (p *referenceImpersonationDenialPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action != "identity.impersonation.deny" {
		return (referenceImpersonationPolicy{}).Decide(ctx, c)
	}
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	r := c.Request
	grantID, exactGrant := r.Attributes["impersonation.grant-id"].String()
	scope, exactScope := r.Attributes["impersonation.scope"].StringSet()
	if p.actor != "" && p.target != "" && p.grantID != "" && r.Tenant == otpTenant && c.PolicyRevision == 9 &&
		r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == authorization.SubjectID(p.actor) &&
		r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.target) &&
		exactGrant && grantID == string(p.grantID) && exactScope && len(scope) == 1 && scope[0] == "profile.read" {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
}

// The caller supplies the existing PostgreSQL/TLS graph and real password/TOTP
// sessions. Denial uses its own pending grant, separate from start/stop proof.
func proveReferenceImpersonationDenialHTTP(t *testing.T, ctx context.Context, native *reference.ImpersonationService, pool *database.Pool, sessionSchema string, policy *referenceImpersonationDenialPolicy, client *http.Client, base, origin string, requesterCookies, approverCookies []*http.Cookie, requesterCSRF, approverCSRF string, target identity.UserID) {
	t.Helper()
	if native == nil || pool == nil || pool.Raw() == nil || sessionSchema == "" || policy == nil || client == nil || !strings.HasPrefix(base, "https://") {
		t.Fatal("denial acceptance requires the real native owner and TLS client")
	}
	ordinary := func(cookies []*http.Cookie, csrf string) impersonationpg.Authentication {
		t.Helper()
		var bearer string
		for _, cookie := range cookies {
			if cookie == nil {
				continue
			}
			if cookie.Name == impersonationhttp.ChildCookieName || cookie.Name == impersonationhttp.ChildCSRFCookieName {
				t.Fatal("denial requires an ordinary administrator bundle without child credentials")
			}
			if cookie.HttpOnly {
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
		t.Fatal("denial requires distinct original administrator credentials")
	}

	const denialReason = "synthetic independent administrator denial"
	const approvalReasonText = "synthetic competing administrator approval"
	const requestReasonText = "synthetic reference request to deny"
	assertSecretFree := func(data []byte) {
		t.Helper()
		for _, secret := range []string{requester.Bearer.Token(), approver.Bearer.Token(), requesterCSRF, approverCSRF, denialReason, approvalReasonText, requestReasonText} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("denial response exposed private credential or reason material")
			}
		}
	}
	// Ambient jar state cannot change which ordinary session submits a decision.
	transport := *client
	transport.Jar = nil
	invoke := func(method, path string, body any, cookies []*http.Cookie, csrf, requestOrigin string) (*http.Response, []byte) {
		t.Helper()
		var payload []byte
		if body != nil {
			var err error
			payload, err = json.Marshal(body)
			if err != nil {
				t.Fatal("cannot encode denial acceptance request")
			}
			defer clear(payload)
		}
		request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal("cannot construct denial acceptance request")
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
		for _, cookie := range cookies {
			if cookie != nil {
				request.AddCookie(cookie)
			}
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("denial HTTPS transport unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		// The server's outer CORS guard owns this rejection before the
		// selected operation's protected JSON response pipeline.
		jsonResponse := response.Header.Get("Content-Type") == "application/json"
		corsDenied := requestOrigin == "https://foreign.example.invalid" && response.StatusCode == http.StatusForbidden &&
			response.Header.Get("Content-Type") == "text/plain; charset=utf-8" && string(data) == "identity.http.origin_denied\n"
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" ||
			response.Header.Get("X-Content-Type-Options") != "nosniff" || (!jsonResponse && !corsDenied) {
			t.Fatalf("%s %s: unprotected response: status=%d readable=%t bounded=%t no-store=%t nosniff=%t json=%t",
				method, path, response.StatusCode, readErr == nil && closeErr == nil, len(data) <= 16384,
				response.Header.Get("Cache-Control") == "no-store", response.Header.Get("X-Content-Type-Options") == "nosniff", jsonResponse)
		}
		if len(response.Header.Values("Set-Cookie")) != 0 {
			t.Fatal("denial acceptance mutated an ordinary or child cookie")
		}
		assertSecretFree(data)
		for _, values := range response.Header {
			for _, value := range values {
				assertSecretFree([]byte(value))
			}
		}
		return response, data
	}
	readOriginal := func(cookies []*http.Cookie) sessionhttp.GetResponse {
		t.Helper()
		response, data := invoke(http.MethodGet, "/v1/session/get", nil, cookies, "", "")
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.Unmarshal(data, &result) != nil || !result.Authenticated || result.Session == nil || result.Principal == nil || result.Principal.TenantID != otpTenant {
			t.Fatal("original ordinary administrator session is not readable")
		}
		return result
	}
	originalRequester := readOriginal(requesterCookies)
	originalApprover := readOriginal(approverCookies)
	if originalRequester.Principal.UserID == originalApprover.Principal.UserID || originalRequester.Principal.UserID == target || originalApprover.Principal.UserID == target {
		t.Fatal("denial requires independent requester, administrator and target users")
	}

	requestID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("cannot generate denial grant request identity")
	}
	policy.selectGrant(originalApprover.Principal.UserID, target, impersonation.GrantID(requestID))
	scope, err := impersonation.NewScope([]string{"profile.read"})
	if err != nil {
		t.Fatal("cannot construct denial grant scope")
	}
	requestReason, err := impersonation.NewReason(requestReasonText)
	if err != nil {
		t.Fatal("cannot construct denial grant request reason")
	}
	prepared, err := native.PrepareRequest(ctx, impersonationpg.RequestInput{Authentication: requester, CommandID: requestID, Target: target, Scope: scope, Reason: requestReason, Duration: 10 * time.Minute, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal("real password/TOTP requester could not prepare denial grant")
	}
	requestBinding, err := prepared.Binding()
	if err != nil || requestBinding.TenantID != otpTenant || identity.UserID(requestBinding.ActorID) != originalRequester.Principal.UserID || requestBinding.UserID != target {
		t.Fatal("denial request binding lost the original actor, target or tenant")
	}
	pending, err := native.Execute(ctx, prepared)
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted || pending.Binding != requestBinding || pending.Feature == nil || pending.Feature.BeforeVersion != 0 || pending.Feature.AfterVersion != 1 {
		t.Fatal("denial grant request did not commit exact pending metadata")
	}
	approvalID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("cannot generate competing approval identity")
	}
	approvalReason, err := impersonation.NewReason(approvalReasonText)
	if err != nil {
		t.Fatal("cannot construct competing approval reason")
	}
	approvalInput := impersonationpg.ApproveInput{Authentication: approver, CommandID: approvalID, GrantID: impersonation.GrantID(requestID), ExpectedVersion: 1, Reason: approvalReason, Network: "127.0.0.1"}
	approval, err := native.PrepareApproval(ctx, approvalInput)
	if err != nil {
		t.Fatal("independent real administrator could not prepare competing approval")
	}
	approvalBinding, err := approval.Binding()
	if err != nil || identity.UserID(approvalBinding.ActorID) != originalApprover.Principal.UserID || approvalBinding.ActorID == requestBinding.ActorID || approvalBinding.UserID != target || approvalBinding.RecordID != string(requestID) {
		t.Fatal("competing approval lost independent actor or exact grant")
	}
	credentialCounts := func() [2]int64 {
		t.Helper()
		var counts [2]int64
		schema := pgx.Identifier{sessionSchema}.Sanitize()
		query := `SELECT (SELECT count(*) FROM ` + schema + `.sessions WHERE tenant_id=$1),
			(SELECT count(*) FROM ` + schema + `.session_issuances WHERE tenant_id=$1)`
		if err := pool.Raw().QueryRow(ctx, query, otpTenant).Scan(&counts[0], &counts[1]); err != nil {
			t.Fatal("cannot observe original session and credential issuance counts")
		}
		return counts
	}
	originalCredentialCounts := credentialCounts()
	quotaCount := func() int64 {
		t.Helper()
		var count int64
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.rate_limit_atomic_commands`).Scan(&count); err != nil {
			t.Fatal("selected denial lacks the durable atomic quota owner")
		}
		return count
	}
	for _, path := range []string{"/v1/impersonation/start", "/v1/impersonation/stop"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal("cannot construct unavailable activation route request")
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("X-CSRF-Token", approverCSRF)
		for _, cookie := range approverCookies {
			if cookie != nil {
				request.AddCookie(cookie)
			}
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("unavailable activation route HTTPS transport failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.StatusCode != http.StatusNotFound || len(response.Header.Values("Set-Cookie")) != 0 {
			t.Fatal("denial-only HTTP selected an activation route or changed credentials")
		}
		assertSecretFree(data)
	}

	body := map[string]any{"grantID": requestID, "expectedVersion": uint64(1), "reason": denialReason}
	assertRejected := func(cookies []*http.Cookie, csrf, requestOrigin string, status int, code string) {
		t.Helper()
		response, data := invoke(http.MethodPost, "/v1/impersonation/deny", body, cookies, csrf, requestOrigin)
		var result struct {
			Denied        bool   `json:"denied"`
			CommitOutcome string `json:"commitOutcome"`
			Error         string `json:"error"`
		}
		if response.StatusCode != status || json.Unmarshal(data, &result) != nil || result.Denied || result.CommitOutcome == "committed" || result.Error != code {
			t.Fatal("denial rejection lost safe noncommitted metadata", response.StatusCode)
		}
	}
	assertRejected(requesterCookies, requesterCSRF, origin, http.StatusForbidden, "denied")
	foreign, foreignBody := invoke(http.MethodPost, "/v1/impersonation/deny", body, approverCookies, approverCSRF, "https://foreign.example.invalid")
	if foreign.StatusCode != http.StatusForbidden || foreign.Header.Get("Content-Type") != "text/plain; charset=utf-8" ||
		string(foreignBody) != "identity.http.origin_denied\n" {
		t.Fatal("foreign Origin did not stop at the outer CORS owner")
	}
	assertRejected(approverCookies, requesterCSRF, origin, http.StatusForbidden, "denied")

	priorDebits := quotaCount()
	response, data := invoke(http.MethodPost, "/v1/impersonation/deny", body, approverCookies, approverCSRF, origin)
	if quotaCount() != priorDebits+1 {
		t.Fatal("admitted denial did not make exactly one atomic quota decision")
	}
	var denied struct {
		Denied        bool                  `json:"denied"`
		CommitOutcome string                `json:"commitOutcome"`
		CommandID     identity.CommandID    `json:"commandID"`
		GrantID       impersonation.GrantID `json:"grantID"`
	}
	var fields map[string]json.RawMessage
	if response.StatusCode != http.StatusOK || json.Unmarshal(data, &denied) != nil || json.Unmarshal(data, &fields) != nil || len(fields) != 4 || !denied.Denied || denied.CommitOutcome != "committed" || denied.GrantID != impersonation.GrantID(requestID) || denied.CommandID == requestID || denied.CommandID == approvalID {
		t.Fatal("HTTP denial did not return exact safe committed grant metadata", response.StatusCode)
	}
	if _, err := identity.ParseCommandID(string(denied.CommandID)); err != nil {
		t.Fatal("HTTP denial did not return a valid distinct command identity")
	}
	for _, field := range []string{"denied", "commitOutcome", "commandID", "grantID"} {
		if _, ok := fields[field]; !ok {
			t.Fatal("HTTP denial omitted required safe metadata")
		}
	}

	// The same semantic POST has no Idempotency-Key and is a new attempted
	// decision, not keyed recovery of the first command's successful metadata.
	assertRejected(approverCookies, approverCSRF, origin, http.StatusConflict, "conflict")
	result, err := native.Execute(ctx, approval)
	if err == nil || result.Binding != approvalBinding || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatalf("a preprepared approval did not settle as not committed: outcome=%v error=%T exactBinding=%t",
			result.Outcome, err, result.Binding == approvalBinding)
	}
	var storedCommand, storedDenier, storedRequester, storedTarget string
	var beforeVersion, afterVersion, denials, approvals, activations, revocations int64
	var ciphertext []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT d.command_id,d.denier_id,d.requester_id,d.target_id,
		d.before_version,d.after_version,d.encrypted_payload,
		(SELECT count(*) FROM identity_impersonation.denials WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id),
		(SELECT count(*) FROM identity_impersonation.approvals WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id),
		(SELECT count(*) FROM identity_impersonation.active_grants WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id),
		(SELECT count(*) FROM identity_impersonation.revocations WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id)
		FROM identity_impersonation.denials d WHERE d.tenant_id=$1 AND d.grant_id=$2`, otpTenant, string(requestID)).
		Scan(&storedCommand, &storedDenier, &storedRequester, &storedTarget, &beforeVersion, &afterVersion, &ciphertext, &denials, &approvals, &activations, &revocations); err != nil {
		t.Fatal("cannot read durable terminal denial")
	}
	defer clear(ciphertext)
	if storedCommand != string(denied.CommandID) || storedDenier != string(originalApprover.Principal.UserID) ||
		storedRequester != string(originalRequester.Principal.UserID) || storedTarget != string(target) ||
		beforeVersion != 1 || afterVersion != 2 || denials != 1 || approvals != 0 || activations != 0 || revocations != 0 ||
		len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte(denialReason)) {
		t.Fatal("HTTP denial lost its exact independent actor, protected intent or single terminal effect")
	}
	commandBytes, err := base64.RawURLEncoding.DecodeString(string(denied.CommandID))
	if err != nil {
		t.Fatal("cannot decode denial command identity")
	}
	var audits, lifecycle, leakedReasons int64
	if err := pool.Raw().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),
		(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
		(SELECT count(*) FROM audit.records WHERE correlation_id=$2 AND position(convert_to($3,'UTF8') in canonical_record)>0)`,
		commandBytes, string(denied.CommandID), denialReason).Scan(&audits, &lifecycle, &leakedReasons); err != nil || audits != 1 || lifecycle != 1 || leakedReasons != 0 {
		t.Fatal("denial omitted or repeated protected effects or exposed its private reason")
	}
	if credentialCounts() != originalCredentialCounts {
		t.Fatal("denial or a terminal retry created an ordinary or child credential")
	}
	if !reflect.DeepEqual(readOriginal(requesterCookies), originalRequester) || !reflect.DeepEqual(readOriginal(approverCookies), originalApprover) {
		t.Fatal("denial changed an original ordinary administrator session")
	}
}
