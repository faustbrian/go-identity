//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	impersonationhttp "github.com/faustbrian/go-identity/http/impersonation"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresImpersonationQuorumHTTPS(t *testing.T) {
	for _, profile := range []struct {
		name       string
		standalone bool
	}{{"shared-with-deny", false}, {"quorum-only", true}} {
		t.Run(profile.name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
				postgresBaseline: true, mfaEnrollment: true, passwordMFA: true,
				impersonationQuorum: true, impersonationQuorumStandalone: profile.standalone,
			}, true)
		})
	}
}

// Quorum authority is separate from request/approval and restricted to one
// ordinary administrator, current policy revision and exact grant resource.
type referenceImpersonationQuorumPolicy struct {
	mu      sync.RWMutex
	actor   identity.UserID
	grantID impersonation.GrantID
	denial  *referenceImpersonationDenialPolicy
}

func (p *referenceImpersonationQuorumPolicy) selectGrant(actor identity.UserID, grantID impersonation.GrantID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.actor, p.grantID = actor, grantID
}

func (p *referenceImpersonationQuorumPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action != "identity.impersonation.quorum" {
		return p.denial.Decide(ctx, c)
	}
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	r := c.Request
	if p.actor != "" && p.grantID != "" && r.Tenant == otpTenant && c.PolicyRevision == 9 &&
		r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == authorization.SubjectID(p.actor) &&
		r.Resource.Type == "identity.impersonation.grant" && r.Resource.ID == authorization.ResourceID(p.grantID) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
}

func proveReferenceImpersonationQuorumHTTP(t *testing.T, ctx context.Context, native *reference.ImpersonationService, pool *database.Pool, sessionSchema, riskSchema string, policy *referenceImpersonationQuorumPolicy, client *http.Client, base string, requesterCookies, approverCookies []*http.Cookie, requesterCSRF, approverCSRF string, target identity.UserID) {
	t.Helper()
	if native == nil || pool == nil || pool.Raw() == nil || sessionSchema == "" || riskSchema == "" || policy == nil || client == nil || !strings.HasPrefix(base, "https://") {
		t.Fatal("quorum acceptance requires the existing native owner, PostgreSQL and TLS client")
	}
	ordinary := func(cookies []*http.Cookie, csrf string) impersonationpg.Authentication {
		t.Helper()
		var bearer string
		for _, cookie := range cookies {
			if cookie == nil {
				continue
			}
			if cookie.Name == impersonationhttp.ChildCookieName || cookie.Name == impersonationhttp.ChildCSRFCookieName {
				t.Fatal("quorum requires original ordinary administrator credentials")
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
			t.Fatal("administrator lacks its original CSRF synchronizer")
		}
		return impersonationpg.Authentication{Tenant: otpTenant, Bearer: authentication.NewBearerCredential(bearer), CSRF: synchronizer}
	}
	requester := ordinary(requesterCookies, requesterCSRF)
	approver := ordinary(approverCookies, approverCSRF)
	if requester.Bearer.Token() == approver.Bearer.Token() || requesterCSRF == approverCSRF {
		t.Fatal("quorum requires distinct original administrator credentials")
	}
	const requestReasonText = "synthetic private quorum support request"
	const approvalReasonText = "synthetic private quorum independent approval"
	assertSecretFree := func(data []byte) {
		t.Helper()
		for _, secret := range []string{requester.Bearer.Token(), approver.Bearer.Token(), requesterCSRF, approverCSRF, requestReasonText, approvalReasonText} {
			if bytes.Contains(data, []byte(secret)) {
				t.Fatal("quorum response exposed credential or private reason material")
			}
		}
	}
	// A read sends only its explicit ordinary cookie bundle: no Origin, CSRF,
	// body or idempotency input can accidentally supply mutation authority.
	transport := *client
	transport.Jar = nil
	read := func(path string, cookies []*http.Cookie) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal("cannot construct quorum acceptance request")
		}
		for _, cookie := range cookies {
			if cookie != nil {
				request.AddCookie(cookie)
			}
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("quorum HTTPS transport unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" ||
			response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Set-Cookie")) != 0 {
			t.Fatal("quorum response is unbounded, unprotected or mutates cookies")
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
		response, data := read("/v1/session/get", cookies)
		var result sessionhttp.GetResponse
		if response.StatusCode != http.StatusOK || json.Unmarshal(data, &result) != nil || !result.Authenticated || result.Session == nil || result.Principal == nil || result.Principal.TenantID != otpTenant {
			t.Fatal("original ordinary administrator session is not readable")
		}
		return result
	}
	originalRequester := readOriginal(requesterCookies)
	originalApprover := readOriginal(approverCookies)
	if originalRequester.Principal.UserID == originalApprover.Principal.UserID || originalRequester.Principal.UserID == target || originalApprover.Principal.UserID == target {
		t.Fatal("quorum requires independent requester, administrator and target users")
	}
	requestID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("cannot generate quorum grant identity")
	}
	grantID := impersonation.GrantID(requestID)
	policy.selectGrant(originalApprover.Principal.UserID, grantID)
	scope, err := impersonation.NewScope([]string{"profile.read"})
	if err != nil {
		t.Fatal("cannot construct quorum grant scope")
	}
	reason, err := impersonation.NewReason(requestReasonText)
	if err != nil {
		t.Fatal("cannot construct quorum request reason")
	}
	prepared, err := native.PrepareRequest(ctx, impersonationpg.RequestInput{Authentication: requester, CommandID: requestID, Target: target, Scope: scope, Reason: reason, Duration: 10 * time.Minute, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal("real password/TOTP requester could not prepare quorum grant")
	}
	pending, err := native.Execute(ctx, prepared)
	if err != nil || pending.Outcome != identity.CommitOutcomeCommitted || pending.Feature == nil || pending.Feature.BeforeVersion != 0 || pending.Feature.AfterVersion != 1 || pending.Binding.RecordID != string(grantID) || pending.Binding.UserID != target || identity.UserID(pending.Binding.ActorID) != originalRequester.Principal.UserID {
		t.Fatal("quorum grant did not commit exact pending metadata")
	}
	quotaCount := func() int64 {
		t.Helper()
		var count int64
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.rate_limit_atomic_commands`).Scan(&count); err != nil {
			t.Fatal("selected quorum lacks the shared durable atomic quota owner")
		}
		return count
	}
	snapshot := func() []string {
		t.Helper()
		// Full projections stay in memory: equal counts would miss session or
		// grant rewrites. Administrative quota is the only permitted read effect.
		tables := [][2]string{
			{"identity_impersonation", "grants"}, {"identity_impersonation", "approvals"},
			{"identity_impersonation", "active_grants"}, {"identity_impersonation", "revocations"},
			{"identity_impersonation", "denials"}, {"identity_impersonation", "stop_proofs"}, {"identity_impersonation", "stops"},
			{sessionSchema, "sessions"}, {sessionSchema, "families"}, {sessionSchema, "session_issuances"},
			{"identity", "identity_command_id_claims"}, {"identity", "commands"},
			{"audit", "identity_command_bindings"}, {"audit", "records"},
			{"public", "identity_outbox_bindings"}, {"public", "outbox_messages"},
			{riskSchema, "counter_windows"}, {riskSchema, "counter_aliases"},
			{riskSchema, "counter_charges"}, {riskSchema, "counter_snapshots"},
		}
		state := make([]string, len(tables))
		for i, table := range tables {
			query := `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM ` + pgx.Identifier{table[0], table[1]}.Sanitize() + ` r`
			if err := pool.Raw().QueryRow(ctx, query).Scan(&state[i]); err != nil {
				t.Fatal("cannot observe quorum read-only fixture state", table)
			}
		}
		return state
	}
	path := "/v1/impersonation/quorum?grantID=" + url.QueryEscape(string(grantID))
	assertRejected := func(path string, cookies []*http.Cookie) {
		t.Helper()
		before, debits := snapshot(), quotaCount()
		response, data := read(path, cookies)
		var fields map[string]json.RawMessage
		var result struct {
			Error string `json:"error"`
		}
		if response.StatusCode != http.StatusForbidden || json.Unmarshal(data, &result) != nil || json.Unmarshal(data, &fields) != nil || len(fields) != 1 || result.Error != "denied" {
			t.Fatal("unauthorized quorum read exposed grant metadata or a successful outcome", response.StatusCode)
		}
		if quotaCount() != debits || !reflect.DeepEqual(snapshot(), before) {
			t.Fatal("unauthorized quorum read debited quota or mutated protected state")
		}
	}
	assertRejected(path, requesterCookies)
	assertRejected(path, nil)
	otherGrant, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("cannot generate a separately unauthorized grant locator")
	}
	assertRejected("/v1/impersonation/quorum?grantID="+url.QueryEscape(string(otherGrant)), approverCookies)
	assertQuorum := func(status impersonation.Status, approvals []impersonationpg.QuorumApproval) {
		t.Helper()
		before, debits := snapshot(), quotaCount()
		response, data := read(path, approverCookies)
		var result impersonationpg.QuorumResult
		var fields map[string]json.RawMessage
		if response.StatusCode != http.StatusOK || json.Unmarshal(data, &result) != nil || json.Unmarshal(data, &fields) != nil ||
			len(fields) != 4 || result.GrantID != grantID || result.RequiredApprovals != 1 || result.Status != status || !reflect.DeepEqual(result.Approvals, approvals) {
			t.Fatal("quorum read lost exact safe grant, fixed-one approval or current decision metadata", response.StatusCode)
		}
		for _, field := range []string{"grantID", "requiredApprovals", "approvals", "status"} {
			if _, present := fields[field]; !present {
				t.Fatal("quorum read omitted required safe metadata")
			}
		}
		var approvalFields []map[string]json.RawMessage
		if json.Unmarshal(fields["approvals"], &approvalFields) != nil || len(approvalFields) != len(approvals) {
			t.Fatal("quorum read returned malformed safe approval metadata")
		}
		for _, fields := range approvalFields {
			if len(fields) != 2 || fields["approverID"] == nil || fields["decidedAt"] == nil {
				t.Fatal("quorum read exposed reserved approval material")
			}
		}
		if quotaCount() != debits+1 {
			t.Fatal("successful quorum read did not make exactly one shared atomic quota decision")
		}
		if !reflect.DeepEqual(snapshot(), before) {
			t.Fatal("quorum read mutated grants, sessions, credentials, commands or protected effects")
		}
	}
	assertQuorum(impersonation.StatusPendingApproval, []impersonationpg.QuorumApproval{})
	approvalID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("cannot generate independent quorum approval identity")
	}
	approvalReason, err := impersonation.NewReason(approvalReasonText)
	if err != nil {
		t.Fatal("cannot construct independent quorum approval reason")
	}
	approval, err := native.PrepareApproval(ctx, impersonationpg.ApproveInput{Authentication: approver, CommandID: approvalID, GrantID: grantID, ExpectedVersion: 1, Reason: approvalReason, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal("real independent administrator could not prepare quorum approval")
	}
	approved, err := native.Execute(ctx, approval)
	if err != nil || approved.Outcome != identity.CommitOutcomeCommitted || approved.Feature == nil || approved.Feature.BeforeVersion != 1 || approved.Feature.AfterVersion != 2 || approved.Binding.RecordID != string(grantID) || approved.Binding.UserID != target || identity.UserID(approved.Binding.ActorID) != originalApprover.Principal.UserID {
		t.Fatal("independent quorum approval did not commit exact grant metadata")
	}
	var storedApprover identity.UserID
	var decidedAt time.Time
	if err := pool.Raw().QueryRow(ctx, `SELECT approver_id,decided_at FROM identity_impersonation.approvals WHERE tenant_id=$1 AND grant_id=$2`, otpTenant, string(grantID)).Scan(&storedApprover, &decidedAt); err != nil || storedApprover != originalApprover.Principal.UserID || decidedAt.IsZero() {
		t.Fatal("cannot observe exact independent committed approval metadata")
	}
	assertQuorum(impersonation.StatusApproved, []impersonationpg.QuorumApproval{{ApproverID: storedApprover, DecidedAt: decidedAt.UTC()}})
	if !reflect.DeepEqual(readOriginal(requesterCookies), originalRequester) || !reflect.DeepEqual(readOriginal(approverCookies), originalApprover) {
		t.Fatal("quorum reads changed an original ordinary administrator session")
	}
}
