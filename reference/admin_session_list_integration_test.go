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
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

func TestReferencePostgresAdminSessionListHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, mfaEnrollment: true, passwordMFA: true, adminSessionListHTTP: true,
	}, true)
}

type referenceAdminSessionListPolicy struct {
	actor, target identity.UserID
	calls         atomic.Int64
}

func (p *referenceAdminSessionListPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action != "identity.admin.session-list" {
		return (referenceRegistrationPolicy{}).Decide(ctx, c)
	}
	p.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if p.actor != "" && p.target != "" && c.PolicyRevision == 9 && r.Tenant == otpTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == authorization.SubjectID(p.actor) && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(p.target) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, nil
}

func configureReferenceAdminSessionListHTTP(t *testing.T, c *reference.StoreConfiguration) {
	t.Helper()
	c.HTTPAdminSessionList = &reference.HTTPAdminSessionListConfiguration{
		PolicyRevision: 9, MaximumDuration: time.Second,
		AdminNamespace: "reference-session-list-admin", AdminKey: [32]byte{222},
		Denied: func(ctx context.Context, event organizationhttp.AdminRateEvent) error {
			if event.Operation != "identity.admin.session-list" || event.Reason != "limited" && event.Reason != "unavailable" {
				t.Error("administrator session list quota lost exact operation or redacted denial reason")
			}
			return ctx.Err()
		},
	}
}

type referenceAdminSessionListDevice struct {
	SessionID  string    `json:"sessionID"`
	Label      string    `json:"label"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Current    bool      `json:"current"`
	Inactive   bool      `json:"inactive"`
}

func proveReferenceAdminSessionListHTTP(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, config reference.StoreConfiguration, policy *referenceAdminSessionListPolicy, client *http.Client, base, origin string, messages <-chan string) {
	t.Helper()
	if !strings.HasPrefix(base, "https://") || config.HTTPAdminSessionList == nil || config.HTTPRate == nil || config.UserStatusAdministration != nil || config.Impersonation != nil {
		t.Fatal("administrator session list requires standalone HTTPS selection and canonical rate owner")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	transport := *client
	transport.Jar = nil
	actorCookies, actorCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "session-list-administrator")
	actor := organizationHumanFromSession(t, ctx, sessions, actorCookies, actorCSRF)
	otherCookies, otherCSRF := referenceImpersonationAdmin(t, ctx, &transport, base, origin, features, workers, messages, "session-list-unauthorized")
	other := organizationHumanFromSession(t, ctx, sessions, otherCookies, otherCSRF)
	target := registerReferenceOrganizationHuman(t, ctx, &transport, base, origin, features, workers, messages, "session-list-target")
	fresh, freshToken := referencePasswordLogin(t, ctx, f, &transport, base, origin, nil, config.PasswordSignin.Native, "synthetic-registration-password", "session-list-target@example.invalid")
	if actor.user == other.user || actor.user == target.user || other.user == target.user || !fresh.SignedIn || fresh.SessionID == target.sessionID {
		t.Fatal("administrator list requires independent genuine actors and two target sessions")
	}
	freshWire, err := freshToken.Reveal()
	if err != nil {
		t.Fatal("second genuine target credential unavailable")
	}
	policy.actor, policy.target = actor.user, target.user
	metadata := func(token session.Token) referenceAdminSessionListDevice {
		t.Helper()
		credential, err := session.NewCredential(session.CredentialCookie, token)
		if err != nil {
			t.Fatal(err)
		}
		observed, err := sessions.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
		if err != nil || !observed.Authenticated || observed.ValidateAt(time.Now()) != nil {
			t.Fatal("genuine target session is not readable", err)
		}
		binding, bindingErr := observed.Session.Bindings()
		lifetime, lifetimeErr := observed.Session.Lifetime(time.Now())
		if bindingErr != nil || lifetimeErr != nil || binding.UserID != target.user {
			t.Fatal("target session metadata is not native owned")
		}
		return referenceAdminSessionListDevice{SessionID: binding.SessionID, LastSeenAt: binding.LastActivityAt.UTC(), ExpiresAt: lifetime.ExpiresAt.UTC()}
	}
	oldToken, err := session.ParseToken(target.cookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]referenceAdminSessionListDevice{target.sessionID: metadata(oldToken), fresh.SessionID: metadata(freshToken)}
	orderedIDs := []string{target.sessionID, fresh.SessionID}
	slices.Sort(orderedIDs)
	quotaCount := func() int64 {
		t.Helper()
		var count int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.rate_limit_atomic_commands`).Scan(&count); err != nil {
			t.Fatal("administrator session list lacks native durable atomic quota", err)
		}
		return count
	}
	snapshot := func() []string {
		t.Helper()
		schema := config.Session.Native.Execution.Repository.Schema
		tables := [][2]string{{schema, "sessions"}, {schema, "families"}, {schema, "session_issuances"}, {schema, "session_labels"}, {"identity", "users"}, {"identity", "identity_command_id_claims"}, {"identity", "commands"}, {"identity", "request_key_mappings"}, {"audit", "identity_command_bindings"}, {"audit", "records"}, {"public", "identity_outbox_bindings"}, {"public", "outbox_messages"}}
		state := make([]string, len(tables))
		for i, table := range tables {
			query := `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM ` + pgx.Identifier{table[0], table[1]}.Sanitize() + ` r`
			if err := f.pool.Raw().QueryRow(ctx, query).Scan(&state[i]); err != nil {
				t.Fatal("cannot observe administrator list read-only state", table)
			}
		}
		return state
	}
	invoke := func(subject identity.UserID, cursor string, cookies []*http.Cookie) (int, []byte) {
		t.Helper()
		query := url.Values{"targetSubjectID": []string{string(subject)}, "limit": []string{"1"}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/admin/session-list?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := transport.Do(request)
		if err != nil {
			t.Fatal("administrator session list HTTPS transport unavailable", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Content-Type") != "application/json" || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("administrator session list violated bounded credential-free response custody")
		}
		for _, secret := range []string{actorCookies[0].Value, actorCSRF, otherCookies[0].Value, otherCSRF, target.cookies[0].Value, target.csrf, freshWire} {
			if secret != "" && bytes.Contains(data, []byte(secret)) {
				t.Fatal("administrator session list disclosed original credential custody")
			}
		}
		if response.StatusCode != http.StatusOK {
			var denied map[string]json.RawMessage
			if json.Unmarshal(data, &denied) != nil || denied["error"] == nil || denied["sessions"] != nil || denied["nextCursor"] != nil {
				t.Fatal("denied administrator list disclosed partial session metadata or a cursor")
			}
		}
		return response.StatusCode, data
	}
	decode := func(data []byte, wantSession string, wantEnd bool) string {
		t.Helper()
		var page struct {
			Sessions   []referenceAdminSessionListDevice `json:"sessions"`
			NextCursor string                            `json:"nextCursor"`
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(data, &page) != nil || json.Unmarshal(data, &fields) != nil || len(fields) != 2 || fields["nextCursor"] == nil || len(page.Sessions) != 1 || page.Sessions[0] != expected[wantSession] || (page.NextCursor == "") != wantEnd {
			t.Fatal("administrator list did not return exact safe target metadata and cursor boundary")
		}
		var devices []map[string]json.RawMessage
		if json.Unmarshal(fields["sessions"], &devices) != nil || len(devices) != 1 || len(devices[0]) != 6 {
			t.Fatal("administrator list returned fields outside safe device metadata")
		}
		for _, field := range []string{"sessionID", "label", "lastSeenAt", "expiresAt", "current", "inactive"} {
			if devices[0][field] == nil {
				t.Fatal("administrator list replaced required safe device metadata")
			}
		}
		return page.NextCursor
	}
	before, quota := snapshot(), quotaCount()
	status, _ := invoke(target.user, "", otherCookies)
	if status != http.StatusForbidden || quotaCount() != quota {
		t.Fatal("unauthorized genuine MFA actor read target sessions or charged quota", status)
	}
	status, _ = invoke(actor.user, "", actorCookies)
	if status != http.StatusForbidden || quotaCount() != quota {
		t.Fatal("administrator list substituted the actor for the authorized target", status)
	}
	status, first := invoke(target.user, "", actorCookies)
	if status != http.StatusOK || quotaCount() != quota+1 {
		t.Fatal("authorized target page did not charge native administrative quota once", status)
	}
	cursor := decode(first, orderedIDs[0], false)
	policyCalls := policy.calls.Load()
	status, _ = invoke(other.user, cursor, actorCookies)
	if status != http.StatusBadRequest || quotaCount() != quota+1 || policy.calls.Load() != policyCalls {
		t.Fatal("cross-target cursor reached target policy or quota admission", status)
	}
	status, replay := invoke(target.user, "", actorCookies)
	if status != http.StatusOK || !bytes.Equal(first, replay) || quotaCount() != quota+2 {
		t.Fatal("repeated first page changed the exact cursor or charged quota incorrectly", status)
	}
	status, second := invoke(target.user, cursor, actorCookies)
	if status != http.StatusOK || quotaCount() != quota+3 {
		t.Fatal("exact original cursor did not fetch the second target page with one debit", status)
	}
	decode(second, orderedIDs[1], true)
	if !reflect.DeepEqual(snapshot(), before) {
		t.Fatal("administrator session read mutated identity, credentials, labels, commands, audit or lifecycle state")
	}
}
