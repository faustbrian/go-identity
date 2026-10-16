//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/reference"
)

// This is an explicit bounded application policy, not an identity store. Its
// IDs come only from two genuine public registration/verification/signin flows.
// An ID shaped like an administrator or an authenticated session grants nothing.
type administrativeEmailGrant struct {
	mu            sync.Mutex
	actor, target identity.UserID
	deny          bool
	removal       bool
}

func (p *administrativeEmailGrant) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	p.mu.Lock()
	selectedAction := !p.removal && (c.Request.Action == "identity.email.address-get" || c.Request.Action == "identity.email.address-list") || p.removal && (c.Request.Action == "identity.email.address-remove" || c.Request.Action == "identity.email.address-remove.recover")
	allowed := !p.deny && p.actor != "" && p.target != "" && c.PolicyRevision == 9 && c.Request.Tenant == otpTenant && c.Request.Subject.Kind == authorization.SubjectUser && c.Request.Subject.ID == authorization.SubjectID(p.actor) && c.Request.Resource.Type == "identity.user" && c.Request.Resource.ID == authorization.ResourceID(p.target) && selectedAction
	p.mu.Unlock()
	if allowed {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func TestReferencePostgresAdministrativeEmailQueriesHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, administrativeEmailQueries: true})
}

func proveAdministrativeEmailReads(t *testing.T, ctx context.Context, f liveStores, features reference.FeatureSet, workers reference.WorkerSet, client *http.Client, base, origin string, messages <-chan string, invoke func(string, any, string, []*http.Cookie) (*http.Response, []byte), issue func(string) (sessionhttp.PreAuthResponse, []*http.Cookie), actorCookies []*http.Cookie, actorCSRF string, actorSession string, actor identity.UserID) {
	t.Helper()
	flow, device := issue("signup")
	r, payload := invoke("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": "target@example.invalid", "password": "synthetic-target-password", "callbackURL": origin + "/confirm"}, "target-registration", device)
	var registered passwordhttp.SignupResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &registered) != nil || !registered.VerificationRequired {
		t.Fatal("real target registration", r.StatusCode)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("target verification delivery", err)
	}
	var link string
	select {
	case link = <-messages:
	case <-ctx.Done():
		t.Fatal("target delivery absent")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal("target verification link")
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	r, payload = invoke("/v1/email/verification-confirm", map[string]string{"token": u.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(command)}, "", nil)
	var confirmed emailhttp.ConfirmationResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &confirmed) != nil || !confirmed.Confirmed || confirmed.Recovery == nil {
		t.Fatal("target verification", r.StatusCode)
	}
	target, address := confirmed.Recovery.UserID, identity.IdentifierID(confirmed.Recovery.RecordID)
	if target == actor {
		t.Fatal("administrative test must have distinct real identities")
	}
	login, device := issue("password")
	r, payload = invoke("/v1/password/signin", map[string]string{"flowID": string(login.FlowID), "identifier": "target@example.invalid", "password": "synthetic-target-password", "callbackURL": origin + "/reset"}, "", device)
	var signed passwordhttp.SigninResponse
	if r.StatusCode != 200 || json.Unmarshal(payload, &signed) != nil || !signed.SignedIn || len(r.Cookies()) != 1 {
		t.Fatal("real target signin", r.StatusCode)
	}
	targetCookies := r.Cookies()
	observe := func() [5]int64 {
		t.Helper()
		var state [5]int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT COALESCE(sum(version),0) FROM identity.users),(SELECT COALESCE(sum(version),0) FROM identity.identifiers),(SELECT COALESCE(sum(verification_version),0) FROM identity.identifiers),(SELECT count(*) FROM identity.commands),(SELECT COALESCE(sum(uses),0) FROM capability_identity_one_use)`).Scan(&state[0], &state[1], &state[2], &state[3], &state[4]); err != nil {
			t.Fatal("primary read effect observation", err)
		}
		return state
	}
	before := observe()
	request := func(path string, cookies []*http.Cookie, want int) []byte {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, "GET", base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(body) > 1<<20 || response.StatusCode != want || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || response.Header.Get("X-CSRF-Token") != "" {
			t.Fatal("administrative read boundary", response.StatusCode, want)
		}
		if want != 200 && (bytes.Contains(body, []byte(target)) || bytes.Contains(body, []byte(actor)) || bytes.Contains(body, []byte("@example.invalid"))) {
			t.Fatal("denial disclosed personal data")
		}
		return body
	}
	get := "/v1/email/address-get?addressID=" + url.QueryEscape(string(address)) + "&targetSubjectID=" + url.QueryEscape(string(target))
	list := "/v1/email/address-list?targetSubjectID=" + url.QueryEscape(string(target))
	request(get, actorCookies, 403) // Real authentication alone is insufficient.
	f.adminEmailGrant.mu.Lock()
	f.adminEmailGrant.actor, f.adminEmailGrant.target = actor, target
	f.adminEmailGrant.mu.Unlock()
	for _, path := range []string{get, list} {
		body := request(path, actorCookies, 200)
		if !bytes.Contains(body, []byte(target)) || bytes.Contains(body, []byte(actor)) || !bytes.Contains(body, []byte("target@example.invalid")) || bytes.Contains(body, []byte("registered@example.invalid")) {
			t.Fatal("target became actor or crossed subject boundary")
		}
	}
	request("/v1/email/address-get?addressID="+url.QueryEscape(string(address)), actorCookies, 403)
	request("/v1/email/address-get?addressID=missing-address&targetSubjectID="+url.QueryEscape(string(target)), actorCookies, 403)
	request("/v1/email/address-list?targetSubjectID="+url.QueryEscape(string(actor)), targetCookies, 403)
	request(list+"&targetSubjectID="+url.QueryEscape(string(target)), actorCookies, 400)
	queries, err := features.EmailAddresses()
	if err != nil || !queries.AdministrativeQueriesConfigured() {
		t.Fatal("native audit composition unavailable", err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: otpTenant, Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: "identity.email.address-get", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(target)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	got, err := queries.AddressGet(ctx, email.AddressGetRequest{TenantID: otpTenant, TargetSubjectID: target, AddressID: address, Caller: caller})
	if err != nil {
		t.Fatal("public native administrative query", err)
	}
	binding, err := got.Address.Bindings()
	if err != nil || binding.UserID != target || binding.IdentifierID != address {
		t.Fatal("native target mismatch")
	}
	caller.PolicyRevision = 8
	denied, err := queries.AddressGet(ctx, email.AddressGetRequest{TenantID: otpTenant, TargetSubjectID: target, AddressID: address, Caller: caller})
	if err == nil || denied.Address != (identity.IdentifierProjection{}) {
		t.Fatal("stale policy disclosed projection")
	}
	caller.PolicyRevision, caller.Request.Tenant = 9, "foreign"
	denied, err = queries.AddressGet(ctx, email.AddressGetRequest{TenantID: "foreign", TargetSubjectID: target, AddressID: address, Caller: caller})
	if err == nil || denied.Address != (identity.IdentifierProjection{}) {
		t.Fatal("foreign tenant disclosed projection")
	}
	var successes, denials int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FILTER(WHERE actor_id=$1 AND subject_id=$2 AND outcome=$3),count(*) FILTER(WHERE subject_id='undisclosed' AND outcome=$4) FROM audit.records WHERE action IN ('identity.email.address-get','identity.email.address-list')`, string(actor), string(target), int16(audit.OutcomeSucceeded), int16(audit.OutcomeDenied)).Scan(&successes, &denials); err != nil || successes != 3 || denials < 3 {
		t.Fatal("required durable actor/target access records missing", successes, denials, err)
	}
	var leaked int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE action IN ('identity.email.address-get','identity.email.address-list') AND (convert_from(canonical_record,'UTF8') LIKE '%@example.invalid%' OR convert_from(canonical_record,'UTF8') LIKE '%targetSubjectID%')`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("administrative audit leaked input", err)
	}
	// A real failing primary audit write must withhold otherwise allowed data.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION admin_access_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action IN ('identity.email.address-get','identity.email.address-list') THEN RAISE EXCEPTION 'synthetic unavailable audit'; END IF; RETURN NEW; END $$; CREATE TRIGGER admin_access_fail BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION admin_access_fail()`); err != nil {
		t.Fatal(err)
	}
	request(get, actorCookies, 503)
	request("/v1/email/address-list", actorCookies, 200) // Self reads still work.
	if _, err := f.pool.Raw().Exec(ctx, `DROP TRIGGER admin_access_fail ON audit.records; DROP FUNCTION admin_access_fail()`); err != nil {
		t.Fatal(err)
	}
	f.adminEmailGrant.mu.Lock()
	f.adminEmailGrant.deny = true
	f.adminEmailGrant.mu.Unlock()
	request(get, actorCookies, 403)
	f.adminEmailGrant.mu.Lock()
	f.adminEmailGrant.deny = false
	f.adminEmailGrant.mu.Unlock()
	if observe() != before {
		t.Fatal("administrative reads mutated identity, verification, command or one-use authority")
	}
	proveRegistrationSessionLogout(t, ctx, client, base, origin, actorCookies, actorCSRF, actorSession, f, features)
	request(get, actorCookies, 403)
}
