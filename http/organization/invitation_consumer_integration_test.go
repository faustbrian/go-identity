//go:build integration

package organizationhttp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// The startup composition and genuine registration helpers are retained from
// go-organization/postgres consumer fixtures at 2cbf261. Only the email sender
// and outbound HIBP HTTP provider are controlled seams; no user, session,
// verified identifier, invitation, capability or membership is fabricated.
func TestInvitationGenuineHTTPConsumer(t *testing.T) {
	ctx, pool, db := consumerDatabase(t)
	keys := make(map[string][32]byte)
	for _, name := range strings.Fields("fingerprint request counter risk-evidence risk-seal preauth-cookie session-token session-csrf http-device delivery-envelope dummy-password capability-binding capability-signing signin-proof migration counter-replay http-rate otp-lockout otp-wrap otp-attempt otp-code otp-intent identifier delivery-digest delivery-namespace password-flow signup-binding signup-intent verification-scope capability-replay capability-envelope counter-envelope verification-http") {
		var key [32]byte
		if _, e := rand.Read(key[:]); e != nil {
			t.Fatal("consumer entropy unavailable")
		}
		keys[name] = key
	}
	t.Cleanup(func() { clear(keys) })
	material := func(name string) []byte { key := keys[name]; return append([]byte(nil), key[:]...) }
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	mailbox := new(registrationMailbox)
	graph, err := fixtureGraph(ctx, origin, keys, pool, mailbox, hibpTransport{})
	if err != nil {
		t.Fatal("genuine Reference graph rejected", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if graph.close(cleanup) != nil {
			t.Error("genuine Reference cleanup failed")
		}
		mailbox.mu.Lock()
		mailbox.body = ""
		mailbox.mu.Unlock()
	})
	installOrganizationHTTPConsumer(t, ctx, graph, db)
	lookup, err := session.NewDigestKey(11, material("session-token"))
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	sessions, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
	if err != nil {
		t.Fatal(err)
	}
	native := consumerOrganizationService(t, pool, sessions, profile, lookup, keys, material)
	invitations, restartInvitations, status, limits := invitationConsumerOwners(t, ctx, pool, sessions, profile, lookup, keys, material, origin)
	policy, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("invitation-http-consumer", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("invitation-http", map[string][]byte{"invitation-http": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	memberReader, err := organizationpg.NewOperationService(native, organizationpg.OperationServiceConfig{ConfigurationID: "invitation-http-consumer", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(ctx context.Context) (organization.ID, error) {
		id, e := identity.NewSubjectID()
		return organization.ID(id), errors.Join(ctx.Err(), e)
	}})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := ratepg.OpenStrict(ctx, pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	safe, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: backend, Namespace: "invitation-http-consumer", Now: time.Now, MaximumDuration: time.Second, EmergencyMaximumKeys: 128, Degraded: func(ctx context.Context, _ identityhttp.SafeRateEvent) error { return ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if e := safe.Close(); e != nil {
			t.Error("safe rate cleanup failed")
		}
	})
	parsedOrigin, _ := url.Parse(origin)
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 2048, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: parsedOrigin.Hostname(), TenantID: baselineTenant}, {Host: "foreign.example", TenantID: "foreign-tenant"}}}
	transport := identityhttp.TransportPolicy{Network: network, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Genuine invitation consumer", Version: "1"}}
	cfg := organizationhttp.Config{Network: network, Sessions: sessions, Service: memberReader, Invitations: invitations, SafeRate: safe, Now: time.Now, MaximumDuration: 4 * time.Second}
	build := func(current *organizationpg.InvitationService) (http.Handler, identityhttp.OpenAPIDocument) {
		t.Helper()
		selected := cfg
		selected.Invitations = current
		feature, e := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: selected, Get: true, InvitationGet: true, InvitationListMine: true})
		if e != nil {
			t.Fatal(e)
		}
		ops, e := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if e != nil {
			t.Fatal(e)
		}
		h, doc, e := identityhttp.NewRouter(transport, ops, nil)
		if e != nil {
			t.Fatal(e)
		}
		return h, doc
	}
	handler, document := build(invitations)
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil || len(document.Operations()) != 3 {
		t.Fatal("selected invitation document invalid", err)
	}
	validateResponse := func(path string, status int, body []byte) {
		t.Helper()
		schema := parsed.Raw()
		for _, key := range []string{"paths", strings.SplitN(path, "?", 2)[0], "get", "responses", strconv.Itoa(status), "content", "application/json", "schema"} {
			var found bool
			schema, found = schema.Lookup(key)
			if !found {
				t.Fatal("native response undocumented", status)
			}
		}
		instance, e := parse.JSON(ctx, bytes.NewReader(body), parse.DefaultLimits())
		if e != nil {
			t.Fatal("native response not JSON")
		}
		report, e := validate.SchemaInstance(ctx, parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if e != nil || !report.Valid() {
			t.Fatal("native response violates wire metadata", status)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/organization/", handler)
	mux.Handle("/", graph.server.Handler())
	server.Config.Handler = mux
	server.Config.ReadHeaderTimeout = time.Second
	server.StartTLS()
	owner, ownerID := registerOrganizationHTTPHuman(t, ctx, server, origin, graph, mailbox, sessions)
	recipient, recipientID := registerOrganizationHTTPHuman(t, ctx, server, origin, graph, mailbox, sessions)
	if ownerID == recipientID {
		t.Fatal("genuine distinct recipients not created")
	}
	directory, e := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	identifiers, e := directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: baselineTenant, UserID: recipientID, MaximumIdentifiers: 128})
	if e != nil || len(identifiers.Identifiers) != 1 || !identifiers.Identifiers[0].Verified {
		t.Fatal("genuine current verified identifier missing", e)
	}
	invitationMailbox := new(registrationMailbox)
	worker, e := status.NewWorker(deliverypg.WorkerConfig{ProviderConfigVersion: 2, Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "invitation-worker", Request: authorization.Request{Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "invitation-worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "invitation-worker"}}}}, invitationMailbox)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { invitationMailbox.mu.Lock(); invitationMailbox.body = ""; invitationMailbox.mu.Unlock() })
	type issued struct {
		org, id organization.ID
		proof   capability.Proof
		wire    string
	}
	issue := func(slug string) issued {
		t.Helper()
		org, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		create, e := native.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(org), Name: "Genuine invitation HTTP", Slug: slug, CorrelationID: "invitation-http-create"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if out, e := native.Execute(ctx, create); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine organization create failed", e)
		}
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		send, e := invitations.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(id), OrganizationID: organization.ID(org), OrganizationVersion: 1, RecipientUserID: recipientID, RecipientIdentifierID: identifiers.Identifiers[0].ID, CorrelationID: "invitation-http-send"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if out, e := invitations.Execute(ctx, send); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine invitation send failed", e)
		}
		if _, e := worker.ProcessOne(ctx); e != nil {
			t.Fatal("genuine encrypted delivery failed", e)
		}
		invitationMailbox.mu.Lock()
		link := invitationMailbox.body
		invitationMailbox.body = ""
		invitationMailbox.mu.Unlock()
		u, e := url.Parse(link)
		if e != nil || u.Query().Get("token") == "" {
			t.Fatal("actual invitation delivery missing")
		}
		proof, e := capability.ParseProof(u.Query().Get("token"), limits)
		if e != nil {
			t.Fatal("delivered invitation proof rejected")
		}
		return issued{org: organization.ID(org), id: organization.ID(id), proof: proof, wire: u.Query().Get("token")}
	}
	first, second := issue("http-invitation-one"), issue("http-invitation-two")
	getPath := func(i issued) string {
		return "/v1/organization/invitation/get?organizationID=" + string(i.org) + "&invitationID=" + string(i.id)
	}
	call := func(auth organization.Authentication, path string, local http.Handler, host string) (int, []byte) {
		t.Helper()
		var response *http.Response
		if local != nil {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Host, r.RemoteAddr, r.TLS = parsedOrigin.Host, "127.0.0.1:12345", &tls.ConnectionState{}
			if host != "" {
				r.Host = host
			}
			r.Header.Set("Authorization", "Bearer "+auth.Bearer.Token())
			w := httptest.NewRecorder()
			local.ServeHTTP(w, r)
			response = w.Result()
		} else {
			r, e := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("Authorization", "Bearer "+auth.Bearer.Token())
			if host != "" {
				r.Host = host
			}
			response, e = server.Client().Do(r)
			if e != nil {
				t.Fatal("genuine invitation HTTPS failed")
			}
		}
		body, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closed := response.Body.Close()
		if e != nil || closed != nil || len(body) > 1<<20 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Authorization") != "" {
			t.Fatal("invitation response custody failed")
		}
		for label, secret := range map[string]string{"owner bearer": owner.Bearer.Token(), "recipient bearer": recipient.Bearer.Token(), "first proof": first.wire, "second proof": second.wire, "email": "@example.invalid", "encrypted custody": "ciphertext", "identifier field": "recipientIdentifier", "capability field": "capability"} {
			if secret != "" && bytes.Contains(body, []byte(secret)) {
				t.Fatal("HTTP leaked private custody category", label)
			}
		}
		// The signup owner may allocate the same scalar as user and identifier
		// IDs. Member reads deliberately include their safe userID; invitation
		// projections must disclose neither recipient nor identifier metadata.
		if strings.HasPrefix(path, "/v1/organization/invitation/") && bytes.Contains(body, []byte(identifiers.Identifiers[0].ID)) {
			t.Fatal("invitation HTTP disclosed recipient identifier")
		}
		validateResponse(path, response.StatusCode, body)
		return response.StatusCode, body
	}
	decodePage := func(status int, body []byte) organizationhttp.InvitationListMineResponse {
		t.Helper()
		var page organizationhttp.InvitationListMineResponse
		if status != 200 || json.Unmarshal(body, &page) != nil {
			t.Fatal("genuine recipient page unavailable", status)
		}
		return page
	}
	statusCode, body := call(recipient, "/v1/organization/invitation/list-mine?limit=1", nil, "")
	page1 := decodePage(statusCode, body)
	if len(page1.Invitations) != 1 || page1.NextCursor == "" || page1.Invitations[0].Status != "pending" {
		t.Fatal("recipient cannot discover pending invitation before membership")
	}
	statusCode, body = call(recipient, "/v1/organization/invitation/list-mine?limit=1&cursor="+string(page1.NextCursor), nil, "")
	page2 := decodePage(statusCode, body)
	ids := []string{string(first.id), string(second.id)}
	sort.Strings(ids)
	if len(page2.Invitations) != 1 || page2.NextCursor != "" || string(page1.Invitations[0].ID) != ids[0] || string(page2.Invitations[0].ID) != ids[1] {
		t.Fatal("native recipient keyset pagination changed")
	}
	if code, _ := call(recipient, "/v1/organization/get?organizationID="+string(first.org), nil, ""); code != 403 {
		t.Fatal("pending invitation manufactured membership", code)
	}
	if code, _ := call(recipient, getPath(first), nil, ""); code != 403 {
		t.Fatal("recipient bypassed native owner-only Get", code)
	}
	statusCode, body = call(owner, getPath(first), nil, "")
	var metadata organizationhttp.InvitationReadResponse
	if statusCode != 200 || json.Unmarshal(body, &metadata) != nil || metadata.Invitation.Status != "pending" {
		t.Fatal("native owner metadata missing", statusCode)
	}
	statusCode, body = call(owner, "/v1/organization/invitation/list-mine", nil, "")
	if page := decodePage(statusCode, body); len(page.Invitations) != 0 {
		t.Fatal("foreign recipient saw invitations")
	}
	if code, _ := call(owner, "/v1/organization/invitation/list-mine?limit=1&cursor="+string(page1.NextCursor), nil, ""); code != 400 {
		t.Fatal("native recipient cursor crossed subjects", code)
	}
	if code, _ := call(recipient, "/v1/organization/invitation/list-mine", nil, "foreign.example"); code != 403 {
		t.Fatal("recipient bearer crossed tenant", code)
	}
	accept, e := invitations.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: first.id, OrganizationID: first.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: first.proof, CorrelationID: "invitation-http-accept"}, "127.0.0.1")
	if e != nil {
		t.Fatal("genuine native acceptance prepare failed", e)
	}
	if out, e := invitations.Execute(ctx, accept); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine native acceptance failed", e)
	}
	statusCode, body = call(recipient, "/v1/organization/get?organizationID="+string(first.org), nil, "")
	var member organizationhttp.ReadResponse
	if statusCode != 200 || json.Unmarshal(body, &member) != nil || member.Membership.UserID != recipientID || member.Membership.Role != organization.RoleMember {
		t.Fatal("native acceptance did not unlock actual HTTP member read", statusCode)
	}
	// Reconstruct the native invitation owner and selected router. No page or
	// membership cache is carried across this process-equivalent boundary.
	restarted, _ := build(restartInvitations(pool))
	statusCode, body = call(recipient, "/v1/organization/invitation/list-mine", restarted, "")
	current := decodePage(statusCode, body)
	found := false
	for _, i := range current.Invitations {
		if i.ID == first.id {
			found = i.Status == "accepted" && i.Version == 2
		}
	}
	if !found {
		t.Fatal("restarted HTTP recipient listing retained pending state")
	}
	statusCode, body = call(owner, getPath(first), restarted, "")
	if statusCode != 200 || json.Unmarshal(body, &metadata) != nil || metadata.Invitation.Status != "accepted" || metadata.Invitation.Version != 2 {
		t.Fatal("restarted owner Get retained pending state", statusCode)
	}
	// Fault injection only withdraws existing primary authority. It creates no
	// user, verified identifier, bearer, invitation, proof or membership.
	for _, withdrawal := range []string{"unverified", "replaced"} {
		t.Run("current identifier "+withdrawal, func(t *testing.T) {
			column := "verified"
			if withdrawal == "replaced" {
				column = "version"
			}
			statement := `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=verification_version+1,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`
			restore := `UPDATE identity.identifiers SET verified=true,is_primary=true,verification_state=2,verification_version=verification_version-1,version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`
			if column == "version" {
				statement = `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`
				restore = `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`
			}
			if _, e := pool.Raw().Exec(ctx, statement, baselineTenant, string(recipientID), string(identifiers.Identifiers[0].ID)); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if _, e := pool.Raw().Exec(ctx, restore, baselineTenant, string(recipientID), string(identifiers.Identifiers[0].ID)); e != nil {
					t.Error("identifier fixture restoration failed")
				}
			}()
			code, wire := call(recipient, "/v1/organization/invitation/list-mine", restarted, "")
			if code == 200 {
				if page := decodePage(code, wire); len(page.Invitations) != 0 {
					t.Fatal("withdrawn original identifier retained invitation discovery")
				}
			} else if code != 403 {
				t.Fatal("withdrawn identifier misclassified", code)
			}
		})
	}
	token, e := session.ParseToken(recipient.Bearer.Token())
	if e != nil {
		t.Fatal(e)
	}
	credential, e := session.NewCredential(session.CredentialBearer, token)
	if e != nil {
		t.Fatal(e)
	}
	observed, e := sessions.Get(ctx, session.GetRequest{TenantID: baselineTenant, Credential: credential})
	if e != nil {
		t.Fatal(e)
	}
	binding, e := observed.Session.Bindings()
	if e != nil {
		t.Fatal(e)
	}
	if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, baselineTenant, binding.SessionID); e != nil {
		t.Fatal(e)
	}
	if code, _ := call(recipient, "/v1/organization/invitation/list-mine", restarted, ""); code != 403 {
		t.Fatal("restarted HTTP accepted revoked recipient session", code)
	}
}

type baselineGraph struct {
	stores   reference.StoreSet
	features reference.FeatureSet
	workers  reference.WorkerSet
	server   *reference.Server
	hibp     *hibp.Client
	http     *httpclient.Client
}

func (g *baselineGraph) close(ctx context.Context) error {
	if g == nil {
		return nil
	}
	return errors.Join(g.stores.Close(ctx), g.hibp.Close(ctx), g.http.Close())
}

type fixedTenant struct{}

func (*fixedTenant) ResolveTenant(ctx context.Context) (identity.TenantID, error) {
	return baselineTenant, ctx.Err()
}

func baselineRiskPolicy(version uint64, screening, reset bool, change ...bool) (risk.Policy, error) {
	return risk.NewPolicy(baselineRiskPolicyConfig(version, screening, reset, change...))
}

func baselineRiskPolicyConfig(version uint64, screening, reset bool, change ...bool) risk.PolicyConfig {
	c := risk.PolicyConfig{Version: version, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}}
	if screening {
		c.HIBP = risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.signup"}}
		if reset {
			c.HIBP.Operations = append(c.HIBP.Operations, "identity.password.reset-complete")
		}
		if len(change) == 1 && change[0] {
			c.HIBP.Operations = append(c.HIBP.Operations, "identity.password.change")
		}
	}
	return c
}

// fixtureGraph is test-only composition from the public identity baseline
// graph (go-identity/reference, source 02c6195). Only startup configuration is
// copied: all authentication, authority, SQL, replay, audit and issuance remain
// the public native owners. Reset/change/MFA workloads are not selected here.
func fixtureGraph(ctx context.Context, origin string, fixtureKeys map[string][32]byte, pool *database.Pool, sender delivery.Sender, outbound http.RoundTripper) (_ *baselineGraph, err error) {
	key := func(name string) [32]byte { return fixtureKeys[name] }
	bytes := func(name string) []byte { k := key(name); return append([]byte(nil), k[:]...) }
	authorize, err := fixtureAuthorization()
	if err != nil {
		return nil, err
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: authorize, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: key("fingerprint")}, QueryPolicy: &query, AdmissionPolicy: &query}
	requestKeys, err := kernel.NewRequestKeyConfig("local-baseline", key("request"), query)
	if err != nil {
		return nil, err
	}
	policy, err := baselineRiskPolicy(3, false, false)
	if err != nil {
		return nil, err
	}
	protectedPolicy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		return nil, err
	}
	screeningPolicy, err := baselineRiskPolicy(3, true, false)
	if err != nil {
		return nil, err
	}
	digest, err := risk.NewCounterDigestKey(1, bytes("counter"))
	if err != nil {
		return nil, err
	}
	evidence, err := risk.NewEvidenceKey(1, bytes("risk-evidence"), bytes("risk-seal"))
	if err != nil {
		return nil, err
	}
	flowKey, err := session.NewDigestKey(3, bytes("preauth-cookie"))
	if err != nil {
		return nil, err
	}
	lookup, err := session.NewDigestKey(11, bytes("session-token"))
	if err != nil {
		return nil, err
	}
	csrf, err := session.NewCSRFKey(12, bytes("session-csrf"))
	if err != nil {
		return nil, err
	}
	flowCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		return nil, err
	}
	sessionCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	if err != nil {
		return nil, err
	}
	deviceCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		return nil, err
	}
	deviceKey, err := session.NewBrowserDeviceKey(1, bytes("http-device"))
	if err != nil {
		return nil, err
	}
	codeProfile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		return nil, err
	}
	codePolicy, err := otp.NewAttemptPolicy(codeProfile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	if err != nil {
		return nil, err
	}
	envelope, err := keyring.New(map[string][]byte{"delivery-envelope": bytes("delivery-envelope")})
	if err != nil {
		return nil, err
	}
	profile := primitive.DefaultPolicy()
	crypto, err := primitive.New(profile)
	if err != nil {
		return nil, err
	}
	dummy, err := crypto.Hash(ctx, bytes("dummy-password"))
	if err != nil {
		return nil, err
	}
	transport, err := httpclient.New(httpclient.Config{Transport: outbound})
	if err != nil {
		return nil, err
	}
	checker, err := hibp.New(hibp.Config{UserAgent: "golib-identity/local-baseline", AddPadding: true, CacheEntries: 100, CacheTTL: time.Hour, ResponseBytes: 1 << 20, MaxBreachCount: 1000000000, OutboundConcurrency: 1, Timeout: 2 * time.Second, PolicyVersion: "local-baseline-v1", MaxWaiters: 8, MaxCandidateBytes: 128, CacheBytes: 8 << 20, DisableCache: true}, transport, clock.System{})
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	g := &baselineGraph{hibp: checker.(*hibp.Client), http: transport}
	defer func() {
		if err != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_ = g.close(cleanup)
		}
	}()
	provider, err := hibp.NewSignalProvider(g.hibp, screeningPolicy)
	if err != nil {
		return nil, err
	}
	collect := func(ctx context.Context, b risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		command, err := identity.ParseCommandID(b.Attempt)
		if err != nil {
			return nil, err
		}
		signal, err := provider.Assess(ctx, hibp.CheckRequest{OperationID: "identity.password.signup", TenantID: identity.TenantID(b.Tenant), Action: b.Operation, Purpose: "identity.password.signup", SubjectScope: "password-screening", PolicyVersion: "local-baseline-v1", ReplayID: command, Candidate: candidate})
		return []risk.Signal{signal}, err
	}
	normalization, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "local-email-nfc", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		return nil, err
	}
	addressPolicy := email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization}
	address, err := email.NewAddressParser(addressPolicy)
	if err != nil {
		return nil, err
	}
	callback := origin + "/confirm"
	verification, err := email.NewRegistrationVerificationPolicy(email.RegistrationVerificationConfig{Address: addressPolicy, Issuer: origin, Audience: "email", MaximumLifetime: 5 * time.Minute, Redirects: []string{callback}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: key("capability-binding")}})
	if err != nil {
		return nil, err
	}
	signer, err := capability.NewHMACSHA256Signer("local-baseline", bytes("capability-signing"))
	if err != nil {
		return nil, err
	}
	verifier, err := capability.NewHMACSHA256Verifier(bytes("capability-signing"))
	if err != nil {
		return nil, err
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "local-baseline", Verifier: verifier}})
	if err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(bytes("signin-proof"))
	loginSigner, err := passwordpg.NewSigninSigningKey("local-baseline", private)
	if err != nil {
		return nil, err
	}
	schema := identity.AttributeSchema{ID: "local-signup-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1, Default: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "registered"}}}}}
	fields, err := identity.NewAttributeProcessor(schema, authorize, func(ctx context.Context, _ identity.NormalizationPolicy, value identity.AttributeScalar) (identity.AttributeScalar, error) {
		return value, ctx.Err()
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 9, ValidateCanonicalUserID: func(ctx context.Context, user identity.UserID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := identity.ParseSubjectID(string(user))
		return err
	}, ValidateValue: func(ctx context.Context, _ identity.FieldPolicy, _ identity.AttributeValue) error { return ctx.Err() }})
	if err != nil {
		return nil, err
	}
	storage := sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
	issuance := session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 4 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: sessionCookie}
	preauth := &reference.PasswordPreAuthConfiguration{ActorID: baselineActor, Origin: origin, CallbackURL: callback, FlowKeyIndex: 0, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: flowCookie}
	configured := reference.StoreConfiguration{
		DurableAdmission: &reference.DurableAdmissionConfiguration{Schema: "risk_store", Namespace: "local-baseline", Policy: policy, Keys: []risk.CounterDigestKey{digest}, ReplayKey: bytes("counter-replay"), Tenants: []string{baselineTenant}, MaximumRecords: 100000, Timeout: 10 * time.Second},
		Migrations:       &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "local-operator", LookupKey: key("migration"), LockTimeout: time.Second, CleanupTimeout: time.Second},
		HTTPRate:         &reference.HTTPRateConfiguration{Namespace: "local-baseline", IdentifierKey: key("http-rate"), MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond},
		HTTPPreAuth:      &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Device: &session.BrowserDeviceConfig{Namespace: "local-baseline", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: deviceCookie}},
		OTP: &reference.OTPSendConfiguration{
			BootstrapTenantIDs: []identity.TenantID{baselineTenant}, Store: otppg.ContributorConfig{Schema: "otp_store", GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: key("otp-lockout"), PreAuth: storage, PreAuthCookieKeys: map[uint32][]byte{3: bytes("preauth-cookie")}},
			Codec:       otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"otp-wrap": bytes("otp-wrap")}, CurrentWrappingKey: "otp-wrap", AttemptKeys: map[uint32][32]byte{7: key("otp-attempt")}, CodeKeys: map[uint32][32]byte{4: key("otp-code")}, CurrentCodeKeyVersion: 4, MaximumDuration: time.Second},
			Coordinator: coordinator, RequestKeys: requestKeys, Policy: codePolicy, TemplateID: "otp-code", TemplateVersion: 1, LocaleChain: []string{"en"}, ProviderVersion: 1, PolicyID: "otp-policy", PolicyVersion: 9, PreAuthAction: "identity.otp.signin", IntentKey: key("otp-intent"), IdentifierKey: key("identifier"), Timeout: 4 * time.Second, RiskTimeout: 2 * time.Second, AuditTimeout: time.Second, RiskPolicyID: baselineTenant, ConfigurationID: "local-baseline-v1", RiskKeys: []risk.EvidenceKey{evidence},
			PreAuth: &reference.OTPPreAuthConfiguration{ActorID: baselineActor, Origin: origin, LookupKeyVersion: 3, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: flowCookie},
			Signin:  &otppg.SigninConfig{Coordinator: coordinator, CurrentAttemptKeyVersion: 7, Session: storage, Profile: sessionpg.OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline"}, Issuer: issuance, CSRFKey: csrf},
		},
	}
	deliveryPolicy := delivery.DefaultConfig()
	deliveryPolicy.Production = true
	configured.Delivery = &reference.DeliveryConfiguration{Enqueue: deliverypg.EnqueueConfig{Custody: deliverypg.ContributorConfig{Deployment: "deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: key("delivery-digest")}, ActiveEnvelopeKeyID: "delivery-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "local-mailbox", PolicyVersion: 1}}}, Coordinator: coordinator, PolicyID: "delivery-policy", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 4 * time.Second, NamespaceKey: key("delivery-namespace"), Policies: map[uint64]delivery.Config{1: deliveryPolicy}, StateTracking: true}, Templates: []delivery.Template{
		{ID: "otp-code", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Subject: "Verification", Body: "{{.code}}", ContentType: "text/plain"},
		{ID: "registration", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096},
	}}
	signin := passwordpg.SigninConfig{
		Repository: passwordpg.Config{MaximumDuration: 4 * time.Second, HashPolicy: profile}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: 2 * time.Second, DummyHash: dummy, Now: time.Now}, Session: storage,
		Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Address: addressPolicy, FlowKeys: []session.DigestKey{flowKey}, Issuance: issuance, CSRFKey: csrf,
		Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "local-password-v1", Keys: []risk.EvidenceKey{evidence}}, Coordinator: coordinator, SigningKey: loginSigner, VerificationKeys: map[string]ed25519.PublicKey{"local-baseline": private.Public().(ed25519.PublicKey)}, Issuer: origin, Environment: "local-capture", PolicyID: "password-login", ProofTTL: time.Minute, IdentifierKey: bytes("password-flow"), Origins: []string{origin}, CallbackURLs: []string{callback},
	}
	configured.PasswordSignin = &reference.PasswordSigninConfiguration{Native: signin, PreAuth: preauth}
	configured.HTTPPasswordSignin = &reference.HTTPPasswordSigninConfiguration{ActorID: baselineActor, PolicyRevision: 9}
	configured.PasswordSignup = &reference.PasswordSignupConfiguration{
		Native: passwordpg.SignupConfig{
			Repository: signin.Repository, Registration: password.RegistrationPolicy{Enabled: true, RequireVerifiedEmail: true, MinimumBytes: 12, MaximumBytes: 128}, ConfigurationID: "local-signup-v1", PolicyID: "password-signup", Fields: fields, FieldSchema: schema, Address: address, SelectUser: func(ctx context.Context) (identity.UserID, error) {
				if err := ctx.Err(); err != nil {
					return "", err
				}
				id, err := identity.NewSubjectID()
				return identity.UserID(id), err
			}, Session: storage, FlowKeys: signin.FlowKeys, Origins: []string{origin}, CallbackURLs: []string{callback}, AuthorizationNamespace: "users",
			RegistrationDomain: kernel.PasswordRegistrationDomainConfig{ComparisonProfile: "local-email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: key("signup-binding")}}, RequestKeys: requestKeys, IntentKey: key("signup-intent"), ActiveEnvelopeKeyID: "delivery-envelope",
			Screening: password.HashPreparationConfig{Primitive: crypto, MinimumBytes: 12, MaximumBytes: 128, Timeout: 3 * time.Second, DummyHash: dummy, Policy: screeningPolicy, Now: time.Now, Collect: collect}, Risk: signin.Risk, Coordinator: coordinator,
			Verification: passwordpg.SignupVerificationConfig{Policy: verification, Lifetime: 5 * time.Minute}, Delivery: passwordpg.SignupDeliveryConfig{Resolver: resolver, Endpoint: origin + "/email/confirm", TemplateID: "registration", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: key("verification-scope"), Timeout: time.Second},
		},
		Issuer:      issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "email", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: key("capability-replay")}, PreparationTimeout: time.Second},
		Preparation: issuerpg.IssuancePreparationConfig{Deployment: "deployment", ActiveEnvelopeKey: "capability-envelope", EnvelopeKeys: map[string][]byte{"capability-envelope": bytes("capability-envelope")}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "local-baseline", HMAC: bytes("capability-signing")}}, Clock: time.Now},
		Counters:    riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": bytes("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: protectedPolicy, Keys: []risk.CounterDigestKey{digest}}}, PreAuth: preauth,
	}
	configured.HTTPPasswordSignup = &reference.HTTPPasswordSignupConfiguration{ActorID: baselineActor, PolicyRevision: 9}
	configured.HTTPRegistrationVerification = &reference.HTTPRegistrationVerificationConfiguration{Origin: origin, ActorID: baselineActor, PolicyRevision: 9, VerificationNamespace: "local-registration", VerificationKey: key("verification-http")}
	configured.Session = &reference.SessionConfiguration{Native: sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: storage, Profile: sessionpg.IssueAdmissionConfig(signin.Profile), Coordinator: coordinator, Authorization: authorize, Clock: clock.System{}, PolicyID: "session-signout", PolicyVersion: 9, AuditRetentionVersion: 1}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "local-baseline", MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}, Cookie: sessionCookie, MaximumDuration: 4 * time.Second}, CSRFKeys: []session.CSRFKey{csrf}}
	configured.HTTPSession = &reference.HTTPSessionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "local-session", EmergencyMaximumKeys: 128, Degraded: func(ctx context.Context, _ identityhttp.SafeRateEvent) error { return ctx.Err() }}
	dependencies := reference.ReferenceDependencies{PostgreSQL: pool, EnvelopeKeys: envelope, DeliverySender: sender}
	g.stores, err = reference.ComposeStores(configured, dependencies)
	if err != nil {
		return nil, err
	}
	providers, err := reference.ComposeProviders(g.stores)
	if err != nil {
		return nil, err
	}
	worker := deliverypg.WorkerConfig{ProviderConfigVersion: 1, Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "local-worker", Request: authorization.Request{Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "baseline-worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "baseline-worker"}}}}
	g.workers, err = reference.ComposeWorkers(g.stores, providers, worker)
	if err != nil {
		return nil, err
	}
	g.features, err = reference.ComposeFeatures(g.stores, providers, g.workers)
	if err != nil {
		return nil, err
	}
	parsedOrigin, _ := url.Parse(origin) // The fixture constructs this exact HTTPS origin.
	g.server, err = reference.NewServer(reference.ReferenceConfig{Profile: reference.PostgresOnly, Policies: fixturePolicies(authorize), HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: parsedOrigin.Hostname(), TenantID: baselineTenant}}}, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Local identity baseline", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: 5 * time.Second}, Tenant: reference.TenantPolicy{Resolver: &fixedTenant{}}}, dependencies, g.features)
	if err != nil {
		return nil, err
	}
	return g, nil
}

const (
	baselineTenant = "AAAAAAAAAAAAAAAAAAAAAQ"
	baselineActor  = "AAAAAAAAAAAAAAAAAAAAAw"
)

// This finite application policy is evaluated by the public authorization
// engine. It is not native user/session authority: actual owners independently
// authenticate original flows, credentials, sessions and organization membership.
type baselineEvaluator struct{}

func (*baselineEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	allow := false
	if string(r.Tenant) == baselineTenant && r.Subject.ID != "" && r.Resource.ID != "" {
		if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == baselineActor {
			switch r.Action {
			case "identity.session.preauth-issue":
				allow = r.Resource.Type == "identity.anonymous-flow"
			case "identity.password.signup", "identity.password.signup.recover", "identity.password.signin", "identity.password.signin.recover":
				allow = r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) || r.Resource.Type == "identity.anonymous-flow" || r.Resource.Type == "identity.user"
			case "identity.user.create", "identity.email.verification-confirm":
				allow = r.Resource.Type == "identity.user"
			}
		}
		if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "baseline-worker" && r.Action == "identity.delivery.process" {
			allow = r.Resource.Type == "identity.delivery-worker" && r.Resource.ID == "baseline-worker"
		}
		if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "invitation-worker" && r.Action == "identity.delivery.process" {
			allow = r.Resource.Type == "identity.delivery-worker" && r.Resource.ID == "invitation-worker"
		}
		if r.Subject.Kind == authorization.SubjectUser {
			switch r.Action {
			case "identity.organization.role.create", "identity.organization.role.update", "identity.organization.role.delete", "identity.organization.role.get", "identity.organization.role.list", "identity.organization.role.assign", "identity.organization.role.revoke", "identity.organization.permission-check":
				allow = r.Resource.Type == "organization" || r.Resource.Type == "identity.user"
			case "identity.organization.domain.reserve", "identity.organization.domain.withdraw", "identity.organization.domain.get", "identity.organization.domain.evidence.apply", "identity.organization.domain.evidence.revoke":
				allow = r.Resource.Type == "organization" || r.Resource.Type == "identity.user"
			case "identity.password.verify":
				allow = r.Resource.Type == "identity.request-admission" && r.Resource.ID == "identity.password.verify" || r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID)
			case "identity.session.revoke-one", "identity.session.revoke-one.recover":
				allow = r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID)
			case "identity.organization.create", "identity.organization.update", "identity.organization.member.add", "identity.organization.member.update", "identity.organization.member.remove", "identity.organization.member.leave", "identity.organization.get", "identity.organization.list", "identity.organization.member.list", "identity.organization.owner-transfer", "identity.organization.archive", "identity.organization.restore":
				allow = r.Resource.Type == "organization" || r.Resource.Type == "identity.user"
				if (r.Action == "identity.organization.create" || r.Action == "identity.organization.member.add") && r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) {
					allow = true
				}
			case "identity.organization.team.create", "identity.organization.team.member-add", "identity.organization.team.member-remove", "identity.organization.team.list", "identity.organization.team.list-mine", "identity.organization.team.member-list", "identity.organization.team.get", "identity.organization.team.update", "identity.organization.team.delete":
				allow = r.Resource.Type == "organization" || r.Resource.Type == "identity.user"
			case "identity.organization.invitation-send", "identity.organization.invitation.accept", "identity.organization.invitation.cancel", "identity.organization.invitation.reject", "identity.organization.invitation.expire", "identity.organization.invitation.resend", "identity.organization.invitation.get", "identity.organization.invitation.list", "identity.organization.invitation.list-mine":
				allow = r.Resource.Type == "organization" || r.Resource.Type == "identity.user"
			case "identity.delivery.status-get":
				allow = r.Resource.Type == "identity.user"
			}
		}
	}
	if allow {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny}, nil
}
func fixtureAuthorization() (authorization.Service, error) {
	snapshot, e := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-consumer", Revision: 9, Evaluator: &baselineEvaluator{}})
	if e != nil {
		return nil, e
	}
	engine, e := authorization.NewEngine(snapshot)
	if e != nil {
		return nil, e
	}
	return authorization.NewDecisionService(engine)
}
func fixturePolicies(service authorization.Service) identity.PolicySet {
	return identity.PolicySet{
		Authorize: service,
		AssessRisk: func(ctx context.Context, _ identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			return identity.RiskPolicyDecision{}, identity.ForbiddenError{}
		},
		MapClaims: func(ctx context.Context, _ identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			return identity.ClaimsPolicyDecision{}, identity.ForbiddenError{}
		},
		DecideRetention: func(ctx context.Context, _ identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			return identity.RetentionPolicyDecision{}, identity.ForbiddenError{}
		},
		Redact: func(ctx context.Context, _ identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{}, identity.ForbiddenError{}
		},
	}
}

type registrationMailbox struct {
	mu   sync.Mutex
	body string
}

func (m *registrationMailbox) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	if ctx == nil || ctx.Err() != nil || a.Validate() != nil || a.TenantID != baselineTenant || len(a.Body) > 4096 {
		return delivery.DeliveryResult{}, delivery.ErrInvalidInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.body != "" {
		return delivery.DeliveryResult{}, delivery.ErrUnavailable
	}
	m.body = strings.Clone(a.Body)
	return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
}

type hibpTransport struct{}

func (hibpTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Err() != nil {
		return nil, r.Context().Err()
	}
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.pwnedpasswords.com" || !strings.HasPrefix(r.URL.Path, "/range/") || len(r.URL.Path) != 12 {
		return nil, io.ErrUnexpectedEOF
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("0", 35) + ":0\r\n")), Request: r}, nil
}

func consumerDatabase(t *testing.T) (context.Context, *database.Pool, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN")
	parsed, e := pgx.ParseConfig(dsn)
	if dsn == "" || e != nil || parsed.Host != "127.0.0.1" {
		t.Fatal("explicit task-owned loopback PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("isolated primary unavailable")
	}
	var existing int
	if e = admin.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&existing); e != nil || existing != 0 {
		_ = admin.Close(ctx)
		t.Fatal("consumer fixture requires absent native audit roles")
	}
	id, e := identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	name := "organization_consumer_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+quoted); e != nil {
		t.Fatal("consumer database creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+quoted); e != nil {
			t.Error("consumer database cleanup failed")
		}
		if _, e := admin.Exec(cleanup, "DROP ROLE IF EXISTS audit_writer,audit_reader,audit_retention"); e != nil {
			t.Error("consumer audit-role cleanup failed")
		}
		_ = admin.Close(cleanup)
	})
	parsed.Database = name
	parsed.RuntimeParams["search_path"] = "public"
	db := stdlib.OpenDB(*parsed)
	t.Cleanup(func() { _ = db.Close() })
	pool, e := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = name
		c.ConnConfig.RuntimeParams["search_path"] = "public"
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("consumer pool cleanup failed")
		}
	})
	return ctx, pool, db
}

type migrationList []migrations.Migration

func (s migrationList) Load(ctx context.Context) ([]migrations.Migration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]migrations.Migration(nil), s...), nil
}
func commandID(t *testing.T) identity.CommandID {
	t.Helper()
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func invitationConsumerOwners(t *testing.T, ctx context.Context, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, origin string) (*organizationpg.InvitationService, func(*database.Pool) *organizationpg.InvitationService, *deliverypg.EnqueueService, capability.Limits) {
	t.Helper()
	policy, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}
	provider, err := keyring.New(map[string][]byte{"delivery-envelope": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	deliveryPolicy := delivery.DefaultConfig()
	deliveryPolicy.DedupeTTL = 72 * time.Hour
	deliveryPolicy.Production = true
	custody := deliverypg.ContributorConfig{Deployment: "deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: keys["delivery-digest"]}, ActiveEnvelopeKeyID: "delivery-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{2: {Provider: "invitation-mailbox", PolicyVersion: 2}}}
	templates := []delivery.Template{{ID: "organization-invitation", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096}}
	status, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: custody, Coordinator: coordinator, PolicyID: "organization", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 4 * time.Second, NamespaceKey: keys["delivery-namespace"], Policies: map[uint64]delivery.Config{2: deliveryPolicy}, StateTracking: true}, crypto, policy, templates)
	if err != nil {
		t.Fatal("invitation delivery graph rejected", err)
	}
	deliverer, err := deliverypg.NewContributor(custody, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer(templates)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("local-baseline", material("capability-signing"))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(material("capability-signing"))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "local-baseline", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	limits := capability.DefaultLimits()
	limits.MaxLifetime = 48 * time.Hour
	riskPolicy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := risk.NewCounterDigestKey(1, material("counter"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: riskPolicy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	configuration := organizationpg.InvitationServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, err := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), err)
	}}, Invitation: organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100}, Admission: organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000}, Sessions: sessions, Authorization: policy, Coordinator: coordinator, Risk: counters, Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: limits}, Audience: "organization-invitation", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: keys["capability-replay"]}, PreparationTimeout: time.Second}, Preparation: issuerpg.IssuancePreparationConfig{Deployment: "organization-invitation", ActiveEnvelopeKey: "capability-envelope", EnvelopeKeys: map[string][]byte{"capability-envelope": material("capability-envelope")}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "local-baseline", HMAC: material("capability-signing")}}, Clock: time.Now}, Delivery: organizationpg.InvitationDeliveryConfig{Owner: deliverer, Status: status, Renderer: renderer, Policy: deliveryPolicy, PolicyVersion: 2, ProviderVersion: 2, StatusPolicyVersion: 9, TemplateID: "organization-invitation", TemplateVersion: 1, LocaleChain: []string{"en"}, ScopeKey: keys["verification-scope"], Endpoint: origin + "/invitation"}}
	service, err := organizationpg.NewInvitationService(repository, configuration)
	if err != nil {
		t.Fatal("actual invitation composition rejected", err)
	}
	newService := func(primary *database.Pool) *organizationpg.InvitationService {
		t.Helper()
		r, e := organizationpg.NewRepository(primary, organizationpg.Config{MaximumDuration: 2 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		s, e := organizationpg.NewInvitationService(r, configuration)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}

	return service, newService, status, limits
}

func consumerOrganizationService(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte) *organizationpg.Service {
	t.Helper()
	repository, e := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	participant, e := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000})
	if e != nil {
		t.Fatal(e)
	}
	policy, e := baselineRiskPolicy(9, false, false)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := risk.NewCounterDigestKey(1, material("counter"))
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if e != nil {
		t.Fatal(e)
	}
	counters, e := riskpg.NewRepository(riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true})
	if e != nil {
		t.Fatal(e)
	}
	domain, e := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	audits, e := auditpg.NewIdentityContributor(auditpg.Config{})
	if e != nil {
		t.Fatal(e)
	}
	outbox, e := lifecyclepg.NewContributor()
	if e != nil {
		t.Fatal(e)
	}
	registry, e := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, counters, participant})
	if e != nil {
		t.Fatal(e)
	}
	authorize, e := fixtureAuthorization()
	if e != nil {
		t.Fatal(e)
	}
	coordinator, e := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}})
	if e != nil {
		t.Fatal(e)
	}
	service, e := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, e := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), e)
	}}, Sessions: sessions, Authorization: authorize, Risk: counters, Coordinator: coordinator, Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	return service
}

func installOrganizationHTTPConsumer(t *testing.T, ctx context.Context, graph *baselineGraph, db *sql.DB) {
	t.Helper()
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	plan, err := graph.stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("organization-http-consumer-install"))
	if err != nil {
		t.Fatal(err)
	}
	applied, err := graph.stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "organization_http_consumer_install", Plan: plan.Plan, IdempotencyKey: key})
	if err != nil || applied.Result.State() != reference.MigrationApplied {
		t.Fatal("native public migration application failed", err)
	}
	// Reference baseline 02c6195 migration_catalog.go includes the native atomic
	// rate migration in identity_http_rate when registration verification is
	// selected. Reuse that existing owner/history rather than reinstalling it.
	kernelSteps, err := (kernel.CounterPreparationMigrationSource{Base: graph.stores.MigrationSource(), Version: 1700}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	riskBase := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "risk_store", Version: 1}, Version: 2}, Version: 3}, Version: 4}
	riskSteps, err := (riskpg.LockoutMigrationSource{Base: riskBase, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	orgSteps, err := (organizationpg.MigrationSource{Version: 7000}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var indexSteps []migrations.Migration
	for _, source := range []migrations.Source{organizationpg.InvitationMigrationSource{Version: 7001}, organizationpg.InvitationCapabilityMigrationSource{Version: 7002}, organizationpg.InvitationRecipientIndexMigrationSource{Version: 7006}, organizationpg.OperationLookupMigrationSource{Version: 7099}} {
		steps, e := source.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		indexSteps = append(indexSteps, steps...)
	}
	for _, extension := range []struct {
		namespace string
		steps     []migrations.Migration
	}{{"identity_password_change_kernel", kernelSteps[len(kernelSteps)-1:]}, {"identity_risk_lockouts", riskSteps[len(riskSteps)-1:]}, {"organization", append(orgSteps, indexSteps...)}} {
		backend, err := migrationpg.New(db)
		if err != nil {
			t.Fatal(err)
		}
		backend, err = backend.ForNamespace(extension.namespace)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(migrationList(extension.steps), backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("native HTTP consumer extension migration failed", err)
		}
	}
	if err := graph.features.Initialize(ctx); err != nil {
		t.Fatal("genuine Reference initialization failed", err)
	}
}

func registerOrganizationHTTPHuman(t *testing.T, ctx context.Context, server *httptest.Server, origin string, graph *baselineGraph, mailbox *registrationMailbox, sessions *session.SessionService) (organization.Authentication, identity.UserID) {
	t.Helper()
	client := server.Client()
	client.Timeout = 6 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	post := func(path string, body any, key string) ([]byte, []*http.Cookie) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("genuine identity HTTPS unavailable")
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if response.StatusCode != 200 || readErr != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("genuine identity operation failed", path, response.StatusCode)
		}
		return payload, response.Cookies()
	}
	preauth := func(method string) sessionhttp.PreAuthResponse {
		t.Helper()
		payload, _ := post("/v1/session/preauth-issue", map[string]string{"method": method}, "")
		var out sessionhttp.PreAuthResponse
		if json.Unmarshal(payload, &out) != nil || !out.Issued {
			t.Fatal("genuine preauth did not issue")
		}
		return out
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	address, candidate := "organization-http-"+hex.EncodeToString(random[:8])+"@example.invalid", hex.EncodeToString(random[:])
	clear(random[:])
	flow := preauth("signup")
	payload, cookies := post("/v1/password/signup", map[string]any{"flowID": flow.FlowID, "email": address, "password": candidate, "callbackURL": origin + "/confirm"}, "http-signup-"+string(flow.FlowID))
	var signup passwordhttp.SignupResponse
	if json.Unmarshal(payload, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatal("genuine signup failed verification-only contract")
	}
	if _, err := graph.workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	mailbox.mu.Lock()
	link := mailbox.body
	mailbox.body = ""
	mailbox.mu.Unlock()
	verification, err := url.Parse(link)
	if err != nil || verification.Query().Get("token") == "" {
		t.Fatal("genuine verification delivery unavailable")
	}
	payload, cookies = post("/v1/email/verification-confirm", map[string]string{"token": verification.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(commandID(t))}, "")
	var confirmed emailhttp.ConfirmationResponse
	if json.Unmarshal(payload, &confirmed) != nil || !confirmed.Confirmed || confirmed.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatal("genuine verification did not commit without session")
	}
	flow = preauth("password")
	payload, cookies = post("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": address, "password": candidate, "callbackURL": origin + "/confirm"}, "")
	var signed passwordhttp.SigninResponse
	if json.Unmarshal(payload, &signed) != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || len(cookies) != 1 {
		t.Fatal("genuine password signin did not issue session")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal("genuine issued token rejected")
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: baselineTenant, Credential: credential})
	if err != nil || current.ValidateAt(time.Now()) != nil || !current.Authenticated {
		t.Fatal("genuine current session unavailable", err)
	}
	bindings, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return organization.Authentication{TenantID: baselineTenant, Bearer: auth.NewBearerCredential(cookies[0].Value)}, bindings.UserID
}
