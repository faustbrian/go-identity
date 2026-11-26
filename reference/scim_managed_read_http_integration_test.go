//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authoritypg "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	scimpg "github.com/faustbrian/go-scim/postgres"
)

func TestReferencePostgresSCIMManagedReadHTTPS(t *testing.T) {
	// Reuse real signup, delivery, signin, organization and installed SCIM
	// owners. The additional profile runs only under its dedicated flag.
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{
		postgresBaseline: true, organization: true, scimBulk: true, scimManagedRead: true,
	})
}

type referenceManagedReadPolicy struct {
	mu           sync.RWMutex
	actor        identity.UserID
	organization organization.ID
	denyRead     atomic.Bool
}

func (p *referenceManagedReadPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	if ctx.Err() != nil || d.Validate() != nil {
		return authorization.Decision{}, authorization.ErrDecisionUnavailable
	}
	p.mu.RLock()
	actor := p.actor
	p.mu.RUnlock()
	if d.PolicyRevision == 9 && d.Request.Tenant == otpTenant && d.Request.Subject.Kind == authorization.SubjectUser && d.Request.Subject.ID == authorization.SubjectID(actor) {
		allowed := false
		switch d.Request.Action {
		case "org:scim-read":
			allowed = !p.denyRead.Load() && d.Request.Resource.Type == "organization" && d.Request.Resource.ID == authorization.ResourceID(p.organization)
		case "org:scim-write":
			allowed = d.Request.Resource.Type == "organization" && d.Request.Resource.ID == authorization.ResourceID(p.organization)
		case "identity.scim.connection-create", "identity.scim.connection-create.recover":
			allowed = d.Request.Resource.Type == "identity.user" && d.Request.Resource.ID == authorization.ResourceID(actor) ||
				d.Request.Resource.Type == "identity.request-admission" && d.Request.Resource.ID == "identity.scim.connection-create"
		}
		if allowed {
			return authorization.Decision{Outcome: authorization.Allow, Revision: d.PolicyRevision}, nil
		}
	}
	return referenceDirectorySCIMPolicy{}.Decide(ctx, d)
}

func configureReferenceSCIMManagedRead(t *testing.T, c *reference.StoreConfiguration, source referenceDirectorySCIMSource) {
	t.Helper()
	policy := &referenceManagedReadPolicy{organization: source.config.Scope.OrganizationID}
	c.HTTPManagedSCIMRead = &reference.HTTPManagedSCIMReadConfiguration{
		Get: true, List: true, Authorization: policy, PolicyVersion: 9, MaximumDuration: 3 * time.Second,
		CursorKey: [32]byte{0xa3}, Limits: source.config.Limits, SafeNamespace: "reference-managed-read", EmergencyMaximumKeys: 32,
		Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
			t.Error("unexpected PostgreSQL managed read rate fallback")
			return identityhttp.ErrUnavailable
		},
	}
}

func proveReferenceSCIMManagedReadHTTPS(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, features reference.FeatureSet, client *http.Client, base string, cookies []*http.Cookie, csrf string, source referenceDirectorySCIMSource, document []byte) {
	t.Helper()
	guardedSessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	human := organizationHumanFromSession(t, ctx, guardedSessions, cookies, csrf)
	organizationID := source.config.Scope.OrganizationID
	policy := c.HTTPManagedSCIMRead.Authorization.(*referenceManagedReadPolicy)
	policy.mu.Lock()
	policy.actor = human.user
	policy.mu.Unlock()

	validation := c.Session.Native.Validation
	validation.Clock = clock.System{}
	execution := c.Session.Native.Execution
	sessions, err := sessionpg.NewSessionService(f.pool, sessionpg.SessionServiceConfig{
		Repository: execution.Repository, Profile: sessionpg.IdentifierAdmissionConfig(execution.Profile), Validation: validation,
	})
	if err != nil {
		t.Fatal("compose actual primary session reader", err)
	}
	provisioning := source.config
	provisioning.Scope = scim.Scope{}
	provisioning.Credential = scimpg.ConfiguredCredential{}
	provisioning.ConnectionVersion = 0
	provisioning.CredentialExpiresAt = time.Time{}
	provisioning.AuthorityNamespace = execution.Profile.PolicyNamespace
	provisioning.Authorization = policy
	if _, err := authoritypg.InitializeAuthority(ctx, f.pool.Raw(), authoritypg.AuthorityScope{TenantID: otpTenant, PolicyNamespace: provisioning.AuthorityNamespace, SubjectID: authorization.SubjectID(provisioning.ActorID)}, time.Second); err != nil {
		t.Fatal("initialize actual provisioning principal authority", err)
	}
	managed, err := scimpg.NewManagedConnectionService(f.pool, scimpg.ManagedConnectionServiceConfig{
		Sessions: sessions, Authorization: policy, PolicyVersion: 9, MaximumDuration: 3 * time.Second,
		CursorKey: [32]byte{0xa3}, Limits: provisioning.Limits,
		Writes: &scimpg.ManagedConnectionWriteConfig{SessionStorage: execution.Repository, Provisioning: provisioning, Keyring: source.keys, CredentialKey: [32]byte{0xa4}, CredentialLifetime: time.Hour},
	})
	if err != nil {
		t.Fatal("compose public managed owner", err)
	}
	path, err := scim.ParseMappingPath("userName", nil, provisioning.Limits)
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := scim.NewMappingSet([]scim.Mapping{{Source: path, Target: provisioning.UserNameField, Writable: true}})
	if err != nil {
		t.Fatal(err)
	}
	var created []scim.ConnectionID
	var bearerSecrets []string
	for _, keyText := range []string{"reference-managed-read-first", "reference-managed-read-second"} {
		key, err := identity.NewIdempotencyKey([]byte(keyText))
		if err != nil {
			t.Fatal(err)
		}
		result, err := managed.ConnectionCreate(ctx, scimpg.ConnectionCreateRequest{Authentication: human.auth, OrganizationID: organizationID, ProviderID: "reference-managed-provider", Mappings: mappings, IdempotencyKey: key})
		if err != nil || result.Connection.Version() != 1 || result.Bearer.Token() == "" {
			t.Fatal("create actual managed record through its native owner", err)
		}
		created = append(created, result.Connection.Scope().ProviderConnectionID)
		bearerSecrets = append(bearerSecrets, result.Bearer.Token())
	}
	sort.Slice(created, func(i, j int) bool { return created[i] < created[j] })
	call := func(path string, bearer bool, want int) []byte {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer {
			request.Header.Set("Authorization", "Bearer "+human.auth.Bearer.Token())
		} else {
			request.AddCookie(cookies[0])
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if response.StatusCode != want || readErr != nil || closeErr != nil || len(wire) > 1<<20 {
			t.Fatalf("managed read HTTPS status %d, want %d; cleanup %v/%v", response.StatusCode, want, readErr, closeErr)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Set-Cookie") != "" {
			t.Fatal("unsafe management response headers")
		}
		for _, secret := range append(bearerSecrets, human.auth.Bearer.Token()) {
			if bytes.Contains(wire, []byte(secret)) || bytes.Contains(document, []byte(secret)) {
				t.Fatal("managed read disclosed credential")
			}
		}
		return wire
	}
	get := "/v1/scim/connection-get?connectionID=" + string(created[0])
	call(get, false, 401)
	var record scimhttp.ManagedConnectionView
	if json.Unmarshal(call(get, true, 200), &record) != nil || record.ConnectionID != created[0] || record.OrganizationID != organizationID || record.TenantID != otpTenant || record.Version != 1 || len(record.Mappings) != 1 || record.Mappings[0].Source != "userName" {
		t.Fatal("actual stored managed metadata differs from HTTPS projection")
	}
	list := "/v1/scim/connection-list?organizationID=" + string(organizationID) + "&limit=1"
	var page scimhttp.ManagedConnectionListResponse
	if json.Unmarshal(call(list, true, 200), &page) != nil || len(page.Connections) != 1 || page.Connections[0].ConnectionID != created[0] || page.NextCursor == "" {
		t.Fatal("actual first native page differs")
	}
	cursor := page.NextCursor
	page = scimhttp.ManagedConnectionListResponse{}
	if json.Unmarshal(call(list+"&cursor="+url.QueryEscape(cursor), true, 200), &page) != nil || len(page.Connections) != 1 || page.Connections[0].ConnectionID != created[1] || page.NextCursor != "" {
		t.Fatal("actual next native page differs")
	}
	otherScope, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	call("/v1/scim/connection-get?connectionID="+string(otherScope), true, 403)
	call("/v1/scim/connection-list?organizationID="+string(otherScope)+"&limit=1", true, 403)
	call("/v1/scim/connection-list?organizationID="+string(otherScope)+"&limit=1&cursor="+url.QueryEscape(cursor), true, 400)
	policy.denyRead.Store(true)
	call(get, true, 403)
	call(list+"&cursor="+url.QueryEscape(cursor), true, 403)
	policy.denyRead.Store(false)
	call(get, true, 200)
	token, err := session.ParseToken(human.auth.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = guardedSessions.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, Credential: credential, Transport: session.CredentialBearer, CommandID: commandID, CorrelationID: string(commandID)}, session.CSRFToken{})
	if err != nil {
		t.Fatal("revoke actual original session through its native owner", err)
	}
	call(get, true, 403)
	call(list+"&cursor="+url.QueryEscape(cursor), true, 403)
}
