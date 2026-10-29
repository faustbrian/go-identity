package apikeyhttp

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
)

// This port observes transport mapping and projections only. Actual organization
// membership, custody and persistence are proven by the real native/Reference
// consumers, never by these wire fixtures.
type organizationWireOwner struct {
	request apikey.OrganizationCreateRequest
	result  apikey.IssuanceResult
	calls   int
	err     error
}

func (o *organizationWireOwner) CreateOrganization(_ context.Context, r apikey.OrganizationCreateRequest) (apikey.IssuanceResult, error) {
	o.calls++
	o.request = r
	return o.result, o.err
}

func TestOrganizationCreateMapsExplicitOwnerAndKeepsHumanActor(t *testing.T) {
	f := newFixture(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "org-a", Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := wireFixtureResult(t, f, "create", identity.CommitOutcomeCommitted, false, owner)
	o := &organizationWireOwner{result: issued}
	f.config.OrganizationOwned, f.config.OrganizationCreator = true, o
	h := fixtureHandler(t, f)
	for attempt := range 2 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, f.request("create", `{"organizationID":"org-a","name":"consumer key","permissions":["read"],"expiresAt":"2026-10-29T12:00:00Z"}`))
		var out commandResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.Key == nil || out.Recovery == nil || out.Recovery.UserID != "user-a" || out.Recovery.ActorID != "user-a" {
			t.Fatal("organization issuance lost committed owner/manager separation", w.Code)
		}
		if attempt == 0 {
			if _, err := apikey.ParseSecret(out.Secret); err != nil {
				t.Fatal("original invocation did not reveal committed material")
			}
		} else if out.Secret != "" {
			t.Fatal("organization replay revealed material again")
		}
	}
	if o.calls != 2 || f.native.calls != 0 || o.request.Validate() != nil || o.request.OrganizationID != "org-a" || o.request.Authentication.TenantID != "tenant-a" || o.request.Authentication.Bearer.Token() != f.token || o.request.Network != "198.51.100.1" {
		t.Fatal("organization request used self-key fallback or request-selected authority")
	}
}

func TestUnselectedOrganizationInputDeniesBeforeAuthority(t *testing.T) {
	f := newFixture(t)
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("create", `{"organizationID":"org-a","name":"consumer key","permissions":["read"],"expiresAt":"2026-10-29T12:00:00Z"}`))
	if w.Code != 400 || f.native.calls != 0 || f.sessions.calls != 0 || f.rate.calls != 0 {
		t.Fatal("disabled owner input acquired authority", w.Code)
	}
}

func TestOrganizationMutationProjectionRequiresExplicitSelection(t *testing.T) {
	for _, action := range []string{"rotate", "delete"} {
		for _, selected := range []bool{false, true} {
			f := newFixture(t)
			owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "org-a", Version: 1})
			issued, receipt := wireFixtureResult(t, f, action, identity.CommitOutcomeCommitted, false, owner)
			f.native.issued, f.native.receipt = &issued, &receipt
			f.config.Create, f.config.OrganizationOwned = false, selected
			w := httptest.NewRecorder()
			fixtureHandler(t, f).ServeHTTP(w, f.request(action, `{"keyID":"key-a","expectedVersion":1}`))
			var out commandResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil {
				t.Fatal("invalid response")
			}
			if selected {
				if w.Code != 200 || !out.Committed || out.Recovery == nil || out.Recovery.UserID != "user-a" {
					t.Fatal("selected organization mutation lost manager custody", action, w.Code)
				}
			} else if w.Code != 503 || out.Committed || out.Secret != "" || out.Key != nil {
				t.Fatal("unselected organization outcome escaped projection", action, w.Code)
			}
		}
	}
}

func TestOrganizationCreateRejectsInvalidOrAlternateOwnerBeforeAuthority(t *testing.T) {
	for _, body := range []string{
		`{"organizationID":null,"name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`,
		`{"organizationID":"","name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`,
		`{"OrganizationID":"org-a","name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`,
		`{"organizationID":"org-a","organizationID":"org-b","name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`,
		`{"organizationID":"org-a","tenantID":"tenant-b","name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`,
		`{"organizationID":"org a","name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`,
		`{"organizationID":"` + strings.Repeat("a", 129) + `","name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`,
	} {
		f := newFixture(t)
		o := &organizationWireOwner{err: apikey.ErrDenied}
		f.config.OrganizationOwned, f.config.OrganizationCreator = true, o
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("create", body))
		if w.Code != 400 || o.calls != 0 || f.native.calls != 0 || f.sessions.calls != 0 || f.rate.calls != 0 {
			t.Fatal("invalid organization owner reached authority", w.Code)
		}
	}
}

func TestOrganizationCreateCannotRevealAnotherOwnerOrRenewUnknown(t *testing.T) {
	for _, kind := range []string{"foreign-organization", "self", "unknown"} {
		f := newFixture(t)
		owner, _ := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "org-b", Version: 1})
		outcome := identity.CommitOutcomeCommitted
		if kind == "self" {
			owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
		}
		if kind == "unknown" {
			outcome = identity.CommitOutcomeUnknown
		}
		issued, _ := wireFixtureResult(t, f, "create", outcome, false, owner)
		o := &organizationWireOwner{result: issued}
		f.config.OrganizationOwned, f.config.OrganizationCreator = true, o
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("create", `{"organizationID":"org-a","name":"consumer key","permissions":["read"],"expiresAt":"2026-10-29T12:00:00Z"}`))
		var out commandResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.Secret != "" || out.Key != nil {
			t.Fatal("wrong or unknown organization owner disclosed authority", kind, w.Code)
		}
		if kind == "unknown" && (out.Recovery == nil || out.CommitOutcome != "unknown") {
			t.Fatal("unknown lost its original human recovery scope")
		}
	}
}

func TestOrganizationSelectionControlsSchemaAndRequiredPort(t *testing.T) {
	for _, selected := range []bool{false, true} {
		f := newFixture(t)
		f.config.OrganizationOwned = selected
		if selected {
			if _, err := NewFeature(f.config); err == nil {
				t.Fatal("selected organization creation accepted a missing owner")
			}
			var absent *organizationWireOwner
			f.config.OrganizationCreator = absent
			if _, err := NewFeature(f.config); err == nil {
				t.Fatal("selected organization creation accepted typed nil")
			}
			f.config.OrganizationCreator = &organizationWireOwner{err: apikey.ErrDenied}
		}
		feature, err := NewFeature(f.config)
		if err != nil {
			t.Fatal(err)
		}
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		_, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: 3 * time.Second, Document: identityhttp.DocumentConfig{Title: "API keys", Version: "1"}}, ops, nil)
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Paths map[string]map[string]struct {
				RequestBody struct {
					Content map[string]struct {
						Schema struct {
							Properties map[string]json.RawMessage `json:"properties"`
						} `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
			}
		}
		if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 3 {
			t.Fatal("selected document lost actual route bijection")
		}
		properties := document.Paths["/v1/apikey/create"]["post"].RequestBody.Content["application/json"].Schema.Properties
		if (properties["organizationID"] != nil) != selected {
			t.Fatal("advertised owner input differs from selected parser")
		}
	}
}
