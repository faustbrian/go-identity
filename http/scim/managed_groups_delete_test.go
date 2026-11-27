package scimhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedGroupDeletePath = "/scim/v2/Groups/source-group"

type managedGroupsDeleteExecutor struct {
	*managedUsersDeleteExecutor
	maximumMembers int
}

func (e *managedGroupsDeleteExecutor) ExecuteManagedAdmittedGroupDelete(ctx context.Context, tenant identity.TenantID, request scim.Request, maximumMembers int, admit scim.ProtocolAdmission) (scim.Response, error) {
	e.maximumMembers = maximumMembers
	return e.ExecuteManagedAdmittedDelete(ctx, tenant, request, admit)
}

var _ scimhttp.ManagedGroupsDeleteExecutor = (*scimpostgres.ManagedConnectionService)(nil)

func managedGroupDeleteFeature(t *testing.T, fixture managedUserDeleteFixture, executor *managedGroupsDeleteExecutor) identityhttp.Feature {
	t.Helper()
	c := fixture.config
	feature, err := scimhttp.NewManagedGroupsDeleteFeature(scimhttp.ManagedGroupsDeleteConfig{
		Network: c.Network, Executor: executor, Rate: c.Rate, Limits: c.Limits, MaximumDuration: c.MaximumDuration, MaximumMembers: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return feature
}

func managedGroupDeleteRequest() *http.Request {
	r := protocolRequest(http.MethodDelete, managedGroupDeletePath, "")
	r.Header.Set("If-Match", managedUserDeleteETag)
	return r
}

func TestManagedGroupsDeleteForwardsOptionalAliasAndLeavesUsersIndependent(t *testing.T) {
	fixture := newManagedUserDeleteFixture()
	executor := &managedGroupsDeleteExecutor{managedUsersDeleteExecutor: fixture.executor}
	group := managedGroupDeleteFeature(t, fixture, executor)
	h, document := protocolRouter(t, fixture.config.Network, group.Operations())
	for _, alias := range []string{"", "delete-original-alias"} {
		r := managedGroupDeleteRequest()
		if alias != "" {
			r.Header.Set("Idempotency-Key", alias)
		}
		out := managedServe(h, r)
		if out.Code != http.StatusNoContent || out.Body.Len() != 0 || out.Header().Get("ETag") != "" ||
			out.Header().Get("Location") != "" || out.Header().Get("Content-Type") != "" || out.Header().Get("Set-Cookie") != "" {
			t.Fatal("DELETE changed the native empty 204", out.Code)
		}
		got := executor.request
		if got.Operation != scim.GroupDelete || got.ResourceID != "source-group" || got.IfMatch != managedUserDeleteETag ||
			got.IdempotencyKey != alias || got.Credential.Token() != syntheticBearer || got.Body != nil || got.Query != (scim.Query{}) ||
			executor.tenant != executor.client.TenantID || executor.maximumMembers != 3 {
			t.Fatal("DELETE rewrote native Group scope, precondition, or client alias")
		}
	}
	if executor.calls != 2 || fixture.base.backend.calls != 2 || len(fixture.base.backend.last.Requests) != 3 {
		t.Fatal("each retry must earn one fresh native quota admission")
	}
	var wire struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name     string `json:"name"`
				In       string `json:"in"`
				Required bool   `json:"required"`
			} `json:"parameters"`
			RequestBody json.RawMessage `json:"requestBody"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(document.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	operation, ok := wire.Paths["/scim/v2/Groups/{resource_id}"]["delete"]
	var alias, precondition bool
	for _, p := range operation.Parameters {
		alias = alias || p.Name == "Idempotency-Key" && p.In == "header" && !p.Required
		precondition = precondition || p.Name == "If-Match" && p.In == "header" && p.Required
	}
	if !ok || !alias || !precondition || len(operation.RequestBody) != 0 || len(document.Operations()) != 1 ||
		document.Operations()[0].Record.OperationID != "identity.scim.group-delete" || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("wire contract does not match the selected bodyless Group DELETE")
	}
	if out := managedServe(h, fixture.request()); out.Code != http.StatusNotFound || executor.calls != 2 {
		t.Fatal("Group DELETE implicitly selected User DELETE", out.Code)
	}
	user, err := scimhttp.NewManagedUsersDeleteFeature(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	combined, _ := protocolRouter(t, fixture.config.Network, append(group.Operations(), user.Operations()...))
	r := fixture.request()
	r.Header.Set("Idempotency-Key", "user-route-forbids-alias")
	if out := managedServe(combined, r); out.Code != http.StatusBadRequest || executor.calls != 2 {
		t.Fatal("Group alias policy widened co-selected User DELETE", out.Code)
	}
	if out := managedServe(combined, fixture.request()); out.Code != http.StatusNoContent || executor.request.Operation != scim.UserDelete {
		t.Fatal("co-selected User DELETE no longer reaches its own native operation", out.Code)
	}
}

func TestManagedGroupsDeleteRejectsInvalidAliasAndDoesNotPublishNativeErrorsAsSuccess(t *testing.T) {
	for _, name := range []string{"duplicate alias", "invalid alias", "query alias", "reused native alias", "native produced representation"} {
		t.Run(name, func(t *testing.T) {
			fixture := newManagedUserDeleteFixture()
			executor := &managedGroupsDeleteExecutor{managedUsersDeleteExecutor: fixture.executor}
			r := managedGroupDeleteRequest()
			want, calls := http.StatusBadRequest, 0
			switch name {
			case "duplicate alias":
				r.Header.Add("Idempotency-Key", "one")
				r.Header.Add("Idempotency-Key", "two")
			case "invalid alias":
				r.Header.Set("Idempotency-Key", "not a token")
			case "query alias":
				r.URL.RawQuery = "idempotency_key=untrusted"
			case "reused native alias":
				r.Header.Set("Idempotency-Key", "already-bound")
				executor.afterAdmissionError = scim.NewError(http.StatusConflict, "uniqueness")
				want, calls = http.StatusConflict, 1
			case "native produced representation":
				executor.response.ETag = managedUserDeleteETag
				want, calls = http.StatusServiceUnavailable, 1
			}
			h, _ := protocolRouter(t, fixture.config.Network, managedGroupDeleteFeature(t, fixture, executor).Operations())
			out := managedServe(h, r)
			if name == "duplicate alias" || name == "query alias" {
				if out.Code != want || out.Header().Get("Content-Type") != "application/json" || strings.TrimSpace(out.Body.String()) != `{"error":"invalid_request"}` {
					t.Fatal("router did not reject the malformed credential envelope", out.Code)
				}
			} else {
				assertProtocolError(t, out, want)
			}
			if executor.calls != calls || fixture.base.backend.calls != calls || out.Header().Get("ETag") != "" || out.Header().Get("Location") != "" {
				t.Fatal("invalid or rejected DELETE changed quota or disclosed the native result")
			}
		})
	}
}
