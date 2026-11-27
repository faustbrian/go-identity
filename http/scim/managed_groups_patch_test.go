package scimhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedGroupPatchInput = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"replace-person"}]}`

type managedGroupsPatchExecutor struct {
	*managedUsersExecutor
	maximum int
	deny    *scim.Error
}

func (e *managedGroupsPatchExecutor) ExecuteManagedAdmittedGroupPatch(ctx context.Context, tenant identity.TenantID, request scim.Request, maximum int, admit scim.ProtocolAdmission) (scim.Response, error) {
	e.maximum = maximum
	request.Body = bytes.Clone(request.Body)
	response, err := e.ExecuteManagedAdmittedRead(ctx, tenant, request, admit)
	if err == nil && e.deny != nil {
		return scim.Response{}, e.deny
	}
	return response, err
}

var _ scimhttp.ManagedGroupsPatchExecutor = (*scimpostgres.ManagedConnectionService)(nil)

func managedGroupPatchFeature(t *testing.T, f managedGroupReplaceFixture, exec *managedGroupsPatchExecutor) identityhttp.Feature {
	t.Helper()
	feature, err := scimhttp.NewManagedGroupsPatchFeature(scimhttp.ManagedGroupsPatchConfig{
		Network: f.config.Network, Executor: exec, Rate: f.config.Rate, Limits: scim.DefaultLimits(), MaximumDuration: time.Second, MaximumMembers: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	return feature
}

func managedGroupPatchRequest() *http.Request {
	r := protocolRequest(http.MethodPatch, managedGroupReplacePath, managedGroupPatchInput)
	r.Header.Set("Content-Type", "application/scim+json")
	r.Header.Set("If-Match", managedGroupReplaceOriginalETag)
	return r
}

func TestManagedGroupsPatchSelectsOnlyConditionalPatchAndPreservesNativeOutcome(t *testing.T) {
	f := newManagedGroupReplaceFixture()
	exec := &managedGroupsPatchExecutor{managedUsersExecutor: f.executor.managedUsersExecutor}
	patch := managedGroupPatchFeature(t, f, exec)
	h, document := protocolRouter(t, f.config.Network, patch.Operations())
	response := managedServe(h, managedGroupPatchRequest())
	if response.Code != http.StatusOK || response.Body.String() != managedGroupReplaceBody || response.Header().Get("ETag") != managedGroupReplaceETag ||
		response.Header().Get("Location") != managedGroupReplaceLocation || response.Header().Get("Content-Type") != "application/scim+json" || response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("PATCH did not retain the admitted native representation: status=%d", response.Code)
	}
	request := exec.request
	if request.Operation != scim.GroupPatch || request.ResourceID != managedGroupReplaceID || request.IfMatch != managedGroupReplaceOriginalETag ||
		request.Credential.Token() != syntheticBearer || request.IdempotencyKey != "" || request.Query != (scim.Query{}) ||
		string(request.Body) != managedGroupPatchInput || request.ContentType != "application/scim+json" || request.ContentEncoding != "" ||
		exec.tenant != exec.client.TenantID || exec.maximum != 3 || exec.calls != 1 || f.base.backend.calls != 1 || len(f.base.backend.last.Requests) != 3 {
		t.Fatal("PATCH rewrote the conditional request or changed exact-once quota admission")
	}
	var wire struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(document.JSON(), &wire); err != nil {
		t.Fatal(err)
	}
	ops := wire.Paths["/scim/v2/Groups/{resource_id}"]
	if len(document.Operations()) != 1 || document.Operations()[0].Record.OperationID != "identity.scim.group-patch" || len(ops) != 1 || !bytes.Contains(ops["patch"], []byte("PatchOp")) ||
		!bytes.Contains(ops["patch"], []byte("If-Match")) || !bytes.Contains(ops["patch"], []byte("Operations")) || strings.Contains(string(document.JSON()), syntheticBearer) {
		t.Fatal("PATCH wire does not describe only the selected conditional PatchOp")
	}
	if out := managedServe(h, f.request(managedGroupReplaceInput)); out.Code != http.StatusMethodNotAllowed || exec.calls != 1 {
		t.Fatal("PATCH implicitly enabled PUT", out.Code)
	}
	replace, err := scimhttp.NewManagedGroupsReplaceFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	combined, _ := protocolRouter(t, f.config.Network, append(patch.Operations(), replace.Operations()...))
	if out := managedServe(combined, f.request(managedGroupReplaceInput)); out.Code != http.StatusOK || exec.request.Operation != scim.GroupReplace {
		t.Fatal("co-selected replacement no longer reaches its own native operation", out.Code)
	}
}

func TestManagedGroupsPatchDenialsExposeNoNativeResult(t *testing.T) {
	for _, scenario := range []string{"stale original", "input key", "incorrect success target", "ignored quota"} {
		t.Run(scenario, func(t *testing.T) {
			f := newManagedGroupReplaceFixture()
			exec := &managedGroupsPatchExecutor{managedUsersExecutor: f.executor.managedUsersExecutor}
			r := managedGroupPatchRequest()
			want, calls := http.StatusServiceUnavailable, 1
			switch scenario {
			case "stale original":
				exec.deny, want = scim.NewError(412, ""), http.StatusPreconditionFailed
			case "input key":
				r.Header.Set("Idempotency-Key", "do-not-select-an-original")
				want, calls = http.StatusBadRequest, 0
			case "incorrect success target":
				exec.response.Location = "https://foreign.example" + managedGroupReplacePath
			case "ignored quota":
				exec.mode, f.base.backend.limited = "ignore", true
			}
			h, _ := protocolRouter(t, f.config.Network, managedGroupPatchFeature(t, f, exec).Operations())
			out := managedServe(h, r)
			assertProtocolError(t, out, want)
			if exec.calls != calls || f.base.backend.calls != calls || out.Header().Get("ETag") != "" || out.Header().Get("Location") != "" ||
				strings.Contains(out.Body.String(), managedGroupReplaceID) {
				t.Fatal("PATCH denial leaked a Group or changed the native/quota boundary")
			}
		})
	}
}
