//go:build integration

package reference_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
)

// Called with actual signup-issued humans and the independently reconstructed
// native Reference graph. No storage writes or substituted domain owners make
// self-leave or its historical recovery succeed.
func proveReferenceOrganizationSelfLeave(t *testing.T, ctx context.Context, graph *reference.OrganizationService, owner, member organizationTestHuman, org organization.ID, removedMemberVersion uint64, call func(organizationTestHuman, string, string, any, string) (int, []byte)) organization.OperationRecoveryRequest {
	t.Helper()
	read := func(h organizationTestHuman, want int) organizationhttp.ReadResponse {
		t.Helper()
		code, wire := call(h, http.MethodGet, "/v1/organization/get?organizationID="+string(org), nil, "")
		var out organizationhttp.ReadResponse
		if code != want || code == 200 && json.Unmarshal(wire, &out) != nil {
			t.Fatal("self-leave current scoped read", code, want)
		}
		return out
	}
	mutate := func(h organizationTestHuman, path string, value any, key string, want int) organizationhttp.MutationResponse {
		t.Helper()
		code, wire := call(h, http.MethodPost, path, value, key)
		var out organizationhttp.MutationResponse
		if code != want || json.Unmarshal(wire, &out) != nil || want == 200 && (!out.Committed || out.Recovery == nil) {
			t.Fatal("genuine Reference self-leave mutation", path, code, want)
		}
		return out
	}
	view := read(owner, 200)
	add := map[string]any{"organizationID": org, "organizationVersion": view.Organization.Version, "userID": member.user, "memberVersion": removedMemberVersion, "role": "member"}
	mutate(owner, "/v1/organization/member/add", add, "reference-before-natural-leave", 200)
	view = read(member, 200)
	leave := map[string]any{"organizationID": org, "organizationVersion": view.Organization.Version}
	original := mutate(member, "/v1/organization/member/leave", leave, "", 200)
	if original.MemberID != member.user || original.OrganizationID != org || original.BeforeVersion != view.Organization.Version || original.AfterVersion != view.Organization.Version+1 {
		t.Fatal("self-leave changed actor or exact version")
	}
	read(member, 403)
	repeated := mutate(member, "/v1/organization/member/leave", leave, "", 200)
	if repeated.CommandID != original.CommandID || repeated.AfterVersion != original.AfterVersion {
		t.Fatal("natural self-leave repeated the mutation instead of original metadata")
	}
	scope := original.Recovery
	b := identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: scope.OperationID, RecordID: scope.RecordID, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, SchemaID: scope.SchemaID, SchemaVersion: scope.SchemaVersion, CorrelationID: scope.CorrelationID}
	recovery := organization.OperationRecoveryRequest{Authentication: member.auth, Binding: b}
	if out, err := graph.RecoverOperation(ctx, recovery); err != nil || out.Receipt.Binding != b || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("reconstructed native owner lost departed-self receipt", err)
	}
	wrong := recovery
	wrong.Authentication = owner.auth
	if out, err := graph.RecoverOperation(ctx, wrong); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("manager recovered another human's self-history")
	}
	viewOwner := read(owner, 200)
	add["organizationVersion"], add["memberVersion"] = viewOwner.Organization.Version, view.Membership.Version+1
	mutate(owner, "/v1/organization/member/add", add, "reference-after-natural-leave", 200)
	mutate(member, "/v1/organization/member/leave", leave, "", 409)
	if current := read(member, 200); current.Membership.Version != view.Membership.Version+2 || current.Membership.UserID != member.user {
		t.Fatal("old self-leave removed a newer membership")
	}
	if out, err := graph.RecoverOperation(ctx, recovery); err != nil || out.Receipt.Binding != b || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("readmission reinterpreted original self-history", err)
	}
	viewOwner = read(owner, 200)
	mutate(owner, "/v1/organization/member/leave", map[string]any{"organizationID": org, "organizationVersion": viewOwner.Organization.Version}, "", 409)
	return recovery
}
