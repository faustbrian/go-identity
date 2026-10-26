//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
)

// Uses the actual invitation owner after graph reconstruction, genuine humans
// and guarded native role transitions. Nothing seeds invitation or membership storage.
func proveReferenceOwnerInvitationList(t *testing.T, ctx context.Context, native *reference.OrganizationInvitationService, organizations *reference.OrganizationService, owner, recipient organizationTestHuman, org, existing organization.ID, workers reference.WorkerSet, messages <-chan string, call func(organizationTestHuman, string, string, any, string) (int, []byte)) {
	t.Helper()
	key := func(value string) identity.IdempotencyKey {
		t.Helper()
		out, err := identity.NewIdempotencyKey([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// Send/member HTTP paths already have their own assertions in this journey.
	// Prepare this read profile through the supported guarded native commands,
	// retaining their real risk/authority/transaction owners. Adding setup HTTP
	// attempts to the accumulated admin budget made success depend on refill
	// timing (30 actor attempts/minute), not on invitation-list correctness.
	sent, err := native.Send(ctx, organization.InvitationSendOperationRequest{Authentication: owner.auth, IdempotencyKey: key("reference-owner-list-second-invitation"), OrganizationID: org, OrganizationVersion: 1, RecipientUserID: recipient.user, RecipientIdentifierID: recipient.identifier, CorrelationID: "owner-list-second-invitation"}, "127.0.0.1")
	if err != nil || sent.Receipt.Outcome != identity.CommitOutcomeCommitted || sent.InvitationID == "" || sent.InvitationID == existing {
		t.Fatal("owner-list second real invitation", err)
	}
	if _, err := workers.ProcessDeliveryOne(ctx, 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-messages:
	case <-ctx.Done():
		t.Fatal("second list invitation delivery missing")
	}
	path := "/v1/organization/invitation/list?organizationID=" + url.QueryEscape(string(org)) + "&limit=1"
	var got []organization.ID
	cursor := ""
	var code int
	var wire []byte
	for n := 0; n < 2; n++ {
		selected := path
		if cursor != "" {
			selected += "&cursor=" + url.QueryEscape(cursor)
		}
		code, wire = call(owner, http.MethodGet, selected, nil, "")
		var page organizationhttp.InvitationListResponse
		if code != 200 || json.Unmarshal(wire, &page) != nil || len(page.Invitations) != 1 || page.Invitations[0].OrganizationID != org {
			t.Fatal("genuine owner page", code)
		}
		for _, hidden := range []string{string(recipient.user), string(recipient.identifier), owner.auth.Bearer.Token(), "recipientIdentifier", "effectID", "token"} {
			if bytes.Contains(wire, []byte(hidden)) {
				t.Fatal("private invitation data exported")
			}
		}
		got = append(got, page.Invitations[0].ID)
		cursor = string(page.NextCursor)
		if n == 0 && cursor != string(got[0]) || n == 1 && cursor != "" {
			t.Fatal("native invitation-ID continuation not conserved")
		}
	}
	want := []organization.ID{existing, sent.InvitationID}
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatal("owner page lost native C ordering")
	}
	r := organization.InvitationReadRequest{Authentication: owner.auth, OrganizationID: org, Limit: 100, CorrelationID: "reconstructed-owner-list"}
	page, err := native.List(ctx, r)
	if err != nil || len(page.Invitations) != 2 || page.Invitations[0].Invitation.ID != want[0] || page.Invitations[1].Invitation.ID != want[1] {
		t.Fatal("guarded reconstructed owner list", err)
	}
	foreign := r
	foreign.Authentication.TenantID = "unconfigured-tenant"
	if out, err := native.List(ctx, foreign); err == nil || len(out.Invitations) != 0 {
		t.Fatal("native list crossed configured tenant")
	}
	if code, _ := call(recipient, http.MethodGet, path, nil, ""); code != 403 {
		t.Fatal("recipient became owner through invitation", code)
	}
	// Actual role withdrawal changes authority; a previous successful page or
	// continuation is never sufficient to authorize another read.
	added, err := organizations.AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: key("reference-owner-list-new-owner"), OrganizationID: org, OrganizationVersion: 1, UserID: recipient.user, Role: organization.RoleOwner, CorrelationID: "owner-list-new-owner"}, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted || added.Receipt.Feature == nil {
		t.Fatal("second owner admission", err)
	}
	demoted, err := organizations.UpdateMember(ctx, organization.UpdateMemberOperationRequest{Authentication: owner.auth, IdempotencyKey: key("reference-owner-list-withdraw-owner"), OrganizationID: org, OrganizationVersion: added.Receipt.Feature.AfterVersion, UserID: owner.user, MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "owner-list-withdraw-owner"}, "127.0.0.1")
	if err != nil || demoted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual owner withdrawal", err)
	}
	if code, _ := call(owner, http.MethodGet, path+"&cursor="+url.QueryEscape(string(want[0])), nil, ""); code != 403 {
		t.Fatal("old continuation retained owner authority", code)
	}
	if out, err := native.List(ctx, r); err == nil || len(out.Invitations) != 0 {
		t.Fatal("reconstructed owner survived demotion")
	}
	if code, _ := call(recipient, http.MethodGet, path, nil, ""); code != 200 {
		t.Fatal("current replacement owner cannot list", code)
	}
}
