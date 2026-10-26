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

	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/reference"
	organization "github.com/faustbrian/go-organization"
)

// Uses the actual invitation owner after graph reconstruction, genuine humans
// and HTTP role transitions. Nothing seeds invitation or membership storage.
func proveReferenceOwnerInvitationList(t *testing.T, ctx context.Context, native *reference.OrganizationInvitationService, owner, recipient organizationTestHuman, org, existing organization.ID, workers reference.WorkerSet, messages <-chan string, call func(organizationTestHuman, string, string, any, string) (int, []byte)) {
	t.Helper()
	send := map[string]any{"organizationID": org, "organizationVersion": uint64(1), "recipientUserID": recipient.user, "recipientIdentifierID": recipient.identifier}
	code, wire := call(owner, http.MethodPost, "/v1/organization/invitation-send", send, "reference-owner-list-second-invitation")
	var sent organizationhttp.InvitationSendResponse
	if code != 200 || json.Unmarshal(wire, &sent) != nil || !sent.Committed || sent.InvitationID == "" || sent.InvitationID == existing {
		t.Fatal("owner-list second real invitation", code)
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
	code, wire = call(owner, http.MethodPost, "/v1/organization/member/add", map[string]any{"organizationID": org, "organizationVersion": uint64(1), "userID": recipient.user, "memberVersion": uint64(0), "role": "owner"}, "reference-owner-list-new-owner")
	var added organizationhttp.MutationResponse
	if code != 200 || json.Unmarshal(wire, &added) != nil || !added.Committed {
		t.Fatal("second owner admission", code)
	}
	code, wire = call(owner, http.MethodPost, "/v1/organization/member/update", map[string]any{"organizationID": org, "organizationVersion": added.AfterVersion, "userID": owner.user, "memberVersion": uint64(1), "role": "member"}, "reference-owner-list-withdraw-owner")
	var demoted organizationhttp.MutationResponse
	if code != 200 || json.Unmarshal(wire, &demoted) != nil || !demoted.Committed {
		t.Fatal("actual owner withdrawal", code)
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
