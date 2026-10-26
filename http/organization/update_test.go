package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type updatePort struct {
	*nativePort
	metadata organization.UpdateOperationRequest
	member   organization.UpdateMemberOperationRequest
}

func (p *updatePort) Update(ctx context.Context, r organization.UpdateOperationRequest, network string) (organization.StoreResult, error) {
	p.metadata, p.network = r, network
	out, err := p.mutation(ctx, organization.Update, r.Authentication, r.OrganizationID, "user-a")
	if out.Receipt.Feature != nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = r.OrganizationVersion, r.OrganizationVersion+1
	}
	return out, err
}

func (p *updatePort) UpdateMember(ctx context.Context, r organization.UpdateMemberOperationRequest, network string) (organization.StoreResult, error) {
	p.member, p.network = r, network
	out, err := p.mutation(ctx, organization.UpdateMember, r.Authentication, r.OrganizationID, r.UserID)
	if out.Receipt.Feature != nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = r.OrganizationVersion, r.OrganizationVersion+1
	}
	return out, err
}

func updateHandler(t *testing.T, f *fixture, p *updatePort) http.Handler {
	t.Helper()
	f.c.Service = nil
	f.c.MetadataUpdater, f.c.MemberUpdater = p, p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, Update: true, MemberUpdate: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestOrganizationUpdatesUseIndependentNativePortsAndOriginalIntent(t *testing.T) {
	f := newFixture(t)
	p := &updatePort{nativePort: f.port}
	h := updateHandler(t, f, p)
	for _, tc := range []struct{ path, body string }{
		{"/v1/organization/update", `{"organizationID":"organization-a","organizationVersion":7,"name":"New name","slug":"new-name"}`},
		{"/v1/organization/member/update", `{"organizationID":"organization-a","organizationVersion":7,"userID":"user-b","memberVersion":2,"role":"administrator"}`},
	} {
		w := serve(t, h, request(f, tc.path, tc.body, true))
		var out organizationhttp.MutationResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil {
			t.Fatal("native update outcome missing", w.Code)
		}
	}
	key, _ := identity.NewIdempotencyKey([]byte("original-key"))
	expected, _ := key.Digest([32]byte{1})
	metadataKey, metadataErr := p.metadata.IdempotencyKey.Digest([32]byte{1})
	memberKey, memberErr := p.member.IdempotencyKey.Digest([32]byte{1})
	if metadataErr != nil || memberErr != nil || metadataKey != expected || memberKey != expected {
		t.Fatal("transport replaced original request-key bytes")
	}
	if p.metadata.Validate() != nil || p.member.Validate() != nil || p.metadata.Name != "New name" || p.metadata.Slug != "new-name" || p.member.UserID != "user-b" || p.member.Role != organization.RoleAdministrator || p.member.MemberVersion != 2 || p.metadata.Authentication.Bearer.Token() != f.wire || p.network != "198.51.100.7" || p.calls != 2 || f.rate.calls != 2 {
		t.Fatal("transport replaced original intent, actor custody or shared admission")
	}
	w := serve(t, h, request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true))
	if w.Code != 404 || p.calls != 2 {
		t.Fatal("unselected operation became available")
	}
}

func TestOrganizationUpdatesRejectMalformedIntentBeforeNativeAdmission(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		keyed      bool
	}{
		{"/v1/organization/update", `{"organizationID":"organization-a","organizationVersion":7,"name":"Name","slug":"slug"}`, false},
		{"/v1/organization/update", `{"organizationID":"organization-a","organizationVersion":7,"name":"Name","slug":"slug","tenantID":"other"}`, true},
		{"/v1/organization/update", `{"organizationID":"organization-a","organizationVersion":18446744073709551615,"name":"Name","slug":"slug"}`, true},
		{"/v1/organization/update", `{"organizationID":"organization-a","organizationVersion":7,"name":"Name","slug":"bad slug"}`, true},
		{"/v1/organization/member/update", `{"organizationID":"organization-a","organizationVersion":7,"userID":"user-b","memberVersion":0,"role":"member"}`, true},
		{"/v1/organization/member/update", `{"organizationID":"organization-a","organizationVersion":7,"userID":"user-b","memberVersion":2,"role":"unknown"}`, true},
		{"/v1/organization/member/update", `{"organizationID":"organization-a","organizationVersion":7,"userID":"user-b","memberVersion":2,"role":"member","idempotencyKey":"alternate"}`, true},
	} {
		f := newFixture(t)
		p := &updatePort{nativePort: f.port}
		w := serve(t, updateHandler(t, f, p), request(f, tc.path, tc.body, tc.keyed))
		if w.Code != 400 || p.calls != 0 || f.rate.calls != 0 || f.reads.Load() != 0 {
			t.Fatal("invalid update reached authentication or domain owner", w.Code)
		}
	}
}

func TestOrganizationUpdatesKeepCurrentSessionRateAndKnownOutcomeFences(t *testing.T) {
	body := `{"organizationID":"organization-a","organizationVersion":7,"name":"Name","slug":"slug"}`
	for _, mode := range []int{1, 2, 3, 4} {
		f := newFixture(t)
		p := &updatePort{nativePort: f.port}
		f.rate.mode = mode
		w := serve(t, updateHandler(t, f, p), request(f, "/v1/organization/update", body, true))
		want := 503
		if mode == 1 {
			want = 429
		}
		if w.Code != want || p.calls != 0 || f.denials.Load() != 1 {
			t.Fatal("rate failure bypassed shared admission", w.Code)
		}
	}
	f := newFixture(t)
	p := &updatePort{nativePort: f.port}
	f.inactive = true
	w := serve(t, updateHandler(t, f, p), request(f, "/v1/organization/update", body, true))
	if w.Code != 403 || p.calls != 0 || f.rate.calls != 0 {
		t.Fatal("withdrawn session reached mutation", w.Code)
	}
	f = newFixture(t)
	p = &updatePort{nativePort: f.port}
	p.err = organization.ErrUnavailable
	w = serve(t, updateHandler(t, f, p), request(f, "/v1/organization/update", body, true))
	var out organizationhttp.MutationResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.Recovery == nil || strings.Contains(w.Body.String(), f.wire) {
		t.Fatal("late failure erased original outcome or revealed custody", w.Code)
	}
}

func TestOrganizationUpdateSelectionsRequireOnlyTheirActualOwners(t *testing.T) {
	for _, metadata := range []bool{true, false} {
		f := newFixture(t)
		selected := organizationhttp.FeatureConfig{Config: f.c, Update: metadata, MemberUpdate: !metadata}
		selected.Config.Service, selected.Config.SafeRate = nil, nil
		if metadata {
			selected.Config.MemberUpdater = nil
		} else {
			selected.Config.MetadataUpdater = nil
		}
		feature, err := organizationhttp.NewFeature(selected)
		if err != nil {
			t.Fatal("single update required an unrelated owner", err)
		}
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		want := organization.UpdateMember
		if metadata {
			want = organization.Update
		}
		if err != nil || len(ops) != 1 || ops[0].Record.OperationID != string(want) || f.port.calls != 0 || f.reads.Load() != 0 || f.rate.calls != 0 {
			t.Fatal("single selection enabled another route or performed owner IO")
		}
		for _, typedNil := range []bool{false, true} {
			missing := selected
			var owner *updatePort
			if metadata {
				missing.Config.MetadataUpdater = nil
				if typedNil {
					missing.Config.MetadataUpdater = owner
				}
			} else {
				missing.Config.MemberUpdater = nil
				if typedNil {
					missing.Config.MemberUpdater = owner
				}
			}
			if _, err := organizationhttp.NewFeature(missing); !errors.Is(err, identityhttp.ErrInvalidInput) {
				t.Fatal("missing selected update owner became usable")
			}
		}
		selected.Config.AdminRate = nil
		if _, err := organizationhttp.NewFeature(selected); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("update selection omitted mandatory administrative admission")
		}
	}
}
