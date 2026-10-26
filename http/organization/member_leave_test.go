package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// This substituted domain port proves only transport custody and projection.
// Genuine native and Reference journeys must separately prove self-leave,
// natural-repeat recovery, last-owner safety and actual membership withdrawal.
type memberLeavePort struct {
	*invitationSendPort
	last   organization.LeaveMemberOperationRequest
	before func()
}

func newMemberLeavePort(t testing.TB) *memberLeavePort {
	p := &memberLeavePort{invitationSendPort: newInvitationSendPort(t)}
	p.result.MemberID, p.result.InvitationID = "user-a", ""
	b := &p.result.Receipt.Binding
	b.UserID, b.RecordID, b.OperationID = "user-a", "organization-a", string(organization.LeaveMember)
	b.SchemaID = organization.LeaveMember.Descriptor().SchemaID
	p.result.Receipt.Feature.Operation = organization.LeaveMember.Descriptor()
	p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = 7, 8
	return p
}

func (p *memberLeavePort) LeaveMember(ctx context.Context, r organization.LeaveMemberOperationRequest, network string) (organization.StoreResult, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		p.t.Fatal("unbounded native self-leave")
	}
	p.last, p.net, p.sent = r, network, p.sent+1
	if p.before != nil {
		p.before()
	}
	return p.result, p.err
}

func memberLeaveFeature(t testing.TB, f *fixture, p *memberLeavePort) identityhttp.Feature {
	t.Helper()
	f.c.Service, f.c.Invitations, f.c.AdminRate = nil, nil, nil
	f.c.MemberLeaver = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, MemberLeave: true})
	if err != nil {
		t.Fatal("independent self-leave selection", err)
	}
	return feature
}

func memberLeaveHandler(t testing.TB, f *fixture, p *memberLeavePort) http.Handler {
	t.Helper()
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{memberLeaveFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const memberLeaveInput = `{"organizationID":"organization-a","organizationVersion":7}`

func TestMemberLeavePreservesSelfSelectorAndActualOriginalReceipt(t *testing.T) {
	f := newFixture(t)
	p := newMemberLeavePort(t)
	h := memberLeaveHandler(t, f, p)
	for range 2 {
		w := serve(t, h, request(f, "/v1/organization/member/leave", memberLeaveInput, false))
		var out organizationhttp.MutationResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.OrganizationID != "organization-a" || out.MemberID != "user-a" || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil || out.Recovery.CommandID != p.result.Receipt.Binding.CommandID {
			t.Fatal("self-leave lost actual original receipt", w.Code)
		}
		if p.last.Validate() != nil || p.last.Authentication.TenantID != "tenant-a" || p.last.Authentication.Bearer.Token() != f.wire || p.last.OrganizationID != "organization-a" || p.last.OrganizationVersion != 7 || p.last.CorrelationID == "" || p.net != "198.51.100.7" {
			t.Fatal("transport changed exact self-leave scope")
		}
		for _, hidden := range []string{f.wire, "private-effect", "recipient-a", `"membership":`, `"invitation":`, `"deliveryState":`} {
			if strings.Contains(w.Body.String(), hidden) {
				t.Fatal("self-leave disclosed private or unrelated state")
			}
		}
	}
	if p.sent != 2 || p.calls != 0 || f.port.calls != 0 || f.rate.calls != 0 {
		t.Fatal("self-leave required post-leave membership or administrative admission")
	}
}

func TestMemberLeaveRejectsAlternateSelectorsBeforeAuthority(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `{"organizationID":"organization-a"}`, `{"organizationID":"organization-a","organizationVersion":0}`,
		`{"organizationID":"organization-a","organizationVersion":18446744073709551615}`, `{"organizationID":"organization-a","organizationVersion":7.0}`,
		`{"organizationID":"organization-a","organizationVersion":7e0}`, `{"organizationID":"organization-a","organizationVersion":7,"userID":"other"}`,
		`{"organizationID":"organization-a","organizationVersion":7,"memberVersion":1}`, `{"organizationID":"organization-a","organizationVersion":7,"tenantID":"other"}`,
		`{"organizationID":"organization-a","organizationVersion":7,"commandID":"caller"}`, `{"organizationID":"organization-a","organizationVersion":7,"token":"proof"}`,
		`{"organizationID":"organization-a","organizationVersion":7,"organizationVersion":8}`,
	} {
		f := newFixture(t)
		p := newMemberLeavePort(t)
		w := serve(t, memberLeaveHandler(t, f, p), request(f, "/v1/organization/member/leave", body, false))
		if w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 {
			t.Fatal("invalid self-leave selector reached authority", w.Code)
		}
	}
	for name, change := range map[string]func(*http.Request){
		"key":   func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		"query": func(r *http.Request) { r.URL.RawQuery = "userID=other" },
		"cookie": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: "ambient"})
		},
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"method":           func(r *http.Request) { r.Method = http.MethodGet },
		"host":             func(r *http.Request) { r.Host = "foreign.example" },
		"plaintext":        func(r *http.Request) { r.TLS = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := newMemberLeavePort(t)
			h := memberLeaveHandler(t, f, p)
			r := request(f, "/v1/organization/member/leave", memberLeaveInput, false)
			change(r)
			if w := serve(t, h, r); w.Code < 400 || p.sent != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate channel reached native self-leave", w.Code)
			}
		})
	}
}

func TestMemberLeavePreservesUnknownAndRejectsForeignReceipts(t *testing.T) {
	for _, mode := range []string{"unknown", "last-owner", "forbidden", "outage", "foreign-actor", "foreign-member", "foreign-org", "wrong-version", "expired", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			p := newMemberLeavePort(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := 503
			switch mode {
			case "unknown":
				p.result.Receipt.Outcome = identity.CommitOutcomeUnknown
				p.result.Receipt.AuditEventID = ""
				p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = 0, 0
				if err := p.result.Receipt.Validate(); err != nil {
					t.Fatal("unknown fixture is not a real native receipt", err)
				}
				p.err = organization.ErrUnavailable
			case "last-owner":
				p.result = organization.StoreResult{}
				p.err, want = organization.ErrLastOwner, 409
			case "forbidden":
				p.result = organization.StoreResult{}
				p.err, want = organization.ErrForbidden, 403
			case "outage":
				p.result = organization.StoreResult{}
				p.err = organization.ErrUnavailable
			case "foreign-actor":
				p.result.Receipt.Binding.ActorID = "other"
			case "foreign-member":
				p.result.MemberID, p.result.Receipt.Binding.UserID = "other", "other"
			case "foreign-org":
				p.result.OrganizationID, p.result.Receipt.Binding.RecordID = "other", "other"
			case "wrong-version":
				p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = 8, 9
			case "expired":
				p.before = func() { f.now = f.now.Add(20 * time.Second) }
			case "canceled":
				p.before = cancel
			}
			w := serve(t, memberLeaveHandler(t, f, p), request(f, "/v1/organization/member/leave", memberLeaveInput, false).WithContext(ctx))
			var out organizationhttp.MutationResponse
			if w.Code != want || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Error == "" {
				t.Fatal("self-leave failure became success", w.Code)
			}
			if mode == "unknown" && (out.Committed || out.CommitOutcome != "unknown" || out.Recovery == nil || out.CommandID != p.result.Receipt.Binding.CommandID || out.Recovery.OperationID != string(organization.LeaveMember) || out.Recovery.ActorID != p.result.Receipt.Binding.ActorID || out.Recovery.UserID != "user-a" || out.Recovery.RecordID != "organization-a" || out.BeforeVersion != 0 || out.AfterVersion != 0 || p.sent != 1) {
				t.Fatal("unknown self-leave was replayed or lost original correlation")
			}
			if (strings.HasPrefix(mode, "foreign-") || mode == "wrong-version") && (out.Committed || out.CommandID != "" || out.Recovery != nil || out.OrganizationID != "" || out.MemberID != "") {
				t.Fatal("foreign self-leave receipt disclosed original metadata")
			}
			if (mode == "expired" || mode == "canceled") && (!out.Committed || out.CommitOutcome != "committed" || out.CommandID != p.result.Receipt.Binding.CommandID || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil || out.Recovery.CommandID != out.CommandID) {
				t.Fatal("late transport failure erased actual original commitment")
			}
		})
	}
}

func TestMemberLeaveRequiresSelectedOwnersAndIsNotImplicitlyExposed(t *testing.T) {
	for _, missing := range []string{"native", "typed-native", "session", "safe"} {
		f := newFixture(t)
		f.c.MemberLeaver = newMemberLeavePort(t)
		switch missing {
		case "native":
			f.c.MemberLeaver = nil
		case "typed-native":
			f.c.MemberLeaver = (*memberLeavePort)(nil)
		case "session":
			f.c.Sessions = nil
		case "safe":
			f.c.SafeRate = nil
		}
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, MemberLeave: true}); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("self-leave accepted missing owner", missing, err)
		}
	}
	f := newFixture(t)
	p := newMemberLeavePort(t)
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Self leave", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{memberLeaveFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	r := request(f, "/v1/organization/member/leave", memberLeaveInput, false)
	w := serve(t, h, r)
	assertWireResponse(t, doc.JSON(), r, w)
	if w.Code != 200 || p.sent != 1 {
		t.Fatal("documented leave did not execute", w.Code)
	}
	if strings.Contains(string(doc.JSON()), "before the current authorized primary read") {
		t.Fatal("self-leave wire described a read instead of protected mutation")
	}
	base := newFixture(t)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: base.c, Get: true})
	if err != nil {
		t.Fatal(err)
	}
	disabled, off, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "No self leave", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil || strings.Contains(string(off.JSON()), `"/v1/organization/member/leave"`) {
		t.Fatal("disabled leave exposed metadata", err)
	}
	if w := serve(t, disabled, request(base, "/v1/organization/member/leave", memberLeaveInput, false)); w.Code != 404 {
		t.Fatal("disabled leave exposed route", w.Code)
	}
}

func TestMemberLeaveCannotChargeAdministrativeAdmission(t *testing.T) {
	f := newFixture(t)
	resolver, err := identityhttp.NewNetworkResolver(f.c.Network)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := resolver.Resolve(request(f, "/v1/organization/member/leave", memberLeaveInput, false))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := f.c.AdminRate.Admit(t.Context(), facts, organization.LeaveMember, "user-a"); !errors.Is(err, identityhttp.ErrInvalidInput) || out.Allowed || f.rate.calls != 0 {
		t.Fatal("canonical safe self-leave debited administrator budgets", err)
	}
}

func TestMemberLeaveRequiresCurrentSessionAndSharedAdmission(t *testing.T) {
	f, p := newFixture(t), newMemberLeavePort(t)
	f.inactive = true
	if w := serve(t, memberLeaveHandler(t, f, p), request(f, "/v1/organization/member/leave", memberLeaveInput, false)); w.Code != 403 || p.sent != 0 || f.rate.calls != 0 {
		t.Fatal("inactive human dispatched self-leave", w.Code)
	}
	f, p = newFixture(t), newMemberLeavePort(t)
	h := memberLeaveHandler(t, f, p)
	for i := 0; i <= 100; i++ {
		w := serve(t, h, request(f, "/v1/organization/member/leave", memberLeaveInput, false))
		want := 200
		if i == 100 {
			want = 429
		}
		if w.Code != want || p.sent != min(i+1, 100) || f.rate.calls != 0 {
			t.Fatal("self-leave bypassed shared safe budget or used administrator admission", i, w.Code)
		}
	}
	f, p = newFixture(t), newMemberLeavePort(t)
	h = memberLeaveHandler(t, f, p)
	if err := f.c.SafeRate.Close(); err != nil {
		t.Fatal(err)
	}
	if w := serve(t, h, request(f, "/v1/organization/member/leave", memberLeaveInput, false)); w.Code != 503 || p.sent != 0 {
		t.Fatal("closed safe admission dispatched self-leave", w.Code)
	}
}

func FuzzMemberLeaveClosedSelector(f *testing.F) {
	for _, seed := range []string{memberLeaveInput, `{}`, `null`, `{"organizationID":"organization-a","organizationVersion":7,"userID":"other"}`, `{"organizationID":"organization-a","organizationVersion":7e0}`, `{"organizationID":"organization-a","organizationVersion":7,"organizationVersion":8}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			return
		}
		x := newFixture(t)
		p := newMemberLeavePort(t)
		w := serve(t, memberLeaveHandler(t, x, p), request(x, "/v1/organization/member/leave", body, false))
		if p.sent != 0 {
			var fields map[string]json.RawMessage
			var org string
			var version uint64
			if json.Unmarshal([]byte(body), &fields) != nil || len(fields) != 2 || json.Unmarshal(fields["organizationID"], &org) != nil || json.Unmarshal(fields["organizationVersion"], &version) != nil || org != string(p.last.OrganizationID) || version != p.last.OrganizationVersion || version == 0 || version == ^uint64(0) || p.last.Authentication.TenantID != "tenant-a" || p.last.Authentication.Bearer.Token() != x.wire || p.sent != 1 {
				t.Fatal("hostile self-leave input changed native selection")
			}
		}
		if w.Code == 200 && p.sent != 1 {
			t.Fatal("successful self-leave bypassed native owner")
		}
	})
}
