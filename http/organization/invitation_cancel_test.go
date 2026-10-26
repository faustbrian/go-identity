package organizationhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

type invitationCancelPort struct {
	*invitationSendPort
	last   organization.InvitationCancelOperationRequest
	before func()
}

func newInvitationCancelPort(t testing.TB) *invitationCancelPort {
	p := &invitationCancelPort{invitationSendPort: newInvitationSendPort(t)}
	p.result.MemberID = "user-a"
	p.result.Receipt.Binding.UserID = "user-a"
	p.result.Receipt.Binding.OperationID = string(organization.InvitationCancel)
	p.result.Receipt.Binding.SchemaID = organization.InvitationCancel.Descriptor().SchemaID
	p.result.Receipt.Feature.Operation = organization.InvitationCancel.Descriptor()
	p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = 2, 3
	return p
}

func (p *invitationCancelPort) Cancel(ctx context.Context, r organization.InvitationCancelOperationRequest, network string) (organization.StoreResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("unbounded native cancellation")
	}
	p.last, p.net, p.sent = r, network, p.sent+1
	if p.before != nil {
		p.before()
	}
	return p.result, p.err
}

func invitationCancelFeature(t testing.TB, f *fixture, p *invitationCancelPort) identityhttp.Feature {
	t.Helper()
	f.c.Service, f.c.Invitations, f.c.SafeRate = nil, nil, nil
	f.c.InvitationCanceller = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationCancel: true})
	if err != nil {
		t.Fatal("independent cancellation selection", err)
	}
	return feature
}

func invitationCancelHandler(t testing.TB, f *fixture, p *invitationCancelPort) http.Handler {
	t.Helper()
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{invitationCancelFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const cancelInput = `{"organizationID":"organization-a","organizationVersion":7,"invitationID":"invitation-a","invitationVersion":2}`

func TestInvitationCancelPreservesNaturalSelectorAndOriginalOutcome(t *testing.T) {
	f := newFixture(t)
	p := newInvitationCancelPort(t)
	h := invitationCancelHandler(t, f, p)
	for range 2 {
		w := serve(t, h, request(f, "/v1/organization/invitation/cancel", cancelInput, false))
		var out organizationhttp.InvitationCancelResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.State != "cancelled" || out.InvitationID != "invitation-a" || out.BeforeVersion != 2 || out.AfterVersion != 3 || out.MemberID != "" || out.Recovery == nil || out.Recovery.CommandID != p.result.Receipt.Binding.CommandID {
			t.Fatal("natural cancellation lost original terminal outcome", w.Code)
		}
		if p.last.Validate() != nil || p.last.Authentication.Bearer.Token() != f.wire || p.last.Authentication.TenantID != "tenant-a" || p.last.OrganizationID != "organization-a" || p.last.InvitationID != "invitation-a" || p.last.OrganizationVersion != 7 || p.last.InvitationVersion != 2 || p.net != "198.51.100.7" {
			t.Fatal("transport changed natural cancellation selector")
		}
		for _, private := range []string{f.wire, "private-effect", "recipient-a", "identifier-a", `"memberID":`, `"deliveryState":`, `"invitation":`} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("cancellation exported private or invented projection")
			}
		}
	}
	if p.sent != 2 || p.calls != 0 || f.rate.calls != 2 {
		t.Fatal("repeat bypassed admission or queried recipient delivery")
	}
	if w := serve(t, h, request(f, "/v1/organization/invitation/resend", resendInput, true)); w.Code != 404 || p.sent != 2 {
		t.Fatal("cancellation selected sibling mutation")
	}
}

func TestInvitationCancelRejectsKeysOverridesAndMalformedInputBeforeAuthority(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"key":              func(r *http.Request) { r.Header.Set("Idempotency-Key", "not-keyed") },
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fallbackToken})
		},
		"query":       func(r *http.Request) { r.URL.RawQuery = "invitationID=other" },
		"force-query": func(r *http.Request) { r.URL.ForceQuery = true },
	} {
		t.Run(name, func(t *testing.T) {
			f, p := newFixture(t), newInvitationCancelPort(t)
			r := request(f, "/v1/organization/invitation/cancel", cancelInput, false)
			change(r)
			if w := serve(t, invitationCancelHandler(t, f, p), r); w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate channel reached authority", w.Code)
			}
		})
	}
	for _, body := range []string{`{}`, `null`,
		strings.Replace(cancelInput, `"organizationVersion":7`, `"organizationVersion":0`, 1),
		strings.Replace(cancelInput, `"organizationVersion":7`, `"organizationVersion":18446744073709551615`, 1),
		strings.Replace(cancelInput, `"invitationVersion":2`, `"invitationVersion":0`, 1),
		strings.Replace(cancelInput, `"invitationVersion":2`, `"invitationVersion":18446744073709551615`, 1),
		strings.Replace(cancelInput, `"invitationVersion":2`, `"invitationVersion":2.0`, 1),
		strings.Replace(cancelInput, `"invitationID":"invitation-a"`, `"invitationID":null`, 1),
		strings.TrimSuffix(cancelInput, `}`) + `,"commandID":"forged"}`,
		strings.TrimSuffix(cancelInput, `}`) + `,"recipientUserID":"forged"}`,
		strings.TrimSuffix(cancelInput, `}`) + `,"token":"forged"}`,
		strings.TrimSuffix(cancelInput, `}`) + `,"invitationID":"duplicate"}`,
	} {
		f, p := newFixture(t), newInvitationCancelPort(t)
		if w := serve(t, invitationCancelHandler(t, f, p), request(f, "/v1/organization/invitation/cancel", body, false)); w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 {
			t.Fatal("malformed cancellation reached authority", w.Code)
		}
	}
}

func TestInvitationCancelRequiresOwnerCurrentSessionAndSharedAdmission(t *testing.T) {
	for _, owner := range []organizationhttp.InvitationCanceller{nil, (*invitationCancelPort)(nil)} {
		f := newFixture(t)
		f.c.InvitationCanceller = owner
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationCancel: true}); err == nil {
			t.Fatal("selected cancellation accepted missing native owner")
		}
	}
	f, p := newFixture(t), newInvitationCancelPort(t)
	f.inactive = true
	if w := serve(t, invitationCancelHandler(t, f, p), request(f, "/v1/organization/invitation/cancel", cancelInput, false)); w.Code != 403 || p.sent != 0 || f.rate.calls != 0 {
		t.Fatal("inactive session debited or dispatched cancellation", w.Code)
	}
	for _, mode := range []int{1, 2} {
		f, p := newFixture(t), newInvitationCancelPort(t)
		f.rate.mode = mode
		w := serve(t, invitationCancelHandler(t, f, p), request(f, "/v1/organization/invitation/cancel", cancelInput, false))
		if mode == 1 && w.Code != 429 || mode == 2 && w.Code != 503 || p.sent != 0 {
			t.Fatal("denied admission dispatched cancellation", w.Code)
		}
	}
}

func TestInvitationCancelValidatesOriginalReceiptAndLateCommit(t *testing.T) {
	for _, change := range []func(*invitationCancelPort){
		func(p *invitationCancelPort) { p.result.OrganizationID = "foreign" },
		func(p *invitationCancelPort) { p.result.InvitationID = "foreign" },
		func(p *invitationCancelPort) { p.result.Receipt.Binding.ActorID = "foreign" },
		func(p *invitationCancelPort) {
			p.result.Receipt.Binding.UserID = "recipient-a"
			p.result.MemberID = "recipient-a"
		},
		func(p *invitationCancelPort) { p.result.Receipt.Binding.RecordID = "foreign" },
		func(p *invitationCancelPort) {
			p.result.Receipt.Feature.BeforeVersion = 7
			p.result.Receipt.Feature.AfterVersion = 8
		},
	} {
		f, p := newFixture(t), newInvitationCancelPort(t)
		change(p)
		w := serve(t, invitationCancelHandler(t, f, p), request(f, "/v1/organization/invitation/cancel", cancelInput, false))
		var out organizationhttp.InvitationCancelResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.State != "" {
			t.Fatal("foreign receipt became successful cancellation", w.Code)
		}
	}
	f, p := newFixture(t), newInvitationCancelPort(t)
	p.result.Receipt.Outcome, p.result.Receipt.AuditEventID = identity.CommitOutcomeUnknown, ""
	w := serve(t, invitationCancelHandler(t, f, p), request(f, "/v1/organization/invitation/cancel", cancelInput, false))
	var out organizationhttp.InvitationCancelResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.State != "" || out.CommitOutcome != "unknown" {
		t.Fatal("unknown cancellation promoted to success")
	}
	f, p = newFixture(t), newInvitationCancelPort(t)
	p.before = func() { f.now = f.now.Add(6 * time.Minute) }
	w = serve(t, invitationCancelHandler(t, f, p), request(f, "/v1/organization/invitation/cancel", cancelInput, false))
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.State != "" {
		t.Fatal("late session expiry erased commit or exposed successful state")
	}
}

func TestInvitationCancelWireAndDisabledSurface(t *testing.T) {
	f, p := newFixture(t), newInvitationCancelPort(t)
	feature := invitationCancelFeature(t, f, p)
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Cancel", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r := request(f, "/v1/organization/invitation/cancel", cancelInput, false)
	w := serve(t, h, r)
	assertWireResponse(t, doc.JSON(), r, w)
	if w.Code != 200 || p.sent != 1 || p.calls != 0 {
		t.Fatal("documented cancellation did not reach only native owner", w.Code)
	}
	var document struct {
		Paths map[string]struct {
			Post struct {
				RequestBody struct {
					Content map[string]struct {
						Schema struct {
							AdditionalProperties bool
							Properties           map[string]json.RawMessage
							Required             []string
						}
					}
				}
				Parameters []struct{ Name string }
			}
		}
	}
	if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 1 {
		t.Fatal("cancellation selected sibling metadata")
	}
	op := document.Paths["/v1/organization/invitation/cancel"].Post
	schema := op.RequestBody.Content["application/json"].Schema
	if len(op.Parameters) != 0 || schema.AdditionalProperties || len(schema.Required) != 4 || len(schema.Properties) != 4 || !strings.Contains(string(schema.Properties["invitationVersion"]), `18446744073709551614`) || !strings.Contains(string(schema.Properties["organizationVersion"]), `18446744073709551614`) {
		t.Fatal("natural-repeat wire accepted keys or lost exact closed version bounds")
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Disabled", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if w := serve(t, off, request(f, "/v1/organization/invitation/cancel", cancelInput, false)); w.Code != 404 || strings.Contains(string(offDoc.JSON()), "identity.organization.invitation.cancel") || p.sent != 1 {
		t.Fatal("disabled cancellation exposed route, metadata or effects")
	}
}

func TestInvitationCancelPreservesUnsignedTerminalVersionBounds(t *testing.T) {
	f, p := newFixture(t), newInvitationCancelPort(t)
	p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = ^uint64(0)-1, ^uint64(0)
	body := `{"organizationID":"organization-a","organizationVersion":18446744073709551614,"invitationID":"invitation-a","invitationVersion":18446744073709551614}`
	w := serve(t, invitationCancelHandler(t, f, p), request(f, "/v1/organization/invitation/cancel", body, false))
	var out organizationhttp.InvitationCancelResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.AfterVersion != ^uint64(0) || p.last.OrganizationVersion != ^uint64(0)-1 || p.last.InvitationVersion != ^uint64(0)-1 {
		t.Fatal("cancellation narrowed unsigned terminal version bounds", w.Code)
	}
}

func FuzzInvitationCancelClosedRequest(f *testing.F) {
	for _, seed := range []string{cancelInput, `{}`, `null`, `{"invitationID":"x","invitationID":"y"}`, strings.Repeat("x", 4096)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		x, p := newFixture(t), newInvitationCancelPort(t)
		w := serve(t, invitationCancelHandler(t, x, p), request(x, "/v1/organization/invitation/cancel", body, false))
		if p.sent > 0 && p.last.Validate() != nil {
			t.Fatal("invalid cancellation selector crossed native boundary")
		}
		if w.Code >= 200 && w.Code < 300 && p.sent != 1 {
			t.Fatal("successful cancellation bypassed native owner")
		}
		if strings.Contains(w.Body.String(), x.wire) {
			t.Fatal("cancellation disclosed borrowed bearer custody")
		}
	})
}
