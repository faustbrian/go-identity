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
	"github.com/faustbrian/go-identity/delivery"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// This controlled port proves transport custody and original-state projection,
// not domain authority. The actual PostgreSQL/reference consumer proves those.
type invitationResendPort struct {
	*invitationSendPort
	last   organization.InvitationResendOperationRequest
	before func()
}

func newInvitationResendPort(t testing.TB) *invitationResendPort {
	p := &invitationResendPort{invitationSendPort: newInvitationSendPort(t)}
	p.result.Receipt.Binding.OperationID = string(organization.InvitationResend)
	p.result.Receipt.Binding.SchemaID = organization.InvitationResend.Descriptor().SchemaID
	p.result.Receipt.Feature.Operation = organization.InvitationResend.Descriptor()
	p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = 2, 3
	return p
}

func (p *invitationResendPort) Resend(ctx context.Context, r organization.InvitationResendOperationRequest, network string) (organization.InvitationResendOperationResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("unbounded native resend")
	}
	p.last, p.net, p.sent = r, network, p.sent+1
	if p.before != nil {
		p.before()
	}
	return organization.InvitationResendOperationResult{StoreResult: p.result, DeliveryState: p.state}, p.err
}

func invitationResendHandler(t testing.TB, f *fixture, p *invitationResendPort) http.Handler {
	t.Helper()
	f.c.Service, f.c.Invitations, f.c.SafeRate, f.c.InvitationSender = nil, nil, nil, nil
	f.c.InvitationResender = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationResend: true})
	if err != nil {
		t.Fatal("independent native resend selection", err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const resendInput = `{"organizationID":"organization-a","organizationVersion":7,"invitationID":"invitation-a","invitationVersion":2}`

func TestInvitationResendPreservesOriginalKeyAndOriginalDeliveryObservation(t *testing.T) {
	f := newFixture(t)
	p := newInvitationResendPort(t)
	p.state = delivery.StateAccepted
	h := invitationResendHandler(t, f, p)
	for range 2 {
		w := serve(t, h, request(f, "/v1/organization/invitation/resend", resendInput, true))
		var out organizationhttp.InvitationResendResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.InvitationID != "invitation-a" || out.BeforeVersion != 2 || out.AfterVersion != 3 || out.DeliveryState != "accepted" || out.MemberID != "" || out.Recovery == nil || out.Recovery.CommandID != p.result.Receipt.Binding.CommandID {
			t.Fatal("original resend receipt or original delivery lost", w.Code)
		}
		if p.last.Validate() != nil || p.last.Authentication.TenantID != "tenant-a" || p.last.Authentication.Bearer.Token() != f.wire || p.last.OrganizationID != "organization-a" || p.last.InvitationID != "invitation-a" || p.last.OrganizationVersion != 7 || p.last.InvitationVersion != 2 || p.net != "198.51.100.7" {
			t.Fatal("transport replaced exact original resend intent")
		}
		key, _ := identity.NewIdempotencyKey([]byte("original-key"))
		want, _ := key.Digest([32]byte{1})
		got, err := p.last.IdempotencyKey.Digest([32]byte{1})
		if err != nil || got != want {
			t.Fatal("transport changed original request-key bytes")
		}
		for _, private := range []string{f.wire, "original-key", "private-effect", "identifier-a", "capability", "ciphertext", `"invitation":`} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("resend exported private custody or latest invitation projection")
			}
		}
	}
	if p.sent != 2 || p.calls != 0 || f.rate.calls != 2 {
		t.Fatal("retry bypassed admission or read latest invitation metadata")
	}
	if w := serve(t, h, request(f, "/v1/organization/invitation-send", sendInput, true)); w.Code != 404 || p.sent != 2 {
		t.Fatal("resend selection enabled invitation send")
	}
}

func TestInvitationResendRejectsAlternateAndMalformedChannelsBeforeAuthority(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-key":      func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate-key":    func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") },
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fallbackToken})
		},
		"query":       func(r *http.Request) { r.URL.RawQuery = "invitationID=other" },
		"force-query": func(r *http.Request) { r.URL.ForceQuery = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := newInvitationResendPort(t)
			h := invitationResendHandler(t, f, p)
			r := request(f, "/v1/organization/invitation/resend", resendInput, true)
			change(r)
			if w := serve(t, h, r); w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate channels reached current authority", w.Code)
			}
		})
	}
	for _, body := range []string{
		`{}`, strings.Replace(resendInput, `"invitationVersion":2`, `"invitationVersion":0`, 1),
		strings.Replace(resendInput, `"invitationVersion":2`, `"invitationVersion":18446744073709551614`, 1),
		strings.Replace(resendInput, `"organizationVersion":7`, `"organizationVersion":0`, 1),
		strings.Replace(resendInput, `"invitationVersion":2`, `"invitationVersion":2.0`, 1),
		strings.Replace(resendInput, `"invitationID":"invitation-a"`, `"invitationID":null`, 1),
		strings.Replace(resendInput, `"organizationID"`, `"OrganizationID"`, 1),
		strings.TrimSuffix(resendInput, `}`) + `,"commandID":"forged"}`,
		strings.TrimSuffix(resendInput, `}`) + `,"recipientUserID":"forged"}`,
		strings.TrimSuffix(resendInput, `}`) + `,"role":"owner"}`,
		strings.TrimSuffix(resendInput, `}`) + `,"expiresAt":"2099-01-01T00:00:00Z"}`,
		strings.TrimSuffix(resendInput, `}`) + `,"token":"forged"}`,
		strings.TrimSuffix(resendInput, `}`) + `,"invitationID":"duplicate"}`,
	} {
		f := newFixture(t)
		p := newInvitationResendPort(t)
		if w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", body, true)); w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 {
			t.Fatal("malformed original resend reached authority", w.Code)
		}
	}
}

func TestInvitationResendRetainsCommitAndWithholdsFailedObservation(t *testing.T) {
	for _, state := range []delivery.DeliveryState{0, delivery.StateQueued} {
		f := newFixture(t)
		p := newInvitationResendPort(t)
		p.state = state
		p.err = organization.ErrForbidden
		w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", resendInput, true))
		var out organizationhttp.InvitationResendResponse
		if w.Code != 403 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.DeliveryState != "" || out.Error != "forbidden" {
			t.Fatal("late observation failure erased known commitment or disclosed state", w.Code)
		}
	}
	for _, state := range []delivery.DeliveryState{0, 255} {
		f := newFixture(t)
		p := newInvitationResendPort(t)
		p.state = state
		w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", resendInput, true))
		var out organizationhttp.InvitationResendResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.DeliveryState != "" {
			t.Fatal("missing or invalid delivery observation synthesized queued", w.Code)
		}
	}
	f := newFixture(t)
	p := newInvitationResendPort(t)
	p.result.Receipt.Outcome, p.result.Receipt.AuditEventID = identity.CommitOutcomeUnknown, ""
	p.err = errors.New("private native diagnostic")
	w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", resendInput, true))
	var out organizationhttp.InvitationResendResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.CommitOutcome != "unknown" || out.DeliveryState != "" || strings.Contains(w.Body.String(), "private native") {
		t.Fatal("unknown native outcome promoted to success or disclosed diagnostics", w.Code)
	}
}

func TestInvitationResendRejectsForeignReceiptAndMissingOwner(t *testing.T) {
	for _, change := range []func(*invitationResendPort){
		func(p *invitationResendPort) { p.result.OrganizationID = "foreign" },
		func(p *invitationResendPort) { p.result.InvitationID = "foreign" },
		func(p *invitationResendPort) { p.result.Receipt.Binding.ActorID = "foreign" },
		func(p *invitationResendPort) { p.result.Receipt.Binding.TenantID = "foreign" },
		func(p *invitationResendPort) { p.result.Receipt.Binding.RecordID = "foreign" },
		func(p *invitationResendPort) {
			p.result.Receipt.Feature.BeforeVersion = 7
			p.result.Receipt.Feature.AfterVersion = 8
		},
	} {
		f := newFixture(t)
		p := newInvitationResendPort(t)
		change(p)
		w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", resendInput, true))
		var out organizationhttp.InvitationResendResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.DeliveryState != "" {
			t.Fatal("foreign original or wrong version receipt accepted", w.Code)
		}
	}
	for _, owner := range []organizationhttp.InvitationResender{nil, (*invitationResendPort)(nil)} {
		f := newFixture(t)
		f.c.InvitationResender = owner
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationResend: true}); err == nil {
			t.Fatal("selected resend accepted missing owner")
		}
	}
	for _, mode := range []int{1, 2} {
		f := newFixture(t)
		p := newInvitationResendPort(t)
		f.rate.mode = mode
		w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", resendInput, true))
		if mode == 1 && w.Code != 429 || mode == 2 && w.Code != 503 || p.sent != 0 {
			t.Fatal("shared admission denial dispatched resend", w.Code)
		}
	}
}

func TestInvitationResendEnforcesCurrentSessionAndRetainsLateCommit(t *testing.T) {
	f := newFixture(t)
	p := newInvitationResendPort(t)
	f.inactive = true
	w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", resendInput, true))
	if w.Code != 403 || p.sent != 0 || f.rate.calls != 0 {
		t.Fatal("inactive session debited or dispatched resend", w.Code)
	}
	f = newFixture(t)
	p = newInvitationResendPort(t)
	p.before = func() { f.now = f.now.Add(time.Hour) }
	w = serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", resendInput, true))
	var out organizationhttp.InvitationResendResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.DeliveryState != "" {
		t.Fatal("late expiry erased known commit or exposed delivery", w.Code)
	}
}

func TestInvitationResendWireMatchesActualResponseAndDisabledSurface(t *testing.T) {
	f := newFixture(t)
	p := newInvitationResendPort(t)
	f.c.Service, f.c.Invitations, f.c.SafeRate = nil, nil, nil
	f.c.InvitationResender = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationResend: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Resend", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	r := request(f, "/v1/organization/invitation/resend", resendInput, true)
	w := serve(t, h, r)
	assertWireResponse(t, doc.JSON(), r, w)
	if w.Code != 200 || p.sent != 1 {
		t.Fatal("actual documented resend did not run", w.Code)
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
				Parameters []struct {
					Name     string
					Required bool
				}
			}
		}
	}
	if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 1 {
		t.Fatal("independent resend selected unrelated routes")
	}
	op := document.Paths["/v1/organization/invitation/resend"].Post
	schema := op.RequestBody.Content["application/json"].Schema
	if schema.AdditionalProperties || len(schema.Properties) != 4 || len(schema.Required) != 4 || !strings.Contains(string(schema.Properties["invitationVersion"]), `18446744073709551613`) || !strings.Contains(string(schema.Properties["organizationVersion"]), `18446744073709551615`) {
		t.Fatal("wire lost exact closed resend input/version bounds")
	}
	if len(op.Parameters) != 1 || op.Parameters[0].Name != "Idempotency-Key" || !op.Parameters[0].Required {
		t.Fatal("resend wire does not require the original header key")
	}
	if p.calls != 0 {
		t.Fatal("document construction queried latest invitation")
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Disabled", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if w := serve(t, off, request(f, "/v1/organization/invitation/resend", resendInput, true)); w.Code != 404 || strings.Contains(string(offDoc.JSON()), "identity.organization.invitation.resend") || p.sent != 1 {
		t.Fatal("disabled resend exposed route, metadata or effect")
	}
}

func TestInvitationResendAcceptsExactReadOnlyAndSuccessorVersionBounds(t *testing.T) {
	f := newFixture(t)
	p := newInvitationResendPort(t)
	p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = ^uint64(0)-2, ^uint64(0)-1
	body := `{"organizationID":"organization-a","organizationVersion":18446744073709551615,"invitationID":"invitation-a","invitationVersion":18446744073709551613}`
	w := serve(t, invitationResendHandler(t, f, p), request(f, "/v1/organization/invitation/resend", body, true))
	var out organizationhttp.InvitationResendResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.AfterVersion != ^uint64(0)-1 || p.last.OrganizationVersion != ^uint64(0) || p.last.InvitationVersion != ^uint64(0)-2 {
		t.Fatal("transport lost unsigned version bounds or validated organization as invitation epoch", w.Code)
	}
}

func FuzzInvitationResendClosedRequest(f *testing.F) {
	for _, seed := range []string{resendInput, "{}", "null", `{"invitationID":"x","invitationID":"y"}`, strings.Repeat("x", 4096)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		x := newFixture(t)
		p := newInvitationResendPort(t)
		w := serve(t, invitationResendHandler(t, x, p), request(x, "/v1/organization/invitation/resend", body, true))
		if p.sent > 0 && p.last.Validate() != nil {
			t.Fatal("invalid custody crossed native resend boundary")
		}
		if w.Code >= 200 && w.Code < 300 && p.sent != 1 {
			t.Fatal("resend success bypassed native owner")
		}
		if strings.Contains(w.Body.String(), x.wire) {
			t.Fatal("resend disclosed bearer custody")
		}
	})
}
