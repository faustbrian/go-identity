package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// This port proves transport custody/projection only. The tagged genuine
// consumer independently exercises the actual native transaction and delivery.
type invitationSendPort struct {
	invitationReader
	t        testing.TB
	last     organization.InvitationSendOperationRequest
	result   organization.StoreResult
	sent     int
	net      string
	err      error
	state    delivery.DeliveryState
	getErr   error
	getPanic bool
}

func newInvitationSendPort(t testing.TB) *invitationSendPort {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "recipient-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: string(organization.InvitationSend), RecordID: "invitation-a", PolicyID: "organization", PolicyVersion: 1, SchemaID: organization.InvitationSend.Descriptor().SchemaID, SchemaVersion: 1, CorrelationID: "original"}
	p := &invitationSendPort{t: t, state: delivery.StateQueued, result: organization.StoreResult{OrganizationID: "organization-a", MemberID: "recipient-a", InvitationID: "invitation-a", Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: organization.InvitationSend.Descriptor(), BeforeVersion: 0, AfterVersion: 1}}}}
	p.change = func(i *organization.Invitation) { i.CreatedBy, i.RecipientUserID = "user-a", "recipient-a" }
	return p
}

func (p *invitationSendPort) Send(ctx context.Context, r organization.InvitationSendOperationRequest, network string) (organization.StoreResult, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		p.t.Fatal("unbounded native invitation send")
	}
	p.last, p.net, p.sent = r, network, p.sent+1
	return p.result, p.err
}

func (p *invitationSendPort) Get(ctx context.Context, r organization.InvitationReadRequest) (organization.InvitationDelivery, error) {
	if p.getPanic {
		panic("private current-projection diagnostic")
	}
	out, err := p.invitationReader.Get(ctx, r)
	out.EffectID, out.State = "private-effect", p.state
	if p.getErr != nil {
		err = p.getErr
	}
	return out, err
}

func TestInvitationSendProjectionPanicRetainsKnownCommitWithoutMetadata(t *testing.T) {
	f := newFixture(t)
	p := newInvitationSendPort(t)
	p.getPanic = true
	h := invitationSendHandler(t, f, p)
	w := serve(t, h, request(f, "/v1/organization/invitation-send", sendInput, true))
	var out organizationhttp.InvitationSendResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.Invitation != nil || out.DeliveryState != "" || out.Error != "unavailable" || strings.Contains(w.Body.String(), "private current-projection") {
		t.Fatal("current-read panic erased known send outcome or leaked diagnostics", w.Code)
	}
}

func invitationSendHandler(t testing.TB, f *fixture, p *invitationSendPort) http.Handler {
	t.Helper()
	f.c.Service, f.c.SafeRate = nil, nil
	f.c.InvitationSender, f.c.Invitations = p, p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationSend: true})
	if err != nil {
		t.Fatal("independent invitation-send selection rejected", err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const sendInput = `{"organizationID":"organization-a","organizationVersion":3,"recipientUserID":"recipient-a","recipientIdentifierID":"identifier-a"}`

func TestInvitationSendPreservesOriginalKeyAndProjectsCurrentSafeState(t *testing.T) {
	f := newFixture(t)
	p := newInvitationSendPort(t)
	h := invitationSendHandler(t, f, p)
	for attempt := 0; attempt < 2; attempt++ {
		w := serve(t, h, request(f, "/v1/organization/invitation-send", sendInput, true))
		var out organizationhttp.InvitationSendResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.InvitationID != "invitation-a" || out.Invitation == nil || out.Invitation.ID != out.InvitationID || out.DeliveryState != "queued" || out.Recovery == nil || out.Recovery.CommandID != p.result.Receipt.Binding.CommandID {
			t.Fatal("original invitation outcome/current metadata lost", w.Code)
		}
		if p.last.Validate() != nil || p.last.Authentication.TenantID != "tenant-a" || p.last.Authentication.Bearer.Token() != f.wire || p.last.OrganizationVersion != 3 || p.last.OrganizationID != "organization-a" || p.last.RecipientUserID != "recipient-a" || p.last.RecipientIdentifierID != "identifier-a" || p.net != "198.51.100.7" {
			t.Fatal("exact native invitation intent/custody changed")
		}
		key, err := identity.NewIdempotencyKey([]byte("original-key"))
		wantDigest, wantErr := key.Digest([32]byte{1})
		gotDigest, gotErr := p.last.IdempotencyKey.Digest([32]byte{1})
		if err != nil || wantErr != nil || gotErr != nil || gotDigest != wantDigest || p.get.Authentication.Bearer.Token() != f.wire || p.get.ID != "invitation-a" {
			t.Fatal("initiating key or current read custody changed")
		}
		for _, private := range []string{f.wire, "original-key", "private-effect", "identifier-a", "capability", "ciphertext"} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("invitation-send leaked private custody")
			}
		}
	}
	if p.sent != 2 || f.rate.calls != 2 || p.calls != 2 {
		t.Fatal("matching HTTP attempts bypassed shared admission or current owner")
	}
}

func TestInvitationSendRejectsAlternateOrHostileChannelsBeforeOwner(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-key":      func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate-key":    func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") },
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fallbackToken})
		},
		"query-override": func(r *http.Request) { r.URL.RawQuery = "recipientUserID=other" },
		"force-query":    func(r *http.Request) { r.URL.ForceQuery = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := newInvitationSendPort(t)
			h := invitationSendHandler(t, f, p)
			r := request(f, "/v1/organization/invitation-send", sendInput, true)
			change(r)
			if w := serve(t, h, r); w.Code != 400 || p.sent != 0 || p.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("invalid channels reached authority", w.Code)
			}
		})
	}
	for _, body := range []string{
		`{}`, strings.Replace(sendInput, `"organizationVersion":3`, `"organizationVersion":0`, 1),
		strings.Replace(sendInput, `"organizationVersion":3`, `"organizationVersion":3.0`, 1),
		strings.Replace(sendInput, `"recipientUserID":"recipient-a"`, `"recipientUserID":null`, 1),
		strings.Replace(sendInput, `"recipientIdentifierID":"identifier-a"`, `"recipientIdentifierID":"bad identifier"`, 1),
		strings.Replace(sendInput, `"organizationID"`, `"OrganizationID"`, 1),
		strings.TrimSuffix(sendInput, `}`) + `,"actorID":"forged"}`,
		strings.TrimSuffix(sendInput, `}`) + `,"email":"submitted@example.invalid"}`,
		strings.TrimSuffix(sendInput, `}`) + `,"recipientUserID":"other"}`,
	} {
		f := newFixture(t)
		p := newInvitationSendPort(t)
		h := invitationSendHandler(t, f, p)
		if w := serve(t, h, request(f, "/v1/organization/invitation-send", body, true)); w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 {
			t.Fatal("invalid send body reached owner", w.Code)
		}
	}
}

func TestInvitationSendDoesNotEraseOriginalCommitWhenCurrentProjectionFails(t *testing.T) {
	f := newFixture(t)
	p := newInvitationSendPort(t)
	p.getErr = organization.ErrForbidden
	h := invitationSendHandler(t, f, p)
	w := serve(t, h, request(f, "/v1/organization/invitation-send", sendInput, true))
	var out organizationhttp.InvitationSendResponse
	if w.Code != 403 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.Invitation != nil || out.DeliveryState != "" || out.Error != "forbidden" {
		t.Fatal("failed current projection erased commit or disclosed metadata", w.Code)
	}
	p.getErr = nil
	p.result.Receipt.Outcome, p.result.Receipt.AuditEventID = identity.CommitOutcomeUnknown, ""
	p.err = errors.New("private native diagnostic")
	w = serve(t, h, request(f, "/v1/organization/invitation-send", sendInput, true))
	out = organizationhttp.InvitationSendResponse{}
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.CommitOutcome != "unknown" || out.Invitation != nil || p.calls != 1 || strings.Contains(w.Body.String(), "private native") {
		t.Fatal("unknown invitation dispatch became success or current read", w.Code)
	}
}

func TestInvitationSendKeepsQueueAndProviderOutcomesDistinct(t *testing.T) {
	for state, expected := range map[delivery.DeliveryState]string{
		delivery.StateQueued: "queued", delivery.StateAttempting: "attempting", delivery.StateAccepted: "accepted", delivery.StateDelivered: "delivered", delivery.StateRejected: "rejected", delivery.StateBounced: "bounced", delivery.StateCancelled: "cancelled", delivery.StateOutcomeUnknown: "unknown", delivery.StateRetryWait: "retry_wait", delivery.StateExpired: "expired", delivery.StateExhausted: "exhausted", delivery.StateSuperseded: "superseded", delivery.StateTransientFailure: "transient_failure",
	} {
		f := newFixture(t)
		p := newInvitationSendPort(t)
		p.state = state
		w := serve(t, invitationSendHandler(t, f, p), request(f, "/v1/organization/invitation-send", sendInput, true))
		var out organizationhttp.InvitationSendResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.DeliveryState != expected {
			t.Fatal("queue/provider state silently collapsed", w.Code)
		}
	}
}

func TestInvitationSendRejectsForeignOriginalAndCurrentProjections(t *testing.T) {
	for name, change := range map[string]func(*invitationSendPort){
		"original-tenant":         func(p *invitationSendPort) { p.result.Receipt.Binding.TenantID = "foreign" },
		"original-actor":          func(p *invitationSendPort) { p.result.Receipt.Binding.ActorID = "foreign" },
		"original-recipient":      func(p *invitationSendPort) { p.result.Receipt.Binding.UserID = "foreign" },
		"original-record":         func(p *invitationSendPort) { p.result.InvitationID = "foreign" },
		"original-organization":   func(p *invitationSendPort) { p.result.OrganizationID = "foreign" },
		"invalid-receipt-version": func(p *invitationSendPort) { p.result.Receipt.Feature.AfterVersion = 3 },
		"current-tenant":          func(p *invitationSendPort) { p.change = func(i *organization.Invitation) { i.TenantID = "foreign" } },
		"current-recipient": func(p *invitationSendPort) {
			p.change = func(i *organization.Invitation) { i.RecipientUserID = "foreign" }
		},
		"current-identifier": func(p *invitationSendPort) {
			p.change = func(i *organization.Invitation) { i.RecipientIdentifierID = "foreign" }
		},
		"invalid-delivery": func(p *invitationSendPort) { p.state = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := newInvitationSendPort(t)
			change(p)
			w := serve(t, invitationSendHandler(t, f, p), request(f, "/v1/organization/invitation-send", sendInput, true))
			var out organizationhttp.InvitationSendResponse
			if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Invitation != nil || out.DeliveryState != "" {
				t.Fatal("invalid native projection became HTTP success", w.Code)
			}
		})
	}
}

func TestInvitationSendRequiresOnlyItsSelectedOwners(t *testing.T) {
	for _, field := range []string{"sender", "reader", "admin"} {
		f := newFixture(t)
		p := newInvitationSendPort(t)
		f.c.InvitationSender, f.c.Invitations, f.c.Service, f.c.SafeRate = p, p, nil, nil
		switch field {
		case "sender":
			f.c.InvitationSender = nil
		case "reader":
			f.c.Invitations = nil
		case "admin":
			f.c.AdminRate = nil
		}
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationSend: true}); err == nil {
			t.Fatal("selected send accepted a missing required owner")
		}
	}
	for _, mode := range []int{1, 2} {
		f := newFixture(t)
		p := newInvitationSendPort(t)
		f.rate.mode = mode
		w := serve(t, invitationSendHandler(t, f, p), request(f, "/v1/organization/invitation-send", sendInput, true))
		if (mode == 1 && w.Code != 429 || mode == 2 && w.Code != 503) || p.sent != 0 || p.calls != 0 {
			t.Fatal("rate denial/outage dispatched invitation", w.Code)
		}
	}
}

func FuzzInvitationSendClosedRequest(f *testing.F) {
	for _, seed := range []string{sendInput, "{}", "null", `{"organizationID":"x","organizationID":"y"}`, strings.Repeat("x", 4096)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 8192 {
			return
		}
		x := newFixture(t)
		p := newInvitationSendPort(t)
		r := request(x, "/v1/organization/invitation-send", body, true)
		r.Method = http.MethodPost
		w := serve(t, invitationSendHandler(t, x, p), r)
		if p.sent > 0 && p.last.Validate() != nil {
			t.Fatal("hostile input crossed native boundary without valid custody")
		}
		if w.Code >= 200 && w.Code < 300 && (p.sent != 1 || p.calls != 1) {
			t.Fatal("success bypassed actual send/current-read ports")
		}
		if strings.Contains(w.Body.String(), x.wire) {
			t.Fatal("fuzzed send exposed bearer custody")
		}
	})
}
