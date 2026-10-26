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

// Transport boundary only. Genuine native proof invalidation, atomic effects
// and original manager recovery are proven separately through public owners.
type invitationExpirePort struct {
	*invitationSendPort
	last   organization.InvitationExpireOperationRequest
	before func()
}

func newInvitationExpirePort(t testing.TB) *invitationExpirePort {
	p := &invitationExpirePort{invitationSendPort: newInvitationSendPort(t)}
	p.result.MemberID, p.result.Receipt.Binding.UserID = "user-a", "user-a"
	p.result.Receipt.Binding.OperationID = string(organization.InvitationExpire)
	p.result.Receipt.Binding.SchemaID = organization.InvitationExpire.Descriptor().SchemaID
	p.result.Receipt.Feature.Operation = organization.InvitationExpire.Descriptor()
	p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = 2, 3
	return p
}

func (p *invitationExpirePort) Expire(ctx context.Context, r organization.InvitationExpireOperationRequest, network string) (organization.StoreResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("unbounded native expiry")
	}
	p.last, p.net, p.sent = r, network, p.sent+1
	if p.before != nil {
		p.before()
	}
	return p.result, p.err
}

func invitationExpireFeature(t testing.TB, f *fixture, p *invitationExpirePort) identityhttp.Feature {
	t.Helper()
	f.c.Service, f.c.Invitations, f.c.SafeRate = nil, nil, nil
	f.c.InvitationExpirer = p
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationExpire: true})
	if err != nil {
		t.Fatal("independent expiry selection", err)
	}
	return feature
}

func invitationExpireHandler(t testing.TB, f *fixture, p *invitationExpirePort) http.Handler {
	t.Helper()
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{invitationExpireFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

const expireInput = `{"organizationID":"organization-a","organizationVersion":7,"invitationID":"invitation-a","invitationVersion":2,"reason":"security-withdrawal"}`

func TestInvitationExpirePreservesNaturalIntentAndOriginalReceipt(t *testing.T) {
	f, p := newFixture(t), newInvitationExpirePort(t)
	h := invitationExpireHandler(t, f, p)
	for range 2 {
		w := serve(t, h, request(f, "/v1/organization/invitation/expire", expireInput, false))
		var out organizationhttp.InvitationExpireResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.State != "expired" || out.InvitationID != "invitation-a" || out.BeforeVersion != 2 || out.AfterVersion != 3 || out.MemberID != "" || out.Recovery == nil || out.Recovery.CommandID != p.result.Receipt.Binding.CommandID {
			t.Fatal("natural expiry lost original terminal receipt", w.Code)
		}
		if p.last.Validate() != nil || p.last.Authentication.Bearer.Token() != f.wire || p.last.Authentication.TenantID != "tenant-a" || p.last.OrganizationID != "organization-a" || p.last.InvitationID != "invitation-a" || p.last.OrganizationVersion != 7 || p.last.InvitationVersion != 2 || p.last.Reason != "security-withdrawal" || p.net != "198.51.100.7" {
			t.Fatal("expiry changed original selector/reason")
		}
		for _, secret := range []string{f.wire, "private-effect", "recipient-a", "identifier-a", `"memberID":`, `"deliveryState":`, `"reason":`, `"invitation":`} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("expiry exposed custody or invented projection")
			}
		}
	}
	if p.sent != 2 || p.calls != 0 || f.rate.calls != 2 {
		t.Fatal("repeat bypassed shared admin or read unrelated owner")
	}
}

func TestInvitationExpireRejectsMalformedInputBeforeAuthority(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"key":              func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden-key") },
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fallbackToken})
		},
		"query":       func(r *http.Request) { r.URL.RawQuery = "reason=other" },
		"force-query": func(r *http.Request) { r.URL.ForceQuery = true },
	} {
		t.Run(name, func(t *testing.T) {
			f, p := newFixture(t), newInvitationExpirePort(t)
			r := request(f, "/v1/organization/invitation/expire", expireInput, false)
			change(r)
			w := serve(t, invitationExpireHandler(t, f, p), r)
			if w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 || f.rate.calls != 0 {
				t.Fatal("malformed expiry reached authority", w.Code)
			}
		})
	}
	for _, body := range []string{`{}`, `null`,
		strings.Replace(expireInput, `"reason":"security-withdrawal"`, `"reason":null`, 1),
		strings.Replace(expireInput, `"reason":"security-withdrawal"`, `"reason":""`, 1),
		strings.Replace(expireInput, `"reason":"security-withdrawal"`, `"reason":" leading"`, 1),
		strings.Replace(expireInput, `"reason":"security-withdrawal"`, `"reason":"`+strings.Repeat("x", 65)+`"`, 1),
		strings.Replace(expireInput, `"reason":"security-withdrawal"`, `"reason":"x","reason":"y"`, 1),
		strings.Replace(expireInput, `"organizationVersion":7`, `"organizationVersion":0`, 1),
		strings.Replace(expireInput, `"organizationVersion":7`, `"organizationVersion":18446744073709551615`, 1),
		strings.Replace(expireInput, `"invitationVersion":2`, `"invitationVersion":0`, 1),
		strings.Replace(expireInput, `"invitationVersion":2`, `"invitationVersion":18446744073709551615`, 1),
		strings.Replace(expireInput, `"invitationVersion":2`, `"invitationVersion":2.0`, 1),
		strings.TrimSuffix(expireInput, "}") + `,"commandID":"AAAAAAAAAAAAAAAAAAAAAQ"}`,
		strings.TrimSuffix(expireInput, "}") + `,"proofID":"private"}`,
		strings.TrimSuffix(expireInput, "}") + `,"actorID":"other"}`,
	} {
		f, p := newFixture(t), newInvitationExpirePort(t)
		w := serve(t, invitationExpireHandler(t, f, p), request(f, "/v1/organization/invitation/expire", body, false))
		if w.Code != 400 || p.sent != 0 || f.reads.Load() != 0 {
			t.Fatal("invalid closed expiry body reached authority", w.Code)
		}
	}
}

func TestInvitationExpireRequiresOwnerAndCurrentAdminAdmission(t *testing.T) {
	for _, owner := range []organizationhttp.InvitationExpirer{nil, (*invitationExpirePort)(nil)} {
		f := newFixture(t)
		f.c.InvitationExpirer = owner
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationExpire: true}); err == nil {
			t.Fatal("expiry accepted absent native owner")
		}
	}
	f, p := newFixture(t), newInvitationExpirePort(t)
	f.inactive = true
	if w := serve(t, invitationExpireHandler(t, f, p), request(f, "/v1/organization/invitation/expire", expireInput, false)); w.Code != 403 || p.sent != 0 || f.rate.calls != 0 {
		t.Fatal("inactive session admitted expiry", w.Code)
	}
	for _, mode := range []int{1, 2} {
		f, p := newFixture(t), newInvitationExpirePort(t)
		f.rate.mode = mode
		w := serve(t, invitationExpireHandler(t, f, p), request(f, "/v1/organization/invitation/expire", expireInput, false))
		if mode == 1 && w.Code != 429 || mode == 2 && w.Code != 503 || p.sent != 0 {
			t.Fatal("denied administrative admission dispatched expiry", w.Code)
		}
	}
}

func TestInvitationExpireWithholdsForeignAndWrongEpochMetadata(t *testing.T) {
	for _, change := range []func(*invitationExpirePort){
		func(p *invitationExpirePort) { p.result.OrganizationID = "foreign" },
		func(p *invitationExpirePort) { p.result.InvitationID = "foreign" },
		func(p *invitationExpirePort) { p.result.Receipt.Binding.ActorID = "foreign" },
		func(p *invitationExpirePort) {
			p.result.Receipt.Binding.UserID = "recipient-a"
			p.result.MemberID = "recipient-a"
		},
		func(p *invitationExpirePort) { p.result.Receipt.Binding.RecordID = "foreign" },
		func(p *invitationExpirePort) {
			p.result.Receipt.Feature.BeforeVersion = 7
			p.result.Receipt.Feature.AfterVersion = 8
		},
	} {
		f, p := newFixture(t), newInvitationExpirePort(t)
		change(p)
		w := serve(t, invitationExpireHandler(t, f, p), request(f, "/v1/organization/invitation/expire", expireInput, false))
		var out organizationhttp.InvitationExpireResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.State != "" || out.CommandID != "" || out.OrganizationID != "" || out.InvitationID != "" || out.Recovery != nil {
			t.Fatal("unrelated expiry metadata exported", w.Code)
		}
	}
}

func TestInvitationExpireRetainsUnknownAndLateKnownCommit(t *testing.T) {
	f, p := newFixture(t), newInvitationExpirePort(t)
	p.result.Receipt.Outcome, p.result.Receipt.AuditEventID = identity.CommitOutcomeUnknown, ""
	p.result.Receipt.Feature.BeforeVersion, p.result.Receipt.Feature.AfterVersion = 0, 0
	if p.result.Receipt.Validate() != nil {
		t.Fatal("unknown test must use a valid native receipt")
	}
	w := serve(t, invitationExpireHandler(t, f, p), request(f, "/v1/organization/invitation/expire", expireInput, false))
	var out organizationhttp.InvitationExpireResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.CommitOutcome != "unknown" || out.State != "" || out.CommandID != p.result.Receipt.Binding.CommandID || out.InvitationID != "invitation-a" || out.Recovery == nil {
		t.Fatal("unknown expiry lost original correlation or fabricated success")
	}
	for _, mode := range []string{"expired", "cancelled"} {
		f, p := newFixture(t), newInvitationExpirePort(t)
		r := request(f, "/v1/organization/invitation/expire", expireInput, false)
		ctx, cancel := context.WithCancel(r.Context())
		r = r.WithContext(ctx)
		p.before = func() {
			if mode == "expired" {
				f.now = f.now.Add(6 * time.Minute)
			} else {
				cancel()
			}
		}
		w := serve(t, invitationExpireHandler(t, f, p), r)
		cancel()
		var out organizationhttp.InvitationExpireResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.CommitOutcome != "committed" || out.State != "" || out.BeforeVersion != 2 || out.AfterVersion != 3 || out.Recovery == nil || out.CommandID != p.result.Receipt.Binding.CommandID || p.sent != 1 {
			t.Fatal("late failure erased known expiry or redispatched", mode, w.Code)
		}
	}
}

func TestInvitationExpireWireAndDisabledSurface(t *testing.T) {
	f, p := newFixture(t), newInvitationExpirePort(t)
	_, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Expire", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{invitationExpireFeature(t, f, p)}})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Required             []string
						Properties           map[string]json.RawMessage
						AdditionalProperties bool
					}
				}
			}
			Parameters []struct {
				Name string
				In   string
			}
		}
	}
	if json.Unmarshal(doc.JSON(), &wire) != nil {
		t.Fatal("expiry wire not JSON")
	}
	op := wire.Paths["/v1/organization/invitation/expire"]["post"]
	schema := op.RequestBody.Content["application/json"].Schema
	if len(schema.Required) != 5 || len(schema.Properties) != 5 || schema.AdditionalProperties || schema.Properties["reason"] == nil {
		t.Fatal("expiry wire does not describe closed reason-bound input")
	}
	for _, parameter := range op.Parameters {
		if parameter.Name == "Idempotency-Key" {
			t.Fatal("natural expiry advertised a client key")
		}
	}
	f = newFixture(t)
	other, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, Create: true})
	if err != nil {
		t.Fatal(err)
	}
	h, disabled, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Without expire", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{other}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disabled.JSON()), "/v1/organization/invitation/expire") || serve(t, h, request(f, "/v1/organization/invitation/expire", expireInput, false)).Code != 404 {
		t.Fatal("disabled expiry exposed route or metadata")
	}
}

func FuzzInvitationExpireClosedInput(f *testing.F) {
	for _, seed := range []string{expireInput, `{}`, `null`, `{"reason":"x","reason":"y"}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			t.Skip()
		}
		fix, p := newFixture(t), newInvitationExpirePort(t)
		w := serve(t, invitationExpireHandler(t, fix, p), request(fix, "/v1/organization/invitation/expire", body, false))
		if p.sent > 1 || p.sent == 1 && p.last.Validate() != nil || w.Code == 400 && p.sent != 0 {
			t.Fatal("hostile expiry input reached invalid or repeated native dispatch")
		}
	})
}
