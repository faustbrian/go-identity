package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// This neutral port tests HTTP custody, not domain authority. The genuine
// PostgreSQL consumer separately exercises the actual one-use transaction.
type invitationAcceptPort struct {
	last              organization.InvitationAcceptRequest
	source            organization.InvitationAcceptAdmission
	result            organization.StoreResult
	err               error
	prepareErr        error
	calls, executions int
	network           string
}

func (p *invitationAcceptPort) PrepareAcceptance(ctx context.Context, r organization.InvitationAcceptRequest, network string) (organization.PreparedInvitationAcceptance, error) {
	p.last, p.network, p.calls = r, network, p.calls+1
	if p.prepareErr != nil {
		return nil, p.prepareErr
	}
	return &invitationAcceptPreparation{owner: p}, nil
}

type invitationAcceptPreparation struct{ owner *invitationAcceptPort }

func (p *invitationAcceptPreparation) Admission() (organization.InvitationAcceptAdmission, error) {
	return p.owner.source, nil
}
func (p *invitationAcceptPreparation) Execute(context.Context) (organization.StoreResult, error) {
	p.owner.executions++
	return p.owner.result, p.owner.err
}

func acceptanceFixture(t testing.TB) (*fixture, *invitationAcceptPort, string) {
	t.Helper()
	f := newFixture(t)
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", UserID: "user-a", ActorID: "user-a", ActorKind: authorization.SubjectUser, OperationID: string(organization.InvitationAccept), RecordID: "invitation-a", PolicyID: "organization", PolicyVersion: 1, SchemaID: organization.InvitationAccept.Descriptor().SchemaID, SchemaVersion: 1, CorrelationID: string(id)}
	p := &invitationAcceptPort{source: organization.InvitationAcceptAdmission{Binding: b, OrganizationID: "organization-a", ChallengeID: "original-grant", ChallengeLifetime: time.Hour}, result: organization.StoreResult{OrganizationID: "organization-a", MemberID: "user-a", InvitationID: "invitation-a", Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: organization.InvitationAccept.Descriptor(), BeforeVersion: 2, AfterVersion: 3}}}}
	// Generated test-only proof material is used only for bounded syntax ingress.
	signer, err := capability.NewHMACSHA256Signer("test-only", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	token, err := capability.Issue(context.Background(), capability.Payload{Version: 1, Issuer: "https://issuer.example", Audiences: []string{"organization-invitation"}, Subject: "user-a", Resource: "invitation-a", Operation: string(organization.InvitationAccept), IssuedAt: f.now, NotBefore: f.now, ExpiresAt: f.now.Add(time.Hour), ID: "original-grant", Tenant: "tenant-a", MaxUses: 1}, signer, capability.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"commandID": id, "organizationID": "organization-a", "invitationID": "invitation-a", "organizationVersion": 3, "invitationVersion": 2, "token": token})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: f.rate, Namespace: "invitation-accept-test", Key: [32]byte{1}, Now: func() time.Time { return f.now }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	f.c.Service, f.c.SafeRate, f.c.AdminRate = nil, nil, nil
	f.c.InvitationAccepter, f.c.SecretRate = p, rate
	return f, p, string(body)
}

func acceptanceHandler(t testing.TB, f *fixture) http.Handler {
	t.Helper()
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, InvitationAccept: true})
	if err != nil {
		t.Fatal("independent once acceptance selection rejected", err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestInvitationAcceptPreservesOriginalCommandAndNativeRateSource(t *testing.T) {
	f, p, body := acceptanceFixture(t)
	w := serve(t, acceptanceHandler(t, f), request(f, "/v1/organization/invitation/accept", body, false))
	var out organizationhttp.InvitationAcceptResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.InvitationID != "invitation-a" || out.MemberID != "user-a" || out.CommandID != p.source.Binding.CommandID || out.BeforeVersion != 2 || out.AfterVersion != 3 || out.Recovery == nil {
		t.Fatal("original acceptance receipt lost", w.Code)
	}
	if p.calls != 1 || p.executions != 1 || p.last.CommandID != p.source.Binding.CommandID || p.last.CorrelationID != string(p.last.CommandID) || p.last.OrganizationVersion != 3 || p.last.InvitationVersion != 2 || p.last.Authentication.Bearer.Token() != f.wire || p.network != "198.51.100.7" || p.last.Proof.ValidateBounds(1, 8192) != nil {
		t.Fatal("exact original custody changed")
	}
	if f.rate.calls != 1 || len(f.rate.last.Requests) != 3 {
		t.Fatal("canonical secret buckets missing")
	}
	var challenge bool
	for _, r := range f.rate.last.Requests {
		if r.Policy.Limit() == 5 && r.Policy.Period() == time.Hour {
			challenge = true
		}
	}
	if !challenge {
		t.Fatal("signed original challenge lifetime not charged")
	}
	if strings.Contains(w.Body.String(), "token") || strings.Contains(w.Body.String(), "original-grant") {
		t.Fatal("secret/source leaked")
	}
}

func TestInvitationAcceptRejectsAlternateChannelsBeforeNativeWork(t *testing.T) {
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		func(r *http.Request) {
			r.Header.Del("Authorization")
			r.Header.Set("Cookie", "identity_session=ambient")
		},
		func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		func(r *http.Request) { r.URL.RawQuery = "commandID=alternate" },
		func(r *http.Request) { r.Method = http.MethodGet },
	} {
		f, p, body := acceptanceFixture(t)
		h := acceptanceHandler(t, f)
		r := request(f, "/v1/organization/invitation/accept", body, false)
		change(r)
		w := serve(t, h, r)
		if w.Code == 200 || p.calls != 0 || p.executions != 0 || f.rate.calls != 0 {
			t.Fatal("alternate channel reached native acceptance", w.Code)
		}
	}
}

func TestInvitationAcceptRateAndSourceFailuresNeverExecute(t *testing.T) {
	for _, variant := range []string{"limited", "outage", "foreign-command", "foreign-actor", "foreign-invitation", "foreign-organization", "zero-lifetime", "inactive"} {
		t.Run(variant, func(t *testing.T) {
			f, p, body := acceptanceFixture(t)
			switch variant {
			case "limited":
				f.rate.mode = 1
			case "outage":
				f.rate.mode = 3
			case "foreign-command":
				p.source.Binding.CommandID, _ = identity.NewCommandID()
			case "foreign-actor":
				p.source.Binding.ActorID = "other"
			case "foreign-invitation":
				p.source.Binding.RecordID = "other"
			case "foreign-organization":
				p.source.OrganizationID = "other"
			case "zero-lifetime":
				p.source.ChallengeLifetime = 0
			case "inactive":
				f.inactive = true
			}
			w := serve(t, acceptanceHandler(t, f), request(f, "/v1/organization/invitation/accept", body, false))
			if w.Code == 200 || p.executions != 0 {
				t.Fatal("denied source/rate executed acceptance", w.Code)
			}
			if variant == "limited" && (w.Code != 429 || w.Header().Get("Retry-After") != "2") {
				t.Fatal("rate rejection contract lost", w.Code)
			}
		})
	}
}

func TestInvitationAcceptUnknownRetainsScopeWithoutClaimingMembership(t *testing.T) {
	f, p, body := acceptanceFixture(t)
	p.result.Receipt.Outcome = identity.CommitOutcomeUnknown
	p.result.Receipt.AuditEventID = ""
	p.err = organization.ErrUnavailable
	w := serve(t, acceptanceHandler(t, f), request(f, "/v1/organization/invitation/accept", body, false))
	var out organizationhttp.InvitationAcceptResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Committed || out.CommitOutcome != "unknown" || out.Recovery == nil || out.CommandID != p.source.Binding.CommandID || p.executions != 1 {
		t.Fatal("ambiguous outcome replaced or redispatched", w.Code)
	}
}

func TestInvitationAcceptRejectsMalformedClosedBody(t *testing.T) {
	f, p, body := acceptanceFixture(t)
	h := acceptanceHandler(t, f)
	for _, changed := range []string{strings.Replace(body, `"organizationVersion":3`, `"organizationVersion":3e0`, 1), strings.Replace(body, `"invitationVersion":2`, `"invitationVersion":0`, 1), strings.Replace(body, `"token":`, `"proof":`, 1), `{"commandID":"bad"}`, strings.TrimSuffix(body, "}") + `,"actorID":"other"}`, strings.TrimSuffix(body, "}") + `,"commandID":"duplicate"}`} {
		w := serve(t, h, request(f, "/v1/organization/invitation/accept", changed, false))
		if w.Code != 400 || p.calls != 0 {
			t.Fatal("malformed body reached native owner", w.Code)
		}
	}
}

func TestInvitationAcceptSelectionRequiresOnlyActualSelectedOwners(t *testing.T) {
	f, _, _ := acceptanceFixture(t)
	for _, clear := range []func(*organizationhttp.Config){func(c *organizationhttp.Config) { c.InvitationAccepter = nil }, func(c *organizationhttp.Config) { c.SecretRate = nil }, func(c *organizationhttp.Config) { c.Sessions = nil }} {
		c := f.c
		clear(&c)
		if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: c, InvitationAccept: true}); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("missing native owner accepted")
		}
	}
}

func TestInvitationAcceptBeforeHandlerNeverRunsBeforeRateAdmission(t *testing.T) {
	for _, mode := range []string{"allowed", "limited", "unavailable", "native-preparation-denied", "hook-stops"} {
		t.Run(mode, func(t *testing.T) {
			f, p, body := acceptanceFixture(t)
			switch mode {
			case "limited":
				f.rate.mode = 1
			case "unavailable":
				f.rate.mode = 3
			case "native-preparation-denied":
				p.prepareErr = organization.ErrForbidden
			}
			hooks := 0
			m := identityhttp.MiddlewareDescriptor{Owner: "organization", Middleware: identityhttp.Middleware{Name: "accepted-only", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hooks++
					if f.rate.calls != 1 || p.calls != 1 || p.executions != 0 {
						t.Fatal("hook did not follow genuine preparation and secret admission")
					}
					if mode == "hook-stops" {
						w.WriteHeader(403)
						return
					}
					next.ServeHTTP(w, r)
				})
			}}}
			feature, err := organizationhttp.NewFeatureWithMiddleware(organizationhttp.FeatureConfig{Config: f.c, InvitationAccept: true}, []identityhttp.MiddlewareDescriptor{m})
			if err != nil {
				t.Fatal(err)
			}
			h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			w := serve(t, h, request(f, "/v1/organization/invitation/accept", body, false))
			status, wantHooks, wantExecutions := 200, 1, 1
			switch mode {
			case "limited":
				status, wantHooks, wantExecutions = 429, 0, 0
			case "unavailable":
				status, wantHooks, wantExecutions = 503, 0, 0
			case "native-preparation-denied":
				status, wantHooks, wantExecutions = 403, 0, 0
			case "hook-stops":
				status, wantExecutions = 403, 0
			}
			if w.Code != status || hooks != wantHooks || p.executions != wantExecutions || p.calls != 1 {
				t.Fatal("acceptance middleware phase mismatch", w.Code, hooks, p.executions, p.calls)
			}
		})
	}
}

func FuzzInvitationAcceptClosedWire(f *testing.F) {
	f.Add(`{"commandID":"original","organizationID":"organization-a","invitationID":"invitation-a","organizationVersion":3,"invitationVersion":2,"token":"bad"}`, false)
	f.Add(`{"commandID":"duplicate","commandID":"second"}`, true)
	f.Add(`null`, false)
	f.Add(`{"organizationVersion":18446744073709551616}`, false)
	f.Fuzz(func(t *testing.T, body string, forbiddenKey bool) {
		if len(body) > 8192 {
			return
		}
		fixture, port, _ := acceptanceFixture(t)
		w := serve(t, acceptanceHandler(t, fixture), request(fixture, "/v1/organization/invitation/accept", body, forbiddenKey))
		if forbiddenKey && (w.Code != 400 || port.calls != 0 || fixture.rate.calls != 0) {
			t.Fatal("forbidden key reached secret operation")
		}
		if w.Code == 400 && port.calls != 0 {
			t.Fatal("invalid closed request reached native owner")
		}
		if port.calls != 0 && port.last.Validate() != nil {
			t.Fatal("malformed request escaped parser bounds")
		}
		if port.executions != 0 && fixture.rate.calls != 1 {
			t.Fatal("protected acceptance bypassed secret rate")
		}
		if !json.Valid(w.Body.Bytes()) {
			t.Fatal("unbounded or invalid response")
		}
	})
}
