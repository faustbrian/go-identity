package organizationhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	organization "github.com/faustbrian/go-organization"
)

// This native-port fixture proves transport custody, not the signed proof or
// durable lifecycle. Real signup/password/PostgreSQL composition proves those.
type lifecyclePort struct {
	*ownerTransferPort
	request   organization.LifecycleOperationRequest
	operation organization.Operation
}

func (p *lifecyclePort) Archive(ctx context.Context, r organization.LifecycleOperationRequest, network string) (organization.StoreResult, error) {
	return p.mutate(ctx, r, network, organization.Archive)
}
func (p *lifecyclePort) Restore(ctx context.Context, r organization.LifecycleOperationRequest, network string) (organization.StoreResult, error) {
	return p.mutate(ctx, r, network, organization.Restore)
}
func (p *lifecyclePort) mutate(ctx context.Context, r organization.LifecycleOperationRequest, network string, op organization.Operation) (organization.StoreResult, error) {
	p.request, p.operation = r, op
	p.calls++
	p.native.network = network
	out, err := p.native.mutation(ctx, op, r.Authentication, r.OrganizationID, "user-a")
	if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		out.Receipt.Feature.BeforeVersion, out.Receipt.Feature.AfterVersion = r.OrganizationVersion, r.OrganizationVersion+1
	}
	if p.change != nil {
		p.change(&out)
	}
	return out, err
}

const lifecycleBody = `{"organizationID":"organization-a","organizationVersion":7,"reason":"operator-request","proofID":"AAAAAAAAAAAAAAAAAAAAAQ"}`

func lifecycleFixture(t testing.TB, op organization.Operation) (*fixture, *lifecyclePort, http.Handler) {
	t.Helper()
	f := newFixture(t)
	p := &lifecyclePort{ownerTransferPort: &ownerTransferPort{native: f.port, proof: auth.ReauthenticationProof{Proof: auth.Proof{ID: "AAAAAAAAAAAAAAAAAAAAAQ", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "organization-lifecycle", IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(time.Minute)}, SessionID: "session-a", SessionVersion: 1, Action: string(op)}}}
	f.c.Service, f.c.SafeRate, f.c.Invitations = nil, nil, nil
	f.c.LifecycleProofs, f.c.LifecycleAudience = p, "organization-lifecycle"
	selected := organizationhttp.FeatureConfig{Config: f.c}
	if op == organization.Archive {
		selected.Config.Archiver, selected.Archive = p, true
	} else {
		selected.Config.Restorer, selected.Restore = p, true
	}
	feature, err := organizationhttp.NewFeature(selected)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return f, p, h
}
func lifecycleRequest(f *fixture, op organization.Operation, body string) *http.Request {
	path := "/v1/organization/archive"
	if op == organization.Restore {
		path = "/v1/organization/restore"
	}
	return request(f, path, body, true)
}
func TestLifecycleIndependentSelectionAndOriginalCustody(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		t.Run(string(op), func(t *testing.T) {
			f, p, h := lifecycleFixture(t, op)
			// An expired original record may classify a matching historical key.
			// HTTP must not replace it with a fresh proof or today's session.
			p.proof.SessionID = "historical-session"
			p.proof.Proof.IssuedAt, p.proof.Proof.ExpiresAt = f.now.Add(-2*time.Minute), f.now.Add(-time.Minute)
			w := serve(t, h, lifecycleRequest(f, op, lifecycleBody))
			var out organizationhttp.MutationResponse
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Committed || out.BeforeVersion != 7 || out.AfterVersion != 8 || out.Recovery == nil {
				t.Fatal("original lifecycle receipt lost", w.Code)
			}
			if p.operation != op || p.calls != 1 || p.lookups != 1 || p.request.Proof != p.proof || p.request.OrganizationID != "organization-a" || p.request.OrganizationVersion != 7 || p.request.Reason != "operator-request" || p.request.Authentication.Bearer.Token() != f.wire || p.native.network != "198.51.100.7" || f.rate.calls != 1 {
				t.Fatal("lifecycle intent or authority custody changed")
			}
			key, _ := identity.NewIdempotencyKey([]byte("original-key"))
			a, _ := key.Digest([32]byte{1})
			b, _ := p.request.IdempotencyKey.Digest([32]byte{1})
			if a != b {
				t.Fatal("original key changed")
			}
			for _, private := range []string{f.wire, string(p.proof.Proof.ID), "historical-session", "proofID", "operator-request"} {
				if strings.Contains(w.Body.String(), private) {
					t.Fatal("credential/proof/reason escaped")
				}
			}
		})
	}
}
func TestLifecycleRequiresSelectedOwners(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		for _, mode := range []string{"port", "typed-port", "proofs", "audience", "rate", "sessions"} {
			f, p, _ := lifecycleFixture(t, op)
			selected := organizationhttp.FeatureConfig{Config: f.c}
			if op == organization.Archive {
				selected.Config.Archiver, selected.Archive = p, true
			} else {
				selected.Config.Restorer, selected.Restore = p, true
			}
			switch mode {
			case "port":
				selected.Config.Archiver, selected.Config.Restorer = nil, nil
			case "typed-port":
				var missing *lifecyclePort
				selected.Config.Archiver, selected.Config.Restorer = missing, missing
			case "proofs":
				selected.Config.LifecycleProofs = nil
			case "audience":
				selected.Config.LifecycleAudience = ""
			case "rate":
				selected.Config.AdminRate = nil
			case "sessions":
				selected.Config.Sessions = nil
			}
			if _, err := organizationhttp.NewFeature(selected); err == nil {
				t.Fatal("missing lifecycle dependency accepted", op, mode)
			}
		}
	}
}
func TestLifecycleClosedInput(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		for _, body := range []string{`{}`, `null`, strings.Replace(lifecycleBody, `"organizationVersion":7`, `"organizationVersion":7e0`, 1), strings.Replace(lifecycleBody, `"organizationVersion":7`, `"organizationVersion":18446744073709551615`, 1), strings.Replace(lifecycleBody, `"reason":"operator-request"`, `"reason":"bad reason"`, 1), strings.Replace(lifecycleBody, `"reason":"operator-request"`, `"reason":"`+strings.Repeat("x", 65)+`"`, 1), strings.Replace(lifecycleBody, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"proofID":"short"`, 1), strings.Replace(lifecycleBody, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ"`, `"proofID":"AAAAAAAAAAAAAAAAAAAAAQ","commandID":"override"`, 1), strings.Replace(lifecycleBody, `"organizationID":"organization-a"`, `"organizationID":"organization-a","organizationID":"other"`, 1)} {
			f, p, h := lifecycleFixture(t, op)
			w := serve(t, h, lifecycleRequest(f, op, body))
			if w.Code != 400 || p.calls != 0 || p.lookups != 0 || f.reads.Load() != 0 {
				t.Fatal("malformed lifecycle reached authority", op, w.Code)
			}
		}
		for _, mode := range []string{"key", "duplicate-key", "bearer", "cookie", "query", "method"} {
			f, p, h := lifecycleFixture(t, op)
			r := lifecycleRequest(f, op, lifecycleBody)
			want := 400
			switch mode {
			case "key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "other")
			case "bearer":
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			case "cookie":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "__Host-session", Value: fakedCookie})
			case "query":
				r.URL.RawQuery = "actorID=other"
			case "method":
				r.Method = http.MethodPut
				want = 405
			}
			w := serve(t, h, r)
			if w.Code != want || p.calls != 0 || p.lookups != 0 || f.reads.Load() != 0 {
				t.Fatal("alternate channel reached authority", op, mode, w.Code)
			}
		}
	}
}
func TestLifecycleProofAndAdmissionFences(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		for _, mode := range []string{"unknown", "unavailable", "tenant", "actor", "id", "action", "audience", "method", "inactive", "rate", "closed", "expired", "cancelled"} {
			t.Run(string(op)+"/"+mode, func(t *testing.T) {
				f, p, h := lifecycleFixture(t, op)
				r := lifecycleRequest(f, op, lifecycleBody)
				want := 403
				switch mode {
				case "unknown":
					p.proofErr = auth.ErrInvalidProof
				case "unavailable":
					p.proofErr = errors.New("private diagnostic")
					want = 503
				case "tenant":
					p.proof.Proof.Tenant = "other"
				case "actor":
					p.proof.Proof.Subject = "other"
				case "id":
					p.proof.Proof.ID = "BBBBBBBBBBBBBBBBBBBBBB"
				case "action":
					p.proof.Action = string(organization.OwnerTransfer)
				case "audience":
					p.proof.Proof.Audience = "other"
				case "method":
					p.proof.Proof.Method = "passkey"
				case "inactive":
					f.inactive = true
				case "rate":
					f.rate.mode = 1
					want = 429
				case "closed":
					f.c.AdminRate.Close()
					want = 503
				case "expired":
					p.beforeProof = func() { f.now = f.now.Add(20 * time.Second) }
					want = 503
				case "cancelled":
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					r = r.WithContext(ctx)
					p.beforeProof = cancel
					want = 503
				}
				w := serve(t, h, r)
				if w.Code != want || p.calls != 0 || strings.Contains(w.Body.String(), "private") {
					t.Fatal("lifecycle admission fence", w.Code)
				}
				if (mode == "inactive" || mode == "rate" || mode == "closed") && p.lookups != 0 {
					t.Fatal("denied admission read proof")
				}
			})
		}
	}
}
func TestLifecycleReceiptAndLateOutcome(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		for _, mode := range []string{"actor", "user", "tenant", "organization", "epoch", "unknown", "cancelled", "expired"} {
			t.Run(string(op)+"/"+mode, func(t *testing.T) {
				f, p, h := lifecycleFixture(t, op)
				r := lifecycleRequest(f, op, lifecycleBody)
				switch mode {
				case "actor":
					p.change = func(o *organization.StoreResult) { o.Receipt.Binding.ActorID = "other" }
				case "user":
					p.change = func(o *organization.StoreResult) { o.MemberID = "other"; o.Receipt.Binding.UserID = "other" }
				case "tenant":
					p.change = func(o *organization.StoreResult) { o.Receipt.Binding.TenantID = "other" }
				case "organization":
					p.change = func(o *organization.StoreResult) { o.OrganizationID = "other"; o.Receipt.Binding.RecordID = "other" }
				case "epoch":
					p.change = func(o *organization.StoreResult) {
						o.Receipt.Feature.BeforeVersion = 8
						o.Receipt.Feature.AfterVersion = 9
					}
				case "unknown":
					f.port.outcome = identity.CommitOutcomeUnknown
				case "cancelled":
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					r = r.WithContext(ctx)
					f.port.beforeCall = cancel
				case "expired":
					f.port.beforeCall = func() { f.now = f.now.Add(20 * time.Second) }
				}
				w := serve(t, h, r)
				var out organizationhttp.MutationResponse
				if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil {
					t.Fatal("unsafe lifecycle response", w.Code)
				}
				if mode == "unknown" {
					if out.Recovery == nil || out.CommitOutcome != "unknown" || out.Committed {
						t.Fatal("unknown original correlation lost")
					}
				} else if mode == "cancelled" || mode == "expired" {
					if !out.Committed || out.CommitOutcome != "committed" || out.Recovery == nil || out.BeforeVersion != 7 || out.AfterVersion != 8 {
						t.Fatal("late failure erased known commit")
					}
				} else if out.CommandID != "" || out.Recovery != nil || out.Committed {
					t.Fatal("foreign/epoch metadata escaped")
				}
			})
		}
	}
}
func TestLifecycleWireAndDisabledSelection(t *testing.T) {
	for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
		f, p, _ := lifecycleFixture(t, op)
		selected := organizationhttp.FeatureConfig{Config: f.c}
		if op == organization.Archive {
			selected.Config.Archiver, selected.Archive = p, true
		} else {
			selected.Config.Restorer, selected.Restore = p, true
		}
		feature, err := organizationhttp.NewFeature(selected)
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Lifecycle", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		r := lifecycleRequest(f, op, lifecycleBody)
		w := serve(t, h, r)
		assertWireResponse(t, doc.JSON(), r, w)
		if len(doc.Operations()) != 1 || !strings.Contains(string(doc.JSON()), `"proofID"`) || !strings.Contains(string(doc.JSON()), `"reason"`) {
			t.Fatal("lifecycle schema missing")
		}
		f.c.Service = f.port
		feature, err = organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, MemberAdd: true})
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err = identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Disabled", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(doc.JSON()), r.URL.Path) || serve(t, h, r).Code != 404 {
			t.Fatal("disabled lifecycle exposed")
		}
	}
}
func FuzzLifecycleClosedRequest(f *testing.F) {
	for _, seed := range []string{lifecycleBody, `{}`, `null`, strings.Replace(lifecycleBody, `"reason":"operator-request"`, `"reason":"bad reason"`, 1)} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	f.Fuzz(func(t *testing.T, body string, restore bool) {
		if len(body) > 4096 {
			return
		}
		op := organization.Archive
		if restore {
			op = organization.Restore
		}
		x, p, h := lifecycleFixture(t, op)
		w := serve(t, h, lifecycleRequest(x, op, body))
		if p.calls != 0 && (p.calls != 1 || p.lookups != 1 || p.operation != op || p.request.Validate() != nil || p.request.Authentication.Bearer.Token() != x.wire) {
			t.Fatal("forged request reached native lifecycle")
		}
		if w.Code == 200 && p.calls != 1 {
			t.Fatal("success bypassed native lifecycle")
		}
	})
}
