package scimhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const (
	managedCreateOperation = "identity.scim.connection-create"
	// The native MappingSet is at most 65536 encoded bytes; one safe scope,
	// version and bounded configured bearer fit below this single-record bound.
	managedCreateMaximumBytes = 1 << 17
)

// ManagedConnectionCreator owns current administrator/session/org:scim-write
// authority, original-key reservation, atomic creation, final authority fences,
// and invocation-local bearer custody. Exact retries return the original safe
// record without another bearer. Errors must not expose credentials or imply
// that unknown work may be re-executed under a new key. Calls honor cancellation,
// support concurrency, borrow inputs synchronously and retain no HTTP request.
type ManagedConnectionCreator interface {
	ConnectionCreate(context.Context, scimpostgres.ConnectionCreateRequest) (scimpostgres.ConnectionCreateResult, error)
}

// ManagedCreateConfig selects only explicit bearer-session creation. Sessions
// supplies current verified actor custody for AdminRate; Creator retains final
// native authority and the only request-key/credential owner. Supply the same
// shared AdminRate used by other administrator routes, never one per request.
// Limits must match the native core-User mapping profile. Network is copied;
// MaximumDuration is 1ms..30s, with earlier request deadlines winning. Trusted
// Now and borrowed owners must be concurrency-safe and outlive requests. This
// feature owns no pool, rate backend, native store or server lifecycle.
type ManagedCreateConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Creator         ManagedConnectionCreator
	AdminRate       *organizationhttp.AdminRateLimiter
	Limits          scim.Limits
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts all borrowed runtime and credential custody.
func (ManagedCreateConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedCreateConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedCreateConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText refuses implicit runtime configuration export.
func (ManagedCreateConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// NewManagedCreateFeature selects only POST /v1/scim/connection-create using
// the canonical explicit-bearer alternative, required original request key and
// existing rate.admin. Cookies never supply authority; no browser/CSRF profile,
// reads, Bulk, provisioning, rotation or deletion is enabled. For coexistence,
// combine disjoint Operations under one canonical NewFeature with ID "scim".
// Construction performs no owner IO. The server owns raw IO/write deadlines.
func NewManagedCreateFeature(c ManagedCreateConfig) (identityhttp.Feature, error) {
	return NewManagedCreateFeatureWithMiddleware(c, nil)
}

// NewManagedCreateFeatureWithMiddleware exposes real decode/authenticate/
// admission/native-create stages to synchronous trusted hooks. Hooks cannot
// replace frozen tenant, bearer, original key or validated mapping intent.
func NewManagedCreateFeatureWithMiddleware(c ManagedCreateConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	if !c.Sessions.Configured() || !c.AdminRate.Configured() || missingManagedOwner(c.Creator) || c.Now == nil || len(c.Network.TenantHosts) == 0 || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	if _, err := scim.ParseMappingPath("userName", nil, c.Limits); err != nil {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	handler, err := newManagedCreateHandler(c, m)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "scim", OperationID: managedCreateOperation, Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: managedCreateMaximumBytes})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = managedCreateWire()
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
}

type managedCreateBody struct {
	OrganizationID string `json:"organizationID"`
	ProviderID     string `json:"providerID"`
	Mappings       []struct {
		Source   string `json:"source"`
		Target   string `json:"target"`
		Writable *bool  `json:"writable"`
	} `json:"mappings"`
}
type managedCreateInput struct {
	facts    identityhttp.NetworkFacts
	request  scimpostgres.ConnectionCreateRequest
	observed session.GetResult
	actor    identity.UserID
}

func managedCreateReject(w http.ResponseWriter, r *http.Request, err error) {
	var failure managedReadFailure
	if errors.As(err, &failure) && failure.status == 405 {
		w.Header().Set("Allow", http.MethodPost)
		managedReadWrite(w, 405, []byte(`{"error":"method_not_allowed"}`))
		return
	}
	var conflict identity.ConflictError
	var pending identity.InProgressError
	if errors.As(err, &conflict) || errors.As(err, &pending) {
		err = managedReadFailure{status: 409, code: "conflict"}
	}
	managedReadReject(w, r, err)
}

func newManagedCreateHandler(c ManagedCreateConfig, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[managedCreateInput]{
		MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: managedCreateReject,
		Decode: func(r *http.Request) (in managedCreateInput, err error) {
			if r.URL.Path != "/v1/scim/connection-create" || r.URL.EscapedPath() != r.URL.Path {
				return in, managedReadFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodPost {
				return in, managedReadFailure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Trailer) != 0 {
				return in, identityhttp.ErrInvalidInput
			}
			in.facts, err = network.Resolve(r)
			if err != nil {
				return in, err
			}
			if in.facts.Scheme() != "https" || in.facts.Realm() != identityhttp.RealmTenant {
				return in, identity.ForbiddenError{}
			}
			in.request.IdempotencyKey, _, err = decoder.IdempotencyKey(r, identityhttp.HeaderRequired)
			if err != nil {
				return in, identityhttp.ErrInvalidInput
			}
			in.request.Authentication.Bearer, _, err = decoder.Bearer(r, identityhttp.HeaderRequired)
			if err != nil {
				return in, managedReadFailure{status: 401, code: "unauthenticated"}
			}
			in.request.Authentication.TenantID = in.facts.TenantID()
			body, err := identityhttp.DecodeJSON[managedCreateBody](decoder, r)
			if err != nil {
				return in, err
			}
			if _, err := identity.ParseSubjectID(body.OrganizationID); err != nil || !managedCreateProviderID(body.ProviderID) || len(body.Mappings) < 1 || len(body.Mappings) > 128 {
				return in, identityhttp.ErrInvalidInput
			}
			in.request.OrganizationID, in.request.ProviderID = organization.ID(body.OrganizationID), scim.ProviderID(body.ProviderID)
			mappings := make([]scim.Mapping, len(body.Mappings))
			for i, mapping := range body.Mappings {
				if mapping.Writable == nil {
					return in, identityhttp.ErrInvalidInput
				}
				path, err := scim.ParseMappingPath(mapping.Source, nil, c.Limits)
				if err != nil {
					return in, identityhttp.ErrInvalidInput
				}
				mappings[i] = scim.Mapping{Source: path, Target: mapping.Target, Writable: *mapping.Writable}
			}
			in.request.Mappings, err = scim.NewMappingSet(mappings)
			if err != nil {
				return in, identityhttp.ErrInvalidInput
			}
			return in, nil
		},
		Authenticate: func(r *http.Request, in managedCreateInput) (managedCreateInput, error) {
			token, err := session.ParseToken(in.request.Authentication.Bearer.Token())
			if err != nil {
				return in, identity.ForbiddenError{}
			}
			credential, err := session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				return in, identity.ForbiddenError{}
			}
			in.observed, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: in.facts.TenantID(), Credential: credential})
			if err != nil {
				return in, identityhttp.ErrUnavailable
			}
			if !in.observed.Authenticated || in.observed.ValidateAt(c.Now()) != nil {
				return in, identity.ForbiddenError{}
			}
			binding, err := in.observed.Session.Bindings()
			if err != nil || binding.TenantID != in.facts.TenantID() || binding.Authentication.Kind != session.AuthenticationVerified {
				return in, identity.ForbiddenError{}
			}
			if _, err := identity.ParseSubjectID(string(binding.UserID)); err != nil {
				return in, identity.ForbiddenError{}
			}
			in.actor = binding.UserID
			return in, nil
		},
		Admit: func(r *http.Request, in managedCreateInput) error {
			out, err := c.AdminRate.AdmitSCIMConnectionCreate(r.Context(), in.facts, in.actor)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return managedReadFailure{status: 429, code: "rate_limited", retry: out.RetryAfter}
			}
			if err != nil || !out.Allowed || in.observed.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, in managedCreateInput) {
			if in.observed.ValidateAt(c.Now()) != nil {
				managedCreateReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			result, err := c.Creator.ConnectionCreate(r.Context(), in.request)
			if err != nil {
				managedCreateReject(w, r, err)
				return
			}
			view, err := managedCreateView(in, result.Connection)
			if err != nil {
				managedCreateReject(w, r, err)
				return
			}
			secret := result.Bearer.Token()
			if secret != "" && (!managedCreateBearer(secret) || secret == in.request.Authentication.Bearer.Token()) {
				managedCreateReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			// The native owner supplies only invocation-local successful custody.
			// HTTP never stores this response or reconstructs a bearer on retry.
			encoded, err := json.Marshal(struct {
				Connection ManagedConnectionView `json:"connection"`
				Bearer     string                `json:"bearer,omitempty"`
			}{view, secret})
			defer clear(encoded)
			if err != nil || len(encoded) > managedCreateMaximumBytes || r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				managedCreateReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			managedReadWrite(w, 200, encoded)
		},
	})
}

// Native configured provider IDs are visible ASCII without path/query/fragment
// separators. The transport preserves spelling; it does not create a scope.
func managedCreateProviderID(value string) bool {
	if len(value) < 1 || len(value) > 128 || strings.ContainsAny(value, "/\\?#") {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// Match the native ConfiguredCredential's accepted bearer representation.
// This is response-shape validation, not credential authentication or issuance.
func managedCreateBearer(value string) bool {
	if len(value) < 32 || len(value) > 4096 || value[0] == '=' {
		return false
	}
	padding := false
	for i := range len(value) {
		b := value[i]
		if b == '=' {
			padding = true
			continue
		}
		if padding || !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~+/", rune(b))) {
			return false
		}
	}
	return true
}

func managedCreateView(in managedCreateInput, record scim.ConnectionRecord) (ManagedConnectionView, error) {
	// The selected native creation contract returns version one and the original
	// RemoveMembership/core-User configuration, including on a metadata-only retry.
	if record.Version() != 1 || record.DeprovisionPolicy() != scim.RemoveMembership || record.Scope().ProviderID != in.request.ProviderID {
		return ManagedConnectionView{}, identityhttp.ErrUnavailable
	}
	want, got := in.request.Mappings.Entries(), record.Mappings().Entries()
	if len(want) != len(got) {
		return ManagedConnectionView{}, identityhttp.ErrUnavailable
	}
	for i := range want {
		if want[i] != got[i] {
			return ManagedConnectionView{}, identityhttp.ErrUnavailable
		}
	}
	return managedConnectionView(record, in.facts.TenantID(), in.request.OrganizationID)
}
