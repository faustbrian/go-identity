package scimhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const (
	managedGetOperation     = "identity.scim.connection-get"
	managedListOperation    = "identity.scim.connection-list"
	managedReadMaximumBytes = 16 << 20 // 200 native records, each with at most 65536 mapping bytes.
)

// ManagedConnectionGetter owns current native administrator/session and
// org:scim-read authorization, primary reads, and the final authority fence.
// It must honor cancellation and support concurrent calls. Missing and denied
// records must be indistinguishable; a record is not reusable authority.
type ManagedConnectionGetter interface {
	ConnectionGet(context.Context, scimpostgres.ConnectionGetRequest) (scim.ConnectionRecord, error)
}

// ManagedConnectionLister owns exact organization authorization and live,
// bytewise-ID-ordered native pagination. Cursors confer no authority. Failures
// return no partial page. Calls must honor cancellation and support concurrency.
type ManagedConnectionLister interface {
	ConnectionList(context.Context, scimpostgres.ConnectionListRequest) (scimpostgres.ConnectionListResult, error)
}

// ManagedReadConfig independently selects each nonnil native port. Sessions
// supplies the actual currently authenticated verified human for rate.safe;
// the native owner retains the final session/organization/policy authority.
// SafeRate is the shared limiter used by other safe routes, never per request.
// Dependencies and trusted, prompt Now must be concurrency-safe and outlive
// requests. Network policy is copied; MaximumDuration is 1ms..30s, with earlier
// request deadlines winning. No pool, limiter or server lifetime is transferred.
type ManagedReadConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Getter          ManagedConnectionGetter
	Lister          ManagedConnectionLister
	SafeRate        *identityhttp.SafeRateLimiter
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed native/session owners and configuration.
func (ManagedReadConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("scimhttp.ManagedReadConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime configuration export.
func (ManagedReadConfig) MarshalJSON() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// MarshalText refuses implicit runtime configuration export.
func (ManagedReadConfig) MarshalText() ([]byte, error) { return nil, identityhttp.ErrInvalidInput }

// ManagedMappingView contains the safe stored mapping configuration.
type ManagedMappingView struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Writable bool   `json:"writable"`
}

// ManagedConnectionView contains only the native administrative projection,
// never a bearer, digest, authentication proof or refreshed authority.
type ManagedConnectionView struct {
	TenantID          identity.TenantID    `json:"tenantID"`
	OrganizationID    organization.ID      `json:"organizationID"`
	ProviderID        scim.ProviderID      `json:"providerID"`
	ConnectionID      scim.ConnectionID    `json:"connectionID"`
	Mappings          []ManagedMappingView `json:"mappings"`
	DeprovisionPolicy string               `json:"deprovisionPolicy"`
	Version           uint64               `json:"version"`
}

// ManagedConnectionListResponse is a live primary page, not a snapshot or an
// authorization grant. Connections is always an array; absent NextCursor ends it.
type ManagedConnectionListResponse struct {
	Connections []ManagedConnectionView `json:"connections"`
	NextCursor  string                  `json:"nextCursor,omitempty"`
}

// NewManagedReadFeature explicitly selects GET /v1/scim/connection-get and/or
// /v1/scim/connection-list for the corresponding nonnil ports. It selects no
// provisioning or management writes. For Bulk coexistence, combine the two
// factories' Operations in one NewFeature with canonical ID "scim". Omission
// installs neither routes nor metadata. Construction performs no owner IO.
func NewManagedReadFeature(c ManagedReadConfig) (identityhttp.Feature, error) {
	return NewManagedReadFeatureWithMiddleware(c, nil)
}

// NewManagedReadFeatureWithMiddleware binds the real decode, authenticate,
// shared-rate admission and native-read phases. Trusted middleware cannot
// replace the frozen credential, tenant, target or continuation.
func NewManagedReadFeatureWithMiddleware(c ManagedReadConfig, m []identityhttp.MiddlewareDescriptor) (identityhttp.Feature, error) {
	if !c.Sessions.Configured() || !c.SafeRate.Configured() || c.Now == nil ||
		c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second || len(c.Network.TenantHosts) == 0 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	var operations []identityhttp.OperationDescriptor
	for _, selected := range []struct {
		id    string
		owner any
	}{{managedGetOperation, c.Getter}, {managedListOperation, c.Lister}} {
		if missingManagedOwner(selected.owner) {
			continue
		}
		handler, err := newManagedReadHandler(c, selected.id, m)
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "scim", OperationID: selected.id, Handler: handler, CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: managedReadMaximumBytes})
		if err != nil {
			return identityhttp.Feature{}, err
		}
		op.Wire = managedReadWire(selected.id)
		if len(operations) == 0 {
			op.Wire.SecuritySchemes = []identityhttp.WireComponent{{Name: "SCIMAdministratorBearer", Definition: []byte(`{"type":"http","scheme":"bearer","bearerFormat":"opaque native session","description":"Exactly one explicit Authorization bearer; cookies never supply authority."}`)}}
		}
		operations = append(operations, op)
	}
	if len(operations) == 0 {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: operations})
}

func missingManagedOwner(owner any) bool {
	if owner == nil {
		return true
	}
	v := reflect.ValueOf(owner)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

type managedReadInput struct {
	facts        identityhttp.NetworkFacts
	auth         organization.Authentication
	connection   scim.ConnectionID
	organization organization.ID
	limit        uint16
	cursor       string
	actor        identity.UserID
	observed     session.GetResult
}
type managedReadFailure struct {
	status int
	code   string
	retry  time.Duration
}

func (e managedReadFailure) Error() string { return "scimhttp: " + e.code }

func managedReadReject(w http.ResponseWriter, _ *http.Request, err error) {
	f := managedReadFailure{status: 503, code: "unavailable"}
	var invalid identity.InvalidInputError
	var malformed identityhttp.DecodeError
	var denied identity.ForbiddenError
	var protocol *scim.Error
	switch {
	case errors.Is(err, identityhttp.ErrInvalidInput), errors.As(err, &invalid), errors.As(err, &malformed):
		f = managedReadFailure{status: 400, code: "invalid_request"}
	case errors.As(err, &denied):
		f = managedReadFailure{status: 403, code: "forbidden"}
	case errors.As(err, &protocol) && protocol != nil && protocol.StatusCode() == 400:
		f = managedReadFailure{status: 400, code: "invalid_request"}
	}
	var specific managedReadFailure
	if errors.As(err, &specific) {
		f = specific
	}
	if f.status == 401 {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	if f.status == 405 {
		w.Header().Set("Allow", http.MethodGet)
	}
	if f.status == 429 && f.retry > 0 {
		delay := min(max(f.retry, time.Second), time.Hour)
		w.Header().Set("Retry-After", strconv.FormatInt(int64((delay+time.Second-1)/time.Second), 10))
	}
	managedReadWrite(w, f.status, []byte(`{"error":`+strconv.Quote(f.code)+`}`))
}

func managedReadWrite(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func newManagedReadHandler(c ManagedReadConfig, operation string, middleware []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	path := "/v1/scim/connection-get"
	if operation == managedListOperation {
		path = "/v1/scim/connection-list"
	}
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[managedReadInput]{
		MaximumDuration: c.MaximumDuration, Middleware: middleware, Reject: managedReadReject,
		Decode: func(r *http.Request) (in managedReadInput, err error) {
			if r.URL.Path != path || r.URL.EscapedPath() != path {
				return in, managedReadFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodGet {
				return in, managedReadFailure{status: 405, code: "method_not_allowed"}
			}
			if r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 || r.Body != nil && r.Body != http.NoBody {
				return in, identityhttp.ErrInvalidInput
			}
			in.facts, err = network.Resolve(r)
			if err != nil {
				return in, err
			}
			if in.facts.Scheme() != "https" || in.facts.Realm() != identityhttp.RealmTenant {
				return in, identity.ForbiddenError{}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return in, identityhttp.ErrInvalidInput
			}
			query, err := decoder.Query(r)
			if err != nil {
				return in, identityhttp.ErrInvalidInput
			}
			if operation == managedGetOperation {
				if len(query) != 1 || len(query["connectionID"]) != 1 {
					return in, identityhttp.ErrInvalidInput
				}
				in.connection, err = scim.ParseConnectionID(query.Get("connectionID"))
				if err != nil {
					return in, identityhttp.ErrInvalidInput
				}
			} else {
				if len(query) < 2 || len(query) > 3 || len(query["organizationID"]) != 1 || len(query["limit"]) != 1 {
					return in, identityhttp.ErrInvalidInput
				}
				for name := range query {
					if name != "organizationID" && name != "limit" && name != "cursor" {
						return in, identityhttp.ErrInvalidInput
					}
				}
				if _, err := identity.ParseSubjectID(query.Get("organizationID")); err != nil {
					return in, identityhttp.ErrInvalidInput
				}
				in.organization = organization.ID(query.Get("organizationID"))
				limit, err := strconv.ParseUint(query.Get("limit"), 10, 16)
				if err != nil || limit < 1 || limit > 200 || strconv.FormatUint(limit, 10) != query.Get("limit") {
					return in, identityhttp.ErrInvalidInput
				}
				in.limit = uint16(limit)
				if cursor, present := query["cursor"]; present {
					if len(cursor) != 1 || !managedCursorShape(cursor[0]) {
						return in, identityhttp.ErrInvalidInput
					}
					in.cursor = cursor[0]
				}
			}
			in.auth.Bearer, _, err = decoder.Bearer(r, identityhttp.HeaderRequired)
			if err != nil {
				return in, managedReadFailure{status: 401, code: "unauthenticated"}
			}
			in.auth.TenantID = in.facts.TenantID()
			return in, nil
		},
		Authenticate: func(r *http.Request, in managedReadInput) (managedReadInput, error) {
			token, err := session.ParseToken(in.auth.Bearer.Token())
			if err != nil {
				return in, identity.ForbiddenError{}
			}
			credential, err := session.NewCredential(session.CredentialBearer, token)
			if err != nil {
				return in, identity.ForbiddenError{}
			}
			in.observed, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: in.auth.TenantID, Credential: credential})
			if err != nil {
				return in, identityhttp.ErrUnavailable
			}
			if !in.observed.Authenticated || in.observed.ValidateAt(c.Now()) != nil {
				return in, identity.ForbiddenError{}
			}
			binding, err := in.observed.Session.Bindings()
			if err != nil || binding.TenantID != in.auth.TenantID || binding.Authentication.Kind != session.AuthenticationVerified {
				return in, identity.ForbiddenError{}
			}
			if _, err := identity.ParseSubjectID(string(binding.UserID)); err != nil {
				return in, identity.ForbiddenError{}
			}
			in.actor = binding.UserID
			return in, nil
		},
		Admit: func(r *http.Request, in managedReadInput) error {
			result, err := c.SafeRate.Admit(r.Context(), in.facts, operation, in.actor)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return managedReadFailure{status: 429, code: "rate_limited", retry: result.RetryAfter}
			}
			if err != nil || !result.Allowed || in.observed.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, in managedReadInput) {
			if in.observed.ValidateAt(c.Now()) != nil {
				managedReadReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			out, err := managedReadResult(r.Context(), c, operation, in)
			if err != nil {
				managedReadReject(w, r, err)
				return
			}
			encoded, err := json.Marshal(out)
			if err != nil || len(encoded) > managedReadMaximumBytes || r.Context().Err() != nil || in.observed.ValidateAt(c.Now()) != nil {
				managedReadReject(w, r, identityhttp.ErrUnavailable)
				return
			}
			managedReadWrite(w, 200, encoded)
		},
	})
}

// The native managed cursor is exactly 55 bytes (version + 22-byte ID +
// SHA-256 authenticator), encoded as 74 unpadded base64url bytes. HTTP checks
// only this allocation bound; native scope authentication remains authoritative.
func managedCursorShape(raw string) bool {
	if len(raw) != 74 {
		return false
	}
	var decoded [55]byte
	n, err := base64.RawURLEncoding.Strict().Decode(decoded[:], []byte(raw))
	return err == nil && n == len(decoded) && base64.RawURLEncoding.EncodeToString(decoded[:]) == raw
}

func managedReadResult(ctx context.Context, c ManagedReadConfig, operation string, in managedReadInput) (any, error) {
	if operation == managedGetOperation {
		record, err := c.Getter.ConnectionGet(ctx, scimpostgres.ConnectionGetRequest{Authentication: in.auth, ConnectionID: in.connection})
		if err != nil {
			return nil, err
		}
		if record.Scope().ProviderConnectionID != in.connection {
			return nil, identityhttp.ErrUnavailable
		}
		return managedConnectionView(record, in.auth.TenantID, "")
	}
	page, err := c.Lister.ConnectionList(ctx, scimpostgres.ConnectionListRequest{Authentication: in.auth, OrganizationID: in.organization, Limit: in.limit, Cursor: in.cursor})
	if err != nil {
		return nil, err
	}
	if len(page.Connections) > int(in.limit) || page.NextCursor != "" && (!managedCursorShape(page.NextCursor) || len(page.Connections) == 0) {
		return nil, identityhttp.ErrUnavailable
	}
	out := ManagedConnectionListResponse{Connections: make([]ManagedConnectionView, len(page.Connections)), NextCursor: page.NextCursor}
	for i, record := range page.Connections {
		if i > 0 && page.Connections[i-1].Scope().ProviderConnectionID >= record.Scope().ProviderConnectionID {
			return nil, identityhttp.ErrUnavailable
		}
		out.Connections[i], err = managedConnectionView(record, in.auth.TenantID, in.organization)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func managedConnectionView(record scim.ConnectionRecord, tenant identity.TenantID, org organization.ID) (ManagedConnectionView, error) {
	scope := record.Scope()
	if scope.TenantID != tenant || org != "" && scope.OrganizationID != org || record.Version() == 0 {
		return ManagedConnectionView{}, identityhttp.ErrUnavailable
	}
	if _, err := scim.NewConnectionRecord(scope, record.Mappings(), record.DeprovisionPolicy(), record.Version()); err != nil {
		return ManagedConnectionView{}, identityhttp.ErrUnavailable
	}
	policy := ""
	switch record.DeprovisionPolicy() {
	case scim.Suspend:
		policy = "suspend"
	case scim.RemoveMembership:
		policy = "remove-membership"
	case scim.DeleteIdentity:
		policy = "delete-identity"
	}
	entries := record.Mappings().Entries()
	out := ManagedConnectionView{TenantID: scope.TenantID, OrganizationID: scope.OrganizationID, ProviderID: scope.ProviderID, ConnectionID: scope.ProviderConnectionID, Mappings: make([]ManagedMappingView, len(entries)), DeprovisionPolicy: policy, Version: record.Version()}
	for i, mapping := range entries {
		out.Mappings[i] = ManagedMappingView{Source: mapping.Source.String(), Target: mapping.Target, Writable: mapping.Writable}
	}
	return out, nil
}
