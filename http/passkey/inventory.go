package passkeyhttp

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// CredentialMetadata is the explicit safe self-user JSON projection. ReferenceID
// is not an RP credential ID. AAGUID/backup state are verified native metadata;
// labels remain untrusted display text. No key, handle, counter or proof appears.
type CredentialMetadata struct {
	ReferenceID    string     `json:"referenceID"`
	Version        uint64     `json:"version"`
	State          string     `json:"state"`
	Label          string     `json:"label"`
	AAGUID         [16]byte   `json:"aaguid"`
	BackupEligible bool       `json:"backupEligible"`
	BackupState    bool       `json:"backupState"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
}

// InventoryResponse owns one bounded safe page. Next is an exclusive keyset
// cursor, not authority or a stable snapshot of subsequent reads.
type InventoryResponse struct {
	Credentials []CredentialMetadata `json:"credentials"`
	Next        string               `json:"next,omitempty"`
}

// InventoryState retains private actual session custody for the current read.
// Hooks cannot select another user or extend the owner's original validity.
type InventoryState struct{ *inventoryState }
type inventoryState struct {
	facts      identityhttp.NetworkFacts
	credential session.Credential
	present    bool
	read       session.GetResult
	request    passkey.InventoryRequest
}

// Principal returns detached credential-free metadata, never reusable authority.
func (s InventoryState) Principal() (identity.TenantID, identity.UserID, bool) {
	if s.inventoryState == nil || !s.read.Authenticated {
		return "", "", false
	}
	spec, err := s.read.Session.Bindings()
	return spec.TenantID, spec.UserID, err == nil
}
func (InventoryState) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("passkeyhttp.InventoryState(redacted)"))
}

// MarshalJSON prohibits implicit private custody export.
func (InventoryState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText prohibits implicit private custody export.
func (InventoryState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// NewListHandler selects only GET /v1/passkey/list. It permits bounded after
// and limit query fields, no target/credential alternatives or body. Actual
// session custody and shared safe admission precede the single native safe
// inventory call; native read-risk/authorization remain independent owners.
func NewListHandler(c InventoryConfig) (http.Handler, error) {
	return NewListHandlerWithMiddleware(c, nil)
}

// NewListHandlerWithMiddleware preserves original session validity through
// bounded native reads and final response delivery, with no cookie mutation.
func NewListHandlerWithMiddleware(c InventoryConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || absent(c.Service) || !c.Rate.Configured() || c.PolicyRevision == 0 || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return nil, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return nil, err
	}
	cookie, err := c.SessionCookie.DeletionAttributes()
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[InventoryState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (InventoryState, error) {
			s := InventoryState{&inventoryState{}}
			s.request.Limit = 100
			if r.URL.Path != "/v1/passkey/list" || r.URL.EscapedPath() != r.URL.Path {
				return s, failure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodGet {
				return s, failure{status: 405, code: "method_not_allowed", allow: http.MethodGet}
			}
			if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.Trailer) != 0 || r.URL.ForceQuery {
				return s, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name := range r.Header {
				if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-CSRF-Token") {
					return s, identityhttp.ErrInvalidInput
				}
			}
			query, err := decoder.Query(r)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			for name, values := range query {
				if len(values) != 1 {
					return s, identityhttp.ErrInvalidInput
				}
				switch name {
				case "after":
					if _, err := identity.ParseIdentifierID(values[0]); err != nil {
						return s, identityhttp.ErrInvalidInput
					}
					s.request.After = values[0]
				case "limit":
					limit, err := strconv.Atoi(values[0])
					if err != nil || limit < 1 || limit > 100 || strconv.Itoa(limit) != values[0] {
						return s, identityhttp.ErrInvalidInput
					}
					s.request.Limit = limit
				default:
					return s, identityhttp.ErrInvalidInput
				}
			}
			s.facts, err = network.Resolve(r)
			if err != nil || s.facts.Realm() != identityhttp.RealmTenant {
				return s, failure{status: 421, code: "misdirected_request"}
			}
			if s.facts.Scheme() != "https" {
				return s, failure{status: 403, code: "https_required"}
			}
			for name, values := range r.Header {
				if strings.EqualFold(name, "Origin") && (len(values) != 1 || values[0] != s.facts.Origin()) {
					return s, failure{status: 403, code: "origin_denied"}
				}
			}
			bearer, present, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderOptional)
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.present = present
			if !present {
				return s, nil
			}
			token, err := session.ParseToken(bearer.Token())
			if err != nil {
				return s, identityhttp.ErrInvalidInput
			}
			s.credential, err = session.NewCredential(session.CredentialCookie, token)
			return s, err
		},
		Authenticate: func(r *http.Request, s InventoryState) (InventoryState, error) {
			if !s.present {
				return s, nil
			}
			var err error
			s.read, err = c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if !s.read.Authenticated {
				return s, nil
			}
			if s.read.ValidateAt(c.Now()) != nil {
				return s, identityhttp.ErrUnavailable
			}
			spec, err := s.read.Session.Bindings()
			if err != nil || spec.TenantID != s.facts.TenantID() {
				return s, identityhttp.ErrUnavailable
			}
			attempt, err := identity.NewCommandID()
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			s.request.Credential = s.credential
			s.request.AttemptID = attempt
			s.request.Caller = authorization.DecisionContext{PolicyRevision: c.PolicyRevision, CorrelationID: string(attempt), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(spec.UserID)}, Tenant: authorization.TenantID(spec.TenantID), Action: "identity.passkey.list", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(spec.UserID)}}}
			requestDelivery(r).valid = func() bool { return s.read.ValidateAt(c.Now()) == nil }
			return s, nil
		},
		Admit: func(r *http.Request, s InventoryState) error {
			_, user, _ := s.Principal()
			result, err := c.Rate.Admit(r.Context(), s.facts, "identity.passkey.list", user)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return failure{status: 429, code: "rate_limited", retry: result.RetryAfter}
			}
			if err != nil || !result.Allowed {
				return identityhttp.ErrUnavailable
			}
			if !s.read.Authenticated {
				return failure{status: 401, code: "unauthenticated"}
			}
			if s.read.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s InventoryState) {
			if s.read.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			page, err := c.Service.List(r.Context(), s.request)
			if err != nil {
				reject(w, r, domainFailure(err))
				return
			}
			if len(page.Credentials) > s.request.Limit {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			if page.Next != "" {
				if _, err := identity.ParseIdentifierID(page.Next); err != nil {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
			}
			response := InventoryResponse{Credentials: make([]CredentialMetadata, 0, len(page.Credentials)), Next: page.Next}
			for _, item := range page.Credentials {
				if _, err := identity.ParseIdentifierID(item.ReferenceID); err != nil || item.Version == 0 || len(item.Label) > 128 || !utf8.ValidString(item.Label) || item.CreatedAt.IsZero() {
					reject(w, r, identityhttp.ErrUnavailable)
					return
				}
				response.Credentials = append(response.Credentials, CredentialMetadata{item.ReferenceID, item.Version, item.State, item.Label, item.AAGUID, item.BackupEligible, item.BackupState, item.CreatedAt, item.LastUsedAt})
			}
			requestDelivery(r).render(w, r, response, func() bool { return s.read.ValidateAt(c.Now()) == nil })
		},
	})
	if err != nil {
		return nil, err
	}
	return &protectedPipeline{pipeline: h, maximum: c.MaximumDuration}, nil
}
