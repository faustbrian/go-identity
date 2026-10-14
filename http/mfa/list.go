package mfahttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// ListConfig selects cookie-only authenticated safe metadata disclosure. Owners
// are borrowed and must be bounded/concurrency-safe. Share Rate with all safe
// routes. Now is the trusted prompt clock; MaximumDuration is 1ms..30s and
// original session validity/caller deadlines always win. Construction does no IO.
type ListConfig struct {
	Network         identityhttp.NetworkConfig
	Sessions        *session.SessionService
	Service         mfa.FactorListingService
	Rate            *identityhttp.SafeRateLimiter
	Cookie          session.CookiePolicy
	Now             func() time.Time
	MaximumDuration time.Duration
}

// Format redacts borrowed session and policy ownership.
func (ListConfig) Format(s fmt.State, _ rune) { s.Write([]byte("mfahttp.ListConfig(redacted)")) }

type listState struct {
	facts      identityhttp.NetworkFacts
	credential session.Credential
	original   session.GetResult
	user       identity.UserID
}

func (listState) Format(s fmt.State, _ rune)   { s.Write([]byte("mfahttp.listState(redacted)")) }
func (listState) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (listState) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

type listFailure struct {
	status int
	code   string
	retry  time.Duration
}

func (e listFailure) Error() string { return "mfahttp: " + e.code }

// NewListHandler constructs only GET /v1/mfa/list, never registers it. It accepts
// the exact host-mapped HTTPS tenant and one session cookie; Authorization,
// idempotency keys, query/body/trailers and target-user overrides are forbidden.
// It performs no CSRF-protected mutation and sends no cookie, credential, proof,
// redirect or secret. All responses are no-store JSON. Native policy/current
// authority remain decisive; rate/middleware waits cannot renew original expiry.
func NewListHandler(c ListConfig) (http.Handler, error) { return NewListHandlerWithMiddleware(c, nil) }

// NewListHandlerWithMiddleware exposes actual synchronous decode/authenticate/
// safe-admission/native-read phases. Private state contains original owner
// custody, not reusable middleware authority. Final-status/body guards retain
// no-store/no-credential policy across hook short circuits and streaming writes.
func NewListHandlerWithMiddleware(c ListConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	if !c.Sessions.Configured() || enableNil(c.Service) || !c.Rate.Configured() || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 30*time.Second {
		return nil, identityhttp.ErrInvalidInput
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
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
	reject := func(w http.ResponseWriter, _ *http.Request, err error) {
		failure := listFailure{status: 503, code: "unavailable"}
		var specific listFailure
		if errors.As(err, &specific) {
			failure = specific
		} else if errors.Is(err, identityhttp.ErrInvalidInput) {
			failure = listFailure{status: 400, code: "invalid_request"}
		}
		if failure.status == 405 {
			w.Header().Set("Allow", http.MethodGet)
		}
		if failure.retry > 0 {
			w.Header().Set("Retry-After", strconv.FormatInt(int64((failure.retry+time.Second-1)/time.Second), 10))
		}
		w.WriteHeader(failure.status)
		_, _ = w.Write([]byte(`{"error":"` + failure.code + `"}`))
	}
	h, err := identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[listState]{MaximumDuration: c.MaximumDuration, Middleware: m, Reject: reject,
		Decode: func(r *http.Request) (listState, error) {
			zero := listState{}
			if r.URL.Path != "/v1/mfa/list" || r.URL.EscapedPath() != "/v1/mfa/list" {
				return zero, listFailure{status: 404, code: "not_found"}
			}
			if r.Method != http.MethodGet {
				return zero, listFailure{status: 405, code: "method_not_allowed"}
			}
			if _, _, err := decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			if _, _, err := decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || (r.Body != nil && r.Body != http.NoBody) || len(r.Trailer) != 0 {
				return zero, identityhttp.ErrInvalidInput
			}
			facts, err := network.Resolve(r)
			if err != nil {
				return zero, listFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Realm() != identityhttp.RealmTenant {
				return zero, listFailure{status: 421, code: "misdirected_request"}
			}
			if facts.Scheme() != "https" {
				return zero, identityhttp.ErrInvalidInput
			}
			bearer, present, err := decoder.CookieBearer(r, cookie.Name, identityhttp.HeaderOptional)
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			if !present {
				return zero, listFailure{status: 403, code: "denied"}
			}
			token, err := session.ParseToken(bearer.Token())
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			credential, err := session.NewCredential(session.CredentialCookie, token)
			if err != nil {
				return zero, identityhttp.ErrInvalidInput
			}
			return listState{facts: facts, credential: credential}, nil
		},
		Authenticate: func(r *http.Request, s listState) (listState, error) {
			got, err := c.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.facts.TenantID(), Credential: s.credential})
			if err != nil {
				return s, identityhttp.ErrUnavailable
			}
			if got.ValidateAt(c.Now()) != nil {
				return s, listFailure{status: 403, code: "denied"}
			}
			b, err := got.Session.Bindings()
			if err != nil || b.TenantID != s.facts.TenantID() || b.Authentication.Kind == session.AuthenticationAnonymous {
				return s, listFailure{status: 403, code: "denied"}
			}
			s.original, s.user = got, b.UserID
			return s, nil
		},
		Admit: func(r *http.Request, s listState) error {
			admitted, err := c.Rate.Admit(r.Context(), s.facts, "identity.mfa.list", s.user)
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return listFailure{status: 429, code: "rate_limited", retry: admitted.RetryAfter}
			}
			if err != nil || !admitted.Allowed || r.Context().Err() != nil || s.original.ValidateAt(c.Now()) != nil {
				return identityhttp.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s listState) {
			if s.original.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			// This fixed read correlation grants no authority and creates no
			// execution command, journal, replay identity or entropy dependency.
			out, err := c.Service.List(r.Context(), mfa.ListRequest{TenantID: s.facts.TenantID(), Credential: s.credential, CorrelationID: "identity.mfa.list"})
			var denied identity.ForbiddenError
			if errors.As(err, &denied) {
				reject(w, r, listFailure{status: 403, code: "denied"})
				return
			}
			if err != nil || r.Context().Err() != nil || s.original.ValidateAt(c.Now()) != nil || out.ValidateAt(c.Now()) != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			body, err := listBody(out)
			if err != nil {
				reject(w, r, identityhttp.ErrUnavailable)
				return
			}
			defer clear(body)
			writeSecretJSON(w, r, body, map[string]any{}, func() bool { return s.original.ValidateAt(c.Now()) == nil })
		},
	})
	if err != nil {
		return nil, err
	}
	return &enablePipeline{pipeline: h}, nil
}

func listBody(out mfa.ListResult) ([]byte, error) {
	// Closed DTOs exclude transaction outcomes, authority generations and all
	// credential/proof/digest fields. Optional timestamps are omitted, not year1.
	type factor struct {
		ID         mfa.FactorID    `json:"id"`
		Method     string          `json:"method"`
		Label      string          `json:"label,omitempty"`
		State      mfa.FactorState `json:"state"`
		CreatedAt  time.Time       `json:"createdAt"`
		LastUsedAt *time.Time      `json:"lastUsedAt,omitempty"`
		Version    uint64          `json:"version"`
	}
	type device struct {
		ID         mfa.TrustedDeviceID `json:"id"`
		Label      string              `json:"label,omitempty"`
		ExpiresAt  time.Time           `json:"expiresAt"`
		LastUsedAt *time.Time          `json:"lastUsedAt,omitempty"`
		Version    uint64              `json:"version"`
	}
	factors := make([]factor, 0, len(out.Factors))
	devices := make([]device, 0, len(out.TrustedDevices))
	for _, v := range out.Factors {
		f := factor{ID: v.ID, Method: v.Method, Label: v.Label, State: v.State, CreatedAt: v.CreatedAt.UTC(), Version: v.Version}
		if !v.LastUsedAt.IsZero() {
			t := v.LastUsedAt.UTC()
			f.LastUsedAt = &t
		}
		factors = append(factors, f)
	}
	for _, v := range out.TrustedDevices {
		d := device{ID: v.ID, Label: v.Label, ExpiresAt: v.ExpiresAt.UTC(), Version: v.Version}
		if !v.LastUsedAt.IsZero() {
			t := v.LastUsedAt.UTC()
			d.LastUsedAt = &t
		}
		devices = append(devices, d)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(struct {
		Factors           []factor `json:"factors"`
		TrustedDevices    []device `json:"trustedDevices"`
		RecoveryCodeCount uint32   `json:"recoveryCodeCount"`
	}{factors, devices, out.RecoveryCodeCount}) != nil || buffer.Len() > 262144 {
		return nil, identityhttp.ErrUnavailable
	}
	return buffer.Bytes(), nil
}
