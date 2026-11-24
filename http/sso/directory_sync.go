package ssohttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

const (
	directoryStart  = "identity.sso.directory-sync-start"
	directoryStatus = "identity.sso.directory-sync-status"
	directoryCancel = "identity.sso.directory-sync-cancel"
	// The cookie synchronizer cannot precede session issuance. Bound that
	// original age as required by the canonical HTTP CSRF policy, without
	// changing the native owner's much shorter current-authority lease.
	directoryCSRFMaximumAge = 24 * time.Hour
)

// DirectoryBrowser conveys the original cookie and optional write CSRF from
// a mapped HTTPS tenant. It is not a principal proof. The native owner must
// authenticate this original custody and recheck the exact operation scope.
type DirectoryBrowser struct {
	TenantID identity.TenantID
	Network  netip.Addr
	Cookie   authentication.BearerCredential
	CSRF     session.CSRFToken
}

func (DirectoryBrowser) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("ssohttp.DirectoryBrowser(redacted)"))
}

func (DirectoryBrowser) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
func (DirectoryBrowser) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// DirectoryStartRequest names the exact provider and mapping revisions selected
// by the caller. A zero Checkpoint requests the configured source's initial
// position. The native owner establishes command identity from the original Key.
type DirectoryStartRequest struct {
	ProviderID                      sso.ProviderID
	ProviderVersion, MappingVersion uint64
	Mode                            string
	Checkpoint                      [32]byte
	Key                             identity.IdempotencyKey
}

// DirectoryGeneration is the safe native projection, not source/apply authority.
// Checkpoint is a commitment rather than a raw provider cursor or credential.
type DirectoryGeneration struct {
	ID                                       identity.CommandID
	ProviderID                               sso.ProviderID
	Version, ProviderVersion, MappingVersion uint64
	State, Mode                              string
	Checkpoint                               [32]byte
	ReadCount, AppliedCount, RejectedCount   uint64
}

// DirectorySyncOwner authenticates the original browser session for each call.
// It retains exact tenant/organization/source scope, current session and native
// action authorization, synchronizer checks under Work, and original retry
// custody. Cancel uses native natural-repeat identity for the exact generation
// and predecessor, never a transport retry key. Calls must be bounded by ctx
// and support concurrent requests. Direct directory apply is not part of this port.
type DirectorySyncOwner interface {
	StartDirectorySync(context.Context, DirectoryBrowser, DirectoryStartRequest) (DirectoryGeneration, identity.CommandResult, error)
	StatusDirectorySync(context.Context, DirectoryBrowser, identity.CommandID) (DirectoryGeneration, error)
	CancelDirectorySync(context.Context, DirectoryBrowser, identity.CommandID, uint64) (DirectoryGeneration, identity.CommandResult, error)
}

// DirectoryAdminRate is the finite directory Start/Cancel entry into the
// canonical shared admin budget. A nil error means admitted; Retry-After is
// meaningful only on an audited ErrRateLimited result.
type DirectoryAdminRate interface {
	Configured() bool
	AdmitDirectorySync(context.Context, identityhttp.NetworkFacts, string, identity.UserID) (time.Duration, error)
}

// DirectorySyncConfig opts into the browser directory control plane only.
// Sessions must be the current primary, not a cached positive read model. It
// identifies the rate subject and does not replace the Owner's native checks.
// Share both rate owners with other applicable routes and keep dependencies
// alive and concurrency-safe for the handler's lifetime. TrustedOrigins names
// exact mapped HTTPS origins; Referer and bearer fallback are never accepted.
type DirectorySyncConfig struct {
	Network         identityhttp.NetworkConfig
	TrustedOrigins  []identityhttp.Origin
	Cookie          session.CookiePolicy
	Sessions        *session.SessionService
	SafeRate        *identityhttp.SafeRateLimiter
	AdminRate       DirectoryAdminRate
	Owner           DirectorySyncOwner
	Now             func() time.Time
	MaximumDuration time.Duration
}

type directoryHTTP struct {
	config  DirectorySyncConfig
	network *identityhttp.NetworkResolver
	decoder *identityhttp.RequestDecoder
	csrf    *identityhttp.CSRFDecoder
	cookie  string
}

type directoryHTTPState struct {
	facts      identityhttp.NetworkFacts
	browser    DirectoryBrowser
	credential session.Credential
	read       session.GetResult
	user       identity.UserID
	start      DirectoryStartRequest
	generation identity.CommandID
	version    uint64
}

// NewDirectorySyncFeature selects only Start, Status and Cancel and publishes
// their exact OpenAPI wire. Start requires a retained Idempotency-Key, Status
// returns the current generation version, and Cancel is a keyless exact repeat.
// Apply is deliberately not routable. Selection does not perform native work.
func NewDirectorySyncFeature(c DirectorySyncConfig) (identityhttp.Feature, error) {
	invalid := func() (identityhttp.Feature, error) { return identityhttp.Feature{}, identityhttp.ErrInvalidInput }
	if !c.Sessions.Configured() || !c.SafeRate.Configured() || !configuredOwner(c.AdminRate) || !c.AdminRate.Configured() || !configuredOwner(c.Owner) || c.Now == nil || c.MaximumDuration < time.Millisecond || c.MaximumDuration > 5*time.Second || len(c.Network.TenantHosts) == 0 {
		return invalid()
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return invalid()
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return invalid()
	}
	cookie, err := c.Cookie.DeletionAttributes()
	if err != nil {
		return invalid()
	}
	origins, err := identityhttp.NewOriginGuard(identityhttp.OriginGuardConfig{Network: network, TrustedOrigins: c.TrustedOrigins, RefererFallback: identityhttp.RefererFallbackDeny})
	if err != nil {
		return invalid()
	}
	csrf, err := identityhttp.NewCSRFDecoder(identityhttp.CSRFDecoderConfig{Origins: origins, FormField: "csrf_token"})
	if err != nil {
		return invalid()
	}
	h := directoryHTTP{config: c, network: network, decoder: decoder, csrf: csrf, cookie: cookie.Name}
	operations := make([]identityhttp.OperationDescriptor, 0, 3)
	for _, id := range []string{directoryStart, directoryStatus, directoryCancel} {
		handler, err := h.pipeline(id)
		if err != nil {
			return invalid()
		}
		policy := identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
		if id != directoryStatus {
			policy = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionOriginAndToken, TokenHeader: "X-CSRF-Token", TokenMaximumAge: directoryCSRFMaximumAge, RefererFallback: identityhttp.RefererFallbackDeny}
		}
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "sso", OperationID: id, Handler: handler, CSRF: policy, MaximumSerializedBytes: 8192})
		if err != nil {
			return invalid()
		}
		op.Wire = directorySyncWire(id, cookie.Name)
		operations = append(operations, op)
	}
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso", Operations: operations})
}

func (h directoryHTTP) pipeline(op string) (http.Handler, error) {
	return identityhttp.NewOperationPipeline(identityhttp.OperationPipelineConfig[directoryHTTPState]{
		MaximumDuration: h.config.MaximumDuration, Reject: writeSigninError,
		Decode: func(r *http.Request) (directoryHTTPState, error) { return h.decode(r, op) },
		Authenticate: func(r *http.Request, s directoryHTTPState) (directoryHTTPState, error) {
			read, err := h.config.Sessions.Get(r.Context(), session.GetRequest{TenantID: s.browser.TenantID, Credential: s.credential})
			if err != nil {
				return s, sso.ErrUnavailable
			}
			bound, err := read.Session.Bindings()
			if err != nil || bound.TenantID != s.browser.TenantID || read.ValidateAt(h.config.Now()) != nil || read.Session.CSRFState() == (session.CSRFState{}) {
				return s, sso.ErrForbidden
			}
			if op != directoryStatus && !h.config.Now().Before(bound.IssuedAt.Add(directoryCSRFMaximumAge)) {
				return s, sso.ErrForbidden
			}
			s.read, s.user = read, bound.UserID
			return s, nil
		},
		Admit: func(r *http.Request, s directoryHTTPState) error {
			var retry time.Duration
			var err error
			if op == directoryStatus {
				var result identityhttp.SafeRateResult
				result, err = h.config.SafeRate.Admit(r.Context(), s.facts, op, s.user)
				retry = result.RetryAfter
				if err == nil && !result.Allowed {
					err = identityhttp.ErrRateUnavailable
				}
			} else {
				retry, err = h.config.AdminRate.AdmitDirectorySync(r.Context(), s.facts, op, s.user)
			}
			if errors.Is(err, identityhttp.ErrRateLimited) {
				return discoveryRateDenial{retry: retry}
			}
			if err != nil || s.read.ValidateAt(h.config.Now()) != nil {
				return sso.ErrUnavailable
			}
			return nil
		},
		Handle: func(w http.ResponseWriter, r *http.Request, s directoryHTTPState) { h.execute(w, r, op, s) },
	})
}

func (h directoryHTTP) decode(r *http.Request, op string) (directoryHTTPState, error) {
	var s directoryHTTPState
	method := http.MethodPost
	if op == directoryStatus {
		method = http.MethodGet
	}
	path := "/v1/sso/" + strings.TrimPrefix(op, "identity.sso.")
	if r.URL == nil || r.Method != method || r.URL.Path != path || r.URL.EscapedPath() != path || r.URL.ForceQuery || len(r.Trailer) != 0 {
		return s, identityhttp.ErrInvalidInput
	}
	facts, err := h.network.Resolve(r)
	if err != nil || facts.Realm() != identityhttp.RealmTenant || facts.Scheme() != "https" || !discoveryHeadersAllowed(r, facts) {
		return s, sso.ErrForbidden
	}
	if _, _, err = h.decoder.Bearer(r, identityhttp.HeaderForbidden); err != nil {
		return s, identityhttp.ErrInvalidInput
	}
	keyMode := identityhttp.HeaderForbidden
	if op == directoryStart {
		keyMode = identityhttp.HeaderRequired
	}
	key, _, err := h.decoder.IdempotencyKey(r, keyMode)
	if err != nil {
		return s, identityhttp.ErrInvalidInput
	}
	cookie, _, err := h.decoder.CookieBearer(r, h.cookie, identityhttp.HeaderRequired)
	if err != nil {
		return s, sso.ErrForbidden
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return s, sso.ErrForbidden
	}
	s.credential, err = session.NewCredential(session.CredentialCookie, token)
	if err != nil {
		return s, sso.ErrForbidden
	}
	s.facts = facts
	s.browser = DirectoryBrowser{TenantID: facts.TenantID(), Network: facts.ClientIP(), Cookie: cookie}
	if op == directoryStatus {
		query, err := h.decoder.Query(r)
		if err != nil || len(query) != 1 || r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) || headerPresent(r.Header, "X-CSRF-Token") {
			return s, identityhttp.ErrInvalidInput
		}
		s.generation, err = identity.ParseCommandID(query.Get("generationID"))
		if err != nil {
			return s, identityhttp.ErrInvalidInput
		}
		return s, nil
	}
	if r.URL.RawQuery != "" {
		return s, identityhttp.ErrInvalidInput
	}
	s.browser.CSRF, _, err = identityhttp.DecodeCSRF(h.csrf, r, session.ParseCSRFToken)
	if err != nil {
		return s, sso.ErrForbidden
	}
	body, err := identityhttp.DecodeJSON[map[string]json.RawMessage](h.decoder, r)
	if err != nil {
		return s, identityhttp.ErrInvalidInput
	}
	if op == directoryStart {
		s.start, err = directoryDecodeStart(body, key)
	} else {
		var id string
		if len(body) != 2 || json.Unmarshal(body["generationID"], &id) != nil || json.Unmarshal(body["expectedVersion"], &s.version) != nil || s.version == 0 || s.version == math.MaxUint64 {
			return s, identityhttp.ErrInvalidInput
		}
		s.generation, err = identity.ParseCommandID(id)
	}
	if err != nil {
		return s, identityhttp.ErrInvalidInput
	}
	return s, nil
}

func directoryDecodeStart(body map[string]json.RawMessage, key identity.IdempotencyKey) (DirectoryStartRequest, error) {
	var r DirectoryStartRequest
	checkpoint, supplied := body["sourceCursor"]
	want := 4
	if supplied {
		want++
	}
	if len(body) != want || json.Unmarshal(body["providerID"], &r.ProviderID) != nil ||
		json.Unmarshal(body["providerVersion"], &r.ProviderVersion) != nil || json.Unmarshal(body["mappingVersion"], &r.MappingVersion) != nil ||
		json.Unmarshal(body["mode"], &r.Mode) != nil || !directoryProviderID(r.ProviderID) || r.ProviderVersion == 0 || r.MappingVersion == 0 || !directoryMode(r.Mode) {
		return r, identityhttp.ErrInvalidInput
	}
	if supplied {
		var wire string
		if json.Unmarshal(checkpoint, &wire) != nil || len(wire) != base64.RawURLEncoding.EncodedLen(32) {
			return r, identityhttp.ErrInvalidInput
		}
		n, err := base64.RawURLEncoding.Strict().Decode(r.Checkpoint[:], []byte(wire))
		if err != nil || n != len(r.Checkpoint) || r.Checkpoint == ([32]byte{}) {
			return r, identityhttp.ErrInvalidInput
		}
	}
	r.Key = key
	return r, nil
}

func directoryMode(mode string) bool { return mode == "apply" || mode == "dry-run" }

func directoryProviderID(id sso.ProviderID) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, b := range []byte(id) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}

func (h directoryHTTP) execute(w http.ResponseWriter, r *http.Request, op string, s directoryHTTPState) {
	ctx := r.Context()
	if ctx.Err() != nil || s.read.ValidateAt(h.config.Now()) != nil {
		writeSigninError(w, r, sso.ErrUnavailable)
		return
	}
	var g DirectoryGeneration
	var receipt identity.CommandResult
	var err error
	switch op {
	case directoryStart:
		g, receipt, err = h.config.Owner.StartDirectorySync(ctx, s.browser, s.start)
	case directoryStatus:
		g, err = h.config.Owner.StatusDirectorySync(ctx, s.browser, s.generation)
	case directoryCancel:
		g, receipt, err = h.config.Owner.CancelDirectorySync(ctx, s.browser, s.generation, s.version)
	}
	if err != nil {
		writeSigninError(w, r, err)
		return
	}
	if ctx.Err() != nil || s.read.ValidateAt(h.config.Now()) != nil || !directoryResultValid(op, s, g, receipt) {
		writeSigninError(w, r, sso.ErrUnavailable)
		return
	}
	checkpoint := base64.RawURLEncoding.EncodeToString(g.Checkpoint[:])
	reconciling := g.State == "reconciling" || g.State == "canceling"
	switch op {
	case directoryStart:
		writeDiscoveryJSON(w, http.StatusOK, directoryStartResponse{g.ID, g.ProviderID, g.MappingVersion, g.Mode, directoryCompletion{receipt.Binding.CommandID, "committed"}})
	case directoryStatus:
		writeDiscoveryJSON(w, http.StatusOK, directoryStatusResponse{g.ID, g.Version, g.State, g.ReadCount, g.AppliedCount, g.RejectedCount, checkpoint, []string{"direct-group-edges-only"}, reconciling})
	case directoryCancel:
		writeDiscoveryJSON(w, http.StatusOK, directoryCancelResponse{g.ID, true, g.State, checkpoint, reconciling, directoryCompletion{receipt.Binding.CommandID, "committed"}})
	}
}

func directoryResultValid(op string, request directoryHTTPState, g DirectoryGeneration, receipt identity.CommandResult) bool {
	if _, err := identity.ParseCommandID(string(g.ID)); err != nil || g.Version == 0 || g.Checkpoint == ([32]byte{}) ||
		g.AppliedCount > g.ReadCount || g.RejectedCount > g.ReadCount-g.AppliedCount {
		return false
	}
	if op != directoryStart && request.generation != g.ID {
		return false
	}
	if op == directoryStatus {
		switch g.State {
		case "running", "reconciling", "canceling", "canceled", "finished":
			return true
		default:
			return false
		}
	}
	b := receipt.Binding
	if receipt.Validate() != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil ||
		receipt.Feature.Operation.Owner != "sso" || b.OperationID != op || b.ActorKind != authorization.SubjectUser ||
		b.TenantID != request.browser.TenantID || b.UserID != request.user || b.ActorID != identity.ActorID(request.user) || b.RecordID != string(g.ID) {
		return false
	}
	if op == directoryStart {
		return b.CommandID == g.ID && g.State == "running" && g.Version == 1 && g.ReadCount == 0 &&
			g.ProviderID == request.start.ProviderID && g.ProviderVersion == request.start.ProviderVersion && g.MappingVersion == request.start.MappingVersion && g.Mode == request.start.Mode &&
			(request.start.Checkpoint == ([32]byte{}) || request.start.Checkpoint == g.Checkpoint) &&
			receipt.Feature.BeforeVersion == 0 && receipt.Feature.AfterVersion == g.Version
	}
	return (g.State == "canceled" || g.State == "canceling") && receipt.Feature.BeforeVersion == request.version &&
		receipt.Feature.AfterVersion == request.version+1 && g.Version >= receipt.Feature.AfterVersion
}

type directoryCompletion struct {
	CommandID identity.CommandID `json:"commandID"`
	Outcome   string             `json:"outcome"`
}

type directoryStartResponse struct {
	GenerationID   identity.CommandID  `json:"generationID"`
	ProviderID     sso.ProviderID      `json:"providerID"`
	MappingVersion uint64              `json:"mappingVersion"`
	Mode           string              `json:"mode"`
	Completion     directoryCompletion `json:"completion"`
}

type directoryStatusResponse struct {
	GenerationID           identity.CommandID `json:"generationID"`
	Version                uint64             `json:"version"`
	State                  string             `json:"state"`
	ReadCount              uint64             `json:"readCount"`
	AppliedCount           uint64             `json:"appliedCount"`
	RejectedCount          uint64             `json:"rejectedCount"`
	Checkpoint             string             `json:"checkpoint"`
	Limitations            []string           `json:"limitations"`
	ReconciliationRequired bool               `json:"reconciliationRequired"`
}

type directoryCancelResponse struct {
	GenerationID           identity.CommandID  `json:"generationID"`
	Stopped                bool                `json:"stopped"`
	State                  string              `json:"state"`
	Checkpoint             string              `json:"checkpoint"`
	ReconciliationRequired bool                `json:"reconciliationRequired"`
	Completion             directoryCompletion `json:"completion"`
}
