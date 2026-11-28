package impersonationhttp

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/impersonation"
	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
)

const (
	quorumPath             = "/v1/impersonation/quorum"
	quorumOperation        = "identity.impersonation.quorum"
	maximumQuorumApprovals = 1 // The selected native Denial history supports one independent decision.
)

// QuorumService checks native authentication and exact grant permission. It
// calls admission synchronously with the authenticated actor before reading
// the grant, at most once, and never retains the callback.
type QuorumService interface {
	QuorumWithAdmission(context.Context, impersonationpg.QuorumInput, func(context.Context, identity.UserID) error) (impersonationpg.QuorumResult, error)
}

// QuorumRate is the canonical shared administrative quota, not a separate
// read budget. Admission success has no retry hint; only an audited limit
// decision returns ErrRateLimited with bounded whole seconds.
type QuorumRate interface {
	Configured() bool
	AdmitImpersonationQuorum(context.Context, identityhttp.NetworkFacts, identity.UserID) (time.Duration, error)
}

// QuorumConfig selects HTTPS tenant resolution, the login owner's original
// cookie, and the native read and shared rate owners. No CSRF is required.
type QuorumConfig struct {
	Network            identityhttp.NetworkConfig
	OriginalCookieName string
	Native             QuorumService
	Rate               QuorumRate
	MaximumDuration    time.Duration
}

// NewQuorumFeature selects only the administrator quorum read. It requires
// both native and configured rate owners and does not select a writer.
func NewQuorumFeature(c QuorumConfig) (identityhttp.Feature, error) {
	if !validOrdinaryCookie(c.OriginalCookieName, c.MaximumDuration) || missingOwner(c.Native) || missingOwner(c.Rate) || !c.Rate.Configured() {
		return identityhttp.Feature{}, identityhttp.ErrInvalidInput
	}
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		return identityhttp.Feature{}, err
	}
	h := quorumHandler{network: network, decoder: decoder, cookie: c.OriginalCookieName, duration: c.MaximumDuration, native: c.Native, rate: c.Rate}
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/impersonation", OperationID: quorumOperation, Handler: h,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384,
	})
	if err != nil {
		return identityhttp.Feature{}, err
	}
	op.Wire = quorumWire(c.OriginalCookieName)
	return identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/impersonation", Operations: []identityhttp.OperationDescriptor{op}})
}

type quorumHandler struct {
	network  *identityhttp.NetworkResolver
	decoder  *identityhttp.RequestDecoder
	cookie   string
	duration time.Duration
	native   QuorumService
	rate     QuorumRate
}

func (h quorumHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r == nil || r.URL == nil {
		writeQuorumFailure(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if r.URL.EscapedPath() != quorumPath || r.URL.Path != quorumPath {
		writeQuorumFailure(w, http.StatusNotFound, "not_found")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeQuorumFailure(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.duration)
	defer cancel()
	facts, input, err := h.decodeQuorum(r.WithContext(ctx))
	if err != nil {
		status, code := transportError(err)
		writeQuorumFailure(w, status, code)
		return
	}
	var attempted bool
	var retry time.Duration
	var admissionErr error
	result, err := h.native.QuorumWithAdmission(ctx, input, func(bounded context.Context, actor identity.UserID) error {
		if attempted || bounded == nil || bounded.Err() != nil || ctx.Err() != nil || !validQuorumUser(actor) {
			attempted, retry, admissionErr = true, 0, identity.UnavailableError{}
			return admissionErr
		}
		attempted = true
		retry, admissionErr = h.rate.AdmitImpersonationQuorum(bounded, facts, actor)
		if errors.Is(admissionErr, identityhttp.ErrRateLimited) && retry >= time.Second && retry <= time.Minute && retry%time.Second == 0 {
			return admissionErr
		}
		if admissionErr != nil || retry != 0 {
			admissionErr = identity.UnavailableError{}
		}
		return admissionErr
	})
	switch {
	case ctx.Err() != nil:
		writeQuorumFailure(w, http.StatusServiceUnavailable, "unavailable")
	case errors.Is(admissionErr, identityhttp.ErrRateLimited):
		w.Header().Set("Retry-After", strconv.FormatInt(int64(retry/time.Second), 10))
		writeQuorumFailure(w, http.StatusTooManyRequests, "rate_limited")
	case admissionErr != nil:
		writeQuorumFailure(w, http.StatusServiceUnavailable, "unavailable")
	case err != nil:
		status, code := transportError(err)
		if status != http.StatusBadRequest && status != http.StatusForbidden {
			status, code = http.StatusServiceUnavailable, "unavailable"
		}
		writeQuorumFailure(w, status, code)
	case !attempted || !validQuorumResult(result, input.GrantID):
		writeQuorumFailure(w, http.StatusServiceUnavailable, "unavailable")
	default:
		writeJSON(w, http.StatusOK, result)
	}
}

func (h quorumHandler) decodeQuorum(r *http.Request) (identityhttp.NetworkFacts, impersonationpg.QuorumInput, error) {
	// net/http uses a stream reader even for an empty HTTP/2 request. The
	// server enforces the zero HTTP/2 content length; never read that stream.
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		r.ProtoMajor != 2 && r.Body != nil && r.Body != http.NoBody {
		return identityhttp.NetworkFacts{}, impersonationpg.QuorumInput{}, identityhttp.DecodeError{}
	}
	if _, _, err := h.decoder.IdempotencyKey(r, identityhttp.HeaderForbidden); err != nil {
		return identityhttp.NetworkFacts{}, impersonationpg.QuorumInput{}, err
	}
	query, err := h.decoder.Query(r)
	if err != nil {
		return identityhttp.NetworkFacts{}, impersonationpg.QuorumInput{}, err
	}
	id, err := identity.ParseCommandID(query.Get("grantID"))
	if len(query) != 1 || err != nil {
		return identityhttp.NetworkFacts{}, impersonationpg.QuorumInput{}, identityhttp.DecodeError{}
	}
	facts, err := mappedHTTPSFacts(h.network, r)
	if err != nil {
		return identityhttp.NetworkFacts{}, impersonationpg.QuorumInput{}, err
	}
	bearer, present, err := h.decoder.CookieBearer(r, h.cookie, identityhttp.HeaderOptional)
	if err != nil {
		return identityhttp.NetworkFacts{}, impersonationpg.QuorumInput{}, err
	}
	if !present {
		return identityhttp.NetworkFacts{}, impersonationpg.QuorumInput{}, identity.ForbiddenError{}
	}
	return facts, impersonationpg.QuorumInput{Tenant: facts.TenantID(), Bearer: bearer, GrantID: impersonation.GrantID(id)}, nil
}

func validQuorumResult(result impersonationpg.QuorumResult, grant impersonation.GrantID) bool {
	count, required := len(result.Approvals), result.RequiredApprovals
	if result.GrantID != grant || result.Approvals == nil || required != maximumQuorumApprovals || count > required {
		return false
	}
	switch result.Status {
	case impersonation.StatusPendingApproval, impersonation.StatusDenied:
		if count != 0 {
			return false
		}
	case impersonation.StatusApproved, impersonation.StatusActive, impersonation.StatusStopped:
		if count != required {
			return false
		}
	case impersonation.StatusExpired, impersonation.StatusRevoked:
		// Both can follow a pending or an approved grant.
	default:
		return false
	}
	for _, approval := range result.Approvals {
		if !validQuorumUser(approval.ApproverID) || approval.DecidedAt.IsZero() ||
			approval.DecidedAt.Year() < 1 || approval.DecidedAt.Year() > 9999 {
			return false
		}
	}
	return true
}

func validQuorumUser(id identity.UserID) bool {
	if len(id) == 0 || len(id) > 128 || !utf8.ValidString(string(id)) {
		return false
	}
	for _, c := range id {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	return true
}

func writeQuorumFailure(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: code})
}
