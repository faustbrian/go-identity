package mfahttp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

// DisableConfig independently selects cookie-only native sole-TOTP disable.
// Borrowed session, original signed-proof, keyed shared quota and mutation
// owners must be bounded/concurrency-safe. Exact trusted origins and policy
// revision are startup inputs. No route, service or fallback is implicit.
type DisableConfig struct {
	Network                     identityhttp.NetworkConfig
	Sessions                    *session.SessionService
	Proofs                      auth.ReauthenticationSource
	Service                     mfa.DisableService
	Rate                        *identityhttp.KeyedSecretRateLimiter
	Cookie                      session.CookiePolicy
	TrustedOrigins              []identityhttp.Origin
	PolicyRevision              authorization.Revision
	Now                         func() time.Time
	MaximumDuration, MaximumAge time.Duration
}

// NewDisableHandler owns POST /v1/mfa/disable without registration. Closed JSON
// takes target one/all, conditional factorID and proofID. Optimistic authority
// comes from original signed proof custody. All forbids factorID even null/empty.
// cookie, CSRF, Origin and one Idempotency-Key are required. No command override,
// secret output, authenticated successor cookie or replacement proof is allowed.
func NewDisableHandler(c DisableConfig) (http.Handler, error) {
	return NewDisableHandlerWithMiddleware(c, nil)
}

// NewDisableHandlerWithMiddleware binds hooks to the shared real guarded
// phases, preserving original deadlines and the distinct native disable owner.
func NewDisableHandlerWithMiddleware(c DisableConfig, m []identityhttp.MiddlewareDescriptor) (http.Handler, error) {
	base := FactorUpdateConfig{Network: c.Network, Sessions: c.Sessions, Proofs: c.Proofs, Rate: c.Rate, Cookie: c.Cookie, TrustedOrigins: c.TrustedOrigins, PolicyRevision: c.PolicyRevision, Now: c.Now, MaximumDuration: c.MaximumDuration, MaximumAge: c.MaximumAge}
	return newFactorMutationHandler(base, m, &c)
}

func decodeDisableBody(s factorUpdateHTTPState, body map[string]json.RawMessage) (factorUpdateHTTPState, error) {
	bad := func() (factorUpdateHTTPState, error) { return s, identityhttp.ErrInvalidInput }
	if len(body) < 2 || len(body) > 3 {
		return bad()
	}
	var target, proof, factor string
	for name, dst := range map[string]*string{"target": &target, "proofID": &proof} {
		raw, ok := body[name]
		if !ok || len(raw) < 2 || raw[0] != '"' || json.Unmarshal(raw, dst) != nil {
			return bad()
		}
	}
	switch target {
	case "one":
		raw, ok := body["factorID"]
		if !ok || len(body) != 3 || len(raw) < 2 || raw[0] != '"' || json.Unmarshal(raw, &factor) != nil {
			return bad()
		}
		id, err := identity.ParseCommandID(factor)
		if err != nil {
			return bad()
		}
		s.factor = mfa.FactorID(id)
		s.target = mfa.OneFactor
	case "all":
		if _, present := body["factorID"]; present || len(body) != 2 {
			return bad()
		}
		s.target = mfa.AllFactors
	default:
		return bad()
	}
	id, err := identity.ParseCommandID(proof)
	if err != nil {
		return bad()
	}
	s.base.proofID = auth.ProofID(id)
	return s, nil
}

func validDisableFactors(out mfa.DisableResult, r mfa.DisableRequest, now time.Time) bool {
	if out.Factors == nil || (mfa.ListResult{Factors: out.Factors}).ValidateAt(now) != nil || r.Target == mfa.AllFactors && len(out.Factors) != 0 {
		return false
	}
	for _, factor := range out.Factors {
		if factor.ID == r.FactorID || factor.Method != "totp" || factor.State != mfa.FactorPending || !factor.LastUsedAt.IsZero() {
			return false
		}
	}
	return true
}

// The explicit wire DTO matches the selected closed schema and omits unknown
// last-use metadata. Raw Go projections would expose capitalized fields and a
// year-one timestamp that the HTTP contract does not advertise.
func disableBody(out mfa.DisableResult) ([]byte, error) {
	type factor struct {
		ID        mfa.FactorID    `json:"id"`
		Method    string          `json:"method"`
		Label     string          `json:"label,omitempty"`
		State     mfa.FactorState `json:"state"`
		CreatedAt time.Time       `json:"createdAt"`
		Version   uint64          `json:"version"`
	}
	factors := make([]factor, 0, len(out.Factors))
	for _, v := range out.Factors {
		factors = append(factors, factor{v.ID, v.Method, v.Label, v.State, v.CreatedAt.UTC(), v.Version})
	}
	return json.Marshal(struct {
		Outcome string             `json:"commitOutcome"`
		Command identity.CommandID `json:"commandID"`
		Factors []factor           `json:"factors"`
	}{"committed", out.CommandID, factors})
}

// Format prevents implicit configuration and borrowed credential traversal.
func (DisableConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfahttp.DisableConfig(redacted)"))
}

// MarshalJSON refuses implicit configuration export.
func (DisableConfig) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText refuses implicit text/map-key configuration export.
func (DisableConfig) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }

// LogValue exposes only a fixed redaction marker.
func (DisableConfig) LogValue() slog.Value {
	return slog.StringValue("mfahttp.DisableConfig(redacted)")
}
