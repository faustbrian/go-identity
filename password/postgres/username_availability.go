package passwordpostgres

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/username"
	database "github.com/faustbrian/go-postgres"
)

// UsernameAvailabilityConfig selects actual native risk/counter/directory
// owners. Counters must borrow the supplied pool and an explicit tenant
// allowlist; its exact Policy supplies all risk profiles and requires velocity.
// Sources supply the remaining mandatory normalized facts through bounded
// callbacks, not uniqueness or counter stores. PolicyID and OnAuditLoss select
// canonical fail-closed delivery through the actual PostgreSQL audit owner.
// MaximumDuration and RiskTimeout are positive <=1m, the latter <=the former.
// Domain must match the fixed username comparison profile and registration's
// complete retained retirement-key history. Install its histories, the durable
// counter migration and native audit schema before use; no migration runs here.
type UsernameAvailabilityConfig struct {
	Domain                       kernel.UsernameRenameDomainConfig
	Counters                     riskpg.DurableCounterConfig
	Sources                      []risk.Source
	PolicyID                     string
	MaximumDuration, RiskTimeout time.Duration
	OnAuditLoss                  func(context.Context, risk.DecisionDelivery) error
}

// UsernameAvailabilityService supplies advisory rate-limited discovery using
// real primary occupancy/cooldowns and durable counters. It borrows the pool,
// freezes policy values, starts no goroutine and retains no request resources.
// Calls are concurrent-safe when borrowed fact/audit callbacks are. Each call
// receives a new server-generated attempt; there is no client-selected replay
// identity that can suppress rate charging. This is not an authentication API.
type UsernameAvailabilityService struct {
	policy  *username.Policy
	domain  *kernel.UsernameRenameDomain
	risk    risk.Evaluator
	maximum time.Duration
}

var _ username.AvailabilityService = (*UsernameAvailabilityService)(nil)

// NewUsernameAvailabilityService validates and freezes native composition
// without IO, callbacks or implicit feature selection. It owns no pool/shutdown.
func NewUsernameAvailabilityService(pool *database.Pool, p *username.Policy, c UsernameAvailabilityConfig) (*UsernameAvailabilityService, error) {
	if pool == nil || pool.Raw() == nil || p == nil || p.ReservedVersion() == 0 || c.Counters.Pool != pool || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || c.RiskTimeout < time.Millisecond || c.RiskTimeout > c.MaximumDuration || c.OnAuditLoss == nil || c.Domain.NormalizationProfile != string(username.ProfileID) || c.Domain.NormalizationVersion != username.ProfileVersion {
		return nil, username.ErrPolicy
	}
	admission, err := c.Counters.Policy.Admit("identity.username.available")
	if err != nil || admission.Preflight != "" || admission.Profile.Class != risk.StateNeutralRead {
		return nil, username.ErrPolicy
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: min(c.MaximumDuration, 5*time.Second)})
	if err != nil {
		return nil, username.ErrPolicy
	}
	domain, err := kernel.NewUsernameRenameDomain(directory, c.Domain)
	if err != nil {
		return nil, username.ErrPolicy
	}
	store, err := riskpg.NewDurableCounterStore(c.Counters)
	if err != nil {
		return nil, username.ErrPolicy
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: c.Counters.Policy, Store: store, Clock: time.Now, Timeout: c.Counters.Timeout, Keys: c.Counters.Keys})
	if err != nil {
		return nil, username.ErrPolicy
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		return nil, username.ErrPolicy
	}
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: c.Counters.Policy, Counters: &counters, Clock: time.Now, Timeout: c.RiskTimeout, Sources: c.Sources, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: c.PolicyID, Timeout: min(c.RiskTimeout, 5*time.Second), Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: c.OnAuditLoss}})
	if err != nil {
		return nil, username.ErrPolicy
	}
	snapshot := *p
	return &UsernameAvailabilityService{policy: &snapshot, domain: domain, risk: evaluation, maximum: c.MaximumDuration}, nil
}

// Available charges mandatory native risk/rate admission before enrollment
// callbacks or occupancy reads. Unknown/step-up/denied authority cannot disclose
// availability; this selected anonymous profile has no weaker-factor fallback.
// No names/network/user IDs enter the canonical event, only the server attempt.
// Unavailable counter/audit/storage results are never interpreted as free names.
func (s *UsernameAvailabilityService) Available(ctx context.Context, r username.AvailabilityRequest) (out username.AvailabilityResult, err error) {
	if ctx == nil || s == nil || s.policy == nil || s.domain == nil || s.maximum <= 0 {
		return out, username.ErrPolicy
	}
	ctx, stop := context.WithTimeout(ctx, s.maximum)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = username.AvailabilityResult{}, username.ErrUnavailable
		}
		if ctx.Err() != nil {
			out, err = username.AvailabilityResult{}, ctx.Err()
		}
	}()
	if _, e := identity.ParseIdentifierID(r.TenantID); e != nil || len(r.Username) == 0 || len(r.Username) > username.MaximumBytes || len(r.Network) > 45 {
		return out, username.ErrInvalid
	}
	network, e := netip.ParseAddr(r.Network)
	if e != nil || network.Zone() != "" || network.IsUnspecified() || network.IsMulticast() {
		return out, username.ErrInvalid
	}
	id, e := identity.NewCommandID()
	if e != nil {
		return out, username.ErrUnavailable
	}
	result, e := s.risk.Evaluate(ctx, risk.EvaluateRequest{Context: risk.Context{Tenant: r.TenantID, Operation: "identity.username.available", Attempt: string(id)}, Phase: risk.NonIssuing, Subject: risk.Subject{Network: network.Unmap().String()}, Attribution: &risk.DecisionAttribution{CommandID: id, CorrelationID: id, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(id)}})
	if e != nil {
		return out, username.ErrUnavailable
	}
	if result.Decision.Action == risk.Throttle {
		return out, username.ErrThrottled
	}
	if result.Decision.Action != risk.Allow {
		return out, username.ErrDenied
	}
	name, e := s.policy.Validate(ctx, r.Username)
	if e != nil {
		return out, e
	}
	n := name.Record()
	available, e := s.domain.UsernameAvailable(ctx, kernel.UsernameQuery{TenantID: identity.TenantID(r.TenantID), CanonicalValue: n.Canonical, NormalizationProfile: string(n.ProfileID), NormalizationVersion: n.ProfileVersion})
	if e != nil {
		return out, username.ErrUnavailable
	}
	return username.AvailabilityResult{Available: available}, nil
}

// Format redacts borrowed owners and private policy/key configuration.
func (UsernameAvailabilityConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.UsernameAvailabilityConfig(redacted)"))
}

// MarshalJSON refuses implicit export of private native configuration.
func (UsernameAvailabilityConfig) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }

// Format redacts borrowed native owner custody.
func (UsernameAvailabilityService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.UsernameAvailabilityService(redacted)"))
}

// MarshalJSON refuses implicit export of borrowed native owner custody.
func (UsernameAvailabilityService) MarshalJSON() ([]byte, error) { return nil, username.ErrDisclosure }
