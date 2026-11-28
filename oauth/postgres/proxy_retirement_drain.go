package postgres

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ProxyRetirementDrainProgress describes one admitted local traversal.
// Exhausted is a local checkpoint, not a whole-consumer acknowledgement.
// AfterFlowID is the last acknowledged page's nonempty continuation.
type ProxyRetirementDrainProgress struct {
	Exhausted bool
	// Retired counts confirmed local targets, including ones retired by another
	// trusted command. It is not the number of successful commands issued here.
	Retired     uint64
	AfterFlowID identity.PreAuthTransactionID
	Remaining   uint16
}

// ProxyRetirementDrain borrows one native origin with exact sealed authority.
// Its progress is local to the actual custody database, not a second journal.
type ProxyRetirementDrain struct {
	authority          *ProxyRetirementAuthority
	pool               *database.Pool
	schema, deployment string
	kind               kernel.OAuthProxyRetirementKind
	duration           time.Duration
	list               func(context.Context, *ProxyRetirementAuthority, ProxyRetirementDiscoveryRequest) (ProxyRetirementDiscoveryPage, error)
	retire             func(context.Context, *ProxyRetirementAuthority, ProxyOriginRetirementRequest) (identity.CommandResult, error)
}

// NewProductionProxyRetirementDrain selects the live production origin.
// Apply ProxyRetirementDrainMigrationSource before the first Step.
func NewProductionProxyRetirementDrain(s *ProxyForwardService, authority *ProxyRetirementAuthority) (*ProxyRetirementDrain, error) {
	if s == nil || s.providerAuthority == nil {
		return nil, invalidProxyRetirementDrain()
	}
	return newProxyRetirementDrain(ProxyRetirementDrain{authority: authority, pool: s.pool, schema: s.config.Schema,
		deployment: s.config.ProductionDeployment, kind: kernel.OAuthProxyRetireProduction, duration: s.config.MaximumDuration,
		list: s.ListDisabledProviderOrigins, retire: s.RetireDisabledProviderOrigin})
}

// NewPreviewProxyRetirementDrain selects the live bound preview origin.
// The checkpoint and retirement stay within its custody database.
func NewPreviewProxyRetirementDrain(s *ProxyPreviewService, authority *ProxyRetirementAuthority) (*ProxyRetirementDrain, error) {
	if s == nil || s.authority == nil || s.signin == nil || s.signin.start == nil || authority == nil ||
		authority.source.TenantID != s.config.TenantID {
		return nil, invalidProxyRetirementDrain()
	}
	start := s.signin.start
	return newProxyRetirementDrain(ProxyRetirementDrain{authority: authority, pool: start.pool, schema: start.config.Schema,
		deployment: s.config.Target.Deployment, kind: kernel.OAuthProxyRetirePreview, duration: start.config.MaximumDuration,
		list: s.ListDisabledProviderOrigins, retire: s.RetireDisabledProviderOrigin})
}

func newProxyRetirementDrain(d ProxyRetirementDrain) (*ProxyRetirementDrain, error) {
	if !d.authority.selected() || d.authority.sealer == nil || d.pool == nil || d.pool.Raw() == nil || !rpProviderID(d.deployment) ||
		d.authority.sealer.config.Kind != d.kind || d.authority.sealer.config.Schema != d.schema || d.duration <= 0 {
		return nil, invalidProxyRetirementDrain()
	}
	return &d, nil
}

func invalidProxyRetirementDrain() error {
	return identity.InvalidInputError{Field: "oauth_proxy_retirement_drain"}
}

// Step examines at most scanLimit rows plus discovery lookahead when no page
// is pending, and confirms at most one native retirement. It persists the
// generated commands before retiring anything. Run again after a conflict or
// interruption; a pending target uses the same command and kernel journal.
// Any unacknowledged or failed target leaves its cursor in place.
func (d *ProxyRetirementDrain) Step(ctx context.Context, scanLimit uint16) (ProxyRetirementDrainProgress, error) {
	if d == nil || d.authority == nil || d.pool == nil || ctx == nil || scanLimit == 0 || scanLimit > proxyRetirementDiscoveryMaxScan {
		return ProxyRetirementDrainProgress{}, invalidProxyRetirementDrain()
	}
	ctx, stop := context.WithTimeout(ctx, d.duration)
	defer stop()
	sealer := d.authority.sealer
	source, err := sealer.authoritativeDisable(ctx, d.authority.source)
	if err != nil {
		return ProxyRetirementDrainProgress{}, err
	}
	if err := sealer.requireLocalCutoff(ctx, d.pool, source.Disable); err != nil {
		return ProxyRetirementDrainProgress{}, err
	}
	key := proxyRetirementDrainKey{source: source, kind: d.kind, deployment: d.deployment}
	store := proxyRetirementDrainStore{pool: d.pool.Raw(), table: rpQuotedSchema(d.schema) + ".proxy_retirement_drains", key: key}
	state, err := store.read(ctx)
	if err != nil {
		return ProxyRetirementDrainProgress{}, err
	}
	if state.exhausted {
		return state.progress(), nil
	}
	if state.page == nil {
		page, err := d.list(ctx, d.authority, ProxyRetirementDiscoveryRequest{Disable: source.Disable, AfterFlowID: state.after, ScanLimit: scanLimit})
		if err != nil {
			return ProxyRetirementDrainProgress{}, err
		}
		state.page, err = newProxyRetirementDrainPage(page, state.after)
		if err != nil {
			return ProxyRetirementDrainProgress{}, err
		}
		if err := store.save(ctx, &state); err != nil {
			return ProxyRetirementDrainProgress{}, err
		}
	}
	if len(state.page.Targets) != 0 {
		if state.retired == math.MaxInt64 || state.revision == math.MaxInt64 {
			return ProxyRetirementDrainProgress{}, identity.UnavailableError{}
		}
		target := state.page.Targets[state.confirmed]
		result, err := d.retire(ctx, d.authority, ProxyOriginRetirementRequest{
			CommandID: target.Command, OriginCommandID: target.Origin, FlowID: target.Flow, Disable: source.Disable,
		})
		if !confirmedProxyRetirementDrainResult(result, err, source.Disable.Key.TenantID, target) {
			if err != nil {
				return ProxyRetirementDrainProgress{}, err
			}
			return ProxyRetirementDrainProgress{}, identity.UnavailableError{}
		}
		state.confirmed++
		state.retired++
	}
	if int(state.confirmed) == len(state.page.Targets) {
		if state.page.Next == "" {
			state.exhausted = true
		} else {
			state.after = state.page.Next
		}
		state.page, state.confirmed = nil, 0
	}
	if err := store.save(ctx, &state); err != nil {
		return ProxyRetirementDrainProgress{}, err
	}
	return state.progress(), nil
}

func confirmedProxyRetirementDrainResult(r identity.CommandResult, err error, tenant identity.TenantID, target proxyRetirementDrainTarget) bool {
	b := r.Binding
	if r.Validate() != nil || r.Feature == nil || r.Feature.Operation != kernel.OAuthProxyOriginRetirementOperation() ||
		b.ActorKind != authorization.SubjectServiceAccount || b.CommandID != target.Command || b.TenantID != tenant ||
		b.AnonymousFlowID != string(target.Flow) || b.RecordID != string(target.Flow) || b.CorrelationID != string(target.Origin) {
		return false
	}
	if r.Outcome == identity.CommitOutcomeCommitted {
		return err == nil
	}
	var detail kernel.TypedFeatureFailureError
	return r.Outcome == identity.CommitOutcomeNotCommitted && errors.As(err, &detail) && detail.Code == kernel.FeatureFailureOAuthProxyAlreadyRetired
}

func newProxyRetirementDrainPage(found ProxyRetirementDiscoveryPage, after identity.PreAuthTransactionID) (*proxyRetirementDrainPage, error) {
	page := &proxyRetirementDrainPage{Next: found.NextAfterFlowID, Targets: make([]proxyRetirementDrainTarget, 0, len(found.Origins))}
	for _, origin := range found.Origins {
		command, err := identity.NewCommandID()
		if err != nil {
			return nil, identity.UnavailableError{}
		}
		page.Targets = append(page.Targets, proxyRetirementDrainTarget{Flow: origin.FlowID, Origin: origin.OriginCommandID, Command: command})
	}
	if !page.valid(after) {
		return nil, identity.UnavailableError{}
	}
	return page, nil
}
