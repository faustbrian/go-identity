package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type proxyRetirementDrainTarget struct {
	Flow    identity.PreAuthTransactionID `json:"flow"`
	Origin  identity.CommandID            `json:"origin"`
	Command identity.CommandID            `json:"command"`
}

type proxyRetirementDrainPage struct {
	Next    identity.PreAuthTransactionID `json:"next"`
	Targets []proxyRetirementDrainTarget  `json:"targets"`
}

func (p proxyRetirementDrainPage) valid(after identity.PreAuthTransactionID) bool {
	if p.Targets == nil || len(p.Targets) > proxyRetirementDiscoveryMaxScan ||
		(p.Next != "" && (!validProxyRetirementDrainCursor(p.Next) || p.Next <= after)) {
		return false
	}
	seen := make(map[identity.CommandID]bool, 2*len(p.Targets))
	for _, t := range p.Targets {
		_, originErr := identity.ParseCommandID(string(t.Origin))
		_, cmdErr := identity.ParseCommandID(string(t.Command))
		if !validProxyRetirementDrainCursor(t.Flow) || t.Flow <= after || p.Next != "" && t.Flow > p.Next ||
			t.Origin == t.Command || originErr != nil || cmdErr != nil || seen[t.Origin] || seen[t.Command] {
			return false
		}
		seen[t.Origin], seen[t.Command] = true, true
		after = t.Flow
	}
	return true
}

func validProxyRetirementDrainCursor(flow identity.PreAuthTransactionID) bool {
	_, err := identity.ParsePreAuthTransactionID(string(flow))
	return err == nil
}

type proxyRetirementDrainState struct {
	revision, retired int64
	after             identity.PreAuthTransactionID
	page              *proxyRetirementDrainPage
	confirmed         int16
	exhausted         bool
}

func (s proxyRetirementDrainState) progress() ProxyRetirementDrainProgress {
	p := ProxyRetirementDrainProgress{Exhausted: s.exhausted, Retired: uint64(s.retired), AfterFlowID: s.after}
	if s.page != nil {
		p.Remaining = uint16(len(s.page.Targets)) - uint16(s.confirmed)
	}
	return p
}

type proxyRetirementDrainKey struct {
	source     ProviderDisableAdmission
	kind       kernel.OAuthProxyRetirementKind
	deployment string
}

func (k proxyRetirementDrainKey) args() []any {
	return []any{string(k.source.Disable.Key.TenantID), string(k.source.CascadeID), int64(k.source.Generation), int16(k.kind), k.deployment}
}

type proxyRetirementDrainStore struct {
	pool  *pgxpool.Pool
	table string
	key   proxyRetirementDrainKey
}

const proxyRetirementDrainPK = `tenant_id=$1 AND cascade_id=$2 AND generation=$3 AND role=$4 AND deployment=$5`

func proxyRetirementDrainReadSQL(table string) string {
	return `SELECT source_command_id,provider_id,source_version::text,revision,after_flow_id,pending_page,confirmed,retired,exhausted
 FROM ` + table + ` WHERE ` + proxyRetirementDrainPK
}

func proxyRetirementDrainInsertSQL(table string) string {
	return `INSERT INTO ` + table + `(tenant_id,cascade_id,generation,role,deployment,source_command_id,provider_id,source_version,
 revision,after_flow_id,pending_page,confirmed,retired,exhausted)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,1,$9,$10::jsonb,$11,$12,$13) ON CONFLICT DO NOTHING`
}

func proxyRetirementDrainUpdateSQL(table string) string {
	return `UPDATE ` + table + ` SET revision=revision+1,after_flow_id=$10,pending_page=$11::jsonb,confirmed=$12,retired=$13,exhausted=$14
 WHERE ` + proxyRetirementDrainPK + ` AND source_command_id=$6 AND provider_id=$7 AND source_version=$8::numeric AND revision=$9`
}

func (s proxyRetirementDrainStore) read(ctx context.Context) (proxyRetirementDrainState, error) {
	var state proxyRetirementDrainState
	var command, provider, version, after string
	var page []byte
	err := s.pool.QueryRow(ctx, proxyRetirementDrainReadSQL(s.table), s.key.args()...).
		Scan(&command, &provider, &version, &state.revision, &after, &page, &state.confirmed, &state.retired, &state.exhausted)
	if errors.Is(err, pgx.ErrNoRows) {
		return proxyRetirementDrainState{}, nil
	}
	if err != nil || ctx.Err() != nil {
		return proxyRetirementDrainState{}, providerAuthorityFailure(ctx)
	}
	change := s.key.source.Disable
	if command != string(change.CommandID) || provider != change.Key.ProviderID || version != strconv.FormatUint(change.Next.Version, 10) {
		return proxyRetirementDrainState{}, identity.ConflictError{}
	}
	state.after = identity.PreAuthTransactionID(after)
	if state.revision <= 0 || state.retired < 0 || state.confirmed < 0 || int64(state.confirmed) > state.retired ||
		state.after != "" && !validProxyRetirementDrainCursor(state.after) {
		return proxyRetirementDrainState{}, identity.UnavailableError{}
	}
	if page != nil {
		state.page = new(proxyRetirementDrainPage)
		if state.exhausted || json.Unmarshal(page, state.page) != nil || !state.page.valid(state.after) ||
			state.confirmed > 0 && int(state.confirmed) >= len(state.page.Targets) {
			return proxyRetirementDrainState{}, identity.UnavailableError{}
		}
	} else if state.confirmed != 0 {
		return proxyRetirementDrainState{}, identity.UnavailableError{}
	}
	return state, nil
}

// Each write is a short compare-and-set in its own transaction. A lost write
// response is not permission to start a target; reread on the next Step.
func (s proxyRetirementDrainStore) save(ctx context.Context, state *proxyRetirementDrainState) error {
	if state.revision == math.MaxInt64 {
		return identity.UnavailableError{}
	}
	var page any
	if state.page != nil {
		wire, err := json.Marshal(state.page)
		if err != nil {
			return identity.UnavailableError{}
		}
		page = wire
	}
	source := s.key.source.Disable
	args := append(s.key.args(), string(source.CommandID), source.Key.ProviderID, providerAuthorityVersion(source.Next.Version))
	statement := proxyRetirementDrainInsertSQL(s.table)
	if state.revision != 0 {
		statement = proxyRetirementDrainUpdateSQL(s.table)
		args = append(args, state.revision)
	}
	args = append(args, string(state.after), page, state.confirmed, state.retired, state.exhausted)
	tag, err := s.pool.Exec(ctx, statement, args...)
	if err != nil || ctx.Err() != nil {
		return providerAuthorityFailure(ctx)
	}
	if tag.RowsAffected() != 1 {
		return identity.ConflictError{}
	}
	state.revision++
	return nil
}
