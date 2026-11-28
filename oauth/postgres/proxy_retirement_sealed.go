package postgres

import (
	"context"
	"errors"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// NewSealedProxyRetirementAuthority selects the exact pending generation from
// the designated provider primary. Construction performs no I/O. Before each
// operation, the authority rereads the admission and requires a persisted local
// seal on the service's actual custody database. The audit-only constructor
// remains a separate choice: there is no fallback in either direction.
func NewSealedProxyRetirementAuthority(sealer *ProxyCustodyFenceOperator, source ProxyCustodyFenceSealRequest) (*ProxyRetirementAuthority, error) {
	if sealer == nil || sealer.local == nil || sealer.primary == nil || sealer.config.TenantID != source.TenantID ||
		validateProxyCustodyFenceSealRequest(source) != nil {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_sealed_retirement_authority"}
	}
	return &ProxyRetirementAuthority{sealer: sealer, source: source}, nil
}

func (a *ProxyRetirementAuthority) selected() bool {
	return a != nil && ((a.reader != nil) != (a.sealer != nil))
}

func (a *ProxyRetirementAuthority) authenticate(ctx context.Context, custody *database.Pool, schema string,
	kind kernel.OAuthProxyRetirementKind, disable ProviderAuthorityChange) error {
	if !a.selected() || ctx == nil {
		return identity.ForbiddenError{}
	}
	if a.sealer == nil {
		return readProxyProviderDisable(ctx, a.reader, a.operator, disable)
	}
	sealer := a.sealer
	if custody == nil || custody.Raw() == nil || sealer.config.Kind != kind || sealer.config.Schema != schema ||
		disable.Key.TenantID != a.source.TenantID || disable.CommandID != a.source.SourceCommandID {
		return identity.ForbiddenError{}
	}
	admission, err := sealer.authoritativeDisable(ctx, a.source)
	if err != nil {
		return err
	}
	if admission.Disable != disable {
		return identity.ForbiddenError{}
	}
	return sealer.requireLocalCutoff(ctx, custody, admission.Disable)
}

// Query the same pool the subsequent discovery/retirement actually uses, not
// the sealer's privileged local pool or a caller-supplied seal observation.
func (o *ProxyCustodyFenceOperator) requireLocalCutoff(ctx context.Context, custody *database.Pool, disable ProviderAuthorityChange) error {
	pool := custody.Raw()
	var active bool
	table := rpQuotedSchema(o.config.Schema) + "." + o.custody
	if err := pool.QueryRow(ctx, proxyCustodyFenceActiveSQL, table, o.gate).Scan(&active); err != nil {
		return providerAuthorityFailure(ctx)
	}
	if !active {
		return identity.ForbiddenError{}
	}
	var raw string
	err := pool.QueryRow(ctx, proxyCustodyFenceFloorSQL(o.fence), string(disable.Key.TenantID), disable.Key.ProviderID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.ForbiddenError{}
	}
	floor, parseErr := strconv.ParseUint(raw, 10, 64)
	if err != nil || parseErr != nil || ctx.Err() != nil {
		return providerAuthorityFailure(ctx)
	}
	if floor < disable.ExpectedVersion {
		return identity.ForbiddenError{}
	}
	return nil
}
