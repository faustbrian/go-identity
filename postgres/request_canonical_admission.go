package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// NewCoordinatorWithCanonicalRequestKeys selects protocol-canonical DELETE
// correlation instead of client-key allocation. Supply a distinct trusted
// namespace for this mode. Its installed namespace identity differs from the
// legacy mode, so mixed use of one namespace fails closed. Pool, policies,
// registry, original ciphertext and command journal retain their existing
// ownership. Install CanonicalRequestMigrationSource before activation.
// Construction performs no I/O or callback; the pool remains borrowed.
func NewCoordinatorWithCanonicalRequestKeys(pool *database.Pool, registry *ContributorRegistry, config CoordinatorConfig, requestKeys RequestKeyConfig) (*Coordinator, error) {
	return newCoordinatorWithCanonicalRequestMethod(pool, registry, config, requestKeys, "DELETE")
}

// NewCoordinatorWithCanonicalPostRequestKeys selects protocol-canonical POST
// correlation with no client retry key or alias. Install the request-key and
// preparation migrations; the DELETE-only alias migration is not needed.
// Use a distinct trusted namespace. It cannot be shared with legacy client
// keys or canonical DELETE. The registered feature provides the stable
// original selector and independently authorizes the requested command.
// Construction performs no I/O or callback; the pool remains borrowed.
func NewCoordinatorWithCanonicalPostRequestKeys(pool *database.Pool, registry *ContributorRegistry, config CoordinatorConfig, requestKeys RequestKeyConfig) (*Coordinator, error) {
	return newCoordinatorWithCanonicalRequestMethod(pool, registry, config, requestKeys, "POST")
}

// NewCoordinatorWithCanonicalSSOSAMLStartRequestKeys correlates only the
// service-owned SAML browser start GET. The feature supplies the stable
// server-owned selector; an optional client key aliases that same original
// command. Use a distinct namespace and install
// CanonicalSAMLStartRequestMigrationSource before enabling this profile.
// Construction performs no I/O or callback; the pool remains borrowed.
func NewCoordinatorWithCanonicalSSOSAMLStartRequestKeys(pool *database.Pool, registry *ContributorRegistry, config CoordinatorConfig, requestKeys RequestKeyConfig) (*Coordinator, error) {
	return newCoordinatorWithCanonicalRequestMethod(pool, registry, config, requestKeys, "GET")
}

// NewCoordinatorWithCanonicalSCIMBulkRequestKeys selects correlation for the
// exact native SCIM Bulk POST and service account. A supplied retry key aliases
// the original canonical request; it never replaces the server selector. Use a
// distinct trusted namespace per configured connection and install
// CanonicalSCIMBulkRequestMigrationSource before enabling this profile.
// Correlation does not admit or execute children.
func NewCoordinatorWithCanonicalSCIMBulkRequestKeys(pool *database.Pool, registry *ContributorRegistry, config CoordinatorConfig, requestKeys RequestKeyConfig) (*Coordinator, error) {
	c, err := newCoordinatorWithCanonicalRequestMethod(pool, registry, config, requestKeys, "POST")
	if err != nil {
		return nil, err
	}
	c.canonicalSCIMBulk = true
	return c, nil
}

func newCoordinatorWithCanonicalRequestMethod(pool *database.Pool, registry *ContributorRegistry, config CoordinatorConfig, requestKeys RequestKeyConfig, method string) (*Coordinator, error) {
	c, err := NewCoordinatorWithRequestKeys(pool, registry, config, requestKeys)
	if err != nil {
		return nil, err
	}
	c.canonicalRequestMethod = method
	return c, nil
}

func (c *Coordinator) requestNamespaceIdentity() [32]byte {
	namespace := c.requestKeys.Namespace
	switch c.canonicalRequestMethod {
	case "DELETE":
		namespace = "canonical-delete-v1\x00" + namespace
	case "POST":
		if c.canonicalSCIMBulk {
			namespace = "canonical-scim-bulk-v1\x00" + namespace
		} else {
			namespace = "canonical-post-v1\x00" + namespace
		}
	case "GET":
		namespace = "canonical-sso-saml-start-v1\x00" + namespace
	}
	return requestNamespaceIdentity(namespace, c.requestKeys.lookupKey())
}

func (c *Coordinator) acceptsRequestKeyMethod(method string, canonical bool) bool {
	if c.canonicalRequestMethod == "" {
		return !canonical && method != "GET"
	}
	return canonical && c.canonicalRequestMethod == method
}

const scimBulkRequestRoute = "identity.scim.bulk"

func (c *Coordinator) acceptsRequestKeyScope(scope RequestKeyScope, canonical bool) bool {
	if c.canonicalSCIMBulk || scope.RouteID == scimBulkRequestRoute {
		return c.canonicalSCIMBulk && canonical && scope.Method == "POST" &&
			scope.RouteID == scimBulkRequestRoute && scope.ActorKind == authorization.SubjectServiceAccount
	}
	return c.acceptsRequestKeyMethod(scope.Method, canonical)
}

// ResolvePreparedCanonicalRequest retains one original random command and
// authenticated native input for the stable protocol selector. DELETE, the
// exact SAML start GET and the exact SCIM Bulk POST support an optional retry
// key. Other canonical POST selections require nil. A supplied key aliases the
// original mapping in its acknowledgement transaction; it never selects
// another command. An alias already bound elsewhere conflicts and rolls
// back any candidate mapping. Changed full intent conflicts, including after
// fingerprint rotation unless its original key remains retained.
// Preparation runs outside SQL, may run for discarded candidates, and must not
// perform domain effects. Replay never prepares again. Current admission policy,
// exact registered owner and all existing custody checks remain required.
// Binding/ciphertext grant no outcome or execution authority. On any error,
// including lost acknowledgement, no custody is returned; retry the same
// selector/intent. Returned bytes are owned and must be cleared after use.
// Calls are bounded by MaximumDuration/earlier cancellation and concurrent-safe.
func (c *Coordinator) ResolvePreparedCanonicalRequest(ctx context.Context, scope RequestKeyScope, selector CanonicalRequestKey, optional *identity.IdempotencyKey, intent identity.RequestIntent, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyPreparationContributor) (RequestKeyPreparationBinding, []byte, error) {
	lookup, alias, err := c.canonicalRequestLookups(scope, selector, optional)
	if err != nil || c.validateRequestPreparation(scope, feature, owner) != nil {
		return RequestKeyPreparationBinding{}, nil, invalidRequestKey()
	}
	p := &requestKeyPreparation{owner: owner, feature: feature, identity: requestPreparationIdentity(feature), canonicalLookup: &lookup, canonicalAlias: alias}
	_, err = c.resolveRequestKey(ctx, scope, identity.IdempotencyKey{}, intent, caller, p)
	defer clear(p.ciphertext)
	if err != nil {
		clear(p.storedCiphertext)
		return RequestKeyPreparationBinding{}, nil, err
	}
	return p.binding, bytes.Clone(p.storedCiphertext), nil
}

// ReadPreparedCanonicalRequest observes the same original custody without
// allocating, attaching aliases or invoking preparation. A missing optional
// alias does not hide an existing canonical request; Resolve attaches it before
// execution. An alias to another selector conflicts even when this selector is
// absent. Authorized absence returns found=false and no custody. All original
// admission, retained-key, owner and ciphertext checks apply. It grants neither
// execution nor outcome authority; returned owned bytes must be cleared.
func (c *Coordinator) ReadPreparedCanonicalRequest(ctx context.Context, scope RequestKeyScope, selector CanonicalRequestKey, optional *identity.IdempotencyKey, intent identity.RequestIntent, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyPreparationContributor) (RequestKeyPreparationBinding, []byte, bool, error) {
	lookup, alias, err := c.canonicalRequestLookups(scope, selector, optional)
	if err != nil || ctx == nil {
		return RequestKeyPreparationBinding{}, nil, false, invalidRequestKey()
	}
	ctx, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	binding, wire, found, err := c.readPreparedRequestKey(ctx, scope, identity.IdempotencyKey{}, intent, caller, feature, owner, &lookup)
	if err == nil && alias != nil {
		err = c.checkCanonicalAlias(ctx, c.pool.Raw(), scope, *alias, lookup)
	}
	if err != nil {
		clear(wire)
		return RequestKeyPreparationBinding{}, nil, false, err
	}
	return binding, wire, found, nil
}

func (c *Coordinator) canonicalRequestLookups(scope RequestKeyScope, selector CanonicalRequestKey, optional *identity.IdempotencyKey) ([32]byte, *[32]byte, error) {
	if c == nil || c.requestKeys == nil || !validRequestKeyConfig(*c.requestKeys) || !validRequestKeyScope(scope) || !c.acceptsRequestKeyScope(scope, true) {
		return [32]byte{}, nil, invalidRequestKey()
	}
	if optional != nil && scope.Method != "DELETE" && scope.Method != "GET" && !c.canonicalSCIMBulk {
		return [32]byte{}, nil, invalidRequestKey()
	}
	key := c.requestKeys.lookupKey()
	defer clear(key[:])
	lookup, err := selector.digest(key)
	if err != nil {
		return [32]byte{}, nil, err
	}
	if optional == nil {
		return lookup, nil, nil
	}
	alias, err := optional.Digest(key)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return lookup, &alias, nil
}

func (c *Coordinator) attachCanonicalAlias(ctx context.Context, tx pgx.Tx, scope RequestKeyScope, alias, canonical [32]byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO identity.request_key_aliases(namespace,tenant_id,actor_id,actor_kind,method,route_id,alias_digest,canonical_digest)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(namespace,tenant_id,actor_id,actor_kind,method,route_id,alias_digest) DO NOTHING`, c.requestKeys.Namespace, string(scope.TenantID), string(scope.ActorID), string(scope.ActorKind), scope.Method, scope.RouteID, alias[:], canonical[:])
	if err != nil {
		return listFailure(ctx, err)
	}
	return c.checkCanonicalAlias(ctx, tx, scope, alias, canonical)
}

func (c *Coordinator) checkCanonicalAlias(ctx context.Context, reader interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, scope RequestKeyScope, alias, canonical [32]byte) error {
	var stored []byte
	err := reader.QueryRow(ctx, `SELECT canonical_digest FROM identity.request_key_aliases WHERE namespace=$1 AND tenant_id=$2 AND actor_id=$3 AND actor_kind=$4 AND method=$5 AND route_id=$6 AND alias_digest=$7`, c.requestKeys.Namespace, string(scope.TenantID), string(scope.ActorID), string(scope.ActorKind), scope.Method, scope.RouteID, alias[:]).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return readFailure(ctx, err)
	}
	if !hmac.Equal(stored, canonical[:]) {
		return identity.ConflictError{}
	}
	return nil
}
