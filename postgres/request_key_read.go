package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// ReadPreparedRequestKey observes an existing original-input mapping by its
// initiating key under current exact request-admission policy and the retained
// intent fingerprint key. The native registered owner must authenticate the
// ciphertext and its complete binding before using any source projection.
// Found=false,nil means authorized absence only. Conflicting, corrupt, retired
// or unverifiable mappings return no custody and must not select a new source.
// No transaction, allocation, preparation callback, entropy, journal effect or
// takeover occurs; this observation grants no execution or result authority.
// Returned bytes are caller-owned and must be cleared after use. Pool/inputs
// remain borrowed; concurrent calls honor cancellation and MaximumDuration.
func (c *Coordinator) ReadPreparedRequestKey(ctx context.Context, scope RequestKeyScope, key identity.IdempotencyKey, intent identity.RequestIntent, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyPreparationContributor) (binding RequestKeyPreparationBinding, wire []byte, found bool, err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			clear(wire)
			wire = nil
			binding = RequestKeyPreparationBinding{}
		}
	}()
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.requestKeys == nil || !validRequestKeyConfig(*c.requestKeys) || !validRequestKeyScope(scope) || c.maximumDuration <= 0 || c.keys.current == 0 || c.validateRequestPreparation(scope, feature, owner) != nil {
		return binding, nil, false, invalidRequestKey()
	}
	lookupKey := c.requestKeys.lookupKey()
	defer clear(lookupKey[:])
	lookup, err := key.Digest(lookupKey)
	if err != nil {
		return binding, nil, false, invalidRequestKey()
	}
	fields, valid := intent.Fields()
	if !valid {
		return binding, nil, false, invalidRequestKey()
	}
	w, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	if w.Err() != nil {
		return binding, nil, false, readFailure(w, w.Err())
	}
	defer func() {
		if w.Err() != nil {
			err = readFailure(w, w.Err())
		}
	}()
	allowed, err := authorizeRequestKey(w, scope, caller, c.requestKeys)
	if err != nil {
		return binding, nil, false, err
	}
	if !allowed {
		return binding, nil, false, identity.ForbiddenError{}
	}
	var raw, digest, safe, preparation, namespace []byte
	var version int64
	var retired bool
	var claimTenant, claimPurpose *string
	err = c.pool.Raw().QueryRow(w, `SELECT r.command_id,r.fingerprint,r.fingerprint_key_version,
CASE WHEN octet_length(r.safe_fields) BETWEEN 1 AND 65536 THEN r.safe_fields END,
r.request_preparation_identity,
CASE WHEN octet_length(r.request_preparation_ciphertext) BETWEEN 1 AND 1048576 THEN r.request_preparation_ciphertext END,
n.key_identity,coalesce(c.retired,false),c.tenant_id,c.purpose
FROM identity.request_key_mappings r
LEFT JOIN identity.request_key_namespaces n USING(namespace)
LEFT JOIN identity.identity_command_id_claims c ON c.command_id=r.command_id
WHERE r.namespace=$1 AND r.tenant_id=$2 AND r.actor_id=$3 AND r.actor_kind=$4 AND r.method=$5 AND r.route_id=$6 AND r.key_digest=$7`, c.requestKeys.Namespace, string(scope.TenantID), string(scope.ActorID), string(scope.ActorKind), scope.Method, scope.RouteID, lookup[:]).Scan(&raw, &digest, &version, &safe, &preparation, &wire, &namespace, &retired, &claimTenant, &claimPurpose)
	if errors.Is(err, pgx.ErrNoRows) {
		// A missing key must not hide an installed namespace bound to another
		// lookup key. A genuinely unused namespace remains read-only absence.
		err = c.pool.Raw().QueryRow(w, `SELECT key_identity FROM identity.request_key_namespaces WHERE namespace=$1`, c.requestKeys.Namespace).Scan(&namespace)
		if errors.Is(err, pgx.ErrNoRows) {
			return binding, nil, false, nil
		}
		if err != nil {
			return binding, nil, false, readFailure(w, err)
		}
		expected := requestNamespaceIdentity(c.requestKeys.Namespace, lookupKey)
		if !hmac.Equal(namespace, expected[:]) {
			return binding, nil, false, identity.ConflictError{}
		}
		return binding, nil, false, nil
	}
	if err != nil {
		return binding, nil, false, readFailure(w, err)
	}
	found = true
	if len(raw) != 16 || len(digest) != 32 || version < 1 || version > 4294967295 || len(safe) == 0 || len(safe) > 65536 || len(wire) == 0 || len(wire) > maximumPreparationCiphertext {
		return binding, wire, true, identity.UnavailableError{}
	}
	id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		return binding, wire, true, identity.UnavailableError{}
	}
	if retired || claimTenant != nil && (*claimTenant != string(scope.TenantID) || claimPurpose == nil || *claimPurpose != scope.RouteID) {
		return binding, wire, true, identity.ForbiddenError{}
	}
	namespaceIdentity := requestNamespaceIdentity(c.requestKeys.Namespace, lookupKey)
	preparationIdentity := requestPreparationIdentity(feature)
	if !hmac.Equal(namespace, namespaceIdentity[:]) || !hmac.Equal(preparation, preparationIdentity[:]) {
		return binding, wire, true, identity.ConflictError{}
	}
	retained, ok := c.keys.retained[uint32(version)]
	if !ok || retained == ([32]byte{}) {
		return binding, wire, true, identity.UnavailableError{}
	}
	expected, expectedSafe, err := requestIntentFingerprint(scope, fields, c.requestKeys.Policy.PolicyVersion, retained)
	if err != nil {
		return binding, wire, true, err
	}
	if !hmac.Equal(digest, expected[:]) || !bytes.Equal(safe, expectedSafe) {
		return binding, wire, true, identity.ConflictError{}
	}
	return c.requestPreparationBinding(scope, RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: uint32(version)}, feature, expected), wire, true, nil
}
