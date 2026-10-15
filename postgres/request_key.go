package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// RequestKeyConfig opts the Coordinator into pre-preparation request correlation.
// Namespace is a trusted fixed deployment/environment identifier (1..128 bounded
// UTF-8 bytes), not request data. The lookup key is a secret random 32-byte key
// fixed for that namespace: changing it fails closed against installed storage.
// Policy is a distinct current request-admission policy. Nil configuration does
// not enable this feature; existing query/admission policies do not enable it.
// The constructor copies configuration without I/O. Dependencies must support
// bounded concurrent calls. Fingerprint keys retain CoordinatorConfig rotation.
// Construct with NewRequestKeyConfig; zero or literal configuration is invalid.
// The lookup key has no projection and is opaque through nested diagnostics.
type RequestKeyConfig struct {
	Namespace string
	Policy    CommandQueryPolicy
	lookupKey func() [32]byte
}

// NewRequestKeyConfig validates and copies a nonzero lookup key and trusted
// namespace/policy without I/O or policy callbacks. Its private closure prevents
// recursive diagnostic reflection from disclosing key bytes, including when
// fmt cannot dispatch Format through private caller fields. Zero/invalid input
// returns a redacted error and no usable configuration. Copies share immutable
// key custody; edits to public policy/namespace fields are revalidated and copied
// by NewCoordinatorWithRequestKeys. Never mutate input during construction.
func NewRequestKeyConfig(namespace string, lookupKey [32]byte, policy CommandQueryPolicy) (RequestKeyConfig, error) {
	config := RequestKeyConfig{Namespace: namespace, Policy: policy, lookupKey: func() [32]byte { return lookupKey }}
	if !validRequestKeyConfig(config) {
		return RequestKeyConfig{}, invalidRequestKey()
	}
	return config, nil
}

// Format redacts configuration keys and runtime policy dependencies.
func (RequestKeyConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RequestKeyConfig(redacted)"))
}

// MarshalJSON rejects persistence of lookup keys and policy composition.
func (RequestKeyConfig) MarshalJSON() ([]byte, error) { return nil, invalidRequestKey() }

// LogValue never exposes the lookup key.
func (RequestKeyConfig) LogValue() slog.Value {
	return slog.StringValue("postgres.RequestKeyConfig(redacted)")
}

// RequestKeyScope is the exact lookup scope, independent of body, target user,
// purpose, expected versions and all other intent. Actor includes its closed
// authorization kind. Method is POST, PUT, PATCH or DELETE, without normalization;
// RouteID is the trusted canonical route identifier (not a URL or raw path).
// IDs are 1..128 bounded UTF-8 bytes without controls/space. Trusted feature/HTTP
// composition selects method/route; direct callers must use that same mapping.
type RequestKeyScope struct {
	TenantID  identity.TenantID
	ActorID   identity.ActorID
	ActorKind authorization.SubjectKind
	Method    string
	RouteID   string
}

// RequestKeyAdmission is correlation only: the confirmed original random command
// and retained fingerprint-key version. It grants no reservation, mutation,
// outcome, user authority or permission to regenerate secrets on replay. The
// feature must recover the original command journal and native prepared state
// before proceeding. Zero is invalid. Copies are safe for concurrent reads.
type RequestKeyAdmission struct {
	CommandID             identity.CommandID
	FingerprintKeyVersion uint32
}

// ResolveRequestKey authorizes and atomically correlates one scoped client key
// with an original server-random CommandID before generated command preparation.
// Matching retries verify the stored retained fingerprint key; changed intent
// returns Conflict with no ID. Missing historical keys fail closed. Mapping
// rows are immutable and never expire/reassign after 24 hours; journal cleanup,
// pending/unknown state and retired command claims do not reset the mapping.
// Feature owners supply complete schema-validated RequestIntent, including
// target, purpose, options, schema, policy and expected authority versions.
// The configured policy must allow the exact actor/tenant and RouteID action
// on resource type identity.request-admission with that same RouteID. Owned
// resource attributes identity.request.* replace caller overrides; authorization
// runs before SQL, outside transactions, with the trusted current clock/revision.
// Earlier caller deadlines win over MaximumDuration. Cancellation/dependency
// failures are redacted; lost commit acknowledgement returns UnknownCommitError
// and zero admission, never execution permission. Retry the same key/intent.
// No provider callbacks, goroutines or command journal/domain writes occur.
func (c *Coordinator) ResolveRequestKey(ctx context.Context, scope RequestKeyScope, key identity.IdempotencyKey, intent identity.RequestIntent, caller authorization.DecisionContext) (RequestKeyAdmission, error) {
	return c.resolveRequestKey(ctx, scope, key, intent, caller, nil)
}

func (c *Coordinator) resolveRequestKey(ctx context.Context, scope RequestKeyScope, key identity.IdempotencyKey, intent identity.RequestIntent, caller authorization.DecisionContext, preparation *requestKeyPreparation) (RequestKeyAdmission, error) {
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.requestKeys == nil || !validRequestKeyConfig(*c.requestKeys) || !validRequestKeyScope(scope) || c.maximumDuration <= 0 || c.keys.current == 0 {
		return RequestKeyAdmission{}, invalidRequestKey()
	}
	lookupKey := c.requestKeys.lookupKey()
	lookup, err := key.Digest(lookupKey)
	if err != nil {
		return RequestKeyAdmission{}, invalidRequestKey()
	}
	fields, valid := intent.Fields()
	if !valid {
		return RequestKeyAdmission{}, invalidRequestKey()
	}
	w, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	if err := w.Err(); err != nil {
		return RequestKeyAdmission{}, readFailure(w, err)
	}
	allowed, err := authorizeRequestKey(w, scope, caller, c.requestKeys)
	if w.Err() != nil {
		return RequestKeyAdmission{}, readFailure(w, w.Err())
	}
	if err != nil {
		return RequestKeyAdmission{}, err
	}
	if !allowed {
		return RequestKeyAdmission{}, identity.ForbiddenError{}
	}
	current, ok := c.keys.retained[c.keys.current]
	if !ok || current == ([32]byte{}) {
		return RequestKeyAdmission{}, identity.UnavailableError{}
	}
	begin := c.pool.Raw().Begin
	if c.requestKeyBegin != nil {
		begin = c.requestKeyBegin
	}
	tx, err := begin(w)
	if err != nil {
		return RequestKeyAdmission{}, listFailure(w, err)
	}
	defer rollbackList(tx, c.maximumDuration)
	namespace := requestNamespaceIdentity(c.requestKeys.Namespace, lookupKey)
	if _, err := tx.Exec(w, `INSERT INTO identity.request_key_namespaces(namespace,key_identity) VALUES($1,$2) ON CONFLICT(namespace) DO NOTHING`, c.requestKeys.Namespace, namespace[:]); err != nil {
		return RequestKeyAdmission{}, listFailure(w, err)
	}
	var installed []byte
	if err := tx.QueryRow(w, `SELECT key_identity FROM identity.request_key_namespaces WHERE namespace=$1`, c.requestKeys.Namespace).Scan(&installed); err != nil {
		return RequestKeyAdmission{}, listFailure(w, err)
	}
	if !hmac.Equal(installed, namespace[:]) {
		return RequestKeyAdmission{}, identity.ConflictError{}
	}
	args := []any{c.requestKeys.Namespace, string(scope.TenantID), string(scope.ActorID), string(scope.ActorKind), scope.Method, scope.RouteID, lookup[:]}
	read := func() (RequestKeyAdmission, []byte, []byte, error) {
		var raw, digest, safe []byte
		var version int64
		query := `SELECT command_id,fingerprint,fingerprint_key_version,safe_fields`
		values := []any{&raw, &digest, &version, &safe}
		if preparation != nil {
			query += `,request_preparation_identity,request_preparation_ciphertext`
			values = append(values, &preparation.storedIdentity, &preparation.storedCiphertext)
		}
		query += ` FROM identity.request_key_mappings WHERE namespace=$1 AND tenant_id=$2 AND actor_id=$3 AND actor_kind=$4 AND method=$5 AND route_id=$6 AND key_digest=$7`
		err := tx.QueryRow(w, query, args...).Scan(values...)
		if err != nil {
			return RequestKeyAdmission{}, nil, nil, err
		}
		if len(raw) != 16 || version < 1 || version > 4294967295 || len(digest) != 32 || len(safe) == 0 || len(safe) > 65536 {
			return RequestKeyAdmission{}, nil, nil, identity.UnavailableError{}
		}
		id, err := identity.ParseCommandID(base64.RawURLEncoding.EncodeToString(raw))
		return RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: uint32(version)}, digest, safe, err
	}
	admission, storedDigest, storedSafe, err := read()
	if errors.Is(err, pgx.ErrNoRows) {
		digest, safe, fingerprintErr := requestIntentFingerprint(scope, fields, c.requestKeys.Policy.PolicyVersion, current)
		if fingerprintErr != nil {
			return RequestKeyAdmission{}, fingerprintErr
		}
		var candidate identity.CommandID
		if preparation != nil {
			candidate = preparation.candidate.CommandID
		}
		if candidate == "" {
			var entropyErr error
			candidate, entropyErr = identity.NewCommandID()
			if entropyErr != nil {
				return RequestKeyAdmission{}, identity.UnavailableError{}
			}
		}
		if preparation != nil {
			if preparation.candidate.CommandID == "" {
				// No native callback executes while correlation holds a transaction.
				if err := tx.Rollback(w); err != nil {
					return RequestKeyAdmission{}, listFailure(w, err)
				}
				preparation.candidate = RequestKeyAdmission{CommandID: candidate, FingerprintKeyVersion: c.keys.current}
				binding := c.requestPreparationBinding(scope, preparation.candidate, preparation.feature, digest)
				wire, err := generateRequestPreparation(w, preparation.owner, binding, intent)
				if err != nil {
					return RequestKeyAdmission{}, err
				}
				preparation.ciphertext = wire
				return c.resolveRequestKey(w, scope, key, intent, caller, preparation)
			}
			candidate = preparation.candidate.CommandID
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(candidate))
		insert := append(append([]any(nil), args...), raw, digest[:], int64(c.keys.current), safe)
		// Existing global execution claims are never adopted as fresh allocation.
		// A collision fails rather than granting an unrelated historical command.
		query := `INSERT INTO identity.request_key_mappings(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest,command_id,fingerprint,fingerprint_key_version,safe_fields`
		selection := ` SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11`
		if preparation != nil {
			query += `,request_preparation_identity,request_preparation_ciphertext`
			selection += `,$12,$13`
			insert = append(insert, preparation.identity[:], preparation.ciphertext)
		}
		query += `)` + selection + ` WHERE NOT EXISTS(SELECT 1 FROM identity.identity_command_id_claims WHERE command_id=$8)
 ON CONFLICT(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest) DO NOTHING`
		_, err = tx.Exec(w, query, insert...)
		if err != nil {
			var collision *pgconn.PgError
			if errors.As(err, &collision) && collision.Code == "23505" {
				return RequestKeyAdmission{}, identity.ConflictError{}
			}
			return RequestKeyAdmission{}, listFailure(w, err)
		}
		admission, storedDigest, storedSafe, err = read()
	}
	if err != nil {
		return RequestKeyAdmission{}, listFailure(w, err)
	}
	retained, ok := c.keys.retained[admission.FingerprintKeyVersion]
	if !ok || retained == ([32]byte{}) {
		return RequestKeyAdmission{}, identity.UnavailableError{}
	}
	expected, safe, err := requestIntentFingerprint(scope, fields, c.requestKeys.Policy.PolicyVersion, retained)
	if err != nil {
		return RequestKeyAdmission{}, err
	}
	if !hmac.Equal(storedDigest, expected[:]) || !bytes.Equal(storedSafe, safe) {
		return RequestKeyAdmission{}, identity.ConflictError{}
	}
	if preparation != nil {
		if !hmac.Equal(preparation.storedIdentity, preparation.identity[:]) || len(preparation.storedCiphertext) == 0 || len(preparation.storedCiphertext) > maximumPreparationCiphertext {
			return RequestKeyAdmission{}, identity.ConflictError{}
		}
		preparation.binding = c.requestPreparationBinding(scope, admission, preparation.feature, expected)
	}
	if err := tx.Commit(w); err != nil {
		return RequestKeyAdmission{}, identity.UnknownCommitError{CommandID: admission.CommandID}
	}
	return admission, nil
}

func validRequestKeyConfig(c RequestKeyConfig) bool {
	return queryScopeText(c.Namespace) && c.lookupKey != nil && c.lookupKey() != ([32]byte{}) && validCommandQueryPolicy(c.Policy)
}

func validRequestKeyScope(s RequestKeyScope) bool {
	if !queryScopeText(string(s.TenantID)) || !queryScopeText(string(s.ActorID)) || !queryScopeText(s.RouteID) {
		return false
	}
	if s.ActorKind != authorization.SubjectUser && s.ActorKind != authorization.SubjectAPIKey && s.ActorKind != authorization.SubjectServiceAccount {
		return false
	}
	switch s.Method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

func authorizeRequestKey(ctx context.Context, scope RequestKeyScope, caller authorization.DecisionContext, config *RequestKeyConfig) (allowed bool, err error) {
	defer func() {
		if recover() != nil {
			allowed, err = false, identity.UnavailableError{}
		}
	}()
	if !boundedQueryCaller(caller) {
		return false, nil
	}
	dc := caller.Clone()
	r := dc.Request
	if r.Subject.ID != authorization.SubjectID(scope.ActorID) || r.Subject.Kind != scope.ActorKind || r.Tenant != authorization.TenantID(scope.TenantID) || r.Action != authorization.Action(scope.RouteID) || r.Resource.Type != "identity.request-admission" || r.Resource.ID != authorization.ResourceID(scope.RouteID) || dc.PolicyRevision != authorization.Revision(config.Policy.PolicyVersion) {
		return false, nil
	}
	now := config.Policy.Clock.Now()
	if now.IsZero() {
		return false, identity.UnavailableError{}
	}
	dc.Request.Environment.Time = now.UTC()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes)
	}
	for name := range dc.Request.Resource.Attributes {
		if strings.HasPrefix(string(name), "identity.request.") || strings.HasPrefix(string(name), "identity.command.") {
			delete(dc.Request.Resource.Attributes, name)
		}
	}
	dc.Request.Resource.Attributes["identity.request.admission"] = authorization.BoolValue(true)
	dc.Request.Resource.Attributes["identity.request.method"] = authorization.StringValue(scope.Method)
	dc.Request.Resource.Attributes["identity.request.namespace"] = authorization.StringValue(config.Namespace)
	if len(dc.Request.Resource.Attributes) > 128 {
		return false, nil
	}
	decision, err := config.Policy.Authorization.Decide(ctx, dc)
	if err != nil {
		return false, identity.UnavailableError{}
	}
	return decision.Outcome == authorization.Allow && decision.Revision == authorization.Revision(config.Policy.PolicyVersion), nil
}

func requestNamespaceIdentity(namespace string, key [32]byte) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("golib.identity.request-namespace.v1\x00"))
	_, _ = mac.Write(cborText(namespace))
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func requestIntentFingerprint(scope RequestKeyScope, fields []identity.FeatureField, policy uint64, key [32]byte) ([32]byte, []byte, error) {
	encoded, kinds := make(map[string][]byte, len(fields)), make(map[string][]byte, len(fields))
	for _, field := range fields {
		value, err := encodeFeatureValue(field.Value)
		if err != nil {
			return [32]byte{}, nil, err
		}
		digest, err := commandSecret(key, "request."+field.Name, value, 8195)
		clear(value)
		if err != nil {
			return [32]byte{}, nil, err
		}
		kind := cborUint(uint64(field.Value.Kind))
		encoded[field.Name] = cborMap(map[string][]byte{"kind": kind, "value": cborBytes(digest)})
		kinds[field.Name] = kind
	}
	metadata := map[string][]byte{"profile": cborText("identity-request-intent-v1"), "tenant": cborText(string(scope.TenantID)), "actor": cborText(string(scope.ActorID)), "actor_kind": cborText(string(scope.ActorKind)), "method": cborText(scope.Method), "route": cborText(scope.RouteID), "policy_version": cborUint(policy)}
	metadata["fields"] = cborMap(kinds)
	safe := cborMap(metadata)
	metadata["fields"] = cborMap(encoded)
	canonical := cborMap(metadata)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(canonical)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, safe, nil
}

func invalidRequestKey() error { return identity.InvalidInputError{Field: "request_key"} }
