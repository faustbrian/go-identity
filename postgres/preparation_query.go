package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// PreparedFeatureRecord is original encrypted native custody, not a credential,
// permission, fresh authority or permission to reexecute a command. The exact
// registered owner must authenticate both envelopes and separately authenticate
// bearer possession and current authority before using their contents. Returned
// byte slices are owned by the caller; do not log or serialize them. Preserve
// InputBinding and OutputGeneration unchanged when restoring original custody.
type PreparedFeatureRecord struct {
	InputBinding     RequestKeyPreparationBinding
	InputCiphertext  []byte
	OutputGeneration uint64
	OutputCiphertext []byte
}

// Format hides encrypted custody and correlation from diagnostics.
func (PreparedFeatureRecord) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PreparedFeatureRecord(redacted)"))
}

// MarshalJSON rejects accidental persistence or transport of native custody.
func (PreparedFeatureRecord) MarshalJSON() ([]byte, error) { return nil, invalidPreparation() }

// MarshalText rejects accidental textual disclosure of native custody.
func (PreparedFeatureRecord) MarshalText() ([]byte, error) { return nil, invalidPreparation() }

// LogValue hides encrypted custody and correlation from structured logs.
func (PreparedFeatureRecord) LogValue() slog.Value {
	return slog.StringValue("postgres.PreparedFeatureRecord(redacted)")
}

// QueryPreparedFeature selects existing committed preparation by its original
// server CommandID. It requires current CommandQueryPolicy authorization, exact
// historical query scope and the exact registered request/preparation owner.
// Both original input and generated output must exist in the existing immutable
// mapping/journal. Legacy, pending, aborted, retired and incomplete history deny
// without creating, recovering or taking over work. No participant callback,
// entropy, external admission or domain mutation runs. Generic QueryCommand's
// metadata-only contract is unchanged.
//
// Input provenance uses the original request policy/key version, not today's
// revision. OutputGeneration is the original ciphertext generation, never a
// later takeover generation. Neither value renews expiry or authority. Native
// owners must separately check current flow possession even on terminal history.
// Reads are uncached, bounded by MaximumDuration and earlier caller deadlines;
// all failures return zero custody and redacted classified errors. The borrowed
// pool stays caller-owned. Immutable configuration supports concurrent queries.
func (c *Coordinator) QueryPreparedFeature(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, feature FeatureRegistration, owner FeaturePreparationContributor) (PreparedFeatureRecord, error) {
	zero := PreparedFeatureRecord{}
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.requestKeys == nil || !validRequestKeyConfig(*c.requestKeys) || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return zero, invalidPreparation()
	}
	inputOwner, ok := owner.(RequestKeyPreparationContributor)
	scope := RequestKeyScope{TenantID: q.TenantID, ActorID: q.ActorID, ActorKind: q.ActorKind, Method: "POST", RouteID: q.OperationID}
	if !ok || c.validateRequestPreparation(scope, feature, inputOwner) != nil {
		return zero, invalidPreparation()
	}
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	var original commandObservation
	var protectedCounters bool
	receipt, err := c.queryCommandReceiptChecked(ctx, q, caller, func(observed commandObservation) error {
		b, op, err := decodeObservedScope(observed.scope)
		if err != nil || op == nil || *op != feature.Operation || len(observed.fingerprint) != 32 {
			return identity.ForbiddenError{}
		}
		plan, err := decodeFeaturePlan(b, [32]byte(observed.fingerprint), observed.plan)
		if err != nil || plan.Feature == nil || *plan.Feature != feature {
			return identity.ForbiddenError{}
		}
		original = observed
		protectedCounters = plan.CommandCounters != nil
		return nil
	})
	if err != nil {
		return zero, err
	}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return zero, identity.ForbiddenError{}
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	var safe, digest, preparationIdentity, namespaceBinding, input, output []byte
	var keyVersion int64
	var generation, started, current string
	var profile int16
	err = c.pool.Raw().QueryRow(ctx, `SELECT r.safe_fields,r.fingerprint,r.fingerprint_key_version,r.request_preparation_identity,n.key_identity,r.method,
CASE WHEN octet_length(r.request_preparation_ciphertext) BETWEEN 1 AND 1048576 THEN r.request_preparation_ciphertext END,
CASE WHEN octet_length(j.preparation_ciphertext) BETWEEN 1 AND 1048576 THEN j.preparation_ciphertext END,
coalesce(j.preparation_ciphertext_generation::text,''),coalesce(j.preparation_started_generation::text,''),j.generation::text,coalesce(j.preparation_profile,0)
FROM identity.request_key_mappings r JOIN identity.request_key_namespaces n USING(namespace)
JOIN identity.identity_command_id_claims c ON c.command_id=r.command_id
JOIN identity.commands j ON j.command_id=c.command_id AND j.tenant_id=c.tenant_id AND j.purpose=c.purpose
WHERE r.command_id=$1 AND r.namespace=$2 AND r.tenant_id=$3 AND r.actor_id=$4 AND r.actor_kind=$5 AND r.route_id=$6
AND NOT c.retired AND c.safe_fields=$7 AND c.fingerprint=$8 AND j.command_plan=$9 AND j.state='committed'`, id, c.requestKeys.Namespace, string(q.TenantID), string(q.ActorID), string(q.ActorKind), q.OperationID, original.scope, original.fingerprint, original.plan).Scan(&safe, &digest, &keyVersion, &preparationIdentity, &namespaceBinding, &scope.Method, &input, &output, &generation, &started, &current, &profile)
	if err != nil {
		return zero, readFailure(ctx, err)
	}
	expectedIdentity := requestPreparationIdentity(feature)
	expectedNamespace := requestNamespaceIdentity(c.requestKeys.Namespace, c.requestKeys.lookupKey())
	version, e := strconv.ParseUint(generation, 10, 64)
	currentVersion, currentError := strconv.ParseUint(current, 10, 64)
	validProfile := !protectedCounters && (profile == 1 || profile == 2) || protectedCounters && (profile == 3 || profile == 4)
	if e != nil || version == 0 || generation != started || currentError != nil || currentVersion < version || !validProfile || keyVersion < 1 || keyVersion > math.MaxUint32 || len(digest) != 32 || len(input) == 0 || len(output) == 0 || !hmac.Equal(expectedIdentity[:], preparationIdentity) || !hmac.Equal(expectedNamespace[:], namespaceBinding) {
		return zero, identity.UnavailableError{}
	}
	if key, ok := c.keys.retained[uint32(keyVersion)]; !ok || key == ([32]byte{}) {
		return zero, identity.UnavailableError{}
	}
	policy, err := preparationRequestPolicy(scope, safe)
	if err != nil {
		return zero, err
	}
	return PreparedFeatureRecord{InputBinding: RequestKeyPreparationBinding{Namespace: c.requestKeys.Namespace, Scope: scope, Admission: RequestKeyAdmission{CommandID: q.CommandID, FingerprintKeyVersion: uint32(keyVersion)}, Feature: feature, PolicyVersion: policy, IntentDigest: [32]byte(digest)}, InputCiphertext: bytes.Clone(input), OutputGeneration: version, OutputCiphertext: bytes.Clone(output)}, nil
}

// The original closed request grammar contains only field kinds, not values.
// Reencoding rejects noncanonical, duplicate, extra and alternate CBOR forms.
func preparationRequestPolicy(scope RequestKeyScope, wire []byte) (uint64, error) {
	fail := func() (uint64, error) { return 0, identity.UnavailableError{} }
	if len(wire) == 0 || len(wire) > 65536 || !validRequestKeyScope(scope) {
		return fail()
	}
	r := attributeReader{data: wire}
	if !r.exact(5, 8) {
		return fail()
	}
	metadata := map[string][]byte{}
	var policy uint64
	for range 8 {
		name, ok := r.text(32)
		if !ok || metadata[name] != nil {
			return fail()
		}
		switch name {
		case "fields":
			count, ok := r.head(5)
			if !ok || count > 128 {
				return fail()
			}
			kinds := map[string][]byte{}
			names := make([]identity.FeatureField, 0, int(count))
			for range count {
				key, ok := r.text(128)
				if !ok || !queryScopeText(key) || kinds[key] != nil {
					return fail()
				}
				kind, ok := r.head(0)
				if !ok || kind < uint64(identity.FeatureText) || kind > uint64(identity.FeatureTime) {
					return fail()
				}
				kinds[key] = cborUint(kind)
				names = append(names, identity.FeatureField{Name: key, Value: identity.FeatureValue{Kind: identity.FeatureText}})
			}
			if _, err := identity.NewRequestIntent(names); err != nil {
				return fail()
			}
			metadata[name] = cborMap(kinds)
		case "policy_version":
			var ok bool
			policy, ok = r.head(0)
			if !ok || policy == 0 {
				return fail()
			}
			metadata[name] = cborUint(policy)
		case "profile", "tenant", "actor", "actor_kind", "method", "route":
			text, ok := r.text(128)
			if !ok {
				return fail()
			}
			expected := map[string]string{"profile": "identity-request-intent-v1", "tenant": string(scope.TenantID), "actor": string(scope.ActorID), "actor_kind": string(scope.ActorKind), "method": scope.Method, "route": scope.RouteID}
			if text != expected[name] {
				return fail()
			}
			metadata[name] = cborText(text)
		default:
			return fail()
		}
	}
	if len(r.data) != 0 || policy == 0 || !bytes.Equal(cborMap(metadata), wire) {
		return fail()
	}
	return policy, nil
}
