package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequestKeyPreparationContributor is an optional exact registered native
// feature owner. PrepareRequestKey performs bounded reads and authenticated
// encryption of original code-free input outside SQL. It must not assess risk,
// charge counters, generate OTPs, deliver messages or mutate domain state.
// Concurrent missing-key callers may prepare discarded candidates. Only the
// acknowledged immutable mapping winner may proceed to the existing journal.
// The ciphertext must bind every PreparationBinding field and the owner's
// immutable configuration. Include configuration identity in RequestIntent.
// Never retain raw bearer/code/key material. Methods must support concurrency.
type RequestKeyPreparationContributor interface {
	FeatureExecutionContributor
	PrepareRequestKey(context.Context, RequestKeyPreparationBinding, identity.RequestIntent) ([]byte, error)
}

// RequestKeyPreparationBinding is original input provenance, not execution or
// current authority. Authenticate the complete scalar binding as envelope AAD.
// Namespace, scope, feature and policy are trusted composition; admission and
// intent digest are coordinator-derived. No raw initiating key is included.
// Copies are immutable by convention and safe for concurrent reads.
type RequestKeyPreparationBinding struct {
	Namespace     string
	Scope         RequestKeyScope
	Admission     RequestKeyAdmission
	Feature       FeatureRegistration
	PolicyVersion uint64
	IntentDigest  [32]byte
}

// Format hides correlation and intent provenance from diagnostics.
func (RequestKeyPreparationBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RequestKeyPreparationBinding(redacted)"))
}

// MarshalJSON rejects serialization outside the native authenticated codec.
func (RequestKeyPreparationBinding) MarshalJSON() ([]byte, error) { return nil, invalidRequestKey() }

// LogValue redacts original request provenance.
func (RequestKeyPreparationBinding) LogValue() slog.Value {
	return slog.StringValue("postgres.RequestKeyPreparationBinding(redacted)")
}

type requestKeyPreparation struct {
	owner                                        RequestKeyPreparationContributor
	feature                                      FeatureRegistration
	identity                                     [32]byte
	candidate                                    RequestKeyAdmission
	ciphertext, storedIdentity, storedCiphertext []byte
	binding                                      RequestKeyPreparationBinding
}

// ResolvePreparedRequestKey retains original native code-free ciphertext in
// the existing immutable request-key mapping, atomically with its command ID.
// Install RequestKeyPreparationMigrationSource after RequestKeyMigrationSource.
// Existing rows are never backfilled or enrolled; missing/incompatible custody
// conflicts. Matching retries recover original ciphertext before native reads,
// counters or code generation; changed initiating intent returns no custody.
// Only the exact registered native feature may prepare input for its route.
// Preparation is outside SQL and may run more than once under races, but replay
// never invokes it. Returned bytes are owned, bounded to 1 MiB and must be
// authenticated by the native codec. Neither ciphertext nor binding proves
// current authority or grants journal execution. Unknown commit returns no
// binding/bytes; retry the same key/intent. Earlier deadlines win, callbacks and
// diagnostics are redacted, and the pool remains caller-owned.
func (c *Coordinator) ResolvePreparedRequestKey(ctx context.Context, scope RequestKeyScope, key identity.IdempotencyKey, intent identity.RequestIntent, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyPreparationContributor) (RequestKeyPreparationBinding, []byte, error) {
	if err := c.validateRequestPreparation(scope, feature, owner); err != nil {
		return RequestKeyPreparationBinding{}, nil, err
	}
	p := &requestKeyPreparation{owner: owner, feature: feature, identity: requestPreparationIdentity(feature)}
	_, err := c.resolveRequestKey(ctx, scope, key, intent, caller, p)
	clear(p.ciphertext)
	if err != nil {
		return RequestKeyPreparationBinding{}, nil, err
	}
	return p.binding, bytes.Clone(p.storedCiphertext), nil
}

func (c *Coordinator) validateRequestPreparation(scope RequestKeyScope, feature FeatureRegistration, owner RequestKeyPreparationContributor) error {
	if c == nil || c.registry == nil || scope.RouteID != feature.Operation.OperationID {
		return invalidRequestKey()
	}
	entry, err := c.registry.selectFeatureOperation(feature)
	if err != nil || !sameParticipant(entry.contributor, owner) {
		return invalidRequestKey()
	}
	return nil
}

func (c *Coordinator) requestPreparationBinding(scope RequestKeyScope, admission RequestKeyAdmission, feature FeatureRegistration, digest [32]byte) RequestKeyPreparationBinding {
	return RequestKeyPreparationBinding{Namespace: c.requestKeys.Namespace, Scope: scope, Admission: admission, Feature: feature, PolicyVersion: c.requestKeys.Policy.PolicyVersion, IntentDigest: digest}
}

func requestPreparationIdentity(f FeatureRegistration) [32]byte {
	wire := cborMap(map[string][]byte{
		"profile": cborText("identity-request-preparation-v1"),
		"owner":   cborText(f.Contributor.Owner), "contract": cborText(f.Contributor.ContractID), "contract_version": cborUint(uint64(f.Contributor.Version)),
		"feature_owner": cborText(f.Operation.Owner), "operation": cborText(f.Operation.OperationID), "schema": cborText(f.Operation.SchemaID), "schema_version": cborUint(uint64(f.Operation.SchemaVersion)),
		"record": cborUint(uint64(f.Operation.RecordRequirement)), "subject": cborUint(uint64(f.Operation.SubjectRequirement)),
	})
	return sha256.Sum256(wire)
}

func generateRequestPreparation(ctx context.Context, p RequestKeyPreparationContributor, b RequestKeyPreparationBinding, intent identity.RequestIntent) (wire []byte, err error) {
	defer func() {
		if recover() != nil {
			wire, err = nil, identity.UnavailableError{}
		}
	}()
	if ctx == nil {
		return nil, invalidRequestKey()
	}
	if ctx.Err() != nil {
		return nil, readFailure(ctx, ctx.Err())
	}
	out, e := p.PrepareRequestKey(ctx, b, intent)
	if ctx.Err() != nil {
		return nil, readFailure(ctx, ctx.Err())
	}
	if e != nil || len(out) == 0 || len(out) > maximumPreparationCiphertext {
		return nil, identity.UnavailableError{}
	}
	return bytes.Clone(out), nil
}
