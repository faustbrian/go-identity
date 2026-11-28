package impersonationpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const maxKeyedStartBinding = 4096

var _ kernel.RequestKeyRecoveryContributor = (*approvalPhase)(nil)

func (p *approvalPhase) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	if p.keyed == nil {
		return nil, identity.ForbiddenError{}
	}
	k := p.keyed
	expected, _ := k.intent.Fields()
	actual, valid := intent.Fields()
	if !valid || !reflect.DeepEqual(expected, actual) {
		return nil, identity.ForbiddenError{}
	}
	aad, err := k.mappingContext(b)
	if err != nil {
		return nil, err
	}
	input := k.input
	input.CommandID = b.Admission.CommandID
	prepared, err := p.service.PrepareStart(ctx, input)
	if err != nil {
		k.failure = err
		return nil, err
	}
	original, err := prepared.Binding()
	if err != nil || !k.matchesBinding(b, original) {
		return nil, identity.UnavailableError{}
	}
	plain, err := json.Marshal(original)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer clear(plain)
	wire, err := encryptCustody(ctx, k.service.custody, k.service.activeKey, aad, plain, maxKeyedStartBinding)
	if err != nil || len(wire) > maxKeyedStartBinding+4096 {
		clear(wire)
		return nil, identity.UnavailableError{}
	}
	k.local, k.projectionHash = prepared, sha256.Sum256(wire)
	return wire, nil
}

func (p *approvalPhase) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	var zero identity.CommandBinding
	if p.keyed == nil || ctx == nil || len(wire) == 0 || len(wire) > maxKeyedStartBinding+4096 {
		return zero, identity.UnavailableError{}
	}
	k := p.keyed
	aad, err := k.mappingContext(b)
	if err != nil {
		return zero, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return zero, identity.UnavailableError{}
	}
	plain, err := k.service.custody.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maxKeyedStartBinding {
		return zero, identity.UnavailableError{}
	}
	var original identity.CommandBinding
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&original) != nil || decoder.Decode(new(any)) != io.EOF || !k.matchesBinding(b, original) {
		return zero, identity.UnavailableError{}
	}
	canonical, err := json.Marshal(original)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) {
		return zero, identity.UnavailableError{}
	}
	return original, nil
}

func (k *keyedStartInvocation) matchesBinding(b kernel.RequestKeyPreparationBinding, original identity.CommandBinding) bool {
	return original.ValidateFor(keyedStartRegistration().Operation) == nil && original.CommandID == b.Admission.CommandID &&
		original.TenantID == b.Scope.TenantID && original.ActorID == b.Scope.ActorID && original.ActorKind == b.Scope.ActorKind &&
		original.RecordID == string(k.input.GrantID) && original.RecordID != string(original.CommandID) && original.UserID != identity.UserID(original.ActorID) &&
		original.PolicyID == k.service.native.config.Policy.ID() && original.PolicyVersion == b.PolicyVersion &&
		original.CorrelationID == string(original.CommandID)
}

func (k *keyedStartInvocation) mappingContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if b.Namespace != k.service.requestKeys.Namespace || b.Scope != k.scope || b.Feature != keyedStartRegistration() ||
		b.PolicyVersion != k.service.native.config.Policy.Version() || b.IntentDigest == ([32]byte{}) || b.Admission.FingerprintKeyVersion == 0 {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(b.Admission.CommandID)); err != nil || string(b.Admission.CommandID) == string(k.input.GrantID) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	// Bind the complete coordinator-owned preparation and independently
	// pinned native configuration, not request ciphertext or secret output.
	frame, err := json.Marshal(struct {
		Namespace       string
		Scope           kernel.RequestKeyScope
		Admission       kernel.RequestKeyAdmission
		Feature         kernel.FeatureRegistration
		PolicyVersion   uint64
		IntentDigest    [32]byte
		ConfigurationID string
		PolicyID        string
	}{b.Namespace, b.Scope, b.Admission, b.Feature, b.PolicyVersion, b.IntentDigest, k.service.configurationID, k.service.native.config.Policy.ID()})
	if err != nil {
		return envelope.Context{}, identity.UnavailableError{}
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-impersonation-keyed-start-v1", "scope": hex.EncodeToString(digest[:])})
}
