package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"reflect"
	"slices"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// This private projection exists only inside the existing preparation journal's
// authenticated encrypted output. It is not a second admission or intent store.
// Restore of signed admission remains the risk owner's responsibility.
type resetStoredAdmission risk.PreparedAuthenticationAdmission
type resetStoredOutput struct {
	Schema    uint8
	Spec      identity.FeatureCommandSpec
	Hash      string
	Admission resetStoredAdmission
	Facts     []risk.Signal
}

const maximumResetOutput = 1 << 20

func resetOutputAAD(input identity.Command, generation uint64, profile [32]byte) (envelope.Context, error) {
	spec, ok := input.PasswordResetInputFeature()
	if !ok || generation == 0 || profile == ([32]byte{}) {
		return envelope.Context{}, password.ErrPasswordWork
	}
	if _, err := passwordResetIntent(spec); err != nil {
		return envelope.Context{}, err
	}
	return resetOutputBindingAAD(spec.Binding, generation, profile)
}

// Original aggregate CAS is authenticated inside ciphertext. Binding remains
// known before decryption even after the account advances; it cannot be
// reconstructed from today's state or confused with a signed security epoch.
func resetOutputBindingAAD(binding identity.CommandBinding, generation uint64, profile [32]byte) (envelope.Context, error) {
	if binding.ValidateFor(resetOperation()) != nil || generation == 0 || profile == ([32]byte{}) {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding    identity.CommandBinding
		Generation uint64
		Profile    [32]byte
	}{binding, generation, profile})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-password-reset-output-v2", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// Storage-shape checks cannot authenticate risk custody or current permission.
// The native phase must Restore admission and fence signed/current authority
// before executing the reconstructed command in its original protected Work.
func (r *Repository) validateResetOutput(out resetStoredOutput) error {
	spec := out.Spec
	p := risk.PreparedAuthenticationAdmission(out.Admission)
	if r == nil || out.Schema != 2 || r.policy.Algorithm() == "" || len(out.Hash) > int(r.policy.Limits().EncodedHashBytes) || len(p.Signals) == 0 || len(p.Signals) > 31 || len(out.Facts) != len(p.Signals)+1 || p.KeyVersion == 0 || p.PolicyVersion == 0 || p.Signature == ([32]byte{}) || p.ProofDigest == ([32]byte{}) || p.ConfigurationDigest == ([32]byte{}) || !reauthenticationText(p.CounterFingerprint, 256) || p.Scope.Tenant != string(spec.Binding.TenantID) || p.Scope.Operation != "identity.password.reset-complete" || p.Scope.Attempt != string(spec.Binding.CommandID) {
		return password.ErrPasswordWork
	}
	if _, err := passwordResetIntent(spec); err != nil {
		return err
	}
	if _, err := issuanceHash(out.Hash, r.policy); err != nil {
		return err
	}
	if !slices.Equal(p.Signals, out.Facts[:len(p.Signals)]) || out.Facts[len(p.Signals)].Name != "hibp" || out.Facts[len(p.Signals)].Trust != risk.ServerVerified {
		return password.ErrPasswordWork
	}
	for i, fact := range out.Facts {
		if fact.Tenant != p.Scope.Tenant || fact.Operation != p.Scope.Operation || fact.Attempt != p.Scope.Attempt || !reauthenticationText(fact.Name, 128) || (i < len(p.Signals) && fact.Name == "hibp") {
			return password.ErrPasswordWork
		}
	}
	return nil
}

func (r *Repository) sealResetOutput(ctx context.Context, crypto *envelope.Service, key string, input identity.Command, generation uint64, profile [32]byte, generated identity.Command, admission risk.AuthenticationAdmission, facts []risk.Signal) (wire []byte, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			clear(wire)
			wire = nil
		}
	}()
	if ctx == nil || crypto == nil || !reauthenticationText(key, 256) {
		return nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, ok := input.PasswordResetInputFeature()
	after, generatedOK := generated.PasswordResetFeature()
	hash, _, custody := generated.PasswordResetCustody()
	if !ok || !generatedOK || !custody || !reflect.DeepEqual(before, after) {
		return nil, password.ErrPasswordWork
	}
	aad, err := resetOutputAAD(input, generation, profile)
	if err != nil {
		return nil, err
	}
	out := resetStoredOutput{Schema: 2, Spec: before, Hash: hash, Admission: resetStoredAdmission(admission.Prepared()), Facts: slices.Clone(facts)}
	if err := r.validateResetOutput(out); err != nil {
		return nil, err
	}
	plain, err := json.Marshal(out)
	defer clear(plain)
	if err != nil || len(plain) > maximumResetOutput-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: key, Context: aad})
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	wire, err = sealed.MarshalBinary()
	if err != nil || len(wire) > maximumResetOutput {
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

// Restoring performs no provider/hash work and does not renew original times.
// It borrows the invocation's original proof rather than storing bearer bytes.
// Proof-free terminal recovery instead uses the existing participant receipts;
// it must not reconstruct a command that can authorize another mutation.
func (r *Repository) restoreResetOutput(ctx context.Context, crypto *envelope.Service, input identity.Command, generation uint64, profile [32]byte, wire []byte) (command identity.Command, admission risk.PreparedAuthenticationAdmission, facts []risk.Signal, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			command, admission, facts = identity.Command{}, risk.PreparedAuthenticationAdmission{}, nil
		}
	}()
	if ctx == nil || crypto == nil || len(wire) == 0 || len(wire) > maximumResetOutput {
		return command, admission, nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return command, admission, nil, err
	}
	spec, ok := input.PasswordResetInputFeature()
	if !ok {
		return command, admission, nil, password.ErrPasswordWork
	}
	stored, err := r.openResetOutput(ctx, crypto, spec.Binding, generation, profile, wire)
	if err != nil || !reflect.DeepEqual(spec, stored.Spec) {
		return command, admission, nil, password.ErrPasswordWork
	}
	_, proof, custody := input.PasswordResetInputCustody()
	if !custody {
		return command, admission, nil, password.ErrPasswordWork
	}
	command, err = identity.NewFeaturePasswordResetCommand(spec, stored.Hash, proof)
	if err != nil {
		return command, admission, nil, password.ErrPasswordWork
	}
	return command, risk.PreparedAuthenticationAdmission(stored.Admission), slices.Clone(stored.Facts), nil
}

// Only native composition uses this code-free original metadata to rebuild
// caller input. It must still authenticate issuance/signed scope and submit the
// supplied raw password/proof to the coordinator's original fingerprint check.
// Decryption is not execution permission or a terminal receipt.
func (r *Repository) readResetOutputIntent(ctx context.Context, crypto *envelope.Service, binding identity.CommandBinding, generation uint64, profile [32]byte, wire []byte) (spec identity.FeatureCommandSpec, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			spec = identity.FeatureCommandSpec{}
		}
	}()
	stored, err := r.openResetOutput(ctx, crypto, binding, generation, profile, wire)
	if err != nil {
		return spec, err
	}
	return stored.Spec, nil
}

func (r *Repository) openResetOutput(ctx context.Context, crypto *envelope.Service, binding identity.CommandBinding, generation uint64, profile [32]byte, wire []byte) (resetStoredOutput, error) {
	zero := resetStoredOutput{}
	if ctx == nil || crypto == nil || len(wire) == 0 || len(wire) > maximumResetOutput {
		return zero, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	aad, err := resetOutputBindingAAD(binding, generation, profile)
	if err != nil {
		return zero, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return zero, password.ErrPasswordWork
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumResetOutput-4096 {
		return zero, password.ErrPasswordWork
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var stored resetStoredOutput
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || stored.Spec.Binding != binding || r.validateResetOutput(stored) != nil {
		return zero, password.ErrPasswordWork
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) {
		return zero, password.ErrPasswordWork
	}
	return stored, nil
}
