package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"slices"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// Explicit private wire projection is confined to the original authenticated
// encrypted output. Risk.Restore still owns its signature/configuration checks;
// serialization or envelope authentication is not renewed risk admission.
type signupStoredAdmission risk.PreparedAuthenticationAdmission

type signupGeneratedOutput struct {
	Schema       uint8
	Hash         string
	Admission    signupStoredAdmission
	Facts        []risk.Signal
	Issuance     kernel.CapabilityIssuancePlan
	IssuanceWire []byte
	DeliveryWire []byte
}

// CapabilityPlan deliberately refuses general JSON export. This private
// projection is used only inside the authenticated, encrypted journal output;
// the issuer still authenticates the original grant during restoration.
type signupStoredGrant kernel.CapabilityPlan

type signupStoredIssuance struct {
	Contributor        kernel.ContributorDescriptor
	Grants             []signupStoredGrant
	RegistrationUserID identity.UserID
}

type signupStoredOutput struct {
	Schema       uint8
	Hash         string
	Admission    signupStoredAdmission
	Facts        []risk.Signal
	Issuance     signupStoredIssuance
	IssuanceWire []byte
	DeliveryWire []byte
}

func signupOutputProjection(out signupGeneratedOutput) signupStoredOutput {
	grants := make([]signupStoredGrant, len(out.Issuance.Grants))
	for i, grant := range out.Issuance.Grants {
		grants[i] = signupStoredGrant(grant)
	}
	return signupStoredOutput{out.Schema, out.Hash, out.Admission, out.Facts, signupStoredIssuance{out.Issuance.Contributor, grants, out.Issuance.RegistrationUserID}, out.IssuanceWire, out.DeliveryWire}
}

func (stored signupStoredOutput) output() signupGeneratedOutput {
	grants := make([]kernel.CapabilityPlan, len(stored.Issuance.Grants))
	for i, grant := range stored.Issuance.Grants {
		grants[i] = kernel.CapabilityPlan(grant)
	}
	return signupGeneratedOutput{stored.Schema, stored.Hash, stored.Admission, stored.Facts, kernel.CapabilityIssuancePlan{Contributor: stored.Issuance.Contributor, Grants: grants, RegistrationUserID: stored.Issuance.RegistrationUserID}, stored.IssuanceWire, stored.DeliveryWire}
}

const maximumSignupOutput = 1 << 20

func signupOutputAAD(original identity.Command, generation uint64, profile [32]byte) (envelope.Context, error) {
	spec, ok := original.PasswordSignupInputFeature()
	if !ok || spec.Operation != passwordSignupOperation() || spec.Binding.ValidateFor(passwordSignupOperation()) != nil || generation == 0 || profile == ([32]byte{}) {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Spec       identity.FeatureCommandSpec
		Generation uint64
		Profile    [32]byte
	}{spec, generation, profile})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-password-signup-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// These are bounds and original-shape fences, not current authorization. The
// workflow must restore native risk, issuer and delivery custody separately;
// expired history must never be replaced by newly generated facts or tokens.
func (r *Repository) validateSignupOutput(original identity.Command, issuer *issuerpg.Issuer, out signupGeneratedOutput) error {
	spec, ok := original.PasswordSignupInputFeature()
	if r == nil || issuer == nil || !ok || out.Schema != 1 || r.policy.Algorithm() == "" || len(out.Hash) > int(r.policy.Limits().EncodedHashBytes) || len(out.Facts) == 0 || len(out.Facts) > 32 || len(out.Admission.Signals) == 0 || len(out.Admission.Signals) > 31 || out.Admission.KeyVersion == 0 || out.Admission.PolicyVersion == 0 || out.Admission.Signature == ([32]byte{}) || out.Admission.ProofDigest == ([32]byte{}) || !reauthenticationText(out.Admission.CounterFingerprint, 256) || out.Admission.Scope.Tenant != string(spec.Binding.TenantID) || out.Admission.Scope.Operation != "identity.password.signup" || out.Admission.Scope.Attempt != string(spec.Binding.CommandID) || len(out.IssuanceWire) == 0 || len(out.IssuanceWire) > 512<<10 || len(out.DeliveryWire) > 512<<10 || len(out.IssuanceWire)+len(out.DeliveryWire) > 512<<10 || len(out.Issuance.Grants) != 1 {
		return password.ErrPasswordWork
	}
	hash, err := primitive.ParseEncodedHash(out.Hash, r.policy.Limits())
	if err != nil || !signinCurrentHash(hash, r.policy) || issuer.ValidateCapabilityIssuance(spec.Binding, out.Issuance) != nil {
		return password.ErrPasswordWork
	}
	selected := ""
	for _, field := range spec.Fields {
		if field.Name == "registration.user" && field.Value.Kind == identity.FeatureText {
			selected = field.Value.Text
		}
	}
	if selected == "" || selected != string(out.Issuance.RegistrationUserID) {
		return password.ErrPasswordWork
	}
	// Hash preparation adds exactly one owned HIBP fact to the signed original
	// authentication facts. A retained frame cannot drop, replace or refresh
	// those observations even though its envelope is authentic.
	originalCount := len(out.Admission.Signals)
	if len(out.Facts) != originalCount+1 || !slices.Equal(out.Admission.Signals, out.Facts[:originalCount]) || out.Facts[originalCount].Name != "hibp" || out.Facts[originalCount].Trust != risk.ServerVerified {
		return password.ErrPasswordWork
	}
	for _, fact := range out.Admission.Signals {
		if fact.Name == "hibp" {
			return password.ErrPasswordWork
		}
	}
	for _, facts := range [][]risk.Signal{out.Admission.Signals, out.Facts} {
		for _, fact := range facts {
			if fact.Tenant != string(spec.Binding.TenantID) || fact.Operation != "identity.password.signup" || fact.Attempt != string(spec.Binding.CommandID) || !reauthenticationText(fact.Name, 128) {
				return password.ErrPasswordWork
			}
		}
	}
	return nil
}

// Seal is called only by the existing journal's acknowledged generation. The
// nested issuer/delivery records are their owners' encrypted checkpoints, not
// plaintext credentials. Empty delivery custody is admissible storage shape,
// never permission to omit delivery from a verification-required final plan.
func (r *Repository) sealSignupOutput(ctx context.Context, crypto *envelope.Service, key string, original identity.Command, generation uint64, profile [32]byte, issuer *issuerpg.Issuer, out signupGeneratedOutput) ([]byte, error) {
	if ctx == nil || crypto == nil || !reauthenticationText(key, 256) {
		return nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	aad, err := signupOutputAAD(original, generation, profile)
	if err != nil || r.validateSignupOutput(original, issuer, out) != nil {
		return nil, password.ErrPasswordWork
	}
	plain, err := json.Marshal(signupOutputProjection(out))
	defer clear(plain)
	if err != nil || len(plain) > maximumSignupOutput-4096 {
		return nil, password.ErrPasswordWork
	}
	sealed, err := crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: key, Context: aad})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	wire, err := sealed.MarshalBinary()
	if err != nil || len(wire) > maximumSignupOutput {
		return nil, password.ErrPasswordWork
	}
	return wire, nil
}

func (r *Repository) restoreSignupOutput(ctx context.Context, crypto *envelope.Service, original identity.Command, generation uint64, profile [32]byte, issuer *issuerpg.Issuer, wire []byte) (out signupGeneratedOutput, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			clear(out.IssuanceWire)
			clear(out.DeliveryWire)
			out = signupGeneratedOutput{}
		}
	}()
	if ctx == nil || crypto == nil || len(wire) == 0 || len(wire) > maximumSignupOutput {
		return out, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	aad, err := signupOutputAAD(original, generation, profile)
	if err != nil {
		return out, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return out, password.ErrPasswordWork
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumSignupOutput-4096 {
		return out, password.ErrPasswordWork
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var stored signupStoredOutput
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF {
		clear(stored.IssuanceWire)
		clear(stored.DeliveryWire)
		return out, password.ErrPasswordWork
	}
	out = stored.output()
	if r.validateSignupOutput(original, issuer, out) != nil {
		return out, password.ErrPasswordWork
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) {
		return out, password.ErrPasswordWork
	}
	return out, nil
}
