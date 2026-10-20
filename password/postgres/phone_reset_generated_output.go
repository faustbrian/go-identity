package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// These projections exist only in the existing journal's encrypted output.
// They retain original plans, never authenticate their omitted owner custody.
// The actual risk/OTP owners reauthenticate every scalar before protected use.
type phoneResetStoredRiskPlan kernel.RiskEvidencePlan
type phoneResetStoredOTPPlan kernel.OTPAttemptPlan
type phoneResetStoredOutput struct {
	Schema uint8
	Spec   identity.FeatureCommandSpec
	Hash   string
	Facts  []risk.Signal
	Risk   phoneResetStoredRiskPlan
	OTP    phoneResetStoredOTPPlan
}

func (phoneResetStoredOutput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.phoneResetStoredOutput(redacted)"))
}

func phoneResetOutputBindingAAD(binding identity.CommandBinding, generation uint64, configuration [32]byte) (envelope.Context, error) {
	if binding.ValidateFor(phonePasswordResetOperation()) != nil || generation == 0 || configuration == ([32]byte{}) {
		return envelope.Context{}, password.ErrPasswordWork
	}
	frame, err := json.Marshal(struct {
		Binding       identity.CommandBinding
		Generation    uint64
		Configuration [32]byte
	}{binding, generation, configuration})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, password.ErrPasswordWork
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-phone-password-reset-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}

// Only framing is checked here, not current provider freshness or permission.
// Original provider times and the risk CheckedAt/OTP version must survive retry
// unchanged; the phase's real owners enforce them in the sole protected Work.
func (r *Repository) validatePhoneResetOutput(out phoneResetStoredOutput) error {
	spec := out.Spec
	if r == nil || r.policy.Algorithm() == "" || out.Schema != 1 || spec.Operation != phonePasswordResetOperation() || len(out.Hash) > int(r.policy.Limits().EncodedHashBytes) || len(out.Facts) == 0 || len(out.Facts) > 32 {
		return password.ErrPasswordWork
	}
	if _, err := passwordResetIntent(spec); err != nil {
		return err
	}
	structural, err := identity.NewFeatureCommand(spec)
	if err != nil {
		return password.ErrPasswordWork
	}
	canonicalSpec, _ := structural.Feature()
	if !reflect.DeepEqual(canonicalSpec, spec) {
		return password.ErrPasswordWork
	}
	if _, err := issuanceHash(out.Hash, r.policy); err != nil {
		return err
	}
	seen := make(map[string]bool, len(out.Facts))
	for _, fact := range out.Facts {
		if fact.Tenant != string(spec.Binding.TenantID) || fact.Operation != risk.Action(spec.Binding.OperationID) || fact.Attempt != string(spec.Binding.CommandID) || !reauthenticationText(fact.Name, 128) || fact.Name == "velocity" || seen[fact.Name] || fact.Trust != risk.ServerVerified || fact.State != risk.SignalClean || fact.RetryAfter != 0 || fact.BreachCount != 0 || fact.Failure != 0 || !phoneResetOutputTime(fact.ObservedAt, false) || !phoneResetOutputTime(fact.ExpiresAt, false) || !fact.ExpiresAt.After(fact.ObservedAt) {
			return password.ErrPasswordWork
		}
		seen[fact.Name] = true
		if fact.Name == "hibp" {
			if !phoneResetOutputTime(fact.CheckedAt, false) || !phoneResetOutputTime(fact.ProviderValidUntil, false) || fact.CheckedAt.Before(fact.ObservedAt) || !fact.ExpiresAt.After(fact.CheckedAt) || fact.ExpiresAt.After(fact.ProviderValidUntil) {
				return password.ErrPasswordWork
			}
		} else if !fact.CheckedAt.IsZero() || !fact.ProviderValidUntil.IsZero() {
			return password.ErrPasswordWork
		}
	}
	if !seen["hibp"] || validatePhoneResetOutputPlans(spec, kernel.RiskEvidencePlan(out.Risk), kernel.OTPAttemptPlan(out.OTP)) != nil {
		return password.ErrPasswordWork
	}
	return nil
}

func phoneResetOutputTime(t time.Time, microseconds bool) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1 && t.Year() <= 9999 && (!microseconds || t.Nanosecond()%1000 == 0)
}

func validatePhoneResetOutputPlans(spec identity.FeatureCommandSpec, r kernel.RiskEvidencePlan, p kernel.OTPAttemptPlan) error {
	b := spec.Binding
	if spec.Operation != phonePasswordResetOperation() || b.ValidateFor(spec.Operation) != nil || r.Tenant != string(b.TenantID) || r.Subject != string(b.UserID) || r.ConsumerCommandID != string(b.CommandID) || r.ConsumerActor != string(b.ActorID) || r.IssuanceCommandID == r.ConsumerCommandID || !reauthenticationText(r.IssuerActor, 128) || r.Purpose != "phone-password-reset-complete" || r.Phase != "phone-reset-completion" || r.RecoveryOperation != b.OperationID || r.PolicyVersion == 0 || r.KeyVersion == 0 || r.IntentDigest == ([32]byte{}) || r.EvidenceDigest == ([32]byte{}) || r.ProofDigest == ([32]byte{}) || r.Signature == ([32]byte{}) || !phoneResetOutputTime(r.IssuedAt, true) || !phoneResetOutputTime(r.CheckedAt, false) || !phoneResetOutputTime(r.ExpiresAt, true) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 2*time.Minute || r.CheckedAt.Before(r.IssuedAt) || !r.CheckedAt.Before(r.ExpiresAt) {
		return password.ErrPasswordWork
	}
	if _, err := identity.ParseCommandID(r.IssuanceCommandID); err != nil {
		return password.ErrPasswordWork
	}
	if _, err := identity.ParseCommandID(p.AttemptID); err != nil {
		return password.ErrPasswordWork
	}
	if p.Mode != kernel.OTPConsume || p.AttemptFingerprint == ([32]byte{}) || p.FingerprintKeyVersion == 0 || !reauthenticationText(p.ChallengeID, 256) || p.ScopeDigest == ([32]byte{}) || p.DigestKeyVersion == 0 || p.ExpectedVersion == 0 {
		return password.ErrPasswordWork
	}
	var key bool
	for _, field := range spec.Fields {
		if field.Name == "otp.digest-key-version" {
			if key || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != uint64(p.DigestKeyVersion) {
				return password.ErrPasswordWork
			}
			key = true
		}
	}
	if !key {
		return password.ErrPasswordWork
	}
	return nil
}

func (r *Repository) sealPhoneResetOutput(ctx context.Context, crypto *envelope.Service, key string, input identity.Command, generation uint64, configuration [32]byte, generated identity.Command, facts []risk.Signal, riskPlan kernel.RiskEvidencePlan, otpPlan kernel.OTPAttemptPlan) (wire []byte, err error) {
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
	before, ok := input.PhonePasswordResetInputFeature()
	after, generatedOK := generated.PhonePasswordResetFeature()
	candidate, _, _, _, borrowed := input.PhonePasswordResetInputCustody()
	hash, _, _, _, custody := generated.PhonePasswordResetCustody()
	cookie, present := input.PhonePasswordResetPreAuthCookie()
	generatedCookie, generatedPresent := generated.PhonePasswordResetPreAuthCookie()
	if !ok || !generatedOK || !borrowed || candidate.Len() == 0 || !custody || !present || !generatedPresent || cookie.Token() != generatedCookie.Token() || !reflect.DeepEqual(before, after) || len(facts) == 0 || len(facts) > 32 {
		return nil, password.ErrPasswordWork
	}
	aad, err := phoneResetOutputBindingAAD(before.Binding, generation, configuration)
	if err != nil {
		return nil, err
	}
	out := phoneResetStoredOutput{Schema: 1, Spec: before, Hash: hash, Facts: slices.Clone(facts), Risk: phoneResetStoredRiskPlan(riskPlan), OTP: phoneResetStoredOTPPlan(otpPlan)}
	if err := r.validatePhoneResetOutput(out); err != nil {
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

// Restore borrows all original live joint inputs without provider/hash work,
// comparison, consumption or renewed facts/plans. Decryption is not authority:
// the native phase must independently authenticate the retained owners and
// original request provenance before executing in the existing coordinator.
func (r *Repository) restorePhoneResetOutput(ctx context.Context, crypto *envelope.Service, input identity.Command, generation uint64, configuration [32]byte, wire []byte) (command identity.Command, facts []risk.Signal, riskPlan kernel.RiskEvidencePlan, otpPlan kernel.OTPAttemptPlan, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			command, facts, riskPlan, otpPlan = identity.Command{}, nil, kernel.RiskEvidencePlan{}, kernel.OTPAttemptPlan{}
		}
	}()
	spec, ok := input.PhonePasswordResetInputFeature()
	candidate, proof, sms, totp, custody := input.PhonePasswordResetInputCustody()
	cookie, present := input.PhonePasswordResetPreAuthCookie()
	if !ok || !custody || !present || candidate.Len() == 0 {
		return command, nil, riskPlan, otpPlan, password.ErrPasswordWork
	}
	stored, err := r.openPhoneResetOutput(ctx, crypto, spec.Binding, generation, configuration, wire)
	if err != nil || !reflect.DeepEqual(spec, stored.Spec) {
		return command, nil, riskPlan, otpPlan, password.ErrPasswordWork
	}
	command, err = identity.NewFeaturePhonePasswordResetCommand(spec, stored.Hash, proof, sms, totp)
	if err == nil {
		command, err = identity.BindPhonePasswordResetPreAuth(command, cookie)
	}
	if err != nil {
		return command, nil, riskPlan, otpPlan, password.ErrPasswordWork
	}
	return command, slices.Clone(stored.Facts), kernel.RiskEvidencePlan(stored.Risk), kernel.OTPAttemptPlan(stored.OTP), nil
}

// Only authenticated native retry uses this code-free original projection.
// Actual risk/OTP owners reauthenticate the retained plans; scalar inspection
// does not establish a factor, permission, one-use reservation or terminal result.
func (r *Repository) readPhoneResetOutputIntent(ctx context.Context, crypto *envelope.Service, binding identity.CommandBinding, generation uint64, configuration [32]byte, wire []byte) (spec identity.FeatureCommandSpec, riskPlan kernel.RiskEvidencePlan, otpPlan kernel.OTPAttemptPlan, err error) {
	defer func() {
		if recover() != nil {
			err = password.ErrPasswordWork
		}
		if ctx != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			spec, riskPlan, otpPlan = identity.FeatureCommandSpec{}, kernel.RiskEvidencePlan{}, kernel.OTPAttemptPlan{}
		}
	}()
	stored, err := r.openPhoneResetOutput(ctx, crypto, binding, generation, configuration, wire)
	if err != nil {
		return spec, riskPlan, otpPlan, err
	}
	return stored.Spec, kernel.RiskEvidencePlan(stored.Risk), kernel.OTPAttemptPlan(stored.OTP), nil
}

func (r *Repository) openPhoneResetOutput(ctx context.Context, crypto *envelope.Service, binding identity.CommandBinding, generation uint64, configuration [32]byte, wire []byte) (phoneResetStoredOutput, error) {
	zero := phoneResetStoredOutput{}
	if ctx == nil || crypto == nil || len(wire) == 0 || len(wire) > maximumResetOutput {
		return zero, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	aad, err := phoneResetOutputBindingAAD(binding, generation, configuration)
	if err != nil {
		return zero, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return zero, password.ErrPasswordWork
	}
	plain, err := crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumResetOutput-4096 || !boundedPhoneResetOutputJSON(plain) {
		return zero, password.ErrPasswordWork
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var stored phoneResetStoredOutput
	if decoder.Decode(&stored) != nil || decoder.Decode(new(any)) != io.EOF || stored.Spec.Binding != binding || r.validatePhoneResetOutput(stored) != nil {
		return zero, password.ErrPasswordWork
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(plain, canonical) {
		return zero, password.ErrPasswordWork
	}
	return stored, nil
}

// Root FeatureCommandSpec permits at most128 fields; this schema's other
// arrays are at most32 provider facts or digest bytes. Reject larger arrays
// before typed JSON decoding can amplify a small array into many large structs.
// The fixed output schema has fewer than16 nested containers.
func boundedPhoneResetOutputJSON(plain []byte) bool {
	type container struct {
		array bool
		count int
	}
	stack := make([]container, 0, 16)
	decoder := json.NewDecoder(bytes.NewReader(plain))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return len(stack) == 0
		}
		if err != nil {
			return false
		}
		delimiter, compound := token.(json.Delim)
		closing := compound && (delimiter == ']' || delimiter == '}')
		if len(stack) > 0 && stack[len(stack)-1].array && !closing {
			stack[len(stack)-1].count++
			if stack[len(stack)-1].count > 128 {
				return false
			}
		}
		if compound {
			if closing {
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
			} else {
				if len(stack) == 16 {
					return false
				}
				stack = append(stack, container{array: delimiter == '['})
			}
		}
	}
}
