package postgres

import (
	"bytes"
	"math"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// This is a closed extension of the existing immutable preparation declaration,
// not a new journal. The native encrypted attempt must survive loss before
// session generation: the final output cannot provide that earlier checkpoint.
// Store only encrypted OTP custody and counter time/key metadata. Original raw
// intent (including network) stays in Command, authenticated by its keyed claim.
func encodeMFAOTPPreparation(spec identity.FeatureCommandSpec, fp [32]byte, p CommandPlan) ([]byte, error) {
	if !mfaOTPNetworkMatches(spec, spec) {
		return nil, invalidPreparation()
	}
	retained := spec
	retained.Fields = nil
	for _, field := range spec.Fields {
		switch field.Name {
		case "otp.attempt-custody", "otp.digest-key-version", "counter.prepared-at", "counter.key-versions":
			retained.Fields = append(retained.Fields, field)
		}
	}
	return encodeMFAOTPPreparedMetadata(retained, fp, p)
}

func encodeMFAOTPPreparedMetadata(spec identity.FeatureCommandSpec, fp [32]byte, p CommandPlan) ([]byte, error) {
	if !validMFACompletionPlan(spec.Binding, p) || p.Feature.Operation.OperationID != "identity.mfa.otp-verify" || spec.Operation != p.Feature.Operation || p.CommandCounters == nil {
		return nil, invalidPreparation()
	}
	if len(spec.Fields) != 4 {
		return nil, invalidPreparation()
	}
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		return nil, invalidPreparation()
	}
	spec, _ = command.Feature()
	plan, err := encodeFeaturePlan(spec.Binding, fp, p)
	if err != nil {
		return nil, err
	}
	fields := make([][]byte, len(spec.Fields))
	for i, field := range spec.Fields {
		switch field.Name {
		case "otp.attempt-custody":
			if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) == 0 {
				return nil, invalidPreparation()
			}
		case "otp.digest-key-version":
			if field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 == 0 || field.Value.Uint64 > math.MaxUint32 {
				return nil, invalidPreparation()
			}
		case "counter.prepared-at":
			if field.Value.Kind != identity.FeatureTime {
				return nil, invalidPreparation()
			}
		case "counter.key-versions":
			if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) == 0 || len(field.Value.Bytes) > 128 || len(field.Value.Bytes)%4 != 0 {
				return nil, invalidPreparation()
			}
		default:
			return nil, invalidPreparation()
		}
		value, err := encodeFeatureValue(field.Value)
		if err != nil {
			return nil, invalidPreparation()
		}
		fields[i] = cborArray([][]byte{cborText(field.Name), cborUint(uint64(field.Value.Kind)), value})
	}
	wire := cborMap(map[string][]byte{"plan": cborBytes(plan), "fields": cborArray(fields), "profile": cborText("identity-mfa-otp-preparation-v1")})
	if len(wire) > 65536 {
		return nil, invalidPreparation()
	}
	return wire, nil
}

func decodeMFAOTPPreparation(b identity.CommandBinding, fp [32]byte, wire []byte) (identity.FeatureCommandSpec, CommandPlan, error) {
	fail := func() (identity.FeatureCommandSpec, CommandPlan, error) {
		return identity.FeatureCommandSpec{}, CommandPlan{}, identity.UnavailableError{}
	}
	if len(wire) == 0 || len(wire) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: wire}, ok: true}
	r.expect(5, 3)
	r.key("plan")
	planBytes := readMFAOTPPreparationBytes(&r, 65536)
	p, err := decodeFeaturePlan(b, fp, planBytes)
	if err != nil || !validMFACompletionPlan(b, p) || p.Feature.Operation.OperationID != "identity.mfa.otp-verify" || p.CommandCounters == nil {
		return fail()
	}
	r.key("fields")
	n, ok := r.head(4)
	if !r.ok || !ok || n != 4 || n > uint64(len(r.data)) {
		return fail()
	}
	spec := identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: make([]identity.FeatureField, int(n))}
	for i := range spec.Fields {
		r.expect(4, 3)
		field := &spec.Fields[i]
		field.Name = r.string(128)
		field.Value.Kind = identity.FeatureKind(r.number(uint64(identity.FeatureTime)))
		switch field.Name {
		case "otp.attempt-custody", "counter.key-versions":
			if field.Value.Kind != identity.FeatureBytes {
				return fail()
			}
			maximum := uint64(8192)
			if field.Name == "counter.key-versions" {
				maximum = 128
			}
			field.Value.Bytes = readMFAOTPPreparationBytes(&r, maximum)
		case "otp.digest-key-version":
			if field.Value.Kind != identity.FeatureUint64 {
				return fail()
			}
			field.Value.Uint64 = r.number(math.MaxUint32)
		case "counter.prepared-at":
			if field.Value.Kind != identity.FeatureTime {
				return fail()
			}
			field.Value.Time = time.UnixMicro(readMFAOTPPreparationInt(&r)).UTC()
		default:
			return fail()
		}
		if !r.ok {
			return fail()
		}
	}
	r.key("profile")
	r.consume(cborText("identity-mfa-otp-preparation-v1"))
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	canonical, err := encodeMFAOTPPreparedMetadata(spec, fp, p)
	if err != nil || !bytes.Equal(canonical, wire) {
		return fail()
	}
	return spec, p, nil
}

// The caller lends unchanged original intent; it is not read from plaintext
// persistence. Native counter validation below still authenticates the complete
// rebuilt projection against the frozen policy/fingerprint and retained keys.
func restoreMFAOTPPreparationSpec(original, retained identity.FeatureCommandSpec, p CommandPlan) (identity.FeatureCommandSpec, error) {
	if original.Binding != retained.Binding || original.Operation != retained.Operation || !validMFACompletionPlan(original.Binding, p) || p.Feature.Operation.OperationID != "identity.mfa.otp-verify" {
		return identity.FeatureCommandSpec{}, invalidPreparation()
	}
	var network string
	for _, field := range original.Fields {
		if field.Name == "otp" || strings.HasPrefix(field.Name, "otp.") || strings.HasPrefix(field.Name, "counter.") {
			return identity.FeatureCommandSpec{}, invalidPreparation()
		}
		if field.Name == "transport.network" {
			if field.Value.Kind != identity.FeatureText || field.Value.Text == "" {
				return identity.FeatureCommandSpec{}, invalidPreparation()
			}
			network = field.Value.Text
		}
	}
	if network == "" {
		return identity.FeatureCommandSpec{}, invalidPreparation()
	}
	original.Fields = append(append([]identity.FeatureField(nil), original.Fields...), retained.Fields...)
	original.Fields = append(original.Fields,
		identity.FeatureField{Name: "counter.network", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: network}},
		identity.FeatureField{Name: "counter.session", Value: identity.FeatureValue{Kind: identity.FeatureText}},
		identity.FeatureField{Name: "counter.subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.MFACompletion.UserID)}},
		identity.FeatureField{Name: "counter.capability", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: p.Capability.CapabilityID}})
	command, err := identity.NewFeatureCommand(original)
	if err != nil {
		return identity.FeatureCommandSpec{}, invalidPreparation()
	}
	spec, _ := command.Feature()
	return spec, nil
}

func mfaOTPNetworkMatches(original, prepared identity.FeatureCommandSpec) bool {
	var network string
	for _, field := range original.Fields {
		if field.Name == "transport.network" && field.Value.Kind == identity.FeatureText {
			network = field.Value.Text
		}
	}
	if network == "" {
		return false
	}
	for _, field := range prepared.Fields {
		if field.Name == "counter.network" {
			return field.Value.Kind == identity.FeatureText && field.Value.Text == network
		}
	}
	return false
}

func readMFAOTPPreparationBytes(r *planReader, maximum uint64) []byte {
	n, ok := r.head(2)
	if !r.ok || !ok || n > maximum || n > uint64(len(r.data)) {
		r.ok = false
		return nil
	}
	value := bytes.Clone(r.data[:int(n)])
	r.data = r.data[int(n):]
	return value
}

func readMFAOTPPreparationInt(r *planReader) int64 {
	if !r.ok || len(r.data) == 0 {
		r.ok = false
		return 0
	}
	major := r.data[0] >> 5
	if major != 0 && major != 1 {
		r.ok = false
		return 0
	}
	v, ok := r.head(major)
	if !ok || v > math.MaxInt64 {
		r.ok = false
		return 0
	}
	if major == 1 {
		return -int64(v) - 1
	}
	return int64(v)
}
