package postgres

import (
	"bytes"
	"crypto/sha256"

	identity "github.com/faustbrian/go-identity"
)

const signupAcceptedEvent = "identity.password.signup.accepted.v1"
const signupAcceptanceProfile = "identity-password-signup-acceptance-v1"

// The wrapper explicitly freezes both possible lifecycle branches while
// preserving every byte of the legacy creation declaration. Its presence is
// never inferred from an absent user or from a contributor's provisional result.
func encodeSignupAcceptancePlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if p.Feature == nil || !passwordRegistrationOperation(p.Feature.Operation) || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || p.Feature.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || b.UserID != "" || b.AnonymousFlowID == "" || p.SubjectType != "user" || p.Lifecycle == nil || p.Lifecycle.EventType != "user.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 0 || len(p.Audits) == 0 || p.Audits[0].RetentionClass != "protected" {
		return nil, invalidPlan()
	}
	p.SignupAcceptance = false
	base, err := encodeFeaturePlan(b, fp, p)
	if err != nil || len(base) > 65000 {
		return nil, invalidPlan()
	}
	return cborMap(map[string][]byte{"base": cborBytes(base), "profile": cborText(signupAcceptanceProfile)}), nil
}

func decodeSignupAcceptancePlan(b identity.CommandBinding, fp [32]byte, wire []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(wire) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: wire}, ok: true}
	r.expect(5, 2)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > 65000 || n > uint64(len(r.data)) || r.data[0] == 0xa2 {
		return fail()
	}
	base := r.data[:int(n)]
	if !signupAcceptanceBaseBounded(base) {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText(signupAcceptanceProfile))
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	p, err := decodeFeaturePlan(b, fp, base)
	if err != nil {
		return fail()
	}
	p.SignupAcceptance = true
	canonical, err := encodeFeaturePlan(b, fp, p)
	if err != nil || !bytes.Equal(canonical, wire) {
		return fail()
	}
	p.Digest = sha256.Sum256(wire)
	return p, nil
}

// The only valid shape is acceptance -> optional delivery -> optional issuance
// -> feature. Reject an interleaved wrapper chain before recursive decoding.
func signupAcceptanceBaseBounded(base []byte) bool {
	for _, header := range []byte{0xa3, 0xa4} {
		if len(base) == 0 {
			return false
		}
		if base[0] != header {
			continue
		}
		r := planReader{attributeReader: attributeReader{data: base}, ok: true}
		r.expect(5, uint64(header&31))
		r.key("base")
		n, ok := r.head(2)
		if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) {
			return false
		}
		base = r.data[:int(n)]
	}
	return len(base) > 0 && base[0] >= 0xa7 && base[0] <= 0xab
}
