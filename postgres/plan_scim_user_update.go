package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"

	identity "github.com/faustbrian/go-identity"
)

// SCIMUserUpdatePlan retains the two original typed scalars needed for kernel
// participant recovery. It grants no mutation, policy or successful receipt.
// Required=false selects no core mutation; ExpectedVersion is never the native
// SCIM projection generation. Admission matches both to the original command.
type SCIMUserUpdatePlan struct {
	Required        bool
	ExpectedVersion uint64
}

func cloneSCIMUserUpdatePlan(p *SCIMUserUpdatePlan) *SCIMUserUpdatePlan {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func encodeSCIMUserUpdatePlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	update := p.SCIMUserUpdate
	if update == nil || update.ExpectedVersion == 0 || update.Required && update.ExpectedVersion == math.MaxUint64 || p.Feature == nil || !scimUserUpdateSelected(p.Feature.Operation) || p.Feature.Contributor != scimUserCreationDescriptor() || p.SubjectType != "scim_user" || p.Delivery != nil || p.Capability != nil || p.CapabilityIssuance != nil || p.OTP != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.MFACompletion != nil || p.MFAContinuation != nil || p.MagicLinkRegistration != nil || p.PasskeyRegistration != nil || p.OrganizationInvitationOrigin != nil || p.APIKeyVerification != nil {
		return nil, invalidPlan()
	}
	if update.Required {
		sequential := p.Feature.Operation
		sequential.VersionPolicy = identity.FeatureVersionSequential
		if p.Lifecycle == nil || sequential.ValidateRecordVersions(p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion) != nil {
			return nil, invalidPlan()
		}
	}
	p.SCIMUserUpdate = nil
	base, err := encodeFeaturePlanMode(b, fp, p, true)
	if err != nil {
		return nil, err
	}
	wire := cborMap(map[string][]byte{"profile": cborText("identity-scim-user-update-plan-v1"), "base": cborBytes(base), "update": cborMap(map[string][]byte{"required": cborBool(update.Required), "expected_version": cborUint(update.ExpectedVersion)})})
	if len(wire) > 65536 {
		return nil, invalidPlan()
	}
	return wire, nil
}

func decodeSCIMUserUpdatePlan(b identity.CommandBinding, fp [32]byte, wire []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(wire) == 0 || len(wire) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: wire}, ok: true}
	r.expect(5, 3)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	p, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("update")
	r.expect(5, 2)
	r.key("required")
	update := &SCIMUserUpdatePlan{Required: len(r.data) > 0 && r.data[0] == 0xf5}
	r.consume(cborBool(update.Required))
	r.key("expected_version")
	update.ExpectedVersion = r.number(math.MaxUint64)
	r.key("profile")
	r.consume(cborText("identity-scim-user-update-plan-v1"))
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	p.SCIMUserUpdate = update
	canonical, err := encodeSCIMUserUpdatePlan(b, fp, p)
	if err != nil || !bytes.Equal(canonical, wire) {
		return fail()
	}
	p.Digest = sha256.Sum256(wire)
	return p, nil
}
