package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"

	identity "github.com/faustbrian/go-identity"
)

// PasskeyRegistrationPlan freezes one prospective passkey-only creation in the
// original anonymous verification command. It is neither a WebAuthn proof nor
// signup permission. The native owner must enlist the creation and outbox phases.
type PasskeyRegistrationPlan struct {
	UserID             identity.UserID
	CredentialID       identity.CredentialID
	CreationDigest     [32]byte
	CreationEventIndex uint16
}

func passkeyRegistrationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-verify", SchemaID: "identity.passkey.register-verify.signup-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func clonePasskeyRegistrationPlan(p *PasskeyRegistrationPlan) *PasskeyRegistrationPlan {
	if p == nil {
		return nil
	}
	snapshot := *p
	return &snapshot
}

func encodePasskeyRegistrationPlan(b identity.CommandBinding, fingerprint [32]byte, p CommandPlan) ([]byte, error) {
	r := p.PasskeyRegistration
	if r == nil || p.Feature == nil || p.Feature.Operation != passkeyRegistrationOperation() || p.Feature.Contributor != (ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) || p.SubjectType != "credential" || p.MagicLinkRegistration != nil || p.MFACompletion != nil || p.MFAContinuation != nil || p.OrganizationInvitationOrigin != nil || p.MagicLinkRequestAcceptance || p.SignupAcceptance || p.Capability != nil || p.CapabilityIssuance != nil || p.Delivery != nil || p.OTP != nil || p.RiskEvidence != nil || p.CaptchaReplayReservation || p.CaptchaEvidence != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "identity.passkey.create_credential" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 1 || p.Lifecycle.EventIndex == r.CreationEventIndex || string(r.CredentialID) != b.RecordID || r.CreationDigest == ([32]byte{}) {
		return nil, invalidPlan()
	}
	c := identity.CredentialRef{ID: r.CredentialID, TenantID: b.TenantID, UserID: r.UserID, Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}
	if c.Validate(b.TenantID, r.UserID) != nil {
		return nil, invalidPlan()
	}
	p.PasskeyRegistration = nil
	base, err := encodeFeaturePlan(b, fingerprint, p)
	if err != nil {
		return nil, err
	}
	encoded := cborMap(map[string][]byte{
		"profile": cborText("identity-passkey-registration-plan-v1"), "base": cborBytes(base),
		"registration": cborMap(map[string][]byte{"user_id": cborText(string(r.UserID)), "credential_id": cborText(string(r.CredentialID)), "creation_digest": cborBytes(r.CreationDigest[:]), "creation_event_index": cborUint(uint64(r.CreationEventIndex))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func decodePasskeyRegistrationPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 3)
	r.key("base")
	n, ok := r.head(2)
	// A fixed-depth ordinary feature/counter base only; never recursive optional
	// wrappers or unbounded attacker-selected allocation.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-passkey-registration-plan-v1"))
	r.key("registration")
	r.expect(5, 4)
	p := &PasskeyRegistrationPlan{}
	r.key("user_id")
	p.UserID = identity.UserID(r.string(128))
	r.key("credential_id")
	p.CredentialID = identity.CredentialID(r.string(128))
	r.key("creation_digest")
	r.digest(&p.CreationDigest)
	r.key("creation_event_index")
	p.CreationEventIndex = uint16(r.number(math.MaxUint16))
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.PasskeyRegistration = p
	canonical, err := encodePasskeyRegistrationPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
