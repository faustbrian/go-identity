package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// APIKeyVerificationPlan declares an original authentication attempt, not a key
// mutation. KeyVersion is the original known key version whose optional Narrow
// transition may advance exactly once; zero is required for an unknown key.
// The exact native owner must compare the secret and recheck current authority
// inside Work. This value conveys neither authentication nor permission to
// narrow. Ordinary verification never advances a key/root/configuration epoch.
type APIKeyVerificationPlan struct {
	KeyVersion uint64
}

const apiKeyVerificationProfile = "identity-apikey-verification-v1"

// Map arity is shared with the existing delivery envelope. Inspect only the
// bounded canonical profile prefix to choose an owner; the selected decoder
// still validates every field and the complete canonical representation.
func apiKeyVerificationEnvelope(wire []byte) bool {
	if len(wire) == 0 || len(wire) > 65536 {
		return false
	}
	r := planReader{attributeReader: attributeReader{data: wire}, ok: true}
	r.expect(5, 3)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > 65000 || n > uint64(len(r.data)) {
		return false
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText(apiKeyVerificationProfile))
	return r.ok
}

func apiKeyVerificationOperation(anonymous bool) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.verify", SchemaID: "apikey-verify-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if anonymous {
		op.SchemaID = "apikey-verify-unknown-v1"
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	return op
}

func apiKeyVerificationDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}
}

func validAPIKeyVerificationPlan(b identity.CommandBinding, p CommandPlan) bool {
	if p.APIKeyVerification == nil || p.Feature == nil || p.Feature.Contributor != apiKeyVerificationDescriptor() || p.Feature.Operation != apiKeyVerificationOperation(b.UserID == "") || b.ValidateFor(p.Feature.Operation) != nil || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "api_key.permissions_changed.v1"}) {
		return false
	}
	// This first native profile is unlimited and has no projected authority or
	// side-channel effects. Other workflows retain their own atomic participants.
	if p.Capability != nil || p.CapabilityIssuance != nil || p.Delivery != nil || p.OTP != nil || p.RiskEvidence != nil || p.CommandCounters != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.IdentifierAdmission != nil || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.MagicLinkRegistration != nil || p.PasskeyRegistration != nil || p.MFACompletion != nil || p.MFAContinuation != nil || p.OrganizationInvitationOrigin != nil {
		return false
	}
	n := 2
	if b.UserID == "" {
		n = 1
		if b.ActorKind != authorization.SubjectServiceAccount || b.AnonymousFlowID != string(b.CommandID) || p.SubjectType != "authentication_attempt" || p.APIKeyVerification.KeyVersion != 0 {
			return false
		}
	} else if b.ActorKind != authorization.SubjectAPIKey || p.SubjectType != "api_key" || p.APIKeyVerification.KeyVersion == 0 || p.APIKeyVerification.KeyVersion == math.MaxUint64 {
		return false
	}
	if len(p.Audits) != n || p.Audits[0].EventType != "identity.api_key.authenticate" || p.Audits[0].EventIndex != 0 {
		return false
	}
	for i, a := range p.Audits {
		if a.RetentionClass != "protected" || !a.Required || i == 1 && (a.EventType != "identity.api_key.update" || a.EventIndex != 1) {
			return false
		}
	}
	return true
}

func encodeAPIKeyVerificationPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if !validAPIKeyVerificationPlan(b, p) {
		return nil, invalidPlan()
	}
	version := p.APIKeyVerification.KeyVersion
	p.APIKeyVerification = nil
	base, err := encodeFeaturePlanMode(b, fp, p, true)
	if err != nil || len(base) > 65000 {
		return nil, invalidPlan()
	}
	return cborMap(map[string][]byte{"base": cborBytes(base), "profile": cborText(apiKeyVerificationProfile), "key_version": cborUint(version)}), nil
}

func decodeAPIKeyVerificationPlan(b identity.CommandBinding, fp [32]byte, wire []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(wire) == 0 || len(wire) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: wire}, ok: true}
	r.expect(5, 3)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > 65000 || n > uint64(len(r.data)) || r.data[0] != 0xa8 {
		return fail()
	}
	// The only base is a plain v2 feature declaration. Never recurse through
	// another wrapper selected by untrusted retained bytes.
	base := r.data[:int(n)]
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText(apiKeyVerificationProfile))
	r.key("key_version")
	version := r.number(math.MaxUint64)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	p, err := decodeFeaturePlanMode(b, fp, base, true)
	if err != nil {
		return fail()
	}
	p.APIKeyVerification = &APIKeyVerificationPlan{KeyVersion: version}
	canonical, err := encodeAPIKeyVerificationPlan(b, fp, p)
	if err != nil || !bytes.Equal(canonical, wire) {
		return fail()
	}
	p.Digest = sha256.Sum256(wire)
	return p, nil
}

func cloneAPIKeyVerificationPlan(p *APIKeyVerificationPlan) *APIKeyVerificationPlan {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}
