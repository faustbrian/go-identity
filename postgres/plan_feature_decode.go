package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"

	identity "github.com/faustbrian/go-identity"
)

// Historical decoding conserves a frozen declaration. It does not consult the
// current registry or grant permission to reserve, execute or recover a feature.
func decodeFeaturePlan(binding identity.CommandBinding, fingerprint [32]byte, encoded []byte) (CommandPlan, error) {
	if len(encoded) > 0 && encoded[0] == 0xa5 {
		return decodeEmailVerificationPlan(binding, fingerprint, encoded)
	}
	if len(encoded) > 0 && encoded[0] == 0xa2 {
		return decodeSignupAcceptancePlan(binding, fingerprint, encoded)
	}
	if len(encoded) > 0 && encoded[0] == 0xa4 {
		return decodeIssuanceWrappedPlan(binding, fingerprint, encoded, decodeFeaturePlan, encodeFeaturePlan)
	}
	if len(encoded) > 0 && encoded[0] == 0xa3 {
		return decodeDeliveryWrappedPlan(binding, fingerprint, encoded, decodeFeaturePlan, encodeFeaturePlan)
	}
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(encoded) == 0 || len(encoded) > 65536 || fingerprint == ([32]byte{}) {
		return fail()
	}
	// Supplied observation scope is also untrusted. Bound it before constructing
	// the expected CBOR map; the exact feature policy is checked after decoding.
	if len(binding.CommandID) > 22 || len(binding.TenantID) > 128 || len(binding.UserID) > 128 || len(binding.AnonymousFlowID) > 128 || len(binding.ActorID) > 128 || len(binding.ActorKind) > 128 || len(binding.OperationID) > 128 || len(binding.RecordID) > 128 || len(binding.PolicyID) > 128 || len(binding.SchemaID) > 128 || len(binding.CorrelationID) > 128 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: encoded}, ok: true}
	fields, ok := r.head(5)
	if !ok || fields != 7 && fields != 8 && fields != 9 && fields != 10 && fields != 11 {
		return fail()
	}
	r.key("audits")
	count, ok := r.head(4)
	// Check the untrusted array count before allocating or narrowing it.
	if !r.ok || !ok || count == 0 || count > 64 {
		return fail()
	}
	p := CommandPlan{Audits: make([]AuditPlan, int(count))}
	for i := range p.Audits {
		a := &p.Audits[i]
		if fields >= 8 {
			r.expect(5, 10)
		} else {
			r.expect(5, 9)
		}
		r.key("required")
		r.consume(cborBool(true))
		a.Required = true
		r.key("event_type")
		a.EventType = r.string(128)
		r.key("event_index")
		a.EventIndex = uint16(r.number(math.MaxUint16))
		r.key("binding_digest")
		r.digest(&a.BindingDigest)
		r.key("schema_version")
		a.SchemaVersion = uint32(r.number(math.MaxUint32))
		if fields >= 8 {
			r.key("retention_class")
			a.RetentionClass = r.string(9)
		}
		r.key("max_record_bytes")
		a.MaxRecordBytes = uint32(r.number(math.MaxUint32))
		r.key("max_aggregate_bytes")
		a.MaxAggregateBytes = uint32(r.number(math.MaxUint32))
		r.key("required_record_count")
		a.RequiredRecordCount = uint16(r.number(math.MaxUint16))
		r.key("retention_policy_version")
		a.RetentionPolicyVersion = r.number(math.MaxUint64)
	}
	r.key("binding")
	r.consume(cborMap(commandScope(binding)))
	r.key("feature")
	featureFields, featureOK := r.head(5)
	if !featureOK || featureFields != 6 && featureFields != 7 {
		return fail()
	}
	f := &FeatureRegistration{}
	r.key("owner")
	f.Operation.Owner = r.string(128)
	r.key("schema_id")
	f.Operation.SchemaID = r.string(128)
	r.key("contributor")
	f.Contributor = readFeaturePlanContributor(&r)
	r.key("operation_id")
	f.Operation.OperationID = r.string(128)
	r.key("schema_version")
	f.Operation.SchemaVersion = uint32(r.number(math.MaxUint32))
	r.key("record_requirement")
	f.Operation.RecordRequirement = identity.FeatureRecordRequirement(r.number(math.MaxUint8))
	if featureFields == 7 {
		r.key("subject_requirement")
		f.Operation.SubjectRequirement = identity.FeatureSubjectRequirement(r.number(math.MaxUint8))
	}
	p.Feature = f
	r.key("profile")
	counterProfile := false
	captchaProfile := false
	captchaUseProfile := false
	otpProfile := false
	if fields >= 9 {
		profile := r.string(64)
		counterProfile = profile == "identity-feature-command-counters-v1"
		captchaProfile = profile == "identity-feature-captcha-replay-v1"
		captchaUseProfile = profile == "identity-feature-captcha-use-v1"
		otpProfile = profile == "identity-feature-otp-attempt-v1"
		if !counterProfile && !captchaProfile && !captchaUseProfile && !otpProfile && profile != "identity-feature-risk-plan-v1" || fields == 10 && !captchaUseProfile && !otpProfile || fields == 11 && !otpProfile {
			return fail()
		}
	} else if fields == 8 {
		r.consume(cborText("identity-feature-plan-v2"))
	} else {
		r.consume(cborText("identity-feature-plan-v1"))
	}
	r.key("lifecycle")
	r.expect(5, 4)
	l := &LifecyclePlan{}
	r.key("event_type")
	l.EventType = r.string(128)
	r.key("event_index")
	l.EventIndex = uint16(r.number(math.MaxUint16))
	r.key("after_version")
	l.AfterVersion = r.number(math.MaxUint64)
	r.key("before_version")
	l.BeforeVersion = r.number(math.MaxUint64)
	p.Lifecycle = l
	r.key("fingerprint")
	r.consume(cborBytes(fingerprint[:]))
	if otpProfile {
		r.key("otp_attempt")
		p.OTP = readOTPPlan(&r)
	}
	r.key("contributors")
	contributors := 4
	if otpProfile {
		if p.Feature.Contributor != otpDescriptor() {
			contributors++
		}
		if fields >= 10 {
			contributors++
		}
	} else if fields >= 9 && !captchaProfile {
		contributors = 5
	}
	r.expect(4, uint64(contributors))
	for range contributors {
		p.Contributors = append(p.Contributors, readFeaturePlanContributor(&r))
	}
	if fields >= 8 {
		r.key("subject_type")
		p.SubjectType = r.string(96)
		if p.SubjectType == "" {
			return fail()
		}
	}
	if captchaUseProfile || otpProfile {
		tail := fields - 8
		if otpProfile {
			tail--
		}
		for range tail {
			switch r.string(32) {
			case "captcha_evidence":
				if p.CaptchaEvidence != nil {
					return fail()
				}
				p.CaptchaEvidence = readCaptchaEvidencePlan(&r)
			case "risk_evidence":
				if !otpProfile && fields != 10 || p.RiskEvidence != nil {
					return fail()
				}
				p.RiskEvidence = readRiskPlan(&r)
			case "command_counters":
				if !otpProfile && fields != 10 || p.CommandCounters != nil {
					return fail()
				}
				r.expect(5, 2)
				p.CommandCounters = &CommandCounterPlan{}
				r.key("fingerprint")
				r.digest(&p.CommandCounters.Fingerprint)
				r.key("policy_version")
				p.CommandCounters.PolicyVersion = r.number(math.MaxUint64)
			default:
				return fail()
			}
		}
		if captchaUseProfile && p.CaptchaEvidence == nil {
			return fail()
		}
	} else if fields == 9 {
		if captchaProfile {
			r.key("captcha_replay")
			r.consume(cborBool(true))
			p.CaptchaReplayReservation = true
		} else if counterProfile {
			r.key("command_counters")
			r.expect(5, 2)
			p.CommandCounters = &CommandCounterPlan{}
			r.key("fingerprint")
			r.digest(&p.CommandCounters.Fingerprint)
			r.key("policy_version")
			p.CommandCounters.PolicyVersion = r.number(math.MaxUint64)
		} else {
			r.key("risk_evidence")
			p.RiskEvidence = readRiskPlan(&r)
		}
	}
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	canonical, err := encodeFeaturePlan(binding, fingerprint, p)
	// One encoder owns semantic bounds; byte equality also rejects nonminimal
	// lengths/integers, alternate keys/order and unsupported representations.
	if err != nil || !bytes.Equal(canonical, encoded) {
		return fail()
	}
	p.Digest = sha256.Sum256(encoded)
	return p, nil
}

func readFeaturePlanContributor(r *planReader) ContributorDescriptor {
	r.expect(5, 3)
	r.key("owner")
	d := ContributorDescriptor{Owner: r.string(128)}
	r.key("version")
	d.Version = uint32(r.number(math.MaxUint32))
	r.key("contract_id")
	d.ContractID = r.string(256)
	return d
}
