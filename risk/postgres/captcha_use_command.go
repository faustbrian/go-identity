package postgres

import (
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

// MapCaptchaUse appends token-free signed CAPTCHA custody to the protected
// feature's complete native fields without replacing its binding or schema.
// The consumer command, verified actor, tenant, subject/anonymous flow and
// operation must match the precheck exactly. The captcha namespace is reserved.
// Risk policy remains separate from authorization policy. Construction copies
// fields, performs no callbacks/IO and grants no durable use or permission.
// The returned plan must be enlisted with the native risk owner in the sole
// coordinator; reservation and all domain-time phases remain mandatory.
// Inputs must not be concurrently mutated. Zero/invalid input returns a redacted
// ErrInvalidEvidenceExecution and zero outputs.
func MapCaptchaUse(use risk.CaptchaEvidenceUse, spec identity.FeatureCommandSpec) (identity.Command, identitypostgres.CaptchaEvidencePlan, error) {
	p := use.Prepared()
	if p.Signature == ([32]byte{}) || !captchaUseBindingMatches(p, spec) || len(spec.Fields) > 99 {
		return identity.Command{}, identitypostgres.CaptchaEvidencePlan{}, risk.ErrInvalidEvidenceExecution
	}
	fields := make([]identity.FeatureField, 0, len(spec.Fields)+27+2*len(p.Original.Binding.Replay.Keys))
	for _, field := range spec.Fields {
		if field.Name == "captcha" || strings.HasPrefix(field.Name, "captcha.") {
			return identity.Command{}, identitypostgres.CaptchaEvidencePlan{}, risk.ErrInvalidEvidenceExecution
		}
		fields = append(fields, field)
	}
	fields = append(fields, captchaPreparedFields(p.Original)...)
	fields = append(fields, textField("captcha.issuance-command", p.Original.Binding.CommandID),
		bytesField("captcha.use-evidence", p.EvidenceDigest), bytesField("captcha.use-signature", p.Signature),
		identity.FeatureField{Name: "captcha.use-issued-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.IssuedAt}},
		// CheckedAt is signed at nanosecond precision, unlike database times.
		// Canonical text conserves those bytes without truncation or resigning.
		textField("captcha.use-checked-at", p.CheckedAt.Format(time.RFC3339Nano)))
	spec.Fields = fields
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		return identity.Command{}, identitypostgres.CaptchaEvidencePlan{}, risk.ErrInvalidEvidenceExecution
	}
	return command, captchaUsePlan(p), nil
}

func captchaUseBindingMatches(p risk.PreparedCaptchaEvidenceUse, s identity.FeatureCommandSpec) bool {
	b, f := s.Binding, p.Original.Binding.Replay.Flow
	return b.ValidateFor(s.Operation) == nil && b.OperationID != "identity.risk.captcha-issue" &&
		string(b.CommandID) == p.ConsumerCommandID && p.ConsumerCommandID != p.Original.Binding.CommandID &&
		string(b.ActorID) == p.ConsumerActor && string(b.TenantID) == f.Tenant &&
		string(b.UserID) == f.Subject && b.AnonymousFlowID == f.AnonymousFlow && b.OperationID == string(f.Operation)
}

func captchaUsePlan(p risk.PreparedCaptchaEvidenceUse) identitypostgres.CaptchaEvidencePlan {
	return identitypostgres.CaptchaEvidencePlan{IssuanceCommandID: p.Original.Binding.CommandID,
		KeyVersion: p.Original.Binding.KeyVersion, PolicyVersion: p.Original.Binding.PolicyVersion,
		OriginalSignature: p.Original.Signature, EvidenceDigest: p.EvidenceDigest, Signature: p.Signature,
		IssuedAt: p.IssuedAt, CheckedAt: p.CheckedAt, ExpiresAt: p.ExpiresAt}
}

func restoreCaptchaUseCommand(command identity.Command, keys []risk.EvidenceKey, policy uint64) (risk.CaptchaEvidenceUseClaim, error) {
	fail := func() (risk.CaptchaEvidenceUseClaim, error) {
		return risk.CaptchaEvidenceUseClaim{}, risk.ErrInvalidEvidenceExecution
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding.ValidateFor(spec.Operation) != nil || len(keys) < 1 || len(keys) > 16 || policy == 0 {
		return fail()
	}
	var original []identity.FeatureField
	extras := make(map[string]identity.FeatureValue, 5)
	for _, field := range spec.Fields {
		switch field.Name {
		case "captcha.issuance-command", "captcha.use-evidence", "captcha.use-signature", "captcha.use-issued-at", "captcha.use-checked-at":
			extras[field.Name] = field.Value
		default:
			if field.Name == "captcha" || strings.HasPrefix(field.Name, "captcha.") {
				original = append(original, field)
			}
		}
	}
	if len(extras) != 5 || len(original) < 24 || len(original) > 54 {
		return fail()
	}
	issuance := extras["captcha.issuance-command"]
	evidence, signature := extras["captcha.use-evidence"], extras["captcha.use-signature"]
	issued, checked := extras["captcha.use-issued-at"], extras["captcha.use-checked-at"]
	if issuance.Kind != identity.FeatureText || evidence.Kind != identity.FeatureBytes || signature.Kind != identity.FeatureBytes ||
		len(evidence.Bytes) != 32 || len(signature.Bytes) != 32 || issued.Kind != identity.FeatureTime || checked.Kind != identity.FeatureText || len(checked.Text) > 35 {
		return fail()
	}
	checkedAt, err := time.Parse(time.RFC3339Nano, checked.Text)
	if err != nil || checkedAt.Location() != time.UTC || checkedAt.Format(time.RFC3339Nano) != checked.Text {
		return fail()
	}
	// This private projection only reuses the closed original-custody codec. It
	// is never admitted, fingerprinted or used as an issuance journal binding:
	// the real original journal retains its own actor/policy/correlation linkage.
	op := CaptchaIssueOperation(spec.Operation.SubjectRequirement)
	b := spec.Binding
	b.CommandID, b.RecordID = identity.CommandID(issuance.Text), issuance.Text
	b.OperationID, b.SchemaID, b.SchemaVersion, b.PolicyVersion = op.OperationID, op.SchemaID, op.SchemaVersion, policy
	originalCommand, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: original})
	if err != nil {
		return fail()
	}
	issue, err := restoreCaptchaCommand(originalCommand, keys, policy)
	if err != nil {
		return fail()
	}
	p := risk.PreparedCaptchaEvidenceUse{Original: issue.Prepared(), ConsumerCommandID: string(spec.Binding.CommandID), ConsumerActor: string(spec.Binding.ActorID),
		EvidenceDigest: [32]byte(evidence.Bytes), Signature: [32]byte(signature.Bytes), IssuedAt: issued.Time, CheckedAt: checkedAt, ExpiresAt: issue.Prepared().ExpiresAt}
	if !captchaUseBindingMatches(p, spec) {
		return fail()
	}
	for _, key := range keys {
		if claim, err := key.RestoreCaptchaUse(p); err == nil {
			return claim, nil
		}
	}
	return fail()
}

// ValidateCaptchaUseCommand authenticates the complete closed consuming custody
// and exact scalar plan under the selected immutable current verifier profiles.
// It runs no clocks, callbacks or SQL and grants no journal/freshness/permission
// authority. Reservation and domain-time expiry/current-authority checks remain
// required. A retained signature from an unselected profile is insufficient.
func (r *Repository) ValidateCaptchaUseCommand(command identity.Command, plan identitypostgres.CaptchaEvidencePlan) error {
	if r == nil || r.schema == "" || len(r.captcha) == 0 {
		return risk.ErrInvalidEvidenceExecution
	}
	claim, err := restoreCaptchaUseCommand(command, r.keys, r.policy)
	if err != nil {
		return err
	}
	p := claim.Prepared()
	if captchaUsePlan(p) != plan {
		return risk.ErrInvalidEvidenceExecution
	}
	for _, custody := range r.captcha {
		if _, err := custody.RestoreCaptchaIssue(p.Original); err == nil {
			return nil
		}
	}
	return risk.ErrInvalidEvidenceExecution
}
