package postgres

import (
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// CaptchaIssueOperation selects a trusted native issuance schema. User and
// anonymous targets have distinct registered schemas; zero retains user scope.
// Unknown requirements return an invalid descriptor. This grants no admission,
// provider verification, commitment, or protected-use authority.
func CaptchaIssueOperation(subject identity.FeatureSubjectRequirement) identity.FeatureOperation {
	schema := "identity-captcha-evidence-user-v1"
	if subject == identity.FeatureSubjectAnonymousFlow {
		schema = "identity-captcha-evidence-flow-v1"
	} else if subject != identity.FeatureSubjectUser {
		return identity.FeatureOperation{}
	}
	return identity.FeatureOperation{Owner: "identity/risk", OperationID: "identity.risk.captcha-issue", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: subject}
}

// MapCaptchaIssue freezes token-free signed core custody for the sole shared
// coordinator. The trusted binding supplies the separately verified actor,
// policy ID and correlation, never an invented user for an anonymous flow.
// Administrator actors must match the signed administrative context. RecordID
// is derived from the original command, not caller-selected. Construction is
// pure and grants neither current authority nor evidence commitment.
func MapCaptchaIssue(issue risk.CaptchaEvidenceIssue, b identity.CommandBinding) (identity.Command, error) {
	p := issue.Prepared()
	f := p.Binding.Replay.Flow
	subject := identity.FeatureSubjectUser
	if f.AnonymousFlow != "" {
		subject = identity.FeatureSubjectAnonymousFlow
	}
	if p.Signature == ([32]byte{}) || p.Binding.KeyVersion == 0 || len(p.Binding.Replay.Keys) == 0 || len(p.Binding.Replay.Keys) > 16 || b.RecordID != "" || string(b.CommandID) != p.Binding.CommandID || string(b.TenantID) != f.Tenant || string(b.UserID) != f.Subject || b.AnonymousFlowID != f.AnonymousFlow || b.PolicyVersion != p.Binding.PolicyVersion || f.Kind == risk.FlowAdministrator && string(b.ActorID) != f.Actor {
		return identity.Command{}, risk.ErrInvalidEvidenceExecution
	}
	b.RecordID = p.Binding.CommandID
	c, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: CaptchaIssueOperation(subject), Fields: captchaPreparedFields(p)})
	if err != nil {
		return identity.Command{}, risk.ErrInvalidEvidenceExecution
	}
	return c, nil
}

func captchaPreparedFields(p risk.PreparedCaptchaEvidence) []identity.FeatureField {
	b, r := p.Binding, p.Binding.Replay
	f := r.Flow
	fields := []identity.FeatureField{
		textField("captcha.flow-kind", string(f.Kind)), textField("captcha.operation", string(f.Operation)),
		textField("captcha.pre-auth", f.PreAuthTransaction), textField("captcha.session", f.Session), textField("captcha.actor", f.Actor),
		textField("captcha.challenge", f.ChallengeID), textField("captcha.request", f.RequestFingerprint),
		textField("captcha.provider", r.Provider), textField("captcha.site", r.Site), textField("captcha.profile", r.APIProfile), textField("captcha.configuration", r.ConfigurationVersion),
		uintField("captcha.alias-count", uint64(len(r.Keys))), uintField("captcha.policy-version", b.PolicyVersion), uintField("captcha.key-version", uint64(b.KeyVersion)),
		bytesField("captcha.intent", b.IntentDigest), bytesField("captcha.configuration-digest", p.ConfigurationDigest), bytesField("captcha.proof", p.ProofDigest), bytesField("captcha.nonce", p.Nonce), bytesField("captcha.signature", p.Signature), textField("captcha.hostname", p.Hostname),
		{Name: "captcha.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.PreparedAt}},
		{Name: "captcha.expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.ExpiresAt}},
	}
	for i, alias := range r.Keys {
		fields = append(fields, uintField(captchaAliasField(i, "version"), uint64(alias.Version)), textField(captchaAliasField(i, "fingerprint"), alias.Fingerprint))
	}
	return fields
}

func captchaAliasField(index int, member string) string {
	return fmt.Sprintf("captcha.key-%02d.%s", index, member)
}

// Restore consumes an exact closed scalar schema before core authentication.
// It preserves original aliases and validity; it cannot create authority or
// choose the current verifier configuration. The durable owner checks that too.
func restoreCaptchaCommand(c identity.Command, keys []risk.EvidenceKey, policy uint64) (risk.CaptchaEvidenceIssue, error) {
	s, ok := c.Feature()
	invalid := func() (risk.CaptchaEvidenceIssue, error) {
		return risk.CaptchaEvidenceIssue{}, risk.ErrInvalidEvidenceExecution
	}
	if !ok || s.Operation != CaptchaIssueOperation(s.Operation.SubjectRequirement) || s.Binding.ValidateFor(s.Operation) != nil || s.Binding.RecordID != string(s.Binding.CommandID) || policy == 0 || s.Binding.PolicyVersion != policy || len(keys) < 1 || len(keys) > 16 || len(s.Fields) < 24 || len(s.Fields) > 54 {
		return invalid()
	}
	fields := make(map[string]identity.FeatureValue, len(s.Fields))
	for _, field := range s.Fields {
		if _, exists := fields[field.Name]; exists {
			return invalid()
		}
		fields[field.Name] = field.Value
	}
	valid := true
	take := func(name string, kind identity.FeatureKind) identity.FeatureValue {
		v, exists := fields[name]
		if !exists || v.Kind != kind {
			valid = false
		}
		delete(fields, name)
		return v
	}
	text := func(name string) string { return take(name, identity.FeatureText).Text }
	uint64Value := func(name string) uint64 { return take(name, identity.FeatureUint64).Uint64 }
	digest := func(name string) [32]byte {
		v := take(name, identity.FeatureBytes).Bytes
		if len(v) != 32 {
			valid = false
			return [32]byte{}
		}
		return [32]byte(v)
	}
	instant := func(name string) time.Time { return take(name, identity.FeatureTime).Time }
	b := s.Binding
	p := risk.PreparedCaptchaEvidence{Binding: risk.CaptchaIntentBinding{CommandID: string(b.CommandID), PolicyVersion: uint64Value("captcha.policy-version")}}
	kv := uint64Value("captcha.key-version")
	if kv == 0 || kv > uint64(^uint32(0)) {
		return invalid()
	}
	p.Binding.KeyVersion = uint32(kv)
	r := &p.Binding.Replay
	r.Flow = risk.FlowContextInput{Tenant: string(b.TenantID), Subject: string(b.UserID), AnonymousFlow: b.AnonymousFlowID, Kind: risk.FlowKind(text("captcha.flow-kind")), Operation: risk.Action(text("captcha.operation")), PreAuthTransaction: text("captcha.pre-auth"), Session: text("captcha.session"), Actor: text("captcha.actor"), ChallengeID: text("captcha.challenge"), RequestFingerprint: text("captcha.request")}
	r.Provider, r.Site, r.APIProfile, r.ConfigurationVersion = text("captcha.provider"), text("captcha.site"), text("captcha.profile"), text("captcha.configuration")
	n := uint64Value("captcha.alias-count")
	if n < 1 || n > 16 || len(s.Fields) != 22+2*int(n) {
		return invalid()
	}
	r.Keys = make([]risk.CaptchaReplayDigest, int(n))
	for i := range r.Keys {
		version := uint64Value(captchaAliasField(i, "version"))
		if version == 0 || version > uint64(^uint32(0)) {
			return invalid()
		}
		r.Keys[i] = risk.CaptchaReplayDigest{Version: uint32(version), Fingerprint: text(captchaAliasField(i, "fingerprint"))}
	}
	p.Binding.IntentDigest, p.ConfigurationDigest, p.ProofDigest, p.Nonce, p.Signature = digest("captcha.intent"), digest("captcha.configuration-digest"), digest("captcha.proof"), digest("captcha.nonce"), digest("captcha.signature")
	p.Hostname, p.PreparedAt, p.ExpiresAt = text("captcha.hostname"), instant("captcha.prepared-at"), instant("captcha.expires-at")
	if !valid || len(fields) != 0 || p.Binding.PolicyVersion != policy || r.Flow.Kind == risk.FlowAdministrator && r.Flow.Actor != string(b.ActorID) {
		return invalid()
	}
	for _, key := range keys {
		if issue, err := key.RestoreCaptchaIssue(p); err == nil {
			return issue, nil
		}
	}
	return invalid()
}
