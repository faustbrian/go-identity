// Package postgres owns the durable risk journal. Native issuance uses the
// identity coordinator's sole Work; no provisional reference is a credential
// or proof of commit. Reservation, consumption and retention remain separate
// required implementation work.
package postgres

import (
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// IssueOperation is the closed native evidence-issuance schema. RecordID is the
// command's opaque canonical ID, never a keyed intent digest. Authorized native
// response resolution must additionally compare the retained private intent.
// Prior pending/failed commands never permit fresh evaluation. This descriptor
// conveys no authorization, durability or one-use consumption authority.
func IssueOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/risk", OperationID: "identity.risk.evaluate", SchemaID: "identity-risk-evidence-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// MapIssue maps an opaque core-owned successful evaluation into an immutable
// coordinator command. Binding must match the signed tenant, subject, actor,
// command and current policy; trusted composition supplies actor kind, policy
// ID and correlation. RecordID must be empty and is derived here, not selected
// by callers. Every signed field is frozen. Zero/foreign input fails redacted;
// construction performs no IO, authorization, issuance or fresh observation.
func MapIssue(issue risk.EvidenceIssue, b identity.CommandBinding) (identity.Command, error) {
	p := issue.Prepared()
	n := p.Binding
	if n.KeyVersion == 0 || p.Signature == ([32]byte{}) || string(b.CommandID) != n.CommandID || string(b.TenantID) != n.Tenant || string(b.UserID) != n.Subject || string(b.ActorID) != n.Actor || b.PolicyVersion != n.PolicyVersion || b.RecordID != "" {
		return identity.Command{}, risk.ErrInvalidEvidenceExecution
	}
	b.RecordID = issueRecordID(n)
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: IssueOperation(), Fields: []identity.FeatureField{
		textField("evidence.recovery-operation", string(n.RecoveryOperation)), textField("evidence.phase", string(n.Phase)), textField("evidence.purpose", n.Purpose),
		uintField("evidence.policy-version", n.PolicyVersion), uintField("evidence.key-version", uint64(n.KeyVersion)),
		bytesField("evidence.intent", n.IntentDigest), bytesField("evidence.proof", p.ProofDigest), bytesField("evidence.nonce", p.Nonce), bytesField("evidence.signature", p.Signature),
		{Name: "evidence.prepared-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.PreparedAt}},
		{Name: "evidence.expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: p.ExpiresAt}},
	}})
}

func issueRecordID(b risk.EvidenceIntentBinding) string { return b.CommandID }
func textField(n, v string) identity.FeatureField {
	return identity.FeatureField{Name: n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
}
func uintField(n string, v uint64) identity.FeatureField {
	return identity.FeatureField{Name: n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
}
func bytesField(n string, v [32]byte) identity.FeatureField {
	return identity.FeatureField{Name: n, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: v[:]}}
}

// The closed decoder validates names, kinds and widths before cryptographic
// work. Authenticating the projection does not replace current policy or Work
// admission. Never infer proof provenance from public structural metadata.
func restoreCommand(c identity.Command, keys []risk.EvidenceKey, policy uint64) (risk.EvidenceIssue, error) {
	s, ok := c.Feature()
	if !ok || s.Operation != IssueOperation() || len(s.Fields) != 11 || policy == 0 || s.Binding.PolicyVersion != policy || len(keys) == 0 || len(keys) > 16 {
		return risk.EvidenceIssue{}, risk.ErrInvalidEvidenceExecution
	}
	b := s.Binding
	p := risk.PreparedEvidence{Binding: risk.EvidenceIntentBinding{CommandID: string(b.CommandID), Tenant: string(b.TenantID), Subject: string(b.UserID), Actor: string(b.ActorID)}}
	for _, f := range s.Fields {
		switch f.Name {
		case "evidence.recovery-operation":
			if f.Value.Kind != identity.FeatureText {
				return invalidIssue()
			}
			p.Binding.RecoveryOperation = risk.Action(f.Value.Text)
		case "evidence.phase":
			if f.Value.Kind != identity.FeatureText {
				return invalidIssue()
			}
			p.Binding.Phase = risk.IssuancePhase(f.Value.Text)
		case "evidence.purpose":
			if f.Value.Kind != identity.FeatureText {
				return invalidIssue()
			}
			p.Binding.Purpose = f.Value.Text
		case "evidence.policy-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 != policy {
				return invalidIssue()
			}
			p.Binding.PolicyVersion = f.Value.Uint64
		case "evidence.key-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 || f.Value.Uint64 > uint64(^uint32(0)) {
				return invalidIssue()
			}
			p.Binding.KeyVersion = uint32(f.Value.Uint64)
		case "evidence.intent", "evidence.proof", "evidence.nonce", "evidence.signature":
			if f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) != 32 {
				return invalidIssue()
			}
			var v [32]byte
			copy(v[:], f.Value.Bytes)
			switch f.Name {
			case "evidence.intent":
				p.Binding.IntentDigest = v
			case "evidence.proof":
				p.ProofDigest = v
			case "evidence.nonce":
				p.Nonce = v
			case "evidence.signature":
				p.Signature = v
			}
		case "evidence.prepared-at":
			if f.Value.Kind != identity.FeatureTime {
				return invalidIssue()
			}
			p.PreparedAt = f.Value.Time
		case "evidence.expires-at":
			if f.Value.Kind != identity.FeatureTime {
				return invalidIssue()
			}
			p.ExpiresAt = f.Value.Time
		default:
			return invalidIssue()
		}
	}
	if b.RecordID != issueRecordID(p.Binding) {
		return invalidIssue()
	}
	for _, key := range keys {
		if issue, err := key.RestoreIssue(p); err == nil {
			return issue, nil
		}
	}
	return invalidIssue()
}
func invalidIssue() (risk.EvidenceIssue, error) {
	return risk.EvidenceIssue{}, risk.ErrInvalidEvidenceExecution
}
