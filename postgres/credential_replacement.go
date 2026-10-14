package postgres

import (
	"context"
	"fmt"
	"io"

	identity "github.com/faustbrian/go-identity"
)

// CredentialReplacementIntent binds an existing password reference and the
// independent user aggregate and credential-authority predecessors. Each must
// have a positive uint64 successor. It contains no password, hash, proof or
// authorization; the native workflow owns those policies and their custody.
type CredentialReplacementIntent struct {
	Credential               identity.CredentialRef
	ExpectedUserVersion      uint64
	ExpectedAuthorityVersion uint64
}

// Format omits correlated credential and account metadata.
func (CredentialReplacementIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.CredentialReplacementIntent(redacted)")
}

// CredentialReplacementContributor is the exact native existing-password
// change participant. CredentialReplacement is pure mapping of the complete
// frozen command, independently checked by the kernel before SQL. ApplyFeature
// owns hash replacement and mandatory policy/proof checks, not kernel tables.
// This trusted composition seam is not an authenticated public endpoint.
// Registration, reset, enabling a disabled credential and hash-only upgrades
// are different profiles and cannot borrow this transition.
type CredentialReplacementContributor interface {
	FeatureExecutionContributor
	CredentialReplacement(identity.Command) (CredentialReplacementIntent, error)
}

// CredentialReplacementLifecycleContributor persists the staged lifecycle and
// exact separate version successors in the existing outbox transaction. The
// coordinator invokes this instead of PersistLifecycle, exactly once. It must
// not retain or close Work, perform network IO, or claim completed cascades.
type CredentialReplacementLifecycleContributor interface {
	LifecycleContributor
	PersistCredentialReplacement(context.Context, Work) error
}

// CredentialReplacementReceipt is provisional metadata for the native outbox
// phase. Only the original journal's committed outcome proves durability. The
// reference remains enabled with its successor version and unchanged expiry.
// This is not a proof, renewable lease, current authority vector or session.
type CredentialReplacementReceipt struct {
	Credential              identity.CredentialRef
	BeforeUserVersion       uint64
	AfterUserVersion        uint64
	BeforeAuthorityVersion  uint64
	AfterAuthorityVersion   uint64
	BeforeCredentialVersion uint64
}

// Format omits correlated credential and account metadata.
func (CredentialReplacementReceipt) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.CredentialReplacementReceipt(redacted)")
}

// CredentialReplacementFields returns owned canonical metadata for a native
// command mapper. Include every field unchanged alongside native policy intent.
// The scalar encoding is shared with denial-only compromise, but the admitted
// operation, native trait, eligibility and effect remain independently checked.
// No missing predecessor is inferred and this function grants no authority.
func CredentialReplacementFields(s CredentialReplacementIntent) ([]identity.FeatureField, error) {
	if s.Credential.Kind != identity.CredentialPassword || s.Credential.Owner != "identity/password" {
		return nil, invalidCredentialReplacement()
	}
	fields, err := CredentialCompromiseFields(CredentialCompromiseIntent(s))
	if err != nil {
		return nil, invalidCredentialReplacement()
	}
	return fields, nil
}

func decodeCredentialReplacement(s identity.FeatureCommandSpec) (CredentialReplacementIntent, error) {
	intent, err := decodeCredentialCompromise(s)
	if err != nil || intent.Credential.Kind != identity.CredentialPassword || intent.Credential.Owner != "identity/password" {
		return CredentialReplacementIntent{}, invalidCredentialReplacement()
	}
	return CredentialReplacementIntent(intent), nil
}

func replacementCommand(p CredentialReplacementContributor, c identity.Command, plan CommandPlan) (CredentialReplacementIntent, error) {
	s, ok := commandFeature(c)
	if !ok || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.SubjectType != "credential" || plan.Capability != nil || plan.Lifecycle == nil || !credentialReplacementOperation(s.Operation) {
		return CredentialReplacementIntent{}, invalidCredentialReplacement()
	}
	intent, err := decodeCredentialReplacement(s)
	if err != nil {
		return CredentialReplacementIntent{}, err
	}
	native, err := p.CredentialReplacement(c)
	if err != nil || native != intent || s.Operation.RecordRequirement != identity.FeatureRecordRequired || plan.Lifecycle.EventType != "password.changed.v1" || plan.Lifecycle.BeforeVersion != intent.Credential.Version || plan.Lifecycle.AfterVersion != intent.Credential.Version+1 {
		return CredentialReplacementIntent{}, invalidCredentialReplacement()
	}
	for _, a := range plan.Audits {
		if a.RetentionClass != "protected" {
			return CredentialReplacementIntent{}, invalidCredentialReplacement()
		}
	}
	return intent, nil
}

func invalidCredentialReplacement() error {
	return identity.InvalidInputError{Field: "credential_replacement"}
}

// StagedCredentialReplacement returns independently owned provisional version
// successors after the kernel mutation and normal lifecycle staging. Missing,
// failed, expired or closed Work denies; success grants no authority or cascade
// acknowledgement. Persist through the existing registered outbox participant.
func (w Work) StagedCredentialReplacement() (CredentialReplacementReceipt, error) {
	if w.usable() != nil || w.state.replacementReceipt == nil || w.state.lifecycle == nil || w.state.lifecycle.record == nil {
		return CredentialReplacementReceipt{}, invalidWork()
	}
	return *w.state.replacementReceipt, nil
}
