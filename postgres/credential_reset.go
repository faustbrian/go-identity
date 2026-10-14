package postgres

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// CredentialResetIntent fixes the existing password reference and independent
// aggregate/credential-authority predecessors. ExpectedEnabled is the original
// primary reference state; a separately authorized reset may restore a disabled
// reference. Neither this metadata nor its fields authorize recovery. The native
// owner must check original signed reset scope, current factors/identifier/risk,
// and password policy. Reset never unblocks an inactive user or removes expiry.
type CredentialResetIntent struct {
	Replacement     CredentialReplacementIntent
	ExpectedEnabled bool
}

// Format omits correlated account and credential metadata.
func (CredentialResetIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CredentialResetIntent(redacted)"))
}

// MarshalJSON rejects accidental export of retained recovery scope.
func (CredentialResetIntent) MarshalJSON() ([]byte, error) { return nil, invalidCredentialReset() }

// CredentialResetContributor is the exact native reset-complete owner, distinct
// from authenticated password change. CredentialReset is pure bounded mapping;
// the kernel compares every predecessor and expected enablement. ApplyFeature
// must verify the original proof and issuance/profile/current recovery authority,
// replace the verifier and apply configured session effects through the same
// Work. CheckFeatureCommit must recheck original admission without renewing it.
// HIBP/risk preparation happens outside SQL before hashing. No private
// transactions, network IO under Work, kernel writes or retained Work are allowed.
// Methods may overlap on independent serial-use Work. This trusted composition
// seam is not a public authenticated endpoint or proof issuer.
type CredentialResetContributor interface {
	FeatureCommitContributor
	CredentialReset(identity.Command) (CredentialResetIntent, error)
}

// CredentialResetLifecycleContributor persists the staged reset successors and
// required lifecycle/session effects in the existing transaction exactly once.
// It must propagate all errors, never close/retain Work or claim asynchronous
// cleanup complete. The credential epoch immediately invalidates prior bound
// authority; lifecycle consumers still own their required cleanup acknowledgements.
type CredentialResetLifecycleContributor interface {
	LifecycleContributor
	PersistCredentialReset(context.Context, Work) error
}

// CredentialResetFields returns independently owned predecessor metadata for
// the exact native reset command. Include every field unchanged before binding
// original proof/verifier custody. This performs no IO or authorization.
func CredentialResetFields(i CredentialResetIntent) ([]identity.FeatureField, error) {
	fields, err := CredentialReplacementFields(i.Replacement)
	if err != nil {
		return nil, invalidCredentialReset()
	}
	return append(fields, identity.FeatureField{Name: "reset.expected-enabled", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: i.ExpectedEnabled}}), nil
}

func decodeCredentialReset(s identity.FeatureCommandSpec) (CredentialResetIntent, error) {
	i, err := decodeCredentialReplacement(s)
	if err != nil {
		return CredentialResetIntent{}, invalidCredentialReset()
	}
	var found bool
	var enabled bool
	for _, f := range s.Fields {
		if f.Name != "reset.expected-enabled" {
			continue
		}
		if found || f.Value.Kind != identity.FeatureBool || f.Value.Text != "" || f.Value.Bytes != nil || f.Value.Uint64 != 0 || f.Value.Int64 != 0 || !f.Value.Time.IsZero() {
			return CredentialResetIntent{}, invalidCredentialReset()
		}
		found, enabled = true, f.Value.Bool
	}
	if !found {
		return CredentialResetIntent{}, invalidCredentialReset()
	}
	return CredentialResetIntent{Replacement: i, ExpectedEnabled: enabled}, nil
}

func credentialResetCommand(p CredentialResetContributor, c identity.Command, plan CommandPlan) (CredentialResetIntent, error) {
	s, ok := c.PasswordResetFeature()
	if !ok || s.Operation != credentialResetOperation() || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.SubjectType != "credential" || plan.Capability == nil || plan.Capability.Purpose != "identity.password.reset-complete" || plan.Lifecycle == nil || plan.Lifecycle.EventType != "password.reset.v1" {
		return CredentialResetIntent{}, invalidCredentialReset()
	}
	i, err := decodeCredentialReset(s)
	if err != nil {
		return CredentialResetIntent{}, err
	}
	native, err := p.CredentialReset(c)
	if err != nil || native != i || plan.Lifecycle.BeforeVersion != i.Replacement.Credential.Version || plan.Lifecycle.AfterVersion != i.Replacement.Credential.Version+1 {
		return CredentialResetIntent{}, invalidCredentialReset()
	}
	for _, a := range plan.Audits {
		if a.RetentionClass != "protected" {
			return CredentialResetIntent{}, invalidCredentialReset()
		}
	}
	return i, nil
}

func invalidCredentialReset() error { return identity.InvalidInputError{Field: "credential_reset"} }

func credentialResetOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-complete", SchemaID: "password-reset-complete", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
