package postgres

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CredentialCompromiseIntent is exact denial-only native intent. All counters
// must have a positive uint64 successor. Credential.Version is the reference
// fence; ExpectedAuthorityVersion is the independent tenant/user epoch, not
// User.Version. No secret, proof, authorization or transaction is carried.
type CredentialCompromiseIntent struct {
	Credential               identity.CredentialRef
	ExpectedUserVersion      uint64
	ExpectedAuthorityVersion uint64
}

// Format redacts reference and scope metadata.
func (CredentialCompromiseIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.CredentialCompromiseIntent(redacted)")
}

// CredentialCompromiseContributor is a native denial-only feature participant.
// CredentialCompromise is pure bounded mapping of its complete frozen command,
// not a callback supplied by a request. The identity-owned phase independently
// matches every metadata scalar before SQL. Actual detection/authorization and
// owned verifier state remain native responsibilities. A name or implementation
// alone grants no authority; the exact registered instance must be invoked.
// This phase cannot set/reset/change a password or enable a credential.
type CredentialCompromiseContributor interface {
	FeatureExecutionContributor
	CredentialCompromise(identity.Command) (CredentialCompromiseIntent, error)
}

// CredentialCompromiseLifecycleContributor persists the normal staged lifecycle
// plus exact separate credential/user successors through the existing outbox
// participant. The coordinator invokes this instead of PersistLifecycle for a
// compromise, once. It must use StagedLifecycle and StagedCredentialCompromise,
// retain command-linked evidence and never close Work or perform network IO.
type CredentialCompromiseLifecycleContributor interface {
	LifecycleContributor
	PersistCredentialCompromise(context.Context, Work) error
}

// CredentialCompromiseReceipt is provisional safe metadata for the owned outbox
// phase. Only the journal's successful shared commit proves durability. It is
// not a current authority vector, completed cascade or authentication proof.
// Credential is the retained disabled reference's successor. Copies own their
// scalar values; aggregate, user credential epoch and record stay separate.
type CredentialCompromiseReceipt struct {
	Credential              identity.CredentialRef
	BeforeUserVersion       uint64
	AfterUserVersion        uint64
	BeforeAuthorityVersion  uint64
	AfterAuthorityVersion   uint64
	BeforeCredentialVersion uint64
}

// Format redacts all scope and reference metadata.
func (CredentialCompromiseReceipt) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.CredentialCompromiseReceipt(redacted)")
}

func validCompromiseIntent(s CredentialCompromiseIntent) bool {
	c := s.Credential
	owned := c.Kind == identity.CredentialPassword && c.Owner == "identity/password" || c.Kind == identity.CredentialPasskey && c.Owner == "passkey"
	return owned && c.Validate(c.TenantID, c.UserID) == nil && c.Version < ^uint64(0) && s.ExpectedUserVersion > 0 && s.ExpectedUserVersion < ^uint64(0) && s.ExpectedAuthorityVersion > 0 && s.ExpectedAuthorityVersion < ^uint64(0)
}

// CredentialCompromiseFields returns eight independently owned canonical
// metadata fields for a native command mapper. Include every field unchanged in
// NewFeatureCommand along with its native fields; never infer a missing epoch.
// This does not enable an operation, classify a breach or authorize a caller.
func CredentialCompromiseFields(s CredentialCompromiseIntent) ([]identity.FeatureField, error) {
	if !validCompromiseIntent(s) {
		return nil, invalidCredentialCompromise()
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "credential." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "credential." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	c := s.Credential
	return []identity.FeatureField{text("id", string(c.ID)), text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("owner", c.Owner), number("kind", uint64(c.Kind)), number("version", c.Version), number("expected-user-version", s.ExpectedUserVersion), number("expected-authority-version", s.ExpectedAuthorityVersion)}, nil
}

func decodeCredentialCompromise(s identity.FeatureCommandSpec) (CredentialCompromiseIntent, error) {
	values := make(map[string]identity.FeatureValue, 8)
	for _, f := range s.Fields {
		if !strings.HasPrefix(f.Name, "credential.") {
			continue
		}
		if _, duplicate := values[f.Name]; duplicate {
			return CredentialCompromiseIntent{}, invalidCredentialCompromise()
		}
		values[f.Name] = f.Value
	}
	if len(values) != 8 {
		return CredentialCompromiseIntent{}, invalidCredentialCompromise()
	}
	intent := CredentialCompromiseIntent{Credential: identity.CredentialRef{ID: identity.CredentialID(values["credential.id"].Text), TenantID: identity.TenantID(values["credential.tenant"].Text), UserID: identity.UserID(values["credential.user"].Text), Owner: values["credential.owner"].Text, Version: values["credential.version"].Uint64}, ExpectedUserVersion: values["credential.expected-user-version"].Uint64, ExpectedAuthorityVersion: values["credential.expected-authority-version"].Uint64}
	kind := values["credential.kind"].Uint64
	if kind < 1 || kind > 4 {
		return CredentialCompromiseIntent{}, invalidCredentialCompromise()
	}
	intent.Credential.Kind = identity.CredentialKind(kind)
	expected, err := CredentialCompromiseFields(intent)
	if err != nil || intent.Credential.TenantID != s.Binding.TenantID || intent.Credential.UserID != s.Binding.UserID || string(intent.Credential.ID) != s.Binding.RecordID || intent.Credential.Owner != s.Operation.Owner {
		return CredentialCompromiseIntent{}, invalidCredentialCompromise()
	}
	for _, f := range expected {
		v, ok := values[f.Name]
		if !ok || v.Kind != f.Value.Kind || v.Text != f.Value.Text || v.Uint64 != f.Value.Uint64 || v.Bytes != nil || v.Int64 != 0 || v.Bool || v.Time != (time.Time{}) {
			return CredentialCompromiseIntent{}, invalidCredentialCompromise()
		}
	}
	return intent, nil
}

func compromiseCommand(p CredentialCompromiseContributor, c identity.Command, plan CommandPlan) (CredentialCompromiseIntent, error) {
	s, ok := c.Feature()
	if !ok || plan.Feature == nil || plan.Feature.Operation != s.Operation || plan.SubjectType != "credential" || plan.Capability != nil || plan.Lifecycle == nil {
		return CredentialCompromiseIntent{}, invalidCredentialCompromise()
	}
	intent, err := decodeCredentialCompromise(s)
	if err != nil {
		return CredentialCompromiseIntent{}, err
	}
	native, err := p.CredentialCompromise(c)
	if err != nil || native != intent {
		return CredentialCompromiseIntent{}, invalidCredentialCompromise()
	}
	op, event := "identity.password.mark-compromised", "password.compromised.v1"
	if intent.Credential.Owner == "passkey" {
		op, event = "identity.passkey.mark-compromised", "passkey.compromised.v1"
	}
	if s.Operation.OperationID != op || s.Operation.RecordRequirement != identity.FeatureRecordRequired || plan.Lifecycle.EventType != event || plan.Lifecycle.BeforeVersion != intent.Credential.Version || plan.Lifecycle.AfterVersion != intent.Credential.Version+1 {
		return CredentialCompromiseIntent{}, invalidCredentialCompromise()
	}
	for _, a := range plan.Audits {
		if a.RetentionClass != "protected" {
			return CredentialCompromiseIntent{}, invalidCredentialCompromise()
		}
	}
	return intent, nil
}

func invalidCredentialCompromise() error {
	return identity.InvalidInputError{Field: "credential_compromise"}
}

// StagedCredentialCompromise exposes the kernel-owned exact provisional
// successors only after its mutation and normal lifecycle staging. Outbox may
// persist them in the same Work; the value cannot grant current authority or
// acknowledge a cascade. Missing/closed/failed Work returns no metadata.
func (w Work) StagedCredentialCompromise() (CredentialCompromiseReceipt, error) {
	if w.usable() != nil || w.state.credentialReceipt == nil || w.state.lifecycle == nil || w.state.lifecycle.record == nil {
		return CredentialCompromiseReceipt{}, invalidWork()
	}
	return *w.state.credentialReceipt, nil
}
