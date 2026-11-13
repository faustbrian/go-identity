package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// SCIMUserUpdateIntent binds prepared typed field replacements to the original
// native SCIM command. SchemaID/Version select the enlisted kernel's registered
// field schema; Binding retains the SCIM operation/schema and service actor.
// ExpectedVersion is the core user aggregate, never the SCIM projection version.
// Empty Attributes select no core mutation; the native owner must still perform
// its current RequireActiveUserStatus and connection/admission checks. Inputs
// remain borrowed for one serial call and must not be mutated concurrently.
type SCIMUserUpdateIntent struct {
	Binding         identity.CommandBinding
	SchemaID        string
	SchemaVersion   uint32
	ExpectedVersion uint64
	Attributes      []identity.AttributeUpdate
}

// Format hides prepared private field values from diagnostics.
func (SCIMUserUpdateIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SCIMUserUpdateIntent(redacted)"))
}

// MarshalJSON rejects accidental persistence of prepared private field values.
func (SCIMUserUpdateIntent) MarshalJSON() ([]byte, error) { return nil, invalidSCIMUpdate() }

// SCIMUserUpdateDomain borrows an exact enlisted kernel repository. It shares
// the existing attribute merge/version-CAS storage, not a transaction, journal,
// field processor or authorization engine. Configuration is immutable and may
// serve independent Work concurrently; each Work remains serial-use.
type SCIMUserUpdateDomain struct{ repository *Repository }

func invalidSCIMUpdate() error { return identity.InvalidInputError{Field: "scim_user_update"} }

func (SCIMUserUpdateDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SCIMUserUpdateDomain(redacted)"))
}
func (SCIMUserUpdateDomain) MarshalJSON() ([]byte, error) { return nil, invalidSCIMUpdate() }

// NewSCIMUserUpdateDomain performs composition validation only, without IO.
// Repository/pool lifetimes remain with the caller.
func NewSCIMUserUpdateDomain(repository *Repository) (*SCIMUserUpdateDomain, error) {
	if repository == nil || repository.pool == nil || repository.read == nil {
		return nil, invalidSCIMUpdate()
	}
	return &SCIMUserUpdateDomain{repository: repository}, nil
}

func scimUserUpdateOperation(id string) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "scim", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	if id == "identity.scim.user-patch" {
		op.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
	}
	return op
}

func scimUserUpdateSelected(op identity.FeatureOperation) bool {
	return (op.OperationID == "identity.scim.user-replace" || op.OperationID == "identity.scim.user-patch") && op == scimUserUpdateOperation(op.OperationID)
}

func scimUserUpdateAttributeDigest(document []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("identity-scim-user-update-attributes-v1\x00"))
	_, _ = h.Write(document)
	return h.Sum(nil)
}

// SCIMUserUpdateFields freezes the required-update marker, exact field schema,
// expected core version and attribute commitment in the original SCIM command.
// The configured schema supplies intrinsic shape/size validation only; Apply
// revalidates against the exact repository's registered policy. No defaults,
// field-policy decisions, command impersonation or IO occur. Returned bytes
// do not alias input values. Empty updates explicitly commit required=false.
func SCIMUserUpdateFields(intent SCIMUserUpdateIntent, schema identity.AttributeSchema) ([]identity.FeatureField, error) {
	op := scimUserUpdateOperation(intent.Binding.OperationID)
	if !scimUserUpdateSelected(op) || intent.Binding.ValidateFor(op) != nil || intent.Binding.ActorKind != authorization.SubjectServiceAccount || intent.SchemaID != schema.ID || intent.SchemaVersion != schema.Version || intent.ExpectedVersion == 0 || len(intent.Attributes) > 64 || len(intent.Attributes) > 0 && intent.ExpectedVersion == math.MaxUint64 {
		return nil, invalidSCIMUpdate()
	}
	document, err := encodeAttributeDocument(schema, intent.Attributes)
	if err != nil {
		return nil, invalidSCIMUpdate()
	}
	defer clear(document)
	return []identity.FeatureField{
		{Name: "scim.update.required", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: len(intent.Attributes) > 0}},
		{Name: "scim.update.schema", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: intent.SchemaID}},
		{Name: "scim.update.schema-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(intent.SchemaVersion)}},
		{Name: "scim.update.expected-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: intent.ExpectedVersion}},
		{Name: "scim.update.attributes", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: scimUserUpdateAttributeDigest(document)}},
	}, nil
}

func scimUserUpdateCommandPlan(command identity.Command) (SCIMUserUpdatePlan, error) {
	spec, ok := command.Feature()
	if !ok || !scimUserUpdateSelected(spec.Operation) || spec.Binding.ActorKind != authorization.SubjectServiceAccount {
		return SCIMUserUpdatePlan{}, invalidSCIMUpdate()
	}
	fields := make(map[string]identity.FeatureValue, 5)
	for _, field := range spec.Fields {
		if strings.HasPrefix(field.Name, "scim.update.") {
			fields[field.Name] = field.Value
		}
	}
	required, schema, version, expected, attributes := fields["scim.update.required"], fields["scim.update.schema"], fields["scim.update.schema-version"], fields["scim.update.expected-version"], fields["scim.update.attributes"]
	if len(fields) != 5 || required.Kind != identity.FeatureBool || schema.Kind != identity.FeatureText || !queryScopeText(schema.Text) || version.Kind != identity.FeatureUint64 || version.Uint64 == 0 || version.Uint64 > math.MaxUint32 || expected.Kind != identity.FeatureUint64 || expected.Uint64 == 0 || required.Bool && expected.Uint64 == math.MaxUint64 || attributes.Kind != identity.FeatureBytes || len(attributes.Bytes) != 32 {
		return SCIMUserUpdatePlan{}, invalidSCIMUpdate()
	}
	if !required.Bool && !bytes.Equal(attributes.Bytes, scimUserUpdateAttributeDigest(cborArray([][]byte{cborUint(1), cborArray(nil)}))) {
		return SCIMUserUpdatePlan{}, invalidSCIMUpdate()
	}
	return SCIMUserUpdatePlan{Required: required.Bool, ExpectedVersion: expected.Uint64}, nil
}

// Apply performs only a nonempty typed kernel update during this exact SCIM
// participant's original synchronous invocation. The original command must bind
// every update field and enlist this repository and a final-check contributor.
// Active status and expected aggregate version fence the write; native current
// security-epoch/connection admission remains mandatory. Every rejected call
// poisons live Work. Returned User is the provisional core effect, not a receipt,
// credential, session or SCIM lifecycle/projection version.
func (d *SCIMUserUpdateDomain) Apply(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent SCIMUserUpdateIntent) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil || len(intent.Attributes) == 0 {
		return fail(invalidSCIMUpdate())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.User{}, err
	}
	b, feature, _, err := w.FeatureScope(p)
	_, finalCheck := p.(FeatureCommitContributor)
	if err != nil || !finalCheck || p.Descriptor() != scimUserCreationDescriptor() || !scimUserUpdateSelected(feature.Operation) || w.state.subjectType != "scim_user" || intent.Binding != b {
		return fail(invalidSCIMUpdate())
	}
	if w.state.scimUserUpdate != nil || w.state.scimUserCreation != nil || w.state.registrationUser != nil || w.state.registrationAccepted || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil || w.state.anonymousCreation != nil || w.state.lifecycle.record != nil {
		return fail(invalidSCIMUpdate())
	}
	enlisted := false
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == d.repository {
			enlisted = true
		}
	}
	if !enlisted {
		return fail(invalidWork())
	}
	registered, _, err := d.repository.prepareAttributeUpdates(schemaKey{intent.SchemaID, intent.SchemaVersion}, b, intent.Attributes)
	if err != nil {
		return fail(err)
	}
	fields, err := SCIMUserUpdateFields(intent, registered.schema)
	if err != nil {
		return fail(err)
	}
	spec, _ := command.Feature()
	matched := 0
	for _, actual := range spec.Fields {
		if !strings.HasPrefix(actual.Name, "scim.update.") {
			continue
		}
		found := false
		for _, wanted := range fields {
			if actual.Name == wanted.Name {
				a, ea := encodeFeatureValue(actual.Value)
				v, ev := encodeFeatureValue(wanted.Value)
				if ea != nil || ev != nil || !bytes.Equal(a, v) {
					return fail(invalidSCIMUpdate())
				}
				found = true
				matched++
				break
			}
		}
		if !found {
			return fail(invalidSCIMUpdate())
		}
	}
	if matched != len(fields) {
		return fail(invalidSCIMUpdate())
	}
	record, err := d.repository.persistAttributeUpdate(ctx, w, identity.ProfileUpdateCommand{Binding: b, ExpectedVersion: intent.ExpectedVersion, AdditionalFields: intent.Attributes}, registered, attributeUpdateStorage{requireActive: true})
	if err != nil {
		return identity.User{}, err
	}
	user := record.User
	w.state.scimUserUpdate = &user
	return user, nil
}

// SCIMUserUpdate observes only the actual provisional effect during the exact
// synchronous Apply invocation. No-op, returned, foreign and final-check calls
// deny; this projection confers neither authority nor durable success.
func (w Work) SCIMUserUpdate(p FeatureExecutionContributor) (identity.User, error) {
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || !w.state.featureApplying || w.state.scimUserUpdate == nil || !scimUserUpdateSelected(feature.Operation) || p.Descriptor() != scimUserCreationDescriptor() {
		return identity.User{}, invalidWork()
	}
	user := *w.state.scimUserUpdate
	if user.ID != b.UserID || user.TenantID != b.TenantID || user.Status != identity.StatusActive || user.Version < 2 {
		return identity.User{}, invalidWork()
	}
	return user, nil
}
