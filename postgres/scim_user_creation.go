package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// SCIMUserCreationDomain borrows the exact enlisted kernel repository. It
// creates an active initial user only inside the original native SCIM creation
// invocation. Connection authentication, current policy and SCIM projections
// belong to the native SCIM owner, not this seam. Construction performs no IO;
// no pool, transaction or goroutine is owned. Immutable composition supports
// concurrent independent Work; each Work and its inputs remain serial-use.
type SCIMUserCreationDomain struct{ repository *Repository }

func invalidSCIMCreation() error { return identity.InvalidInputError{Field: "scim_user_creation"} }

func (SCIMUserCreationDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SCIMUserCreationDomain(redacted)"))
}

func (SCIMUserCreationDomain) MarshalJSON() ([]byte, error) { return nil, invalidSCIMCreation() }

// NewSCIMUserCreationDomain validates explicit borrowed composition without IO.
// Only the existing kernel schema is required; this creates no SCIM storage and
// authenticates no connection. A nil or incomplete repository is invalid.
func NewSCIMUserCreationDomain(repository *Repository) (*SCIMUserCreationDomain, error) {
	if repository == nil || repository.pool == nil || repository.read == nil {
		return nil, invalidSCIMCreation()
	}
	return &SCIMUserCreationDomain{repository: repository}, nil
}

func scimUserCreationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.user-create", SchemaID: "identity.scim.user-create.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func scimUserCreationDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "scim/postgres", ContractID: "identity.scim", Version: 1}
}

// SCIMUserCreationFields commits the kernel-owned initial subject, schema and
// attributes into the original SCIM feature command. Attribute values enter a
// domain-separated digest, not public scalar fields; the coordinator still
// applies its existing keyed request fingerprint. Returned fields own their
// bytes. This performs structural validation, not authorization or field policy.
// Only active initial creation is selected; inactive creation fails closed.
func SCIMUserCreationFields(intent identity.CreateUserCommand) ([]identity.FeatureField, error) {
	command, err := identity.NewUserCreationCommand(intent)
	if err != nil {
		return nil, invalidSCIMCreation()
	}
	creation, _ := command.CreateUser()
	attributes := make(map[string][]byte, len(creation.Attributes))
	for _, attribute := range creation.Attributes {
		value, err := encodeAttribute(attribute.Value)
		if err != nil {
			return nil, invalidSCIMCreation()
		}
		attributes[attribute.Name] = value
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("identity-scim-user-creation-attributes-v1\x00"))
	_, _ = hash.Write(cborMap(attributes))
	return []identity.FeatureField{
		{Name: "scim.creation.user", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(creation.Binding.UserID)}},
		{Name: "scim.creation.schema", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: creation.Binding.SchemaID}},
		{Name: "scim.creation.schema-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(creation.Binding.SchemaVersion)}},
		{Name: "scim.creation.attributes", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: hash.Sum(nil)}},
	}, nil
}

// Apply inserts the kernel user/attributes inside the exact SCIM participant's
// original command and Work. The creation binding must equal the SCIM binding
// except for its kernel operation/schema and omitted projection RecordID. All
// kernel input must match SCIMUserCreationFields in that original command.
// Changed, duplicate, foreign or out-of-invocation attempts poison Work.
// The returned user is provisional, credential-free and not authentication;
// native projection, audit, lifecycle and Coordinator.Commit establish durability.
func (d *SCIMUserCreationDomain) Apply(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent identity.CreateUserCommand) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil {
		return fail(invalidSCIMCreation())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.User{}, err
	}
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil {
		return fail(invalidSCIMCreation())
	}
	_, finalCheck := p.(FeatureCommitContributor)
	originalProfile := p.Descriptor() == scimUserCreationDescriptor() && feature.Operation == scimUserCreationOperation() && w.state.subjectType == "scim_user"
	if !finalCheck || !originalProfile || lifecycle != (LifecyclePlan{EventType: "identity.scim.user_created.v1", AfterVersion: 1}) {
		return fail(invalidSCIMCreation())
	}
	kernelAlreadyMutated := w.state.scimUserUpdate != nil || w.state.scimUserCreation != nil || w.state.registrationUser != nil || w.state.registrationAccepted || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil || w.state.anonymousCreation != nil
	if kernelAlreadyMutated || w.state.lifecycle.record != nil {
		return fail(invalidSCIMCreation())
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != b || spec.Operation != feature.Operation {
		return fail(invalidSCIMCreation())
	}
	expected := b
	expected.OperationID, expected.RecordID = "identity.user.create", ""
	expected.SchemaID, expected.SchemaVersion = intent.Binding.SchemaID, intent.Binding.SchemaVersion
	if expected != intent.Binding {
		return fail(invalidSCIMCreation())
	}
	fields, err := SCIMUserCreationFields(intent)
	if err != nil {
		return fail(err)
	}
	matched := 0
	for _, actual := range spec.Fields {
		if !strings.HasPrefix(actual.Name, "scim.creation.") {
			continue
		}
		found := false
		for _, wanted := range fields {
			if actual.Name != wanted.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			v, ev := encodeFeatureValue(wanted.Value)
			if ea != nil || ev != nil || actual.Value.Kind != wanted.Value.Kind || !bytes.Equal(a, v) {
				return fail(invalidSCIMCreation())
			}
			found, matched = true, matched+1
			break
		}
		if !found {
			return fail(invalidSCIMCreation())
		}
	}
	if matched != len(fields) {
		return fail(invalidSCIMCreation())
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
	creationCommand, _ := identity.NewUserCreationCommand(intent)
	creation, _ := creationCommand.CreateUser()
	user, err := d.repository.insertCreation(ctx, w, creation)
	if err != nil {
		return identity.User{}, err
	}
	w.state.scimUserCreation = &user
	return user, nil
}

// SCIMUserCreation returns the actual provisional kernel effect only to its
// current synchronous SCIM Apply invocation. It grants no credential, retained
// proof, session or current authority. Copies are scalar-only; zero/foreign,
// pre-creation and commit-time observations deny.
func (w Work) SCIMUserCreation(p FeatureExecutionContributor) (identity.User, error) {
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || w.state.scimUserCreation == nil || !w.state.featureApplying || feature.Operation != scimUserCreationOperation() || p.Descriptor() != scimUserCreationDescriptor() {
		return identity.User{}, invalidWork()
	}
	user := *w.state.scimUserCreation
	if user.ID != b.UserID || user.TenantID != b.TenantID || user.Status != identity.StatusActive || user.Version != 1 {
		return identity.User{}, invalidWork()
	}
	return user, nil
}
