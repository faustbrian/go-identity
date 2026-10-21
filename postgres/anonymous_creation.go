package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// AnonymousCreationIntent freezes only the kernel-owned part of anonymous
// signin: an active initial user, admitted attributes and its non-contact
// placeholder. The user is a generated opaque subject, not a caller-selected
// permanent identity. No credential or session authority is represented here.
// Anonymous lifecycle, expiry and risk remain the native feature's obligations.
type AnonymousCreationIntent struct {
	Creation    identity.CreateUserCommand
	Placeholder identity.Identifier
}

// AnonymousCreationDomain borrows the exact enlisted kernel repository. It
// opens no transaction and owns no resource lifetime. Immutable composition is
// concurrent-safe; Work and input mutation remain serial. Applications use the
// anonymous service, not this trusted same-Work adapter seam. Zero denies.
type AnonymousCreationDomain struct{ repository *Repository }

type anonymousCreationProgress struct {
	user        identity.User
	placeholder identity.Identifier
}

func invalidAnonymousCreation() error {
	return identity.InvalidInputError{Field: "anonymous_creation"}
}

func (AnonymousCreationIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.AnonymousCreationIntent(redacted)")
}
func (AnonymousCreationDomain) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.AnonymousCreationDomain(redacted)")
}
func (AnonymousCreationIntent) MarshalJSON() ([]byte, error) {
	return nil, invalidAnonymousCreation()
}
func (AnonymousCreationDomain) MarshalJSON() ([]byte, error) {
	return nil, invalidAnonymousCreation()
}

// NewAnonymousCreationDomain validates explicit composition without IO. Install
// AnonymousIdentityMigrationSource before use. Construction authenticates no
// browser, risk decision or credentials and grants no issuance authority.
func NewAnonymousCreationDomain(repository *Repository) (*AnonymousCreationDomain, error) {
	if repository == nil || repository.pool == nil || repository.read == nil {
		return nil, invalidAnonymousCreation()
	}
	return &AnonymousCreationDomain{repository: repository}, nil
}

func anonymousCreationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.signin", SchemaID: "identity.anonymous.signin.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func anonymousCreationDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}

// AnonymousCreationFields maps the complete prepared kernel intent into scalar
// original-command fields before keyed fingerprinting. Attributes use a
// domain-separated commitment, not public serialized values. Results own their
// bytes. Structural validity does not establish field policy, risk or privilege.
func AnonymousCreationFields(intent AnonymousCreationIntent) ([]identity.FeatureField, error) {
	command, err := identity.NewUserCreationCommand(intent.Creation)
	if err != nil {
		return nil, invalidAnonymousCreation()
	}
	creation, _ := command.CreateUser()
	b, placeholder := creation.Binding, intent.Placeholder
	// The root's placeholder validator owns canonical opaque-ID syntax. Binding
	// its local part to the generated subject forbids a second address authority.
	if placeholder.Validate(b.UserID) != nil || placeholder.Kind != identity.IdentifierAnonymousPlaceholder || placeholder.Version != 1 || placeholder.CanonicalValue != string(b.UserID)+"@anonymous.invalid" {
		return nil, invalidAnonymousCreation()
	}
	attributes := make(map[string][]byte, len(creation.Attributes))
	for _, attribute := range creation.Attributes {
		value, err := encodeAttribute(attribute.Value)
		if err != nil {
			return nil, invalidAnonymousCreation()
		}
		attributes[attribute.Name] = value
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("identity-anonymous-creation-attributes-v1\x00"))
	_, _ = hash.Write(cborMap(attributes))
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "anonymous.creation." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	return []identity.FeatureField{
		text("user", string(b.UserID)), text("schema", b.SchemaID),
		{Name: "anonymous.creation.schema-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(b.SchemaVersion)}},
		{Name: "anonymous.creation.attributes", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: hash.Sum(nil)}},
		text("placeholder", string(placeholder.ID)), text("canonical", placeholder.CanonicalValue),
	}, nil
}

// Apply creates the user/attributes and reserved placeholder only inside the
// exact anonymous participant's original command invocation. Foreign, changed,
// duplicate or out-of-invocation calls poison Work. The repository owns all
// kernel SQL. Returned User is provisional; the anonymous adapter must persist
// its own lifecycle and session effects, then required audit/outbox and the
// existing coordinator commit establish durability. No bearer is returned.
func (d *AnonymousCreationDomain) Apply(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent AnonymousCreationIntent) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil {
		return fail(invalidAnonymousCreation())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.User{}, err
	}
	b, feature, lifecycle, err := w.FeatureScope(p)
	if err != nil || p.Descriptor() != anonymousCreationDescriptor() || feature.Operation != anonymousCreationOperation() || w.state.subjectType != "anonymous_flow" || lifecycle != (LifecyclePlan{EventType: "anonymous.created.v1"}) || w.state.lifecycle.record != nil || w.state.anonymousCreation != nil || w.state.registrationUser != nil || w.state.registrationAccepted || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil {
		return fail(invalidAnonymousCreation())
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != b || spec.Operation != feature.Operation {
		return fail(invalidAnonymousCreation())
	}
	fields, err := AnonymousCreationFields(intent)
	if err != nil {
		return fail(err)
	}
	expected := b
	expected.OperationID, expected.AnonymousFlowID = "identity.user.create", ""
	expected.UserID = intent.Creation.Binding.UserID
	expected.SchemaID, expected.SchemaVersion = intent.Creation.Binding.SchemaID, intent.Creation.Binding.SchemaVersion
	if expected != intent.Creation.Binding {
		return fail(invalidAnonymousCreation())
	}
	matched := 0
	for _, actual := range spec.Fields {
		if !strings.HasPrefix(actual.Name, "anonymous.creation.") {
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
				return fail(invalidAnonymousCreation())
			}
			found, matched = true, matched+1
			break
		}
		if !found {
			return fail(invalidAnonymousCreation())
		}
	}
	if matched != len(fields) {
		return fail(invalidAnonymousCreation())
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
	if err := requireUnusedAnonymousPlaceholder(ctx, w, b.TenantID, intent.Placeholder.ID); err != nil {
		return identity.User{}, err
	}
	creationCommand, _ := identity.NewUserCreationCommand(intent.Creation)
	creation, _ := creationCommand.CreateUser()
	user, err := d.repository.insertCreation(ctx, w, creation)
	if err != nil {
		return identity.User{}, err
	}
	if err := insertRegistrationIdentifier(ctx, w, b.TenantID, user.ID, intent.Placeholder); err != nil {
		return identity.User{}, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return fail(invalidAnonymousCreation())
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.anonymous_creation_bindings(tenant_id,purpose,command_id,user_id,identifier_id) VALUES($1,$2,$3,$4,$5)`, string(b.TenantID), b.OperationID, id, string(user.ID), string(intent.Placeholder.ID)); err != nil {
		return identity.User{}, err
	}
	w.state.anonymousCreation = &anonymousCreationProgress{user: user, placeholder: intent.Placeholder}
	return user, nil
}

func requireUnusedAnonymousPlaceholder(ctx context.Context, w Work, tenant identity.TenantID, id identity.IdentifierID) error {
	// Identifier retirement reserves the structural ID indefinitely, independently
	// of contact-value reuse cooldown. The existing tenant fence also protects
	// this profile; opaque random generation does not waive collision checking.
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2) OR EXISTS(SELECT 1 FROM identity.identifier_retirements WHERE tenant_id=$1 AND identifier_id=$2)`, string(tenant), string(id))
	if err != nil {
		return err
	}
	var occupied bool
	if !rows.Next() || rows.Scan(&occupied) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return w.fail(ctx, identity.UnavailableError{})
	}
	rows.Close()
	if occupied {
		return w.fail(ctx, identity.ConflictError{})
	}
	return nil
}

// AnonymousCreation reads the actual provisional kernel effect during its
// exact current native invocation. Session effects must call this seam, not
// accept a caller-authored user as creation evidence. Copies are scalar-only;
// neither this read nor its output grants authentication or survives Work.
func (w Work) AnonymousCreation(p FeatureExecutionContributor) (identity.User, identity.Identifier, error) {
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || w.state.anonymousCreation == nil || feature.Operation != anonymousCreationOperation() || p.Descriptor() != anonymousCreationDescriptor() || !w.state.featureApplying {
		return identity.User{}, identity.Identifier{}, invalidWork()
	}
	created := w.state.anonymousCreation
	if created.user.Validate(b.TenantID) != nil || created.user.Status != identity.StatusActive || created.user.Version != 1 || created.placeholder.Validate(created.user.ID) != nil {
		return identity.User{}, identity.Identifier{}, invalidWork()
	}
	return created.user, created.placeholder, nil
}

func recoverAnonymousCreation(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil || w.state.plan.feature == nil || w.state.plan.feature.Operation != anonymousCreationOperation() {
		return RecoveryUnknown, invalidAnonymousCreation()
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return RecoveryUnknown, invalidAnonymousCreation()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.anonymous_creation_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3)`, string(b.TenantID), b.OperationID, id)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return RecoveryCommitted, nil
	}
	return RecoveryNotCommitted, nil
}
