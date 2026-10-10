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

// PasswordRegistrationIntent contains prepared structural creation and one
// owner-canonicalized, initially unverified identifier and password reference.
// Creation uses the existing structural command shape solely for validation;
// the durable command remains identity.password.signup. All versions start at
// one. It contains no password, hash, possession proof or authentication grant.
// Attributes must already be admitted by the identity field policy. The native
// password owner remains responsible for HIBP, risk, pre-auth and material.
type PasswordRegistrationIntent struct {
	Creation          identity.CreateUserCommand
	Identifier        identity.Identifier
	Credential        identity.CredentialRef
	ComparisonProfile string
}

// PasswordRegistrationDomainConfig selects the same retained identifier-reuse
// keys used by identifier removal. Missing keys deny while live retirement
// history references them. ComparisonProfile is the exact versioned identifier
// owner's policy identity, not client input. Construction copies the key map.
type PasswordRegistrationDomainConfig struct {
	ComparisonProfile           string
	CurrentIdentifierKeyVersion uint32
	RetainedIdentifierKeys      map[uint32][32]byte
}

// PasswordRegistrationDomain owns only the kernel part of native signup. It
// borrows the exact enlisted repository and pool; it owns no transaction, store,
// goroutine, retry or resource lifetime. Zero denies. Immutable composition is
// concurrent-safe. Applications use the native password service, not this seam.
type PasswordRegistrationDomain struct {
	repository *Repository
	comparison string
	reuse      identifierMutationPolicy
}

func invalidPasswordRegistration() error {
	return identity.InvalidInputError{Field: "password_registration"}
}

func (PasswordRegistrationIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.PasswordRegistrationIntent(redacted)")
}
func (PasswordRegistrationDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.PasswordRegistrationDomainConfig(redacted)")
}
func (PasswordRegistrationDomain) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.PasswordRegistrationDomain(redacted)")
}
func (PasswordRegistrationIntent) MarshalJSON() ([]byte, error) {
	return nil, invalidPasswordRegistration()
}
func (PasswordRegistrationDomainConfig) MarshalJSON() ([]byte, error) {
	return nil, invalidPasswordRegistration()
}
func (PasswordRegistrationDomain) MarshalJSON() ([]byte, error) {
	return nil, invalidPasswordRegistration()
}

// NewPasswordRegistrationDomain validates explicit composition without IO or
// callbacks. Install the existing credential/retirement histories and additive
// PasswordRegistrationMigrationSource before use. This grants no signup policy.
func NewPasswordRegistrationDomain(r *Repository, c PasswordRegistrationDomainConfig) (*PasswordRegistrationDomain, error) {
	if r == nil || r.pool == nil || r.read == nil {
		return nil, invalidPasswordRegistration()
	}
	if _, err := identity.ParseIdentifierID(c.ComparisonProfile); err != nil {
		return nil, invalidPasswordRegistration()
	}
	if len(c.RetainedIdentifierKeys) > 16 {
		return nil, invalidPasswordRegistration()
	}
	p := identifierMutationPolicy{currentKeyVersion: c.CurrentIdentifierKeyVersion, keys: make(map[uint32][32]byte, len(c.RetainedIdentifierKeys))}
	for version, key := range c.RetainedIdentifierKeys {
		p.keys[version] = key
	}
	if !p.valid() {
		return nil, invalidPasswordRegistration()
	}
	return &PasswordRegistrationDomain{repository: r, comparison: strings.Clone(c.ComparisonProfile), reuse: p}, nil
}

// PasswordRegistrationFields maps every kernel-owned input into the original
// native command. Include the returned fields unchanged before fingerprinting.
// Prepared attributes use a domain-separated commitment, not a serialized blob;
// the coordinator subsequently keys all fields. No verifier belongs here.
// Structural validation proves neither field permission nor normalization.
func PasswordRegistrationFields(s PasswordRegistrationIntent) ([]identity.FeatureField, error) {
	command, err := identity.NewUserCreationCommand(s.Creation)
	if err != nil {
		return nil, invalidPasswordRegistration()
	}
	creation, _ := command.CreateUser()
	u, b := creation.Binding.UserID, creation.Binding
	if s.Identifier.Validate(u) != nil || s.Identifier.Version != 1 || s.Identifier.Verified || s.Identifier.Primary || s.Identifier.Kind == identity.IdentifierProviderSubject || s.Credential.Validate(b.TenantID, u) != nil || s.Credential.Version != 1 || s.Credential.Kind != identity.CredentialPassword || s.Credential.Owner != "identity/password" {
		return nil, invalidPasswordRegistration()
	}
	if _, err := identity.ParseIdentifierID(s.ComparisonProfile); err != nil {
		return nil, invalidPasswordRegistration()
	}
	attributes := make(map[string][]byte, len(creation.Attributes))
	for _, a := range creation.Attributes {
		encoded, e := encodeAttribute(a.Value)
		if e != nil {
			return nil, invalidPasswordRegistration()
		}
		attributes[a.Name] = encoded
	}
	h := sha256.New()
	_, _ = h.Write([]byte("identity-password-registration-attributes-v1\x00"))
	_, _ = h.Write(cborMap(attributes))
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "registration." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	return []identity.FeatureField{text("user", string(u)), text("schema", b.SchemaID), {Name: "registration.schema-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(b.SchemaVersion)}}, {Name: "registration.attributes", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: h.Sum(nil)}}, text("identifier", string(s.Identifier.ID)), text("kind", string(s.Identifier.Kind)), text("canonical", s.Identifier.CanonicalValue), text("display", s.Identifier.DisplayValue), text("credential", string(s.Credential.ID)), text("comparison", s.ComparisonProfile)}, nil
}

func passwordRegistrationOperation(op identity.FeatureOperation) bool {
	return op.Owner == "identity/password" && op.OperationID == "identity.password.signup" && op.SchemaID == "password-signup" && op.SchemaVersion == 1 && op.RecordRequirement == identity.FeatureRecordOmitted && op.SubjectRequirement <= identity.FeatureSubjectAnonymousFlow
}

// ApplyOrAccept is the opt-in anonymous signup registration branch. A true
// accepted result contains no User and must not produce password material,
// sessions, verification credentials or delivery. The coordinator alone
// commits the original neutral acknowledgement and required security effects.
func (d *PasswordRegistrationDomain) ApplyOrAccept(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent PasswordRegistrationIntent) (identity.User, bool, error) {
	u, err := d.apply(ctx, w, p, command, intent, true)
	return u, err == nil && w.state.registrationAccepted, err
}

// Apply creates the user/attributes, unverified identifier and enabled initial
// password reference through the original signup Work. The exact native
// participant, command custody, scope, comparison profile and complete intent
// must match. Repeated/foreign/changed invocations poison Work. Canonical value
// uniqueness and retirement cooldown are checked under the existing tenant
// fence before writing. The returned User is provisional, not authentication.
// The password participant must persist its material before returning; required
// audit/outbox, native recovery and the sole coordinator establish durability.
func (d *PasswordRegistrationDomain) Apply(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent PasswordRegistrationIntent) (identity.User, error) {
	return d.apply(ctx, w, p, command, intent, false)
}

func (d *PasswordRegistrationDomain) apply(ctx context.Context, w Work, p FeatureExecutionContributor, command identity.Command, intent PasswordRegistrationIntent, accept bool) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil {
		return fail(invalidPasswordRegistration())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.User{}, err
	}
	b, f, l, err := w.FeatureScope(p)
	if err != nil || p.Descriptor() != (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || !passwordRegistrationOperation(f.Operation) || w.state.subjectType != "user" || l.EventType != "user.created.v1" || l.BeforeVersion != 0 || l.AfterVersion != 0 || w.state.lifecycle.record != nil || w.state.registrationAccepted || w.state.registrationUser != nil || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil {
		return fail(invalidPasswordRegistration())
	}
	if accept && (!w.state.execution.reservation.plan.signupAcceptance || f.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || b.UserID != "" || b.AnonymousFlowID == "") {
		return fail(invalidPasswordRegistration())
	}
	s, ok := commandFeature(command)
	if !ok || s.Binding != b || s.Operation != f.Operation || intent.ComparisonProfile != d.comparison {
		return fail(invalidPasswordRegistration())
	}
	fields, err := PasswordRegistrationFields(intent)
	if err != nil {
		return fail(err)
	}
	expected := b
	expected.OperationID, expected.AnonymousFlowID = "identity.user.create", ""
	expected.UserID = intent.Creation.Binding.UserID
	expected.SchemaID, expected.SchemaVersion = intent.Creation.Binding.SchemaID, intent.Creation.Binding.SchemaVersion
	if intent.Creation.Binding != expected || b.UserID != "" && b.UserID != expected.UserID {
		return fail(invalidPasswordRegistration())
	}
	matched := 0
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "registration.") {
			continue
		}
		found := false
		for _, wanted := range fields {
			if actual.Name != wanted.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			v, ev := encodeFeatureValue(wanted.Value)
			if actual.Value.Kind != wanted.Value.Kind || ea != nil || ev != nil || !bytes.Equal(a, v) {
				return fail(invalidPasswordRegistration())
			}
			found = true
			matched++
			break
		}
		if !found {
			return fail(invalidPasswordRegistration())
		}
	}
	if matched != len(fields) {
		return fail(invalidPasswordRegistration())
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
	// Freeze lists through the existing structural input owner before SQL.
	creationCommand, _ := identity.NewUserCreationCommand(intent.Creation)
	creation, _ := creationCommand.CreateUser()
	if accept {
		// Canonical occupancy is the sole alternate outcome, not an exemption
		// from repository-owned field policy or prospective structural-ID checks.
		registered, attributes, e := d.repository.prepareCreationAttributes(creation)
		clear(attributes)
		if e != nil {
			return fail(e)
		}
		if attributes != nil {
			if e := checkCreationSchema(ctx, w, registered, true); e != nil {
				return identity.User{}, e
			}
		}
		if e := requireAbsentRegistrationUser(ctx, w, creation.Binding.UserID); e != nil {
			return identity.User{}, e
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.User{}, err
	}
	i := intent.Identifier
	blocked, err := classifyIdentifierReuse(ctx, w, identity.IdentifierChange{Action: identity.IdentifierAttach, TenantID: b.TenantID, UserID: creation.Binding.UserID, ID: i.ID, Kind: i.Kind, CanonicalValue: i.CanonicalValue}, d.reuse, now, accept)
	if err != nil {
		return identity.User{}, err
	}
	if blocked {
		if !accept {
			return fail(identity.ConflictError{})
		}
		id, e := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if e != nil || len(id) != 16 {
			return fail(invalidPasswordRegistration())
		}
		if _, e := w.Exec(ctx, `INSERT INTO identity.registration_bindings(tenant_id,purpose,command_id,user_id,identifier_id,credential_id,accepted_only) VALUES($1,$2,$3,NULL,NULL,NULL,true)`, string(b.TenantID), b.OperationID, id); e != nil {
			return identity.User{}, e
		}
		w.state.registrationAccepted = true
		// Selection is kernel-owned and was declared before reservation. Keep
		// the original frozen plan intact; only this Work's actual event changes.
		w.state.lifecycle.plan.EventType = signupAcceptedEvent
		return identity.User{}, nil
	}
	user, err := d.repository.insertCreation(ctx, w, creation)
	if err != nil {
		return identity.User{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version) VALUES($1,$2,$3,$4,$5,$6,false,false,1,1,1)`, string(b.TenantID), string(user.ID), string(i.ID), string(i.Kind), i.CanonicalValue, i.DisplayValue); err != nil {
		return identity.User{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,1,'identity/password',1,true)`, string(b.TenantID), string(user.ID), string(intent.Credential.ID)); err != nil {
		return identity.User{}, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return fail(invalidPasswordRegistration())
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.registration_bindings(tenant_id,purpose,command_id,user_id,identifier_id,credential_id) VALUES($1,$2,$3,$4,$5,$6)`, string(b.TenantID), b.OperationID, id, string(user.ID), string(i.ID), string(intent.Credential.ID)); err != nil {
		return identity.User{}, err
	}
	w.state.registrationUser = &user
	return user, nil
}

func requireAbsentRegistrationUser(ctx context.Context, w Work, user identity.UserID) error {
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE tenant_id=$1 AND user_id=$2)`, string(w.state.binding.TenantID), string(user))
	if err != nil {
		return err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if exists {
		return w.fail(ctx, identity.ConflictError{})
	}
	return nil
}

func recoverPasswordRegistration(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return RecoveryUnknown, invalidPasswordRegistration()
	}
	// A historical creation-only plan cannot mistake a neutral binding for an
	// account creation. The original columns exist even before the optional
	// forward migration, so legacy recovery retains its old storage dependency.
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3 AND ($4 OR user_id IS NOT NULL))`, string(b.TenantID), b.OperationID, id, w.state.plan.signupAcceptance)
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
