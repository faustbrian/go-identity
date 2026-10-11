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

// MagicLinkRegistrationIntent is a prospective passwordless account creation.
// Identifier must be an initially unverified non-primary email. Its eventual
// verification requires original capability consumption and explicit mailbox
// policy, not the caller's Verified flag. No password credential is created.
type MagicLinkRegistrationIntent struct {
	Creation                     identity.CreateUserCommand
	Identifier                   identity.Identifier
	ComparisonProfile            string
	EmailPossessionPolicyVersion uint64
}

// MagicLinkRegistrationFields freezes kernel-owned creation inputs into the
// native consuming command. It does not normalize, prove possession or authorize
// registration. Returned byte fields are independently owned.
func MagicLinkRegistrationFields(s MagicLinkRegistrationIntent) ([]identity.FeatureField, error) {
	command, err := identity.NewUserCreationCommand(s.Creation)
	if err != nil {
		return nil, invalidMagicLinkRegistration()
	}
	creation, _ := command.CreateUser()
	b := creation.Binding
	i := s.Identifier
	if i.Validate(b.UserID) != nil || i.Kind != identity.IdentifierEmail || i.Version != 1 || i.Verified || i.Primary || s.EmailPossessionPolicyVersion == 0 {
		return nil, invalidMagicLinkRegistration()
	}
	if _, err := identity.ParseIdentifierID(s.ComparisonProfile); err != nil {
		return nil, invalidMagicLinkRegistration()
	}
	attributes := make(map[string][]byte, len(creation.Attributes))
	for _, a := range creation.Attributes {
		encoded, err := encodeAttribute(a.Value)
		if err != nil {
			return nil, invalidMagicLinkRegistration()
		}
		attributes[a.Name] = encoded
	}
	h := sha256.New()
	_, _ = h.Write([]byte("identity-magic-link-registration-attributes-v1\x00"))
	_, _ = h.Write(cborMap(attributes))
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "registration." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	number := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "registration." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{text("user", string(b.UserID)), text("schema", b.SchemaID), number("schema-version", uint64(b.SchemaVersion)), {Name: "registration.attributes", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: h.Sum(nil)}}, text("identifier", string(i.ID)), text("kind", string(i.Kind)), text("canonical", i.CanonicalValue), text("display", i.DisplayValue), text("comparison", s.ComparisonProfile), number("email-policy-version", s.EmailPossessionPolicyVersion)}, nil
}

// MagicLinkRegistrationDigest commits the complete kernel-owned field set.
// It is structural binding, not authentication or a keyed command fingerprint.
func MagicLinkRegistrationDigest(s MagicLinkRegistrationIntent) ([32]byte, error) {
	fields, err := MagicLinkRegistrationFields(s)
	if err != nil {
		return [32]byte{}, err
	}
	encoded := make(map[string][]byte, len(fields))
	for _, field := range fields {
		encoded[field.Name], err = encodeFeatureValue(field.Value)
		if err != nil {
			return [32]byte{}, invalidMagicLinkRegistration()
		}
	}
	return sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-magic-link-registration-intent-v1"), "fields": cborMap(encoded)})), nil
}

func invalidMagicLinkRegistration() error {
	return identity.InvalidInputError{Field: "magiclink_registration"}
}

func validateMagicLinkRegistrationIntent(command identity.Command, plan *MagicLinkRegistrationPlan, intent MagicLinkRegistrationIntent) error {
	s, ok := command.Feature()
	if !ok || s.Operation != magicLinkConsumeOperation() || plan == nil || intent.EmailPossessionPolicyVersion != plan.EmailPossessionPolicyVersion || intent.Creation.Binding.UserID != plan.UserID || string(intent.Identifier.ID) != plan.IdentifierID {
		return invalidMagicLinkRegistration()
	}
	digest, err := MagicLinkRegistrationDigest(intent)
	if err != nil || digest != plan.CreationDigest {
		return invalidMagicLinkRegistration()
	}
	expected := s.Binding
	expected.OperationID, expected.AnonymousFlowID, expected.UserID = "identity.user.create", "", plan.UserID
	expected.SchemaID, expected.SchemaVersion = intent.Creation.Binding.SchemaID, intent.Creation.Binding.SchemaVersion
	if intent.Creation.Binding != expected {
		return invalidMagicLinkRegistration()
	}
	fields, _ := MagicLinkRegistrationFields(intent)
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
			if ea != nil || ev != nil || actual.Value.Kind != wanted.Value.Kind || !bytes.Equal(a, v) {
				return invalidMagicLinkRegistration()
			}
			found = true
			matched++
			break
		}
		if !found {
			return invalidMagicLinkRegistration()
		}
	}
	if matched != len(fields) {
		return invalidMagicLinkRegistration()
	}
	return nil
}

func (MagicLinkRegistrationIntent) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.MagicLinkRegistrationIntent(redacted)")
}
func (MagicLinkRegistrationIntent) MarshalJSON() ([]byte, error) {
	return nil, invalidMagicLinkRegistration()
}

// MagicLinkRegistrationContributor is the native consuming owner of a prepared
// prospective creation. The pure bounded mapping must retain original grant,
// browser, mailbox-policy and prospective identity custody without retargeting.
// Current policy, risk, factor and session checks remain its protected phases.
// Implementing this interface alone grants no invocation or SQL authority.
type MagicLinkRegistrationContributor interface {
	MagicLinkConsumptionContributor
	MagicLinkRegistration(identity.Command) (MagicLinkRegistrationIntent, error)
}

// MagicLinkRegistrationDomainConfig selects retained identifier retirement keys
// and explicit mailbox-possession policy version. These are server composition,
// never values chosen by an unauthenticated request. Construction copies keys.
type MagicLinkRegistrationDomainConfig struct {
	ComparisonProfile            string
	EmailPossessionPolicyVersion uint64
	CurrentIdentifierKeyVersion  uint32
	RetainedIdentifierKeys       map[uint32][32]byte
}

// MagicLinkRegistrationDomain borrows the enlisted kernel repository. It owns
// neither a transaction nor a retry/goroutine. Native registration requires
// exact consuming, creation, lifecycle and recovery contributor composition.
// Immutable configuration permits concurrent calls with separate owned Work.
type MagicLinkRegistrationDomain struct {
	repository  *Repository
	comparison  string
	emailPolicy uint64
	reuse       identifierMutationPolicy
}

func (MagicLinkRegistrationDomainConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.MagicLinkRegistrationDomainConfig(redacted)")
}
func (MagicLinkRegistrationDomainConfig) MarshalJSON() ([]byte, error) {
	return nil, invalidMagicLinkRegistration()
}
func (MagicLinkRegistrationDomain) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.MagicLinkRegistrationDomain(redacted)")
}
func (MagicLinkRegistrationDomain) MarshalJSON() ([]byte, error) {
	return nil, invalidMagicLinkRegistration()
}

// NewMagicLinkRegistrationDomain performs bounded structural validation without
// IO or policy callbacks. Install identifier/registration histories and the
// MagicLinkRegistrationMigrationSource first. This does not enable signup.
func NewMagicLinkRegistrationDomain(r *Repository, c MagicLinkRegistrationDomainConfig) (*MagicLinkRegistrationDomain, error) {
	if c.EmailPossessionPolicyVersion == 0 {
		return nil, invalidMagicLinkRegistration()
	}
	shared, err := NewPasswordRegistrationDomain(r, PasswordRegistrationDomainConfig{ComparisonProfile: c.ComparisonProfile, CurrentIdentifierKeyVersion: c.CurrentIdentifierKeyVersion, RetainedIdentifierKeys: c.RetainedIdentifierKeys})
	if err != nil {
		return nil, invalidMagicLinkRegistration()
	}
	return &MagicLinkRegistrationDomain{repository: r, comparison: shared.comparison, emailPolicy: c.EmailPossessionPolicyVersion, reuse: shared.reuse}, nil
}

// Apply creates a genuinely passwordless user and verified email only during
// the exact registered native Apply, after provisional original capability
// consumption in this Work. The frozen prospective IDs, policy and complete
// kernel field set must match. Existing/retired ownership conflicts deny rather
// than retarget. All writes and command-linked recovery evidence share the sole
// transaction. The returned user is provisional; audit, outbox, factors, session
// and final proof consumption must still commit together. Failure poisons Work.
func (d *MagicLinkRegistrationDomain) Apply(ctx context.Context, w Work, p MagicLinkRegistrationContributor, command identity.Command) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil || p == nil {
		return fail(invalidMagicLinkRegistration())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.User{}, err
	}
	consumed, err := w.MagicLinkConsumption(p)
	if err != nil || p.Descriptor() != (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || w.state.registrationUser != nil || w.state.registrationAccepted || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil {
		return fail(invalidMagicLinkRegistration())
	}
	plan := w.state.execution.reservation.plan.magicLinkRegistration
	if plan == nil {
		return fail(invalidMagicLinkRegistration())
	}
	intent, err := p.MagicLinkRegistration(command)
	if err != nil || intent.ComparisonProfile != d.comparison || intent.EmailPossessionPolicyVersion != d.emailPolicy || intent.EmailPossessionPolicyVersion != plan.EmailPossessionPolicyVersion || intent.Creation.Binding.UserID != plan.UserID || string(intent.Identifier.ID) != plan.IdentifierID {
		return fail(invalidMagicLinkRegistration())
	}
	if err := validateMagicLinkRegistrationIntent(command, plan, intent); err != nil {
		return fail(err)
	}
	b := consumed.Command
	enlisted := false
	for _, entry := range w.state.execution.reservation.plan.contributors {
		if entry.descriptor.Owner == "identity/postgres" && entry.contributor == d.repository {
			enlisted = true
		}
	}
	if !enlisted {
		return fail(invalidWork())
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return identity.User{}, err
	}
	i := intent.Identifier
	blocked, err := classifyIdentifierReuse(ctx, w, identity.IdentifierChange{Action: identity.IdentifierAttach, TenantID: b.TenantID, UserID: plan.UserID, ID: i.ID, Kind: i.Kind, CanonicalValue: i.CanonicalValue}, d.reuse, now, false)
	if err != nil {
		return identity.User{}, err
	}
	if blocked {
		return fail(identity.ConflictError{})
	}
	creationCommand, _ := identity.NewUserCreationCommand(intent.Creation)
	creation, _ := creationCommand.CreateUser()
	user, err := d.repository.insertCreation(ctx, w, creation)
	if err != nil {
		return identity.User{}, err
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,display_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES($1,$2,$3,'email',$4,$5,true,false,1,2,1,$6)`, string(b.TenantID), string(user.ID), string(i.ID), i.CanonicalValue, i.DisplayValue, now); err != nil {
		return identity.User{}, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return fail(invalidMagicLinkRegistration())
	}
	if _, err := w.Exec(ctx, `INSERT INTO identity.registration_bindings(tenant_id,purpose,command_id,user_id,identifier_id,credential_id,accepted_only) VALUES($1,$2,$3,$4,$5,NULL,false)`, string(b.TenantID), b.OperationID, id, string(user.ID), string(i.ID)); err != nil {
		return identity.User{}, err
	}
	w.state.registrationUser = &user
	return user, nil
}

// Recipient reads the newly created verified email inside the same native
// consuming invocation. It cannot select a pre-existing or retargeted account,
// grant proof authority or renew original capability/session expiry.
func (d *MagicLinkRegistrationDomain) Recipient(ctx context.Context, w Work, p MagicLinkRegistrationContributor, command identity.Command) (RecipientRecord, error) {
	if err := w.usable(); err != nil {
		return RecipientRecord{}, err
	}
	fail := func(err error) (RecipientRecord, error) { return RecipientRecord{}, w.fail(w.state.ctx, err) }
	if ctx == nil || d == nil || d.repository == nil || p == nil {
		return fail(invalidMagicLinkRegistration())
	}
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return RecipientRecord{}, err
	}
	consumed, err := w.MagicLinkConsumption(p)
	if err != nil {
		return fail(err)
	}
	plan := w.state.execution.reservation.plan.magicLinkRegistration
	if plan == nil || w.state.registrationUser == nil || w.state.registrationUser.ID != plan.UserID {
		return fail(invalidMagicLinkRegistration())
	}
	intent, err := p.MagicLinkRegistration(command)
	if err != nil || intent.ComparisonProfile != d.comparison || intent.EmailPossessionPolicyVersion != d.emailPolicy || validateMagicLinkRegistrationIntent(command, plan, intent) != nil {
		return fail(invalidMagicLinkRegistration())
	}
	// Preserve the original anonymous selection scope; the actual row is
	// separately constrained to the account created by this Work below.
	q := RecipientQuery{TenantID: consumed.Command.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: intent.Identifier.CanonicalValue, Eligibility: RecipientVerified}
	rows, err := w.Query(ctx, recipientSelect+" FOR SHARE OF i", string(q.TenantID), string(q.Kind), q.CanonicalValue)
	if err != nil {
		return RecipientRecord{}, err
	}
	defer rows.Close()
	record, err := readRecipient(q, rows)
	if err != nil {
		return fail(err)
	}
	if record.Suppressed || record.User != *w.state.registrationUser || string(record.Identifier.ID) != plan.IdentifierID {
		return fail(invalidMagicLinkRegistration())
	}
	return record, nil
}

// Exact original-command linkage, never a current user's existence, determines
// recovery. Any contradictory binding remains unknown, not negative evidence.
func recoverMagicLinkRegistration(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	p := w.state.plan.magicLinkRegistration
	if p == nil || b.OperationID != "identity.magic-link.consume" {
		return RecoveryUnknown, invalidMagicLinkRegistration()
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return RecoveryUnknown, invalidMagicLinkRegistration()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3),EXISTS(SELECT 1 FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3 AND user_id=$4 AND identifier_id=$5 AND credential_id IS NULL AND NOT accepted_only)`, string(b.TenantID), b.OperationID, id, string(p.UserID), p.IdentifierID)
	if err != nil {
		return RecoveryUnknown, err
	}
	defer rows.Close()
	var exists, matches bool
	if !rows.Next() || rows.Scan(&exists, &matches) != nil || rows.Next() || rows.Err() != nil {
		return RecoveryUnknown, identity.UnavailableError{}
	}
	if matches {
		return RecoveryCommitted, nil
	}
	if exists {
		return RecoveryUnknown, nil
	}
	return RecoveryNotCommitted, nil
}
