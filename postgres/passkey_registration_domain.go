package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// PasskeyRegistrationContributor is the trusted native signup owner. Its pure
// bounded mapping retains the exact original prospective creation. This grants
// no invocation authority; real WebAuthn verification, risk, pre-auth custody,
// authorization, MFA initialization and session effects remain its obligations.
type PasskeyRegistrationContributor interface {
	FeatureCommitContributor
	PasskeyRegistration(identity.Command) (PasskeyRegistrationIntent, error)
}

// PasskeyRegistrationDomain borrows the exact enlisted repository and sole
// coordinator Work. It has no transaction, pool, retry or goroutine of its own.
// Immutable composition supports concurrent calls with independent owned Work.
type PasskeyRegistrationDomain struct{ repository *Repository }

// NewPasskeyRegistrationDomain validates composition without IO. Install the
// credential and PasskeyRegistrationMigrationSource histories before use.
// Construction enables no public signup route or authentication authority.
func NewPasskeyRegistrationDomain(r *Repository) (*PasskeyRegistrationDomain, error) {
	if r == nil || r.pool == nil || r.read == nil {
		return nil, invalidPasskeyRegistration()
	}
	return &PasskeyRegistrationDomain{repository: r}, nil
}

func (PasskeyRegistrationDomain) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "postgres.PasskeyRegistrationDomain(redacted)")
}
func (PasskeyRegistrationDomain) MarshalJSON() ([]byte, error) {
	return nil, invalidPasskeyRegistration()
}

func validatePasskeyRegistrationIntent(command identity.Command, p *PasskeyRegistrationPlan, intent PasskeyRegistrationIntent) error {
	s, ok := command.Feature()
	if !ok || s.Operation != passkeyRegistrationOperation() || p == nil || intent.Creation.Binding.UserID != p.UserID || intent.Credential.ID != p.CredentialID {
		return invalidPasskeyRegistration()
	}
	digest, err := PasskeyRegistrationDigest(intent)
	if err != nil || digest != p.CreationDigest {
		return invalidPasskeyRegistration()
	}
	expected := s.Binding
	expected.OperationID, expected.AnonymousFlowID, expected.UserID, expected.RecordID = "identity.user.create", "", p.UserID, ""
	expected.SchemaID, expected.SchemaVersion = intent.Creation.Binding.SchemaID, intent.Creation.Binding.SchemaVersion
	if intent.Creation.Binding != expected {
		return invalidPasskeyRegistration()
	}
	fields, _ := PasskeyRegistrationFields(intent)
	matched := make(map[string]bool, len(fields))
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
			if matched[actual.Name] || ea != nil || ev != nil || actual.Value.Kind != wanted.Value.Kind || !bytes.Equal(a, v) {
				return invalidPasskeyRegistration()
			}
			matched[actual.Name], found = true, true
			break
		}
		if !found {
			return invalidPasskeyRegistration()
		}
	}
	if len(matched) != len(fields) {
		return invalidPasskeyRegistration()
	}
	return nil
}

// Apply creates only the original prospective active user, admitted attributes
// and initial passkey reference during the exact native signup Apply. Existing
// subjects, including blocked/deleted ones, conflict without resurrection. It
// creates no email, password, identifier or recovery method. Actual WebAuthn
// verification must precede this call, and protocol credential finalization,
// required authority/MFA/session effects, audit and both lifecycles must follow
// in this same Work. Returned User is provisional, not authentication or commit.
// Any live rejection poisons Work, including an ignored duplicate call.
func (d *PasskeyRegistrationDomain) Apply(ctx context.Context, w Work, p PasskeyRegistrationContributor, command identity.Command) (identity.User, error) {
	if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(ctx, err) }
	if d == nil || d.repository == nil {
		return fail(invalidPasskeyRegistration())
	}
	b, feature, lifecycle, err := w.FeatureScope(p)
	plan := w.state.execution.reservation.plan.passkeyRegistration
	if err != nil || feature.Operation != passkeyRegistrationOperation() || p.Descriptor() != (ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) || plan == nil || lifecycle.EventType != "identity.passkey.create_credential" || lifecycle.BeforeVersion != 0 || lifecycle.AfterVersion != 1 || w.state.lifecycle.record != nil || w.state.registrationUser != nil || w.state.registrationAccepted || w.state.creation != nil || w.state.profile != nil || w.state.update != nil || w.state.status != nil || w.state.identifier != nil || w.state.anonymousCreation != nil {
		return fail(invalidPasskeyRegistration())
	}
	intent, err := p.PasskeyRegistration(command)
	if err != nil || validatePasskeyRegistrationIntent(command, plan, intent) != nil {
		return fail(invalidPasskeyRegistration())
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
	creationCommand, _ := identity.NewUserCreationCommand(intent.Creation)
	creation, _ := creationCommand.CreateUser()
	user, err := d.repository.insertCreation(ctx, w, creation)
	if err != nil {
		return identity.User{}, err
	}
	// Never upsert a disabled credential or retarget a reserved reference.
	if _, err = w.Exec(ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,$3,2,'passkey',1,true)`, string(b.TenantID), string(user.ID), string(intent.Credential.ID)); err != nil {
		return identity.User{}, err
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return fail(invalidPasskeyRegistration())
	}
	if _, err = w.Exec(ctx, `INSERT INTO identity.registration_bindings(tenant_id,purpose,command_id,user_id,identifier_id,credential_id,accepted_only) VALUES($1,$2,$3,$4,NULL,$5,false)`, string(b.TenantID), b.OperationID, id, string(user.ID), string(intent.Credential.ID)); err != nil {
		return identity.User{}, err
	}
	w.state.registrationUser = &user
	return user, nil
}

// PasskeyRegistrationUser returns only this Work's actual created user to its
// exact native owner, during original Apply or final Check. It locks current
// active initial user/reference authority and original creation correlation;
// it cannot resolve a pre-existing account or grant session/proof authority.
// Changed commands, foreign invocations, premature access or changed authority
// poison live Work. The caller must not retain Work or use this as a new lease.
func (w Work) PasskeyRegistrationUser(ctx context.Context, p PasskeyRegistrationContributor, command identity.Command) (identity.User, error) {
	if err := w.usable(); err != nil {
		return identity.User{}, err
	}
	fail := func(err error) (identity.User, error) { return identity.User{}, w.fail(w.state.ctx, err) }
	if ctx == nil {
		return fail(invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || feature.Operation != passkeyRegistrationOperation() || w.state.execution == nil || w.state.execution.reservation == nil {
		return fail(invalidPasskeyRegistration())
	}
	if w.state.featureApplying {
		if err := w.RequireFeatureCommand(ctx, p, command); err != nil {
			return identity.User{}, err
		}
	} else if w.state.featureCommitCommand == nil || *w.state.featureCommitCommand != command {
		return fail(invalidWork())
	}
	plan := w.state.execution.reservation.plan.passkeyRegistration
	u := w.state.registrationUser
	if plan == nil || u == nil || u.ID != plan.UserID || u.TenantID != b.TenantID || u.Version != 1 || u.Status != identity.StatusActive || w.state.registrationAccepted {
		return fail(invalidPasskeyRegistration())
	}
	intent, err := p.PasskeyRegistration(command)
	if err != nil || validatePasskeyRegistrationIntent(command, plan, intent) != nil {
		return fail(invalidPasskeyRegistration())
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return fail(invalidPasskeyRegistration())
	}
	// This creation intent has no expiry input. A later expiry, even future,
	// would change the original reference rather than preserve its admission.
	rows, err := w.Query(ctx, `SELECT 1 FROM identity.users u JOIN identity.credential_references c USING(tenant_id,user_id) JOIN identity.registration_bindings r USING(tenant_id,user_id) WHERE u.tenant_id=$1 AND u.user_id=$2 AND u.status='active' AND u.version=1 AND u.authority_version=1 AND u.identifier_version=1 AND u.credential_version=1 AND c.credential_id=$3 AND c.kind=2 AND c.owner='passkey' AND c.version=1 AND c.enabled AND c.expires_at IS NULL AND r.purpose=$4 AND r.command_id=$5 AND r.credential_id=$3 AND r.identifier_id IS NULL AND NOT r.accepted_only FOR SHARE OF u,c,r`, string(b.TenantID), string(u.ID), string(plan.CredentialID), b.OperationID, id)
	if err != nil {
		return identity.User{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return fail(identity.ForbiddenError{})
	}
	var one int
	if err := rows.Scan(&one); err != nil {
		return fail(err)
	}
	if one != 1 || rows.Next() || rows.Err() != nil {
		return fail(identity.UnavailableError{})
	}
	return *u, nil
}

func recoverPasskeyRegistration(ctx context.Context, w RecoveryWork) (RecoveryStatus, error) {
	b, err := w.Scope()
	if err != nil {
		return RecoveryUnknown, err
	}
	p := w.state.plan.passkeyRegistration
	if p == nil || w.state.plan.feature == nil || w.state.plan.feature.Operation != passkeyRegistrationOperation() {
		return RecoveryUnknown, invalidPasskeyRegistration()
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return RecoveryUnknown, invalidPasskeyRegistration()
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3),EXISTS(SELECT 1 FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose=$2 AND command_id=$3 AND user_id=$4 AND credential_id=$5 AND identifier_id IS NULL AND NOT accepted_only)`, string(b.TenantID), b.OperationID, id, string(p.UserID), string(p.CredentialID))
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
