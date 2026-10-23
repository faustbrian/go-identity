package passwordpostgres

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// ActionPrimaryConfig selects username update, phone enrollment/change/removal, or
// organization ownership transfer/archive/restore, anonymous upgrade or passkey
// enrollment and its
// signed-proof audience. For upgrade, the original bearer/proof belongs to the
// permanent target; the anonymous owner separately proves guest possession.
// MaximumAge is positive and at most
// fifteen minutes. Transport explicitly selects bearer or cookie; cookies need
// retained CSRF keys. The source's exact issuance target must already be allowed.
// This selected profile supports original single-factor password sessions only.
type ActionPrimaryConfig struct {
	Action, Audience string
	MaximumAge       time.Duration
	Transport        session.CredentialKind
	CSRFKeys         []session.CSRFKey
}

// ActionPrimaryRequest preserves the native public name for the adapter-neutral
// original-custody input. The selected native source still owns all validation,
// admission, consumption and final checks; the carrier grants no authority.
type ActionPrimaryRequest = password.ActionPrimaryRequest

// ActionPrimarySource composes the existing password proof/session owners for
// closed native operation profiles. It owns no transaction, cache, retry,
// journal or goroutine. Its borrowed pool must outlive all concurrent calls.
type ActionPrimarySource struct{ primary *EmailPrimarySource }

// ActionPrimaryAdmission is immutable opaque original custody, not permission.
// The protected native owner must Admit, atomically Consume and finally Check
// within the sole coordinator Work, alongside current factor/risk/domain policy.
// For distinct subjects, acquire actor/target locks in canonical order first.
// Zero denies. Copies share immutable custody and cannot renew freshness.
type ActionPrimaryAdmission struct{ primary EmailPrimaryAdmission }

// Replacement sends retain the same signed action and proof owner, but have
// no identifier-attachment effect. Freeze that one native schema without an
// arbitrary schema override or mutating a shared enrollment source.
func phoneChangeSendPrimary(source *ActionPrimarySource) (*ActionPrimarySource, error) {
	if source == nil || source.primary == nil || source.primary.phoneChangeSend ||
		!source.Matches("identity.phone.send-verification", source.primary.config.Audience) {
		return nil, password.ErrPasswordWork
	}
	selected := *source.primary
	selected.phoneChangeSend = true
	return &ActionPrimarySource{primary: &selected}, nil
}

// NewActionPrimarySource validates immutable composition without IO. It does not
// extend the public email profile or change its existing persisted framing.
func NewActionPrimarySource(source *ReauthenticationService, c ActionPrimaryConfig) (*ActionPrimarySource, error) {
	if actionPrimaryOperation(c.Action).Owner == "" {
		return nil, password.ErrPasswordWork
	}
	p, err := newPrimarySource(source, nil, EmailPrimaryConfig{Action: c.Action, Audience: c.Audience, MaximumAge: c.MaximumAge, Transport: c.Transport, CSRFKeys: c.CSRFKeys, AdministrativeTargets: c.Action == "identity.organization.owner-transfer"}, true)
	if err != nil {
		return nil, err
	}
	return &ActionPrimarySource{primary: p}, nil
}

// Matches reports startup selection only; it performs no IO or authorization.
func (s *ActionPrimarySource) Matches(action, audience string) bool {
	return s != nil && s.primary != nil && s.primary.action && s.primary.config.Action == action && s.primary.config.Audience == audience && actionPrimaryOperation(action).Owner != ""
}

func actionPrimaryOperation(action string) identity.FeatureOperation {
	switch action {
	case "identity.anonymous.upgrade":
		return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	case "identity.username.update":
		return identity.FeatureOperation{Owner: "identity/username", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	case "identity.phone.send-verification", "identity.phone.update", "identity.phone.remove":
		return identity.FeatureOperation{Owner: "identity/phone", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	case "identity.passkey.register-options", "identity.passkey.register-verify":
		return identity.FeatureOperation{Owner: "passkey", OperationID: action, SchemaID: action + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	case "identity.organization.owner-transfer":
		return identity.FeatureOperation{Owner: "organization", OperationID: action, SchemaID: "organization-membership", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	case "identity.organization.archive", "identity.organization.restore":
		return identity.FeatureOperation{Owner: "organization", OperationID: action, SchemaID: "organization-lifecycle", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	default:
		return identity.FeatureOperation{}
	}
}

func actionPrimaryDescriptor(action string) kernel.ContributorDescriptor {
	switch action {
	case "identity.anonymous.upgrade":
		return kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
	case "identity.username.update":
		return kernel.ContributorDescriptor{Owner: "identity/username/postgres", ContractID: "identity.username", Version: 1}
	case "identity.phone.send-verification", "identity.phone.update", "identity.phone.remove":
		return kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}
	case "identity.passkey.register-options", "identity.passkey.register-verify":
		return kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
	case "identity.organization.owner-transfer", "identity.organization.archive", "identity.organization.restore":
		return kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}
	default:
		return kernel.ContributorDescriptor{}
	}
}

func (s *ActionPrimarySource) request(r ActionPrimaryRequest) (EmailPrimaryRequest, error) {
	if s == nil || s.primary == nil || !s.primary.action || actionPrimaryOperation(s.primary.config.Action).Owner == "" {
		return EmailPrimaryRequest{}, password.ErrPasswordWork
	}
	if s.primary.config.Action == "identity.organization.owner-transfer" && r.TargetSubjectID == "" || s.primary.config.Action != "identity.organization.owner-transfer" && r.TargetSubjectID != "" {
		return EmailPrimaryRequest{}, identity.ForbiddenError{}
	}
	return EmailPrimaryRequest{TenantID: r.TenantID, TargetSubjectID: r.TargetSubjectID, CommandID: r.CommandID, AddressID: identity.IdentifierID(r.RecordID), Session: r.Session, Proof: r.Proof, Caller: r.Caller, CSRFToken: r.CSRFToken}, nil
}

// Prepare authenticates the original session and exact committed signed proof.
// It neither consumes that proof nor grants workflow permission. The command's
// safe fields retain original provenance for an immutable native contributor.
func (s *ActionPrimarySource) Prepare(ctx context.Context, r ActionPrimaryRequest) (ActionPrimaryAdmission, error) {
	request, err := s.request(r)
	if err != nil {
		return ActionPrimaryAdmission{}, err
	}
	a, err := s.primary.Prepare(ctx, request)
	if err != nil {
		return ActionPrimaryAdmission{}, err
	}
	state := a.custody()
	fields, err := actionPrimaryRecordFields(state.record)
	if err != nil {
		return ActionPrimaryAdmission{}, password.ErrPasswordWork
	}
	state.fields = append(state.fields, fields...)
	return ActionPrimaryAdmission{primary: EmailPrimaryAdmission{custody: func() emailPrimaryCustody { return state }}}, nil
}

// Restore reconstructs original custody from frozen command fields and the
// existing immutable signed-record provenance. The caller must authenticate the
// original command preparation; naked fields are not permission. It does not
// perform IO, reread current sessions or check/renew freshness, so expired or consumed
// provenance can reconcile an already committed command. Protected use still
// repeats all current fences and atomic one-use checks.
func (s *ActionPrimarySource) Restore(ctx context.Context, r ActionPrimaryRequest, fields []identity.FeatureField) (ActionPrimaryAdmission, error) {
	request, err := s.request(r)
	if err != nil {
		return ActionPrimaryAdmission{}, err
	}
	if ctx == nil || len(fields) == 0 || len(fields) > 128 || !validEmailPrimaryCaller(r.Caller) {
		return ActionPrimaryAdmission{}, password.ErrPasswordWork
	}
	// Reuse the kernel's closed union and aggregate bounds before retaining
	// any caller bytes; restoration must not become an unbounded copy boundary.
	if _, err := identity.NewRequestIntent(fields); err != nil {
		return ActionPrimaryAdmission{}, password.ErrPasswordWork
	}
	for _, field := range fields {
		if strings.HasPrefix(field.Name, "password.action-primary.") && !strings.HasPrefix(field.Name, actionPrimaryRecordPrefix) {
			switch field.Name {
			case "password.action-primary.proof.digest", "password.action-primary.proof.id", "password.action-primary.maximum-age-nanos", "password.action-primary.cookie", "password.action-primary.target-subject":
			default:
				return ActionPrimaryAdmission{}, password.ErrPasswordWork
			}
		}
	}
	record, err := actionPrimaryRecord(fields)
	proof := record.Proof
	if err != nil || proof != r.Proof || proof.Action != s.primary.config.Action || proof.Proof.Purpose != "identity.password.verify" || proof.Proof.Audience != s.primary.config.Audience {
		return ActionPrimaryAdmission{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ActionPrimaryAdmission{}, identity.ForbiddenError{}
	}
	if _, err := identity.ParseIdentifierID(r.RecordID); err != nil {
		return ActionPrimaryAdmission{}, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return ActionPrimaryAdmission{}, err
	}
	wire, err := encodeReauthenticationRecord(record)
	if err != nil {
		return ActionPrimaryAdmission{}, err
	}
	defer clear(wire)
	a, err := restoreEmailPrimary(ctx, s.primary, request, fields, wire)
	if err != nil {
		return ActionPrimaryAdmission{}, err
	}
	state := a.custody()
	original, err := state.original.Bindings()
	if err != nil || proof.SessionID != original.SessionID || proof.SessionVersion != original.Version {
		return ActionPrimaryAdmission{}, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return ActionPrimaryAdmission{}, err
	}
	return ActionPrimaryAdmission{primary: a}, nil
}

// RestoreCommand adapts an authenticated original native command without a
// per-request contributor map or a second proof projection. Caller and CSRF are
// trusted original request custody; the exact command/session/actor/target and
// source-owned fields must agree. It grants no current authority.
func (s *ActionPrimarySource) RestoreCommand(ctx context.Context, command identity.Command, caller authorization.DecisionContext, csrf session.CSRFToken) (ActionPrimaryAdmission, error) {
	if s == nil || s.primary == nil {
		return ActionPrimaryAdmission{}, password.ErrPasswordWork
	}
	spec, ok := command.Feature()
	bearer, has := command.SessionToken()
	if !ok || !has || spec.Operation != s.primary.operation() || spec.Binding.ActorKind != authorization.SubjectUser || string(caller.Request.Subject.ID) != string(spec.Binding.ActorID) {
		return ActionPrimaryAdmission{}, identity.ForbiddenError{}
	}
	record, err := actionPrimaryRecord(spec.Fields)
	if err != nil {
		return ActionPrimaryAdmission{}, err
	}
	r := ActionPrimaryRequest{TenantID: spec.Binding.TenantID, CommandID: spec.Binding.CommandID, RecordID: spec.Binding.RecordID, Session: bearer, Proof: record.Proof, Caller: caller, CSRFToken: csrf}
	if s.primary.config.Action == "identity.organization.owner-transfer" {
		r.TargetSubjectID = spec.Binding.UserID
	}
	a, err := s.Restore(ctx, r, spec.Fields)
	if err != nil {
		return ActionPrimaryAdmission{}, err
	}
	if _, err = a.Command(spec.Binding, nil); err != nil {
		return ActionPrimaryAdmission{}, err
	}
	return a, nil
}

// Original returns retained original session provenance, not current authority.
func (a ActionPrimaryAdmission) Original() (session.Session, error) { return a.primary.Original() }

// Deadline is the immutable earliest proof expiry/age and session lifetime.
func (a ActionPrimaryAdmission) Deadline() (time.Time, error) { return a.primary.Deadline() }

// Command binds source-owned fields and borrowed bearer to one closed native
// action/actor/target/record. Additional fields cannot replace protected names.
func (a ActionPrimaryAdmission) Command(b identity.CommandBinding, fields []identity.FeatureField) (identity.Command, error) {
	return a.primary.Command(b, fields)
}

// Admit fences original directory, actor credential/authorization, session and
// selected CSRF in the supplied Work. The native owner must additionally check
// current target, domain, factor and risk policy, in canonical lock order.
func (a ActionPrimaryAdmission) Admit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	return a.primary.Admit(ctx, w, owner, c)
}

// Consume is Apply-only and consumes the existing password-owned one-use record
// atomically with the protected mutation. It repeats Admit and original expiry
// after the exclusive proof lock; propagate every error and finally call Check.
func (a ActionPrimaryAdmission) Consume(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	return a.primary.Consume(ctx, w, owner, c)
}

// Check uses database time to enforce original proof/session limits, including
// the final precommit callback. It cannot renew freshness or authorize itself.
func (a ActionPrimaryAdmission) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command) error {
	return a.primary.Check(ctx, w, owner, c)
}

// Recover reads only the original password-owned consumer marker, never current
// authority or time. It returns no proof or bearer. The native owner must combine
// this result with its own domain/effect evidence; it is not a command receipt.
func (s *ActionPrimarySource) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || s == nil || s.primary == nil || s.primary.source == nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || f.Contributor != s.primary.descriptor() || f.Operation != s.primary.operation() || b.ActorKind != authorization.SubjectUser || b.ActorID == "" {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	rows, err := w.Query(ctx, `SELECT proof_id,consumed_purpose,CASE WHEN octet_length(record)<=$4 THEN record ELSE ''::bytea END FROM identity_password.reauthentication_records WHERE tenant_id=$1 AND user_id=$2 AND consumed_command_id=$3`, string(b.TenantID), string(b.ActorID), id, maximumReauthenticationRecordBytes)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return kernel.RecoveryUnknown, err
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var proofID, purpose string
	var wire []byte
	if rows.Scan(&proofID, &purpose, &wire) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, password.ErrPasswordWork
	}
	record, err := decodeReauthenticationRecord(auth.ProofID(proofID), string(b.TenantID), string(b.ActorID), wire)
	if err != nil || purpose != b.OperationID || record.Proof.Action != b.OperationID || record.Proof.Proof.Purpose != "identity.password.verify" || record.Proof.Proof.Audience != s.primary.config.Audience || record.Issuer != s.primary.source.c.Issuer || record.Environment != s.primary.source.c.Environment {
		return kernel.RecoveryUnknown, nil
	}
	frame, err := record.SigningBytes()
	defer clear(frame)
	key := s.primary.source.c.VerificationKeys[record.KeyID]
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, frame, record.Signature) {
		return kernel.RecoveryUnknown, nil
	}
	return kernel.RecoveryCommitted, nil
}

// Format redacts borrowed owners and startup policy.
func (ActionPrimarySource) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ActionPrimarySource(redacted)")
}

// MarshalJSON rejects implicit source export.
func (ActionPrimarySource) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText rejects implicit source export.
func (ActionPrimarySource) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }

// Format redacts original retained custody.
func (ActionPrimaryAdmission) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.ActionPrimaryAdmission(redacted)")
}

// MarshalJSON rejects implicit admission export.
func (ActionPrimaryAdmission) MarshalJSON() ([]byte, error) { return nil, password.ErrPasswordWork }

// MarshalText rejects implicit admission export.
func (ActionPrimaryAdmission) MarshalText() ([]byte, error) { return nil, password.ErrPasswordWork }
