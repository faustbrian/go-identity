package passwordpostgres

import (
	"bytes"
	"context"
	"net/url"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

// ReadManagedVerification authenticates a delivered management proof and its
// original committed encrypted request. caller describes actual current query
// authority for the signed user and exact confirmation action, not the original
// human actor. No live original session, cookie or password is required.
//
// This trusted native seam returns sensitive original intent, not a public
// inspection response or current authority. Do not log/disclose the projection.
// The retained replay version is original issuer custody, not its active key.
// Historical provenance can outlive consumption; it grants no remaining use.
// Scanner validation must additionally validate current issued state and account,
// identifier/factor/policy authority. Explicit confirmation rechecks those owners
// and atomically consumes through the sole coordinator transaction.
//
// Nothing is renewed, generated, reserved, sent or consumed. Temporary encrypted
// copies and decrypted checkpoint buffers are owned/cleared by this call.
// The pool/proof are borrowed; immutable composition supports concurrent reads.
// MaximumDuration and earlier cancellation bound IO. Errors are redacted and
// return zero intent/version; caller cancellation is preserved.
func (s *EmailManagementService) ReadManagedVerification(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext) (spec email.ManagedVerificationSpec, replayVersion uint32, err error) {
	return s.readManagedVerification(ctx, proof, caller, nil)
}

type managedEmailOriginAdmission struct {
	FactorVersion, UserVersion, IdentifierVersion uint64
	Directory                                     kernel.DirectoryAuthorityAdmission
	Credential                                    kernel.CredentialAdmission
	Authorization                                 kernel.UserAuthorizationAdmission
}

func (s *EmailManagementService) readManagedVerification(ctx context.Context, proof capability.Proof, caller authorization.DecisionContext, originalAdmission *managedEmailOriginAdmission) (spec email.ManagedVerificationSpec, replayVersion uint32, err error) {
	if originalAdmission != nil {
		*originalAdmission = managedEmailOriginAdmission{}
	}
	if ctx == nil || s == nil || s.primary == nil || s.primary.source == nil || s.config == nil || s.crypto == nil {
		return spec, 0, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			spec, replayVersion = email.ManagedVerificationSpec{}, 0
			if originalAdmission != nil {
				*originalAdmission = managedEmailOriginAdmission{}
			}
		}
	}()
	if ctx.Err() != nil {
		return spec, 0, ctx.Err()
	}
	grant, command, version, err := s.issuer.ReadIssuanceOrigin(ctx, s.primary.source.pool, proof, "identity.identifier.verify")
	if err != nil {
		return spec, 0, err
	}
	g := grant.Payload()
	if g.Caveats["email.profile"] != "management-v1" {
		return spec, 0, identity.ForbiddenError{}
	}
	p := &emailManagementPhase{service: s}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return spec, 0, password.ErrPasswordWork
	}
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: emailPrimaryOperation(s.primary.config.Action)}
	q := identity.RecoveryQuery{CommandID: command, TenantID: identity.TenantID(g.Tenant), UserID: identity.UserID(g.Subject), RecordID: g.Resource, ActorID: identity.ActorID(caller.Request.Subject.ID), ActorKind: caller.Request.Subject.Kind, OperationID: g.Caveats["email.confirm_operation"]}
	binding, wire, generation, err := coordinator.QueryManagedEmailPreparation(ctx, q, caller, feature, p)
	defer clear(wire)
	if err != nil {
		return spec, 0, err
	}
	stored, err := s.readOutput(ctx, binding, generation, wire)
	defer clear(stored.IssuanceWire)
	defer clear(stored.DeliveryWire)
	if err != nil {
		return spec, 0, readerFailure(ctx)
	}
	spec, err = s.managedVerificationIntent(stored)
	if err != nil {
		return spec, 0, err
	}
	if s.policy.Authorize(grant, spec, s.primary.source.c.Coordinator.QueryPolicy.Clock.Now()) != nil {
		return spec, 0, identity.ForbiddenError{}
	}
	if originalAdmission != nil {
		var fields []identity.FeatureField
		for _, f := range stored.Spec.Fields {
			if strings.HasPrefix(f.Name, "source-session.") {
				fields = append(fields, f)
			}
			if f.Name == "email.management.factor-version" {
				originalAdmission.FactorVersion = f.Value.Uint64
			}
			if f.Name == "email-attachment.user-version" {
				originalAdmission.UserVersion = f.Value.Uint64
			}
			if f.Name == "email-attachment.authority-version" {
				originalAdmission.IdentifierVersion = f.Value.Uint64
			}
		}
		original, sessionErr := sessionpg.OriginalSessionFromFields(spec.Binding.TenantID, spec.Binding.UserID, fields)
		if sessionErr != nil {
			return spec, 0, password.ErrPasswordWork
		}
		dir, credential, auth, admissionErr := sessionpg.OriginalSessionAdmission(s.primary.source.c.Profile, original, spec.Binding)
		if admissionErr != nil || originalAdmission.UserVersion == 0 || originalAdmission.UserVersion == ^uint64(0) || originalAdmission.IdentifierVersion == 0 || originalAdmission.IdentifierVersion == ^uint64(0) || credential.IdentifierAuthorityVersion != originalAdmission.IdentifierVersion {
			return spec, 0, password.ErrPasswordWork
		}
		// The original request performed exactly one pending attachment. Do not
		// substitute today's epochs: unrelated changes invalidate this intent.
		credential.IdentifierAuthorityVersion++
		originalAdmission.Directory, originalAdmission.Credential, originalAdmission.Authorization = dir, credential, auth
	}
	return spec, version, nil
}

func (s *EmailManagementService) managedVerificationIntent(stored emailManagementOutput) (email.ManagedVerificationSpec, error) {
	b := stored.Spec.Binding
	values := make(map[string]identity.FeatureValue, len(stored.Spec.Fields))
	var sessionFields []identity.FeatureField
	for _, f := range stored.Spec.Fields {
		values[f.Name] = f.Value
		if strings.HasPrefix(f.Name, "source-session.") {
			sessionFields = append(sessionFields, f)
		}
	}
	original, err := sessionpg.OriginalSessionFromFields(b.TenantID, b.UserID, sessionFields)
	if err != nil {
		return email.ManagedVerificationSpec{}, password.ErrPasswordWork
	}
	session, err := original.Bindings()
	if err != nil {
		return email.ManagedVerificationSpec{}, password.ErrPasswordWork
	}
	canonical := values["email-attachment.canonical-address"]
	callback := values["email.management.callback"]
	profile := values["email.management.profile"]
	factor := values["email.management.factor-version"]
	identifierVersion, verificationVersion := uint64(1), uint64(1)
	if stored.Spec.Operation == managedResendOperation() {
		i, v := values["email-attachment.identifier-version"], values["email-attachment.verification-version"]
		if i.Kind != identity.FeatureUint64 || v.Kind != identity.FeatureUint64 || i.Uint64 == 0 || i.Uint64 == ^uint64(0) || i.Uint64 != v.Uint64 {
			return email.ManagedVerificationSpec{}, password.ErrPasswordWork
		}
		identifierVersion, verificationVersion = i.Uint64+1, v.Uint64+1
	}
	if canonical.Kind != identity.FeatureText || callback.Kind != identity.FeatureText || profile.Kind != identity.FeatureBytes || !bytes.Equal(profile.Bytes, s.profile[:]) || factor.Kind != identity.FeatureUint64 || factor.Uint64 == 0 || stored.TokenGeneration != verificationVersion || stored.ExpiresAt.Sub(stored.IssuedAt) != s.config().Lifetime {
		return email.ManagedVerificationSpec{}, password.ErrPasswordWork
	}
	address, err := s.address.Parse(email.AddressInput(canonical.Text))
	if err != nil || address.Canonical().Record().Value != canonical.Text {
		return email.ManagedVerificationSpec{}, password.ErrPasswordWork
	}
	redirect, err := url.Parse(callback.Text)
	if err != nil {
		return email.ManagedVerificationSpec{}, password.ErrPasswordWork
	}
	spec := email.ManagedVerificationSpec{Binding: b, IdentifierID: identity.IdentifierID(b.RecordID), IdentifierVersion: identifierVersion, VerificationVersion: verificationVersion, Payload: email.CapabilityPayload{TenantID: b.TenantID, SubjectID: identity.SubjectID(b.UserID), CanonicalAddress: address.Canonical(), Purpose: "identity.identifier.verify", Redirect: *redirect, Version: stored.TokenGeneration}, IssuedAt: stored.IssuedAt, ExpiresAt: stored.ExpiresAt, SessionID: session.SessionID, SessionVersion: session.Version}
	if b.OperationID == "identity.email.change-request" {
		id, mailbox := values["email-attachment.previous-id"], values["email-attachment.previous-address"]
		i, v := values["email-attachment.previous-identifier-version"], values["email-attachment.previous-verification-version"]
		primary, initial := values["email-attachment.previous-primary"], values["email-attachment.allow-initial-primary"]
		if s.config().Change == nil || id.Kind != identity.FeatureText || mailbox.Kind != identity.FeatureText || i.Kind != identity.FeatureUint64 || v.Kind != identity.FeatureUint64 || primary.Kind != identity.FeatureBool || initial.Kind != identity.FeatureBool || initial.Bool != (s.config().Change.CurrentAddress == email.PrimaryOrSoleVerifiedAddress) {
			return email.ManagedVerificationSpec{}, password.ErrPasswordWork
		}
		spec.Previous = email.PreviousAddress{ID: identity.IdentifierID(id.Text), CanonicalAddress: mailbox.Text, IdentifierVersion: i.Uint64, VerificationVersion: v.Uint64, Primary: primary.Bool}
		spec.ChangeProfile = *s.config().Change
	}
	payload, err := s.payload(spec)
	if err != nil {
		return email.ManagedVerificationSpec{}, password.ErrPasswordWork
	}
	if s.config().ResendInterval != 0 {
		family, err := issuerpg.ManagedEmailScopeFromPayload(payload)
		digest := family.Digest()
		f := values["email.management.family"]
		if err != nil || f.Kind != identity.FeatureBytes || !bytes.Equal(f.Bytes, digest[:]) {
			return email.ManagedVerificationSpec{}, password.ErrPasswordWork
		}
	}
	return spec, nil
}
