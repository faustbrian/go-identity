package anonymouspostgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func creationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.signin", SchemaID: "identity.anonymous.signin.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}
func creationOwner() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}

// CreationFields freezes the complete anonymous-owned initial lifecycle before
// command fingerprinting. Kernel/session fields remain separately owner-mapped.
// The result contains no bearer or credential and grants no current authority.
func CreationFields(subject anonymous.AnonymousSubject) ([]identity.FeatureField, error) {
	s, err := subject.Record()
	if err != nil || s.State != anonymous.StateActive || s.Version != 1 {
		return nil, anonymous.ErrInvalidInput
	}
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "anonymous.subject." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	u := func(name string, value uint64) identity.FeatureField {
		return identity.FeatureField{Name: "anonymous.subject." + name, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: value}}
	}
	return []identity.FeatureField{text("id", string(s.ID)), text("user", string(s.UserID)), {Name: "anonymous.subject.created", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: s.CreatedAt}}, {Name: "anonymous.subject.expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: s.ExpiresAt}}, u("state", uint64(s.State)), u("version", s.Version), u("cleanup", uint64(s.Cleanup))}, nil
}

// CreationSubject reconstructs only this owner's original lifecycle projection
// from the exact closed anonymous command. Missing/extra/foreign fields deny;
// independent namespaces remain their owners' responsibility. It performs no
// IO and cannot authenticate a browser, authorize creation or renew expiry.
func CreationSubject(command identity.Command) (anonymous.AnonymousSubject, error) {
	f, ok := command.Feature()
	if !ok || f.Operation != creationOperation() {
		return anonymous.AnonymousSubject{}, anonymous.ErrInvalidInput
	}
	values := make(map[string]identity.FeatureValue, 7)
	for _, field := range f.Fields {
		if name, owned := strings.CutPrefix(field.Name, "anonymous.subject."); owned {
			values[name] = field.Value
		}
	}
	if len(values) != 7 || values["id"].Kind != identity.FeatureText || values["user"].Kind != identity.FeatureText || values["created"].Kind != identity.FeatureTime || values["expires"].Kind != identity.FeatureTime || values["state"].Kind != identity.FeatureUint64 || values["state"].Uint64 != uint64(anonymous.StateActive) || values["version"].Kind != identity.FeatureUint64 || values["version"].Uint64 != 1 || values["cleanup"].Kind != identity.FeatureUint64 || values["cleanup"].Uint64 < 1 || values["cleanup"].Uint64 > 3 {
		return anonymous.AnonymousSubject{}, anonymous.ErrInvalidInput
	}
	return anonymous.NewAnonymousSubject(anonymous.SubjectSpec{ID: identity.SubjectID(values["id"].Text), TenantID: f.Binding.TenantID, UserID: identity.UserID(values["user"].Text), CreatedAt: values["created"].Time, ExpiresAt: values["expires"].Time, State: anonymous.StateActive, Version: 1, Cleanup: anonymous.CleanupPolicy(values["cleanup"].Uint64)})
}

func creationScope(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (identity.CommandBinding, anonymous.AnonymousSubject, error) {
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != creationOperation() || transition != (kernel.LifecyclePlan{EventType: "anonymous.created.v1"}) || owner.Descriptor() != creationOwner() {
		return identity.CommandBinding{}, anonymous.AnonymousSubject{}, anonymous.ErrInvalidInput
	}
	f, ok := command.Feature()
	if !ok || f.Binding != b || f.Operation != feature.Operation {
		return identity.CommandBinding{}, anonymous.AnonymousSubject{}, anonymous.ErrInvalidInput
	}
	s, err := CreationSubject(command)
	return b, s, err
}

// StageCreation writes only anonymous metadata after actual kernel creation in
// the exact native participant's original Work. Risk and session effects remain
// required owner phases. No independent transaction or identity/session writes
// occur here. Every error must abort Work; success is provisional, not issuance.
func (r *Repository) StageCreation(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || r == nil || r.pool == nil || r.maximum <= 0 {
		return anonymous.ErrInvalidInput
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, subject, err := creationScope(w, owner, command)
	if err != nil {
		return err
	}
	s, _ := subject.Record()
	user, placeholder, err := w.AnonymousCreation(owner)
	if err != nil || user.ID != s.UserID || user.TenantID != s.TenantID {
		return identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	if err := w.RequireAnonymousAuthority(bounded, owner, kernel.AnonymousAuthorityRecord{User: user, Placeholder: placeholder, UserAuthorityVersion: 1, IdentifierAuthorityVersion: 1, CredentialAuthorityVersion: 1}); err != nil {
		return err
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	if err := subject.RequireActive(b.TenantID, now); err != nil {
		return err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return anonymous.ErrInvalidInput
	}
	n, err := w.Exec(bounded, `INSERT INTO `+r.schema+`.subjects(tenant_id,user_id,subject_id,created_at,expires_at,state,version,cleanup,creation_command_id) VALUES($1,$2,$3,$4,$5,$6,1,$7,$8)`, string(s.TenantID), string(s.UserID), string(s.ID), s.CreatedAt, s.ExpiresAt, int16(s.State), int16(s.Cleanup), id)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// RequireCreation repeats exact original lifecycle and expiry under share lock
// in the same owner's final read-only invocation. It neither writes nor renews
// time. Caller must also repeat kernel/session/current-policy admission.
func (r *Repository) RequireCreation(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || r == nil || r.pool == nil || r.maximum <= 0 {
		return anonymous.ErrInvalidInput
	}
	b, subject, err := creationScope(w, owner, command)
	if err != nil {
		return err
	}
	s, _ := subject.Record()
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return anonymous.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := w.Query(bounded, subjectSelect(r.schema)+" WHERE tenant_id=$1 AND user_id=$2 AND creation_command_id=$3 FOR SHARE", string(s.TenantID), string(s.UserID), id)
	if err != nil {
		return err
	}
	actual, err := readSubject(rows)
	rows.Close()
	if err != nil {
		return err
	}
	got, _ := actual.Record()
	if got != s {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(bounded)
	if err != nil {
		return err
	}
	return actual.RequireActive(b.TenantID, now)
}

// RecoverCreation inspects this participant's retained original creation
// correlation only. It grants no access, restores no bearer and performs no
// mutation. Missing metadata describes this participant, never proves overall
// rollback: the existing coordinator must reconcile every enlisted owner.
func (r *Repository) RecoverCreation(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || r == nil || r.pool == nil || r.maximum <= 0 {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != creationOperation() || transition != (kernel.LifecyclePlan{EventType: "anonymous.created.v1"}) || owner.Descriptor() != creationOwner() {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return kernel.RecoveryUnknown, anonymous.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, r.maximum)
	defer stop()
	rows, err := w.Query(bounded, `SELECT user_id,subject_id,version::text FROM `+r.schema+`.subjects WHERE tenant_id=$1 AND creation_command_id=$2`, string(b.TenantID), id)
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
	var user, subject, version string
	if err := rows.Scan(&user, &subject, &version); err != nil {
		return kernel.RecoveryUnknown, err
	}
	v, err := strconv.ParseUint(version, 10, 64)
	_, valid := identity.ParseSubjectID(subject)
	if rows.Next() || rows.Err() != nil || err != nil || v == 0 || valid != nil || user != subject {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
