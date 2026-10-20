package passwordpostgres

import (
	"context"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password/v2"
)

// Called only by the native reset workflow after original issuance, current
// recovery authority, factor and risk checks. The registered participant must
// reproduce the same intent the kernel fenced. This seam neither authorizes a
// proof nor commits; required session and lifecycle effects remain in that Work.
func (r *Repository) applyResetMaterial(ctx context.Context, w kernel.Work, owner kernel.CredentialResetContributor, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || !r.configuredWriter() || owner == nil {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	i, hash, err := passwordResetMaterial(command, r.policy)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	native, err := owner.CredentialReset(command)
	if err != nil || native != i {
		return identity.FeatureReceipt{}, password.ErrPasswordWork
	}
	spec, _ := command.PasswordResetFeature()
	if spec.Operation == (identity.FeatureOperation{}) {
		spec, _ = command.PhonePasswordResetFeature()
	}
	return r.applyReplacement(ctx, w, owner, spec, i.Replacement, hash)
}

func resetOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-complete", SchemaID: "password-reset-complete", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func phonePasswordResetOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Mapping is deliberately private and structural. It supplies no contributor,
// issuance provenance or recovery authority: the reset workflow must establish
// those before lending its sole Work to the material writer.
func passwordResetMaterial(c identity.Command, policy primitive.Policy) (kernel.CredentialResetIntent, primitive.EncodedHash, error) {
	fail := func() (kernel.CredentialResetIntent, primitive.EncodedHash, error) {
		return kernel.CredentialResetIntent{}, primitive.EncodedHash{}, password.ErrPasswordWork
	}
	s, metadata := c.PasswordResetFeature()
	raw, proof, custody := c.PasswordResetCustody()
	if !metadata {
		s, metadata = c.PhonePasswordResetFeature()
		raw, proof, _, _, custody = c.PhonePasswordResetCustody()
	}
	if !metadata || !custody || proof.ValidateBounds(32, 4096) != nil || policy.Algorithm() == "" {
		return fail()
	}
	i, err := passwordResetIntent(s)
	if err != nil {
		return fail()
	}
	hash, err := issuanceHash(raw, policy)
	if err != nil {
		return fail()
	}
	return i, hash, nil
}

// Original input and generated material use exactly the same closed mapping.
// This structural projection grants no issuance, factor or mutation authority.
func passwordResetIntent(s identity.FeatureCommandSpec) (kernel.CredentialResetIntent, error) {
	fail := func() (kernel.CredentialResetIntent, error) {
		return kernel.CredentialResetIntent{}, password.ErrPasswordWork
	}
	phone := s.Operation == phonePasswordResetOperation()
	if !phone && s.Operation != resetOperation() || s.Binding.ValidateFor(s.Operation) != nil || !phone && len(s.Fields) != 9 {
		return fail()
	}
	values := make(map[string]identity.FeatureValue, 9)
	for _, field := range s.Fields {
		// Phone/OTP/risk metadata remains in the full sealed command and its
		// coordinator fingerprint. Its owning workflow validates that scope;
		// this shared writer maps only canonical password predecessors and must
		// not convert joint custody into a generic or emailed-reset command.
		if phone && !strings.HasPrefix(field.Name, "credential.") && !strings.HasPrefix(field.Name, "reset.") {
			continue
		}
		if _, duplicate := values[field.Name]; duplicate {
			return fail()
		}
		values[field.Name] = field.Value
	}
	if len(values) != 9 {
		return fail()
	}
	i := kernel.CredentialResetIntent{Replacement: kernel.CredentialReplacementIntent{
		Credential:          identity.CredentialRef{ID: identity.CredentialID(values["credential.id"].Text), TenantID: identity.TenantID(values["credential.tenant"].Text), UserID: identity.UserID(values["credential.user"].Text), Owner: values["credential.owner"].Text, Kind: identity.CredentialPassword, Version: values["credential.version"].Uint64},
		ExpectedUserVersion: values["credential.expected-user-version"].Uint64, ExpectedAuthorityVersion: values["credential.expected-authority-version"].Uint64,
	}, ExpectedEnabled: values["reset.expected-enabled"].Bool}
	expected, err := kernel.CredentialResetFields(i)
	if err != nil || i.Replacement.Credential.TenantID != s.Binding.TenantID || i.Replacement.Credential.UserID != s.Binding.UserID || string(i.Replacement.Credential.ID) != s.Binding.RecordID {
		return fail()
	}
	for _, field := range expected {
		v := values[field.Name]
		if v.Kind != field.Value.Kind || v.Text != field.Value.Text || v.Uint64 != field.Value.Uint64 || v.Bool != field.Value.Bool || v.Bytes != nil || v.Int64 != 0 || v.Time != (time.Time{}) {
			return fail()
		}
	}
	return i, nil
}
