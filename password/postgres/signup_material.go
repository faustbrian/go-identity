package passwordpostgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
)

// signupMaterial admits only the original paired verifier and its complete
// kernel registration commitment. It does not establish HIBP, field admission,
// cookie possession or permission to insert material; those checks belong to
// the service and its active coordinated registration phase.
func (r *Repository) signupMaterial(c identity.Command, intent kernel.PasswordRegistrationIntent) (primitive.EncodedHash, error) {
	fail := func() (primitive.EncodedHash, error) { return primitive.EncodedHash{}, password.ErrPasswordWork }
	if r == nil || r.policy.Algorithm() == "" {
		return fail()
	}
	s, metadata := c.PasswordSignupFeature()
	raw, _, custody := c.PasswordSignupCustody()
	if !metadata || !custody {
		return fail()
	}
	expected := s.Binding
	expected.OperationID, expected.AnonymousFlowID = "identity.user.create", ""
	expected.UserID = intent.Creation.Binding.UserID
	expected.SchemaID, expected.SchemaVersion = intent.Creation.Binding.SchemaID, intent.Creation.Binding.SchemaVersion
	if intent.Creation.Binding != expected || s.Binding.UserID != "" && s.Binding.UserID != expected.UserID {
		return fail()
	}
	fields, err := kernel.PasswordRegistrationFields(intent)
	if err != nil {
		return fail()
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
			a, b := actual.Value, wanted.Value
			if a.Kind != b.Kind || a.Text != b.Text || a.Uint64 != b.Uint64 || a.Int64 != b.Int64 || a.Bool != b.Bool || !a.Time.Equal(b.Time) || !bytes.Equal(a.Bytes, b.Bytes) {
				return fail()
			}
			found, matched = true, matched+1
			break
		}
		if !found {
			return fail()
		}
	}
	if matched != len(fields) {
		return fail()
	}
	hash, err := primitive.ParseEncodedHash(raw, r.policy.Limits())
	if err != nil || !signinCurrentHash(hash, r.policy) {
		return fail()
	}
	return hash, nil
}

// applySignupMaterial borrows only the active native registration invocation.
// The kernel must already have created the selected account/reference and its
// original registration binding. In particular, a neutral collision cannot
// obtain material, even if its proposed user ID names an existing account.
// The coordinator owns rollback, commit and retry; this helper creates no
// transaction or second effect journal and never exposes driver diagnostics.
func (r *Repository) applySignupMaterial(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, intent kernel.PasswordRegistrationIntent) error {
	if ctx == nil || !r.configuredWriter() {
		return password.ErrPasswordWork
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return err
	}
	hash, err := r.signupMaterial(c, intent)
	if err != nil {
		return err
	}
	s, _ := c.PasswordSignupFeature()
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || b != s.Binding || feature.Operation != s.Operation || feature.Contributor != r.Descriptor() || transition.EventType != "user.created.v1" || transition.BeforeVersion != 0 || transition.AfterVersion != 0 {
		return password.ErrPasswordWork
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return password.ErrPasswordWork
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	n, err := w.Exec(bounded, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash)
SELECT r.tenant_id,r.user_id,r.credential_id,1,$6,$7
FROM identity.registration_bindings r
JOIN identity.users u ON u.tenant_id=r.tenant_id AND u.user_id=r.user_id
JOIN identity.credential_references c ON c.tenant_id=r.tenant_id AND c.user_id=r.user_id AND c.credential_id=r.credential_id
JOIN identity.identifiers i ON i.tenant_id=r.tenant_id AND i.user_id=r.user_id AND i.identifier_id=r.identifier_id
WHERE r.tenant_id=$1 AND r.purpose=$2 AND r.command_id=$3
AND r.user_id=$4 AND r.credential_id=$5 AND r.identifier_id=$8
AND u.status='active' AND u.version=1
AND c.kind=1 AND c.owner='identity/password' AND c.version=1 AND c.enabled AND c.expires_at IS NULL
AND i.version=1 AND NOT i.verified AND NOT i.is_primary AND i.verification_state=1 AND i.verification_version=1`, string(b.TenantID), b.OperationID, id, string(intent.Creation.Binding.UserID), string(intent.Credential.ID), string(hash.Algorithm()), hash.String(), string(intent.Identifier.ID))
	if err != nil {
		return readerFailure(bounded)
	}
	if n != 1 {
		return password.ErrPasswordWork
	}
	if err := mfapg.InitializeSignup(bounded, w, owner, c, intent.Creation.Binding.UserID); err != nil {
		return err
	}
	return bounded.Err()
}
