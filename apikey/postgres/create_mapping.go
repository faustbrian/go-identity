package postgres

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"reflect"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

func createOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.create", SchemaID: "apikey-create-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func rotateOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.rotate", SchemaID: "apikey-rotate-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func revokeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/apikey", OperationID: "identity.apikey.delete", SchemaID: "apikey-revoke-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}
func operationFor(id string) identity.FeatureOperation {
	switch id {
	case "identity.apikey.create":
		return createOperation()
	case "identity.apikey.rotate":
		return rotateOperation()
	case "identity.apikey.delete":
		return revokeOperation()
	case "identity.apikey.import":
		return importOperation()
	default:
		return identity.FeatureOperation{}
	}
}
func intentField(op identity.FeatureOperation) string {
	base := operationFor(op.OperationID)
	if op != base && op != organizationManagementOperation(op.OperationID) {
		return ""
	}
	switch base {
	case createOperation():
		return "apikey.create.intent"
	case rotateOperation():
		return "apikey.rotate.intent"
	case revokeOperation():
		return "apikey.revoke.intent"
	case importOperation():
		return "apikey.import.intent"
	default:
		return ""
	}
}

// REFERENCE_CONFIGURATION.md's API-key expiry row fixes this selected native
// profile to 1d..365d. Core permits a stricter shorter cap for other compositions;
// this adapter must not silently enroll that different issuance profile.
const minimumKeyLifetime = 24 * time.Hour

// REFERENCE_CONFIGURATION.md's freshness operation matrix requires recent
// primary authentication for API-key create/rotate/revoke. A renewed session
// or authoritative read must not restart this original 15-minute window.
const maximumManagementProofAge = 15 * time.Minute

func managementProofDeadline(s session.SessionSpec) time.Time {
	return s.Authentication.Proof.IssuedAt.Add(maximumManagementProofAge).Truncate(time.Microsecond)
}

// The native service alone derives this input from the real public session,
// directory/status and policy owners. Mapping is not authentication or current
// authority. It preserves the original read window without acquiring a lease.
type creationInput struct {
	Configuration                         apikey.Configuration
	Record                                apikey.Record
	PreviousRecord                        *apikey.Record
	PreviousConfiguration                 *apikey.Configuration
	PreviousConfigurationAuthority        *apikey.ConfigurationAuthorityBinding
	Import                                *legacyImportBinding
	Binding                               identity.CommandBinding
	Session                               session.Session
	Bearer                                auth.BearerCredential
	OwnerStatus                           identity.UserStatusRecord
	ConfigurationAuthority                apikey.ConfigurationAuthorityBinding
	ReadStartedAt, VerifiedAt, ValidUntil time.Time
	Network                               string
	Organization                          *organization.CredentialAuthorityObservation
}

func (x creationInput) validate() error {
	// This finite profile accepts genuine token-only bearer issuance. Reusing a
	// browser session's opaque token must not bypass its synchronizer protection.
	if x.Session.CSRFState() != (session.CSRFState{}) {
		return apikey.ErrDenied
	}
	r, b, c := x.Record, x.Binding, x.Configuration.Spec()
	o := r.Owner.Spec()
	ip, ipErr := netip.ParseAddr(x.Network)
	s, err := x.Session.Bindings()
	op := managementOperationForBinding(b)
	ownerVersionValid := x.OwnerStatus.AuthorityVersion == o.Version || op == importOperation() && x.OwnerStatus.AuthorityVersion >= o.Version
	ownerMatches := o.Kind == apikey.OwnerUser && o.UserID == b.UserID && x.Organization == nil && op == operationFor(b.OperationID)
	if o.Kind == apikey.OwnerOrganization && x.Organization != nil {
		query := organization.CredentialAuthorityQuery{TenantID: b.TenantID, OrganizationID: organization.ID(o.OrganizationID), ActorID: b.UserID}
		ownerMatches = op == organizationManagementOperation(b.OperationID) && x.Organization.Validate(query, x.VerifiedAt) == nil && !x.ValidUntil.After(x.Organization.ValidUntil)
		ownerVersionValid = o.Version == x.Organization.CredentialVersion || b.OperationID == "identity.apikey.import" && r.Status == apikey.KeyRevoked && o.Version <= x.Organization.CredentialVersion
	}
	if err != nil || intentField(op) == "" || b.ValidateFor(op) != nil || x.Configuration.Validate() != nil || r.Validate(x.Configuration) != nil || !ownerMatches || b.TenantID != o.TenantID || b.ActorID != identity.ActorID(b.UserID) || b.ActorKind != authorization.SubjectUser || b.RecordID != string(r.ID) || b.OperationID == "identity.apikey.create" && len(r.Name) == 0 || c.Algorithm == apikey.AlgorithmModernHMACSHA256 && c.MaximumLifetime < minimumKeyLifetime || x.OwnerStatus.User.Validate(b.TenantID) != nil || x.OwnerStatus.User.ID != b.UserID || x.OwnerStatus.User.Status != identity.StatusActive || !ownerVersionValid || x.ConfigurationAuthority.Validate(b.TenantID, c.ID) != nil || s.TenantID != b.TenantID || s.UserID != b.UserID || s.Authentication.Kind != session.AuthenticationVerified || s.Authentication.Proof.Method != "password" || s.Authentication.Proof.Assurance != auth.AssuranceSingleFactor || x.Session.MFAAuthentication() != (session.MFAAuthentication{}) || ipErr != nil || ip.Zone() != "" || ip.Unmap().String() != x.Network || ip.IsUnspecified() || ip.IsMulticast() || !exactTime(x.ReadStartedAt) || !exactTime(x.VerifiedAt) || !exactTime(x.ValidUntil) || x.VerifiedAt.Before(x.ReadStartedAt) || x.VerifiedAt.Sub(x.ReadStartedAt) > c.MaximumRead || !x.ValidUntil.After(x.VerifiedAt) || x.ValidUntil.Sub(x.ReadStartedAt) > 20*time.Second || r.CreatedAt.After(x.VerifiedAt) {
		return apikey.ErrInvalid
	}
	if !x.VerifiedAt.Before(managementProofDeadline(s)) || x.ValidUntil.After(managementProofDeadline(s)) {
		return apikey.ErrDenied
	}
	if b.OperationID == "identity.apikey.import" {
		if x.Import == nil || x.PreviousRecord != nil || x.PreviousConfiguration != nil || x.PreviousConfigurationAuthority != nil || c.Algorithm != apikey.AlgorithmLegacySHA256V1 || c.State != apikey.ConfigurationVerifyOnly || !scope(x.Import.SourceID) || x.Import.SourceVersion == 0 || x.Import.Digest == ([32]byte{}) || r.Status == apikey.KeyActive && (r.Version == ^uint64(0) || r.AuthorityVersion == ^uint64(0) || x.ConfigurationAuthority.Version == ^uint64(0)) {
			return apikey.ErrInvalid
		}
	} else if b.OperationID == "identity.apikey.create" {
		if x.Import != nil || x.PreviousConfiguration != nil || x.PreviousConfigurationAuthority != nil {
			return apikey.ErrInvalid
		}
		if x.PreviousRecord != nil || !x.Configuration.AllowsIssuance() || r.Version != 1 || r.AuthorityVersion != 1 || r.RootVersion != 1 || r.Status != apikey.KeyActive || r.PreviousID != "" || r.ExpiresAt.Sub(r.CreatedAt) < minimumKeyLifetime || r.CreatedAt.Before(x.ReadStartedAt) {
			return apikey.ErrInvalid
		}
	} else {
		if x.Import != nil {
			return apikey.ErrInvalid
		}
		if x.PreviousRecord == nil || x.ConfigurationAuthority.Version == ^uint64(0) {
			return apikey.ErrInvalid
		}
		prior := *x.PreviousRecord
		previousConfiguration := x.Configuration
		if x.PreviousConfiguration != nil {
			previousConfiguration = *x.PreviousConfiguration
			if b.OperationID != "identity.apikey.rotate" || x.PreviousConfigurationAuthority == nil || x.PreviousConfigurationAuthority.Validate(b.TenantID, previousConfiguration.Spec().ID) != nil || x.PreviousConfigurationAuthority.Version == ^uint64(0) || previousConfiguration.Spec().Algorithm != apikey.AlgorithmLegacySHA256V1 {
				return apikey.ErrInvalid
			}
		} else if x.PreviousConfigurationAuthority != nil {
			return apikey.ErrInvalid
		}
		if prior.Validate(previousConfiguration) != nil || !prior.Owner.SameIdentity(r.Owner) || prior.Owner.Version() > r.Owner.Version() || o.Kind == apikey.OwnerOrganization && prior.Owner.Version() != r.Owner.Version() || prior.Status != apikey.KeyActive || prior.Version == ^uint64(0) || prior.AuthorityVersion == ^uint64(0) {
			return apikey.ErrInvalid
		}
		want := prior
		want.Owner = r.Owner
		if b.OperationID == "identity.apikey.rotate" {
			if !x.Configuration.AllowsIssuance() || !prior.ExpiresAt.IsZero() && !x.VerifiedAt.Before(prior.ExpiresAt) || r.ID == prior.ID || r.CreatedAt.Before(x.ReadStartedAt) {
				return apikey.ErrInvalid
			}
			want.ID, want.RootID, want.PreviousID, want.CreatedAt = r.ID, r.ID, prior.ID, r.CreatedAt
			want.Version, want.AuthorityVersion, want.RootVersion = 1, 1, 1
			want.ConfigurationID, want.ConfigurationRevision, want.Issuer, want.Environment, want.Audience = c.ID, c.Revision, c.Issuer, c.Environment, c.Audience
			if previousConfiguration.Spec().Algorithm == apikey.AlgorithmLegacySHA256V1 {
				want.ExpiresAt = modernSuccessorExpiry(prior.ExpiresAt, r.CreatedAt, c.MaximumLifetime)
			}
		} else {
			want.Version++
			want.AuthorityVersion++
			want.RootVersion++
			want.Status, want.Grant = apikey.KeyRevoked, []string{}
		}
		if !reflect.DeepEqual(want, r) {
			return apikey.ErrInvalid
		}
	}
	v, err := s.Authority.Bindings()
	if err != nil || v.ActiveOrganizationID != "" || v.Organization.Present || v.Factor.Present || v.Passkey.Present {
		return apikey.ErrDenied
	}
	if _, err := encodeRecord(r, x.Configuration); err != nil {
		return err
	}
	return nil
}

// A bounded SHA-256 commitment binds the complete typed key record and current
// original admission. The session owner's exhaustive scalar vocabulary already
// uses most of the shared 128-field budget; hashing the bounded canonical record
// avoids silently dropping grants or reducing the root's 64-permission ceiling.
// The exact invocation retains and validates the typed preimage; no generic blob
// decoder or caller-provided field can stand in for current owner admission.
func (x creationInput) commitment() ([32]byte, error) {
	if err := x.validate(); err != nil {
		return [32]byte{}, err
	}
	record, err := encodeRecord(x.Record, x.Configuration)
	if err != nil {
		return [32]byte{}, err
	}
	var previous []byte
	if x.PreviousRecord != nil {
		previousConfiguration := x.Configuration
		if x.PreviousConfiguration != nil {
			previousConfiguration = *x.PreviousConfiguration
		}
		previous, err = encodeRecord(*x.PreviousRecord, previousConfiguration)
		if err != nil {
			return [32]byte{}, err
		}
	}
	a := x.ConfigurationAuthority
	var previousConfiguration *apikey.ConfigurationSpec
	var previousAuthority uint64
	if x.PreviousConfiguration != nil {
		spec := x.PreviousConfiguration.Spec()
		previousConfiguration = &spec
		previousAuthority = x.PreviousConfigurationAuthority.Version
	}
	preimage, err := json.Marshal(struct {
		Profile                               string
		Record                                []byte
		Previous                              []byte
		Configuration                         apikey.ConfigurationSpec
		StatusVersion, SecurityVersion        uint64
		ConfigurationTenant                   identity.TenantID
		ConfigurationID                       string
		ConfigurationVersion                  uint64
		ReadStartedAt, VerifiedAt, ValidUntil time.Time
		Network                               string
		PreviousConfiguration                 *apikey.ConfigurationSpec                    `json:",omitempty"`
		PreviousAuthority                     uint64                                       `json:",omitempty"`
		Import                                *legacyImportBinding                         `json:",omitempty"`
		Organization                          *organization.CredentialAuthorityObservation `json:",omitempty"`
	}{x.Binding.OperationID, record, previous, x.Configuration.Spec(), x.OwnerStatus.User.Version, x.OwnerStatus.AuthorityVersion, a.TenantID, a.ConfigurationID, a.Version, x.ReadStartedAt.UTC(), x.VerifiedAt.UTC(), x.ValidUntil.UTC(), x.Network, previousConfiguration, previousAuthority, x.Import, x.Organization})
	if err != nil {
		return [32]byte{}, apikey.ErrInvalid
	}
	return sha256.Sum256(preimage), nil
}

func mapCreation(x creationInput) (identity.Command, error) {
	digest, err := x.commitment()
	if err != nil {
		return identity.Command{}, err
	}
	fields, err := sessionpg.OriginalSessionFields(x.Session)
	if err != nil {
		return identity.Command{}, apikey.ErrDenied
	}
	op := managementOperationForBinding(x.Binding)
	fields = append(fields, identity.FeatureField{Name: intentField(op), Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}})
	return identity.NewFeatureSessionCommand(identity.FeatureCommandSpec{Binding: x.Binding, Operation: op, Fields: fields}, x.Bearer)
}
