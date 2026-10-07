package postgres

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	authorization "github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// AttemptAuthority contains original primary expectations, not authentication
// or an Allow decision. Directory is required. User commands require their
// effective user's UserAuthorization and user/identifier/credential security
// epochs, including passwordless workflows with no credential reference.
// Anonymous commands prohibit every user dimension. Credential is optional
// only when the owning workflow does not use an existing credential.
// All populated epochs are positive full-width
// counters. Capture them through their primary owners before mapping, never
// replace them with current reads during retry, takeover or protected use.
// Trusted composition chooses the deployment ID and policy namespace.
type AttemptAuthority struct {
	Directory                                                                    kernel.DirectoryAuthorityAdmission
	Credential                                                                   identity.CredentialRef
	UserAuthorization                                                            kernel.UserAuthorizationAdmission
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
}

// Format omits correlated identities and authority epochs.
func (AttemptAuthority) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.AttemptAuthority(redacted)"))
}

// MarshalJSON rejects correlated expectation export.
func (AttemptAuthority) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText rejects correlated expectation export.
func (AttemptAuthority) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

func (a AttemptAuthority) validate(b identity.CommandBinding) error {
	d := a.Directory
	if d.Query.Validate() != nil || d.Query.TenantID != b.TenantID || d.GlobalVersion == 0 || d.TenantVersion == 0 {
		return ErrInvalidCommand
	}
	if b.UserID == "" {
		if a.Credential != (identity.CredentialRef{}) || a.UserAuthorization != (kernel.UserAuthorizationAdmission{}) || a.UserAuthorityVersion != 0 || a.IdentifierAuthorityVersion != 0 || a.CredentialAuthorityVersion != 0 {
			return ErrInvalidCommand
		}
		return nil
	}
	u := a.UserAuthorization
	if u.Scope.Validate() != nil || string(u.Scope.TenantID) != string(b.TenantID) || string(u.Scope.SubjectID) != string(b.UserID) || u.Version == 0 || a.UserAuthorityVersion == 0 || a.IdentifierAuthorityVersion == 0 || a.CredentialAuthorityVersion == 0 {
		return ErrInvalidCommand
	}
	c := a.Credential
	if c != (identity.CredentialRef{}) && c.Validate(b.TenantID, b.UserID) != nil {
		return ErrInvalidCommand
	}
	return nil
}

// MapWithAuthority freezes original authority expectations with the original
// encrypted attempt in one authenticated envelope. Existing Map v1/v2 bytes
// remain unchanged. The new v3 profile is code-free and bounded by the same
// 8192-byte wire limit. Input values are copied; concurrent input mutation is
// forbidden. Map once and retain the command for retries and ambiguity.
// It performs no primary read, comparison, reservation or policy decision.
// Context, errors and retained-key semantics are those of Map. Successful
// mapping is not current authority; native phases must compare these exact
// expectations with each owning primary authority before mutation.
func (c *AttemptCodec) MapWithAuthority(ctx context.Context, a otp.AttemptCommand, version uint32, spec identity.FeatureCommandSpec, original AttemptAuthority) (identity.Command, kernel.OTPAttemptPlan, error) {
	return c.mapAttempt(ctx, a, version, spec, &original)
}

func (c *AttemptCodec) restoreAuthority(spec identity.FeatureCommandSpec) (AttemptAuthority, error) {
	value, err := c.restoreCustody(spec)
	if err != nil || value.authority == nil {
		return AttemptAuthority{}, ErrInvalidCommand
	}
	return *value.authority, nil
}

const authorityRecordPrefix = "identity-otp-attempt-custody-v3\x00"

func appendAuthorityText(out []byte, s string) []byte {
	out = binary.BigEndian.AppendUint16(out, uint16(len(s)))
	return append(out, s...)
}

func encodeAuthorityRecord(record []byte, a AttemptAuthority) []byte {
	out := []byte(authorityRecordPrefix)
	out = binary.BigEndian.AppendUint16(out, uint16(len(record)))
	out = append(out, record...)
	out = appendAuthorityText(out, a.Directory.Query.GlobalAuthorityID)
	out = binary.BigEndian.AppendUint64(out, a.Directory.GlobalVersion)
	out = binary.BigEndian.AppendUint64(out, a.Directory.TenantVersion)
	for _, epoch := range []uint64{a.UserAuthorityVersion, a.IdentifierAuthorityVersion, a.CredentialAuthorityVersion} {
		out = binary.BigEndian.AppendUint64(out, epoch)
	}
	if a.UserAuthorization == (kernel.UserAuthorizationAdmission{}) {
		out = append(out, 0)
	} else {
		out = append(out, 1)
		out = appendAuthorityText(out, a.UserAuthorization.Scope.PolicyNamespace)
		out = binary.BigEndian.AppendUint64(out, a.UserAuthorization.Version)
	}
	if a.Credential == (identity.CredentialRef{}) {
		return append(out, 0)
	}
	out = append(out, 1)
	c := a.Credential
	out = appendAuthorityText(out, string(c.ID))
	out = append(out, byte(c.Kind))
	out = appendAuthorityText(out, c.Owner)
	out = binary.BigEndian.AppendUint64(out, c.Version)
	return out
}

func decodeAuthorityRecord(data []byte, binding identity.CommandBinding) ([]byte, *AttemptAuthority, error) {
	return decodeBoundAuthorityRecord(data, binding, false)
}

func decodeBoundAuthorityRecord(data []byte, binding identity.CommandBinding, issuance bool) ([]byte, *AttemptAuthority, error) {
	if !bytes.HasPrefix(data, []byte(authorityRecordPrefix)) {
		return data, nil, nil
	}
	bad := func() ([]byte, *AttemptAuthority, error) { return nil, nil, ErrInvalidCommand }
	if len(data) > 8192 {
		return bad()
	}
	r := recordReader{data: data[len(authorityRecordPrefix):], ok: true}
	size := r.take(2)
	if size == nil {
		return bad()
	}
	record := r.take(int(binary.BigEndian.Uint16(size)))
	a := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: r.text(256), TenantID: binding.TenantID}, GlobalVersion: r.u64(), TenantVersion: r.u64()}}
	a.UserAuthorityVersion, a.IdentifierAuthorityVersion, a.CredentialAuthorityVersion = r.u64(), r.u64(), r.u64()
	switch r.u8() {
	case 0:
	case 1:
		a.UserAuthorization = kernel.UserAuthorizationAdmission{Scope: authoritypg.AuthorityScope{TenantID: authorization.TenantID(binding.TenantID), SubjectID: authorization.SubjectID(binding.UserID), PolicyNamespace: r.text(128)}, Version: r.u64()}
	default:
		return bad()
	}
	switch r.u8() {
	case 0:
	case 1:
		a.Credential = identity.CredentialRef{ID: identity.CredentialID(r.text(256)), TenantID: binding.TenantID, UserID: binding.UserID, Kind: identity.CredentialKind(r.u8()), Owner: r.text(128), Version: r.u64()}
	default:
		return bad()
	}
	validRecord := bytes.HasPrefix(record, []byte(recordPrefix)) || bytes.HasPrefix(record, []byte(boundRecordPrefix)) || bytes.HasPrefix(record, []byte(sessionRecordPrefix))
	if issuance {
		validRecord = bytes.HasPrefix(record, []byte(issuanceRecordPrefix))
	}
	if !r.ok || len(r.data) != 0 || a.validate(binding) != nil || !validRecord {
		return bad()
	}
	return record, &a, nil
}
