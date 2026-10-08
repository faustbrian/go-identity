package postgres

import (
	"bytes"
	"encoding/binary"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
)

const issuanceRecipientRecordPrefix = "identity-otp-recipient-issuance-v1\x00"

func unwrapRecipientIssuance(data []byte) ([]byte, *kernel.RecipientRecord, error) {
	if bytes.HasPrefix(data, []byte(issuanceRecordPrefix)) || bytes.HasPrefix(data, []byte(csrfIssuanceRecordPrefix)) {
		return data, nil, nil
	}
	if !bytes.HasPrefix(data, []byte(issuanceRecipientRecordPrefix)) || len(data) > 8192 {
		return nil, nil, ErrInvalidCommand
	}
	r := recordReader{data: data[len(issuanceRecipientRecordPrefix):], ok: true}
	issuance, selected := r.text(8192), r.text(4096)
	if !r.ok || len(r.data) != 0 {
		return nil, nil, ErrInvalidCommand
	}
	reader := recordReader{data: []byte(selected), ok: true}
	recipient, err := readSendRecipient(&reader)
	if err != nil || !reader.ok || len(reader.data) != 0 {
		return nil, nil, ErrInvalidCommand
	}
	return []byte(issuance), &recipient, nil
}

// Recipient selection remains separate from the original command subject and
// flow. These bytes are original intent, not a primary-authority clearance.
func validateSendRecipient(r kernel.RecipientRecord, scope otp.DigestScopeSpec, binding identity.CommandBinding) error {
	kind := identity.IdentifierEmail
	if scope.Channel == otp.ChannelSMS {
		kind = identity.IdentifierPhone
	}
	eligibility := kernel.RecipientVerified
	if scope.Purpose == otp.PurposeEmailVerification || scope.Purpose == otp.PurposeEmailChange {
		eligibility = kernel.RecipientPendingOrVerified
	}
	if r.Validate() != nil || r.Suppressed || r.Query.TenantID != binding.TenantID || r.Query.UserID != binding.UserID || r.Query.Kind != kind || r.Query.CanonicalValue != scope.Destination.Value() || r.Query.Eligibility != eligibility {
		return ErrInvalidCommand
	}
	return nil
}

func appendSendRecipient(out []byte, r kernel.RecipientRecord) []byte {
	for _, text := range []string{string(r.Query.TenantID), string(r.Query.UserID), string(r.Query.Kind), r.Query.CanonicalValue, string(r.User.ID), string(r.User.TenantID), string(r.User.Status), string(r.Identifier.ID), string(r.Identifier.UserID), string(r.Identifier.Kind), r.Identifier.CanonicalValue, r.Identifier.DisplayValue, string(r.Verification.IdentifierID)} {
		out = appendAuthorityText(out, text)
	}
	out = append(out, byte(r.Query.Eligibility), byte(r.Verification.State))
	flags := byte(0)
	if r.Identifier.Verified {
		flags |= 1
	}
	if r.Identifier.Primary {
		flags |= 2
	}
	out = append(out, flags)
	for _, n := range []uint64{r.User.Version, r.Identifier.Version, r.Verification.Version, r.UserAuthorityVersion, r.IdentifierAuthorityVersion, r.CredentialAuthorityVersion} {
		out = binary.BigEndian.AppendUint64(out, n)
	}
	verified := ""
	if !r.Verification.VerifiedAt.IsZero() {
		verified = r.Verification.VerifiedAt.UTC().Format(time.RFC3339Nano)
	}
	out = appendAuthorityText(out, verified)
	return appendAuthorityText(out, r.ObservedAt.UTC().Format(time.RFC3339Nano))
}

func readSendRecipient(r *recordReader) (kernel.RecipientRecord, error) {
	bad := func() (kernel.RecipientRecord, error) { return kernel.RecipientRecord{}, ErrInvalidCommand }
	selected := kernel.RecipientRecord{}
	selected.Query = kernel.RecipientQuery{TenantID: identity.TenantID(r.text(256)), UserID: identity.UserID(r.text(256)), Kind: identity.IdentifierKind(r.text(32)), CanonicalValue: r.text(512)}
	selected.User = identity.User{ID: identity.UserID(r.text(256)), TenantID: identity.TenantID(r.text(256)), Status: identity.Status(r.text(32))}
	selected.Identifier = identity.Identifier{ID: identity.IdentifierID(r.text(256)), UserID: identity.UserID(r.text(256)), Kind: identity.IdentifierKind(r.text(32)), CanonicalValue: r.text(512), DisplayValue: r.text(512)}
	selected.Verification.IdentifierID = identity.IdentifierID(r.text(256))
	selected.Query.Eligibility = kernel.RecipientEligibility(r.u8())
	selected.Verification.State = identity.VerificationState(r.u8())
	flags := r.u8()
	if flags > 3 {
		return bad()
	}
	selected.Identifier.Verified, selected.Identifier.Primary = flags&1 != 0, flags&2 != 0
	selected.User.Version, selected.Identifier.Version, selected.Verification.Version = r.u64(), r.u64(), r.u64()
	selected.UserAuthorityVersion, selected.IdentifierAuthorityVersion, selected.CredentialAuthorityVersion = r.u64(), r.u64(), r.u64()
	verified, observed := r.text(35), r.text(35)
	var err error
	if verified != "" {
		selected.Verification.VerifiedAt, err = time.Parse(time.RFC3339Nano, verified)
		if err != nil || selected.Verification.VerifiedAt.UTC().Format(time.RFC3339Nano) != verified {
			return bad()
		}
	}
	selected.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
	if !r.ok || err != nil || selected.ObservedAt.UTC().Format(time.RFC3339Nano) != observed || selected.Validate() != nil || selected.Suppressed {
		return bad()
	}
	return selected, nil
}
