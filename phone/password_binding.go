package phone

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	identity "github.com/faustbrian/go-identity"
)

// ErrPasswordSigninBinding denies invalid original identifier-binding input.
const ErrPasswordSigninBinding NumberError = "identity.phone.password_signin_binding_invalid"

// PasswordSigninIdentifierBinding derives the original password-preauth target
// commitment from an already canonical Number, exact tenant and a deployment-
// owned 32..64-byte identifier key. Display/national spelling is not identity.
// It is not a cookie digest, OTP proof, password comparison or authentication.
// Trusted initiation retains it as session.PreAuthIntent.IdentifierBinding;
// the phone/password workflow must recompute and compare it before credential
// work. Never accept a browser-selected commitment instead of deriving it.
//
// HMAC-SHA-256 framing is the UTF-8 domain
// identity-phone-password-signin-binding-v1 NUL, uint32 comparison-profile
// version, then tenant, exact password-signin action, profile ID, metadata version
// and canonical E.164, each preceded by its uint32 byte length, big-endian.
// This separation prevents use as an OTP-signin or cross-tenant commitment.
// Keep the selected key/profile for the original flow lifetime; rotation does
// not renew intent. The borrowed key must remain immutable during this bounded
// synchronous call; the caller retains its lifetime. No IO or callbacks run.
// Invalid input returns a zero commitment and the redacted sentinel above.
func PasswordSigninIdentifierBinding(number Number, tenant identity.TenantID, key []byte) ([32]byte, error) {
	if len(key) < 32 || len(key) > 64 {
		return [32]byte{}, ErrPasswordSigninBinding
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return [32]byte{}, ErrPasswordSigninBinding
	}
	record, err := number.Record()
	if err != nil {
		return [32]byte{}, ErrPasswordSigninBinding
	}
	frame := []byte("identity-phone-password-signin-binding-v1\x00")
	frame = binary.BigEndian.AppendUint32(frame, record.Profile.Version)
	for _, value := range []string{string(tenant), "identity.phone.password-signin", record.Profile.ID, record.Profile.MetadataVersion, record.E164} {
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(value)))
		frame = append(frame, value...)
	}
	defer clear(frame)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(frame)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}
