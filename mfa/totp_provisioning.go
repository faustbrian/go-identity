package mfa

import (
	"context"
	"encoding/base32"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-password/v2"
)

// EnrollmentID identifies one pending factor enrollment, not authentication
// authority. The native TOTP profile uses canonical random128 identifiers.
type EnrollmentID string

// RevealOnceURI is explicit secret-delivery material for one enrollment. URI
// must be transferred only by an error-free first committed reveal operation.
// Construction alone provides no evidence of reveal consumption. Recovery and
// replay must return zero; never persist this plaintext or put it in diagnostics.
// Values are immutable after construction; copies contain the same secret.
// Implicit formatting and serialization are denied. A selected transport must
// deliberately copy URI into its no-store, no-cache success response.
type RevealOnceURI struct {
	URI          string
	EnrollmentID EnrollmentID
}

// NewTOTPProvisioningURI computes bounded otpauth provisioning material from
// the exact encrypted factor's profile and borrowed secret. The native owner
// supplies the account label from a verified identifier, never client input.
// Labels are 1..256 UTF-8 bytes without colon, controls or edge whitespace;
// label/query escaping preserves the issuer and account exactly.
// Key-URI provisioning permits six or eight digits; the broader verifier's
// 7/9/10-digit stored profiles are not silently converted. Authenticator support
// for nondefault algorithm/period must be established by deployment policy.
// Format source: https://github.com/google/google-authenticator/wiki/Key-Uri-Format.
//
// This function owns no IO, transaction, enrollment, clock or consumption. It
// does not authorize disclosure: prepare privately, atomically consume the
// native enrollment's reveal marker, and return only after a known fresh commit.
// The caller must Destroy secret after use. Invalid structure, unavailable
// secret and cancellation return no material and redacted errors. Earlier caller
// cancellation wins; concurrent calls require separate secret owners.
func NewTOTPProvisioningURI(ctx context.Context, secret password.Secret, profile TOTPProfile, account string, enrollment EnrollmentID) (RevealOnceURI, error) {
	if ctx == nil {
		return RevealOnceURI{}, invalidTOTP()
	}
	if err := ctx.Err(); err != nil {
		return RevealOnceURI{}, err
	}
	if profile.Validate() != nil || (profile.Digits != 6 && profile.Digits != 8) || !provisioningAccount(account) {
		return RevealOnceURI{}, invalidTOTP()
	}
	if _, err := identity.ParseCommandID(string(enrollment)); err != nil {
		return RevealOnceURI{}, invalidTOTP()
	}
	if secret.Len() < 20 || secret.Len() > 128 {
		return RevealOnceURI{}, identity.UnavailableError{}
	}
	var result RevealOnceURI
	err := secret.Use(func(bytes []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		query := url.Values{
			"secret":    {base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)},
			"issuer":    {profile.Issuer},
			"algorithm": {profile.Algorithm},
			"digits":    {strconv.FormatUint(uint64(profile.Digits), 10)},
			"period":    {strconv.FormatInt(int64(profile.Period/time.Second), 10)},
		}
		// Escape both label components separately so a slash cannot introduce
		// another path segment and a query/fragment cannot alter profile fields.
		uri := "otpauth://totp/" + url.PathEscape(profile.Issuer) + ":" + url.PathEscape(account) + "?" + strings.ReplaceAll(query.Encode(), "+", "%20")
		if len(uri) > 4096 {
			return invalidTOTP()
		}
		result = RevealOnceURI{URI: uri, EnrollmentID: enrollment}
		return nil
	})
	if cancellation := ctx.Err(); cancellation != nil {
		return RevealOnceURI{}, cancellation
	}
	if err != nil {
		return RevealOnceURI{}, identity.UnavailableError{}
	}
	return result, nil
}

func provisioningAccount(account string) bool {
	if len(account) == 0 || len(account) > 256 || !utf8.ValidString(account) || strings.TrimSpace(account) != account {
		return false
	}
	for _, r := range account {
		if r == ':' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Format redacts plaintext provisioning material for all formatting verbs.
func (RevealOnceURI) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfa.RevealOnceURI(redacted)"))
}

// MarshalJSON denies implicit plaintext provisioning export.
func (RevealOnceURI) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit plaintext/map-key provisioning export.
func (RevealOnceURI) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts plaintext provisioning and correlated enrollment identity.
func (RevealOnceURI) LogValue() slog.Value { return slog.StringValue("mfa.RevealOnceURI(redacted)") }
