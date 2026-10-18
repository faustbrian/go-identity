package postgres

import (
	"bytes"
	"fmt"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// EmailVerificationIntent names the original signup and exact current kernel
// predecessors for registration link confirmation. Change must be Verify of
// the original pending email record. CanonicalAddress and ComparisonProfile
// come from authenticated original signup intent, not callback request fields.
// This metadata carries no proof, session, policy or transaction authority.
type EmailVerificationIntent struct {
	Change                identity.IdentifierChange
	CanonicalAddress      string
	ComparisonProfile     string
	RegistrationCommandID identity.CommandID
	// Empty retains the original password-signup encoding. The only additional
	// profile is the exact username-signup origin, never a caller-selected alias.
	RegistrationOperation string
}

// EmailVerificationContributor is the native registration-link owner. Its pure
// mapper must agree with every frozen kernel field. ApplyFeature owns current
// proof, origin, callback and risk admission; only the kernel writes directory
// records. CheckFeatureCommit must recheck original admission without renewing
// it. Neither method may create sessions for this verification-only profile.
type EmailVerificationContributor interface {
	FeatureCommitContributor
	EmailVerification(identity.Command) (EmailVerificationIntent, error)
}

func invalidEmailVerification() error { return identity.InvalidInputError{Field: "email_verification"} }

// Format redacts original address and correlated account metadata.
func (EmailVerificationIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.EmailVerificationIntent(redacted)"))
}

// MarshalJSON rejects accidental disclosure of retained original intent.
func (EmailVerificationIntent) MarshalJSON() ([]byte, error) { return nil, invalidEmailVerification() }

// EmailVerificationFields returns ten owned canonical fields for the native
// confirmation command. Include all unchanged before fingerprinting. It checks
// structural bounds, not normalization, cryptography or current authority.
// A username signup adds an eleventh exact original-operation field; the empty
// legacy selection retains its original bytes and password-signup meaning.
// Only the initial pending signup email profile is supported here; session
// management, OTP, resend, replacement and address removal are distinct flows.
func EmailVerificationFields(s EmailVerificationIntent) ([]identity.FeatureField, error) {
	return emailVerificationFields(s, false)
}

func emailVerificationFields(s EmailVerificationIntent, managed bool) ([]identity.FeatureField, error) {
	c := s.Change
	i := identity.Identifier{ID: c.ID, UserID: c.UserID, Kind: identity.IdentifierEmail, CanonicalValue: s.CanonicalAddress, Version: 1}
	u := identity.User{ID: c.UserID, TenantID: c.TenantID, Status: identity.StatusActive, Version: 1}
	validVersions := c.ExpectedIdentifierVersion > 0 && c.ExpectedIdentifierVersion < ^uint64(0) && c.ExpectedVerificationVersion > 0 && c.ExpectedVerificationVersion < ^uint64(0)
	if !managed {
		validVersions = c.ExpectedIdentifierVersion == 1 && c.ExpectedVerificationVersion == 1
	}
	if u.Validate(c.TenantID) != nil || i.Validate(c.UserID) != nil || c.Action != identity.IdentifierVerify || c.Kind != "" || c.CanonicalValue != "" || c.DisplayValue != "" || c.ExpectedUserVersion == 0 || c.ExpectedUserVersion == ^uint64(0) || c.ExpectedAuthorityVersion == 0 || c.ExpectedAuthorityVersion == ^uint64(0) || !validVersions {
		return nil, invalidEmailVerification()
	}
	if _, err := identity.ParseIdentifierID(s.ComparisonProfile); err != nil {
		return nil, invalidEmailVerification()
	}
	if _, err := identity.ParseCommandID(string(s.RegistrationCommandID)); err != nil {
		return nil, invalidEmailVerification()
	}
	if s.RegistrationOperation != "" && s.RegistrationOperation != "identity.username.signup" || managed && s.RegistrationOperation != "" {
		return nil, invalidEmailVerification()
	}
	text := func(n, v string) identity.FeatureField {
		return identity.FeatureField{Name: "email-verification." + n, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v}}
	}
	number := func(n string, v uint64) identity.FeatureField {
		return identity.FeatureField{Name: "email-verification." + n, Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v}}
	}
	fields := []identity.FeatureField{text("tenant", string(c.TenantID)), text("user", string(c.UserID)), text("identifier", string(c.ID)), text("canonical-address", s.CanonicalAddress), text("comparison-profile", s.ComparisonProfile), text("registration-command", string(s.RegistrationCommandID)), number("user-version", c.ExpectedUserVersion), number("authority-version", c.ExpectedAuthorityVersion), number("identifier-version", c.ExpectedIdentifierVersion), number("verification-version", c.ExpectedVerificationVersion)}
	if s.RegistrationOperation != "" {
		fields = append(fields, text("registration-operation", s.RegistrationOperation))
	}
	return fields, nil
}

func (s EmailVerificationIntent) registrationPurpose() string {
	if s.RegistrationOperation == "" {
		return "identity.password.signup"
	}
	return s.RegistrationOperation
}

func emailVerificationCommand(p EmailVerificationContributor, command identity.Command, plan CommandPlan) (EmailVerificationIntent, error) {
	s, ok := commandFeature(command)
	if !ok || plan.Feature == nil || plan.Feature.Operation != registrationEmailVerificationOperation() || s.Operation != plan.Feature.Operation || plan.Capability == nil || plan.Lifecycle == nil || plan.Lifecycle.BeforeVersion != 1 || plan.Lifecycle.AfterVersion != 2 || plan.SubjectType != "identifier" {
		return EmailVerificationIntent{}, invalidEmailVerification()
	}
	intent, err := p.EmailVerification(command)
	if err != nil {
		return EmailVerificationIntent{}, invalidEmailVerification()
	}
	fields, err := EmailVerificationFields(intent)
	if err != nil || intent.Change.TenantID != s.Binding.TenantID || intent.Change.UserID != s.Binding.UserID || string(intent.Change.ID) != s.Binding.RecordID || intent.RegistrationCommandID == s.Binding.CommandID {
		return EmailVerificationIntent{}, invalidEmailVerification()
	}
	matched := 0
	for _, actual := range s.Fields {
		if !strings.HasPrefix(actual.Name, "email-verification.") {
			continue
		}
		found := false
		for _, expected := range fields {
			if actual.Name != expected.Name {
				continue
			}
			a, ea := encodeFeatureValue(actual.Value)
			b, eb := encodeFeatureValue(expected.Value)
			if actual.Value.Kind != expected.Value.Kind || ea != nil || eb != nil || !bytes.Equal(a, b) {
				return EmailVerificationIntent{}, invalidEmailVerification()
			}
			found = true
			matched++
			break
		}
		if !found {
			return EmailVerificationIntent{}, invalidEmailVerification()
		}
	}
	if matched != len(fields) {
		return EmailVerificationIntent{}, invalidEmailVerification()
	}
	return intent, nil
}
