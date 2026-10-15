package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// EmailChangeNotificationConfig selects a non-secret old-address notice after
// atomic new-address confirmation. The existing Delivery.Owner stages it; no
// sender runs under SQL locks. Renderer is borrowed, versioned and concurrent-
// safe. Template receives no bearer or candidate address. Zero denies.
type EmailChangeNotificationConfig struct {
	Renderer        *delivery.TemplateRenderer
	TemplateID      string
	TemplateVersion uint32
	ProviderVersion uint64
	Locales         []string
	ScopeKey        [32]byte
	Timeout         time.Duration
}

func (c EmailChangeNotificationConfig) validate() error {
	if c.Renderer == nil || !reauthenticationText(c.TemplateID, 128) || c.TemplateVersion == 0 || c.ProviderVersion == 0 || c.ScopeKey == ([32]byte{}) || c.Timeout <= 0 || c.Timeout > 5*time.Second || len(c.Locales) == 0 || len(c.Locales) > 16 {
		return password.ErrPasswordWork
	}
	return nil
}

// Format omits notification keys and borrowed runtime composition.
func (EmailChangeNotificationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordpostgres.EmailChangeNotificationConfig(redacted)"))
}

// MarshalJSON denies implicit configuration export.
func (EmailChangeNotificationConfig) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit configuration export.
func (EmailChangeNotificationConfig) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

type emailChangeNotificationProfile struct {
	Template        string
	TemplateVersion uint32
	ProviderVersion uint64
	Locales         []string
}

func changeNotificationProfile(c *EmailChangeNotificationConfig) *emailChangeNotificationProfile {
	if c == nil {
		return nil
	}
	return &emailChangeNotificationProfile{c.TemplateID, c.TemplateVersion, c.ProviderVersion, c.Locales}
}

func kernelPrevious(p email.PreviousAddress, profile email.ChangeProfile) kernel.ManagedEmailPrevious {
	return kernel.ManagedEmailPrevious{ID: p.ID, CanonicalAddress: p.CanonicalAddress, IdentifierVersion: p.IdentifierVersion, VerificationVersion: p.VerificationVersion, Primary: p.Primary, AllowInitialPrimary: profile.CurrentAddress == email.PrimaryOrSoleVerifiedAddress}
}

func (s *EmailManagementService) prepareChangeNotification(ctx context.Context, b identity.CommandBinding, spec email.ManagedVerificationSpec) (deliverypg.PreparedDelivery, error) {
	if s.config().ChangeNotification == nil || spec.Previous.ID == "" {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	c := s.config().ChangeNotification
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	// Recipient digest uses original logical intent, not randomized ciphertext or
	// the retry clock. The delivery owner's stable effect ID handles replay.
	wire, err := json.Marshal(struct {
		Binding                     identity.CommandBinding
		PreviousID, PreviousAddress string
	}{b, string(spec.Previous.ID), spec.Previous.CanonicalAddress})
	defer clear(wire)
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	h := hmac.New(sha256.New, c.ScopeKey[:])
	_, _ = h.Write([]byte("identity-email-change-old-notice-v1\x00"))
	_, _ = h.Write(wire)
	recipient := delivery.Recipient{Channel: delivery.ChannelEmail, Address: spec.Previous.CanonicalAddress, ScopeDigest: hex.EncodeToString(h.Sum(nil))}
	message := delivery.Message{Purpose: "identity.email.change-notification", Channel: delivery.ChannelEmail, Recipient: recipient, TemplateID: c.TemplateID, TemplateVersion: uint64(c.TemplateVersion), LocaleChain: slices.Clone(c.Locales)}
	rendered, err := c.Renderer.Render(ctx, message)
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	return s.config().Delivery.Owner.Prepare(ctx, b, []deliverypg.IntentInput{{Purpose: message.Purpose, SubjectID: string(b.UserID), TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, ProviderConfigVersion: c.ProviderVersion, ExpiresAt: spec.ExpiresAt, Recipient: recipient, Rendered: rendered}})
}
