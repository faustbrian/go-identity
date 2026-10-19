package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func (s *phoneChangeService) prepareChangeNotice(ctx context.Context, b identity.CommandBinding, i kernel.PhoneChangeIntent, at time.Time) (deliverypg.PreparedDelivery, error) {
	n := s.config().Notice
	frame, err := json.Marshal([]string{string(b.TenantID), string(b.UserID), i.PreviousNumber, i.PreviousNormalizationProfile})
	if err != nil {
		return deliverypg.PreparedDelivery{}, password.ErrPasswordWork
	}
	key := s.config().IntentKey
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-phone-change-notice-recipient-v1\x00"))
	_, _ = mac.Write(frame)
	clear(frame)
	recipient := delivery.Recipient{Channel: delivery.ChannelSMS, Address: i.PreviousNumber, ScopeDigest: hex.EncodeToString(mac.Sum(nil))}
	message := delivery.Message{Purpose: "identity.phone.change-notification", Channel: delivery.ChannelSMS, Recipient: recipient, TemplateID: n.TemplateID, TemplateVersion: uint64(n.TemplateVersion), LocaleChain: n.LocaleChain}
	rendered, err := s.renderer.Render(ctx, message)
	if err != nil {
		return deliverypg.PreparedDelivery{}, err
	}
	return s.notices.Prepare(ctx, b, []deliverypg.IntentInput{{EffectIndex: 0, Purpose: message.Purpose, SubjectID: string(b.UserID), TemplateID: n.TemplateID, TemplateVersion: n.TemplateVersion, ProviderConfigVersion: n.ProviderVersion, ExpiresAt: at.Add(n.TTL).UTC().Truncate(time.Microsecond), Recipient: recipient, Rendered: rendered}})
}
