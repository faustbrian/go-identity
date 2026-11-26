package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func (s *OneTapStartService) readOneTapCallbackBrowser(ctx context.Context, flow identity.PreAuthTransactionID, cookie auth.BearerCredential, keys map[uint32]session.DigestKey) (session.PreAuthTransaction, session.ProviderPreAuthTransactionSpec, session.TokenDigest, error) {
	var record session.PreAuthTransaction
	var original session.ProviderPreAuthTransactionSpec
	var digest session.TokenDigest
	if s == nil || s.config == nil || s.pool == nil || s.pool.Raw() == nil || ctx == nil {
		return record, original, digest, identity.InvalidInputError{Field: "oauth_onetap_callback"}
	}
	token, err := session.ParseToken(cookie.Token())
	if err != nil {
		return record, original, digest, identity.ForbiddenError{}
	}
	c := s.config()
	stored, err := sessionpg.ReadProviderPreAuth(ctx, s.pool.Raw(), c.Session, c.TenantID, flow, s.selected)
	if err != nil {
		return record, original, digest, err
	}
	bindings, err := stored.ProviderBindings()
	if err != nil {
		return record, original, digest, identity.ForbiddenError{}
	}
	b := bindings.Transaction.Binding
	computed, err := token.ProviderPreAuthDigest(keys[bindings.Transaction.Cookie.KeyVersion], b, s.selected)
	if err != nil || b.ID != flow || b.Intent.TenantID != c.TenantID || b.Intent.Action != oneTapStartOperationID ||
		b.Intent.Origin != c.Issuance.Origin || b.Intent.PolicyID != c.Issuance.PolicyID || b.Intent.PolicyVersion != c.Issuance.PolicyVersion ||
		stored.CheckProvider(c.Issuance.Clock.Now().UTC(), b, s.selected, computed) != nil {
		return record, original, digest, identity.ForbiddenError{}
	}
	return stored, bindings, computed, nil
}

// Intent is keyed and length-framed because the callback credential and Google
// CSRF material must never enter the journal. Browser and network admission keep
// separate owners, and the original persisted cookie digest proves possession.
func oneTapCallbackIntent(key [32]byte, browser session.TokenDigest, c onetap.Callback) [32]byte {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-oauth-onetap-callback-intent-v1\x00"))
	writeField := func(value []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(value)
	}
	var version [4]byte
	binary.BigEndian.PutUint32(version[:], browser.KeyVersion)
	writeField(version[:])
	writeField(browser.Sum[:])
	writeField([]byte(c.Origin))
	writeField([]byte(c.CSRFCookies[0]))
	writeField([]byte(c.CSRFBody[0]))
	writeField(c.Credential.IDToken)
	var out [32]byte
	mac.Sum(out[:0])
	return out
}
