package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// Original request correlation precedes primary preparation, providers and
// hashing. Only purpose-bound keyed digests enter the existing request-key
// mapping. Neither plaintext password nor bearer is serialized or retained.
// The configured identity commits the immutable service policy, not a caller-
// selected revision. This is correlation, never field approval or admission.
func (*Repository) signupRequestIntent(ctx context.Context, r password.SignupRequest, key, profile [32]byte, policy password.RegistrationPolicy) (identity.RequestIntent, error) {
	if ctx == nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	if ctx.Err() != nil {
		return identity.RequestIntent{}, ctx.Err()
	}
	if key == ([32]byte{}) || profile == ([32]byte{}) || r.Validate() != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	if err := policy.CheckPassword(r.Password); err != nil {
		return identity.RequestIntent{}, err
	}
	digest := func(purpose string, raw []byte) []byte {
		mac := hmac.New(sha256.New, key[:])
		_, _ = mac.Write([]byte("golib.identity.password.signup.intent.v1\x00" + purpose + "\x00"))
		_, _ = mac.Write(binary.BigEndian.AppendUint64(nil, uint64(len(raw))))
		_, _ = mac.Write(raw)
		return mac.Sum(nil)
	}
	var candidate []byte
	if err := r.Password.Use(func(raw []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if len(raw) < int(policy.MinimumBytes) || len(raw) > int(policy.MaximumBytes) {
			return password.ErrInvalidPassword
		}
		candidate = digest("password", raw)
		return nil
	}); err != nil {
		if ctx.Err() != nil {
			return identity.RequestIntent{}, ctx.Err()
		}
		return identity.RequestIntent{}, password.ErrInvalidPassword
	}
	defer clear(candidate)
	remember, err := r.RememberPolicy.Bindings()
	if err != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	fields := slices.Clone(r.AllowedFields)
	slices.SortFunc(fields, func(a, b identity.AttributeUpdate) int { return strings.Compare(a.Name, b.Name) })
	// Shape is bounded before this allocation by SignupRequest.Validate. Field
	// schema/authorization/defaults remain the identity processor's later work.
	frame, err := json.Marshal(struct {
		Tenant, Actor, ActorKind, Action string
		Flow, Address, Origin, Callback  string
		Network, Device                  string
		Remember                         session.RememberPolicySpec
		Policy                           password.RegistrationPolicy
		Fields                           []identity.AttributeUpdate
		// Omission preserves the legacy password-only request commitment. Raw
		// spelling remains bound even when two names have the same canonical form.
		Username string `json:",omitempty"`
	}{string(r.TenantID), string(r.Caller.Request.Subject.ID), string(r.Caller.Request.Subject.Kind), string(r.Caller.Request.Action), string(r.PreAuthID), string(r.Email), r.Origin, r.CallbackURL, r.Network, r.Device, remember, policy, fields, r.Username})
	defer clear(frame)
	if err != nil {
		return identity.RequestIntent{}, password.ErrPasswordWork
	}
	if ctx.Err() != nil {
		return identity.RequestIntent{}, ctx.Err()
	}
	return identity.NewRequestIntent([]identity.FeatureField{
		{Name: "profile", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: profile[:]}},
		{Name: "password", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: candidate}},
		{Name: "cookie", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("cookie", []byte(r.Cookie.Token()))}},
		{Name: "input", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest("input", frame)}},
	})
}
