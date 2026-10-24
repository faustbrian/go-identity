package reference

import (
	"context"

	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
)

// ConditionalAuthenticationOptions selects outer conditional presentation of
// genuine discoverable options. Original native discovery policy, browser flow,
// risk, remember choice and expiry remain authoritative. Graph startup, tenant
// and lifetime guards are unchanged; completion uses DiscoverableSignin.
// This does not enable HTTP or prove browser support or actual mediation.
func (f *PasskeyService) ConditionalAuthenticationOptions(ctx context.Context, r native.DiscoverableSigninRequest) (passkey.ConditionalAssertionOptions, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return passkey.ConditionalAssertionOptions{}, err
	}
	defer done()
	return f.state.features.passkey.signin.ConditionalAuthenticationOptions(w, r)
}

// KeyedConditionalAuthenticationOptions preserves the same original keyed
// discoverable command across ordinary/conditional presentation. Only the
// fresh acknowledged winner can reveal options; retries/recovery return native
// metadata without a challenge or session. No new durable mode is introduced.
func (f *PasskeyService) KeyedConditionalAuthenticationOptions(ctx context.Context, r passkey.KeyedDiscoverableOptionsRequest) (passkey.KeyedConditionalOptionsResult, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return passkey.KeyedConditionalOptionsResult{}, err
	}
	defer done()
	return f.state.features.passkey.signin.KeyedConditionalAuthenticationOptions(w, r)
}
