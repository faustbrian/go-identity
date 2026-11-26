package postgres

import (
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// OneTapCallbackSessionFields freezes the complete prospective single-factor
// session for an existing linked Google account. The representation is the
// existing provider session record; it creates no account, proof or session.
// The One Tap native owner separately proves its original provider, browser
// and one-use capability and includes these fields in the protected command.
func OneTapCallbackSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return providerSigninSessionFields(record)
}

// OneTapCallbackSession restores the prospective session only for the exact
// One Tap callback contract with its original anonymous flow and pre-auth
// credential. It does not authenticate the projection or permit issuance.
func OneTapCallbackSession(command identity.Command) (session.Session, error) {
	feature, ok := command.Feature()
	if !ok || feature.Binding.RecordID != feature.Binding.AnonymousFlowID {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return providerSigninSession(command, kernel.OneTapCallbackOperation())
}
