package identity

import (
	"encoding/base64"
	"slices"
	"strings"

	"github.com/faustbrian/go-authentication/v2"
)

// AccountLinkPreparationCommand is original explicit-self OAuth linking intent,
// before provider exchange establishes a subject or a signed link grant exists.
// Binding is the final root account-link scope, never a feature operation or a
// placeholder subject. FlowFingerprint is native flow intent, not proof of raw
// state possession. Provider/configuration/session/counters must be independently
// checked against current authority by the selected native owner. Construction
// grants no provider identity, fresh session, permission or execution authority.
type AccountLinkPreparationCommand struct {
	Binding               CommandBinding
	ProviderID            string
	ProviderConfigVersion uint64
	FlowID                string
	FlowFingerprint       [32]byte
	SessionID             string
	SessionVersion        uint64
	Counters              AccountLinkCounterContext
}

type accountLinkPreparationState struct {
	spec    AccountLinkPreparationCommand
	custody func() (OAuthCallbackInput, authentication.BearerCredential)
}

// NewAccountLinkPreparationCommand freezes exact final scope and original
// callback/session custody. Only explicit self-user links in identity-account v1
// are admitted. The real session bearer uses the existing canonical 32..64-byte
// transport; raw RP state is not a capability or an authentication bearer.
// Callback aliases share terminal Destroy, and input/output counter slices do
// not alias. Keep custody live through bounded preparation, then Destroy it.
//
// Legacy command accessors deny this preparation-only variant. A native adapter
// must explicitly bind all original inputs in the existing keyed command claim,
// acknowledge state reservation before exchange, and attach authenticated output
// without changing that original claim. This constructor performs no I/O or
// callbacks and never permits ordinary link execution without a signed proof.
func NewAccountLinkPreparationCommand(spec AccountLinkPreparationCommand, input OAuthCallbackInput, bearer authentication.BearerCredential) (Command, error) {
	b := spec.Binding
	if !validCommandBinding(b) || b.OperationID != "identity.account.link-token" || b.SchemaID != "identity-account" || b.SchemaVersion != 1 || b.LinkMode != AccountLinkExplicit || !validLinkActor(b.LinkMode, b.ActorKind, b.ActorID, b.UserID) || !validDirectoryID(spec.ProviderID) || spec.ProviderConfigVersion == 0 || !validDirectoryID(spec.FlowID) || spec.FlowFingerprint == ([32]byte{}) || !validDirectoryID(spec.SessionID) || spec.SessionVersion == 0 || !spec.Counters.valid() || !input.live() {
		return Command{}, invalidAccountLinkPreparation()
	}
	wire := bearer.Token()
	if len(wire) < 43 || len(wire) > 86 {
		return Command{}, invalidAccountLinkPreparation()
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire)
	defer clear(raw)
	if err != nil || len(raw) < 32 || len(raw) > 64 || base64.RawURLEncoding.EncodeToString(raw) != wire {
		return Command{}, invalidAccountLinkPreparation()
	}
	spec.Counters.KeyVersions = slices.Clone(spec.Counters.KeyVersions)
	frozen := authentication.NewBearerCredential(strings.Clone(wire))
	return Command{linkPreparation: &accountLinkPreparationState{spec: spec, custody: func() (OAuthCallbackInput, authentication.BearerCredential) { return input, frozen }}}, nil
}

func invalidAccountLinkPreparation() error {
	return InvalidInputError{Field: "account_link_preparation"}
}

// AccountLinkPreparationInput returns an independently owned original metadata
// projection and bounded borrowed callback/session custody only for this exact
// variant. Metadata remains readable after Destroy but callback Use then denies.
// Returned values are trusted adapter input, never diagnostics, recovery input,
// proof verification or execution authority. Zero/mixed/other commands deny.
func (c Command) AccountLinkPreparationInput() (AccountLinkPreparationCommand, OAuthCallbackInput, authentication.BearerCredential, bool) {
	if c.linkPreparation == nil || c.create != nil || c.update != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.link != nil || c.linkCounters != nil || c.identifier != nil || c.identifierProof != nil || c.feature != nil || c.privacy != nil || c.privacyProof != nil {
		return AccountLinkPreparationCommand{}, OAuthCallbackInput{}, authentication.BearerCredential{}, false
	}
	spec := c.linkPreparation.spec
	spec.Counters.KeyVersions = slices.Clone(spec.Counters.KeyVersions)
	input, bearer := c.linkPreparation.custody()
	return spec, input, bearer, true
}
