package identity

import (
	"github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
)

type samlIDPConfirmationCommandState struct {
	browserCookie authentication.BearerCredential
	synchronizer  authentication.BearerCredential
}

// NewFeatureSAMLIDPConfirmationCommand retains the exact browser cookie and
// independent form synchronizer for a linked user's pending unsolicited SAML
// confirmation. A trusted native adapter supplies the service-account actor,
// resolved user and pending record. Neither value may be reused as the other;
// both must be canonical unpadded base64url of 32 bytes.
//
// This is structural custody, not browser or provider authentication, verified
// intent, a session or permission to consume. The native owner must recheck the
// exact pending record, original deadline, current authority and both submitted
// values before committing one-use and session effects together. Invalid input
// returns a zero command and a redacted error. No I/O or callbacks run.
func NewFeatureSAMLIDPConfirmationCommand(spec FeatureCommandSpec, browserCookie, synchronizer authentication.BearerCredential) (Command, error) {
	if !samlIDPConfirmationOperation(spec.Operation) || spec.Binding.ActorKind != authorization.SubjectServiceAccount {
		return Command{}, invalidFeatureCommand()
	}
	cookie, err := freezeFeatureBearer(browserCookie, 32, 32)
	if err != nil {
		return Command{}, err
	}
	form, err := freezeFeatureBearer(synchronizer, 32, 32)
	if err != nil {
		return Command{}, err
	}
	if cookie.Token() == form.Token() {
		return Command{}, invalidFeatureCommand()
	}
	c, err := NewFeatureCommand(spec)
	if err != nil {
		return Command{}, err
	}
	// As with other compound feature commands, formatting the internal state
	// cannot traverse closure custody to recover bearer bytes.
	c.feature.samlIDPConfirmation = func() samlIDPConfirmationCommandState {
		return samlIDPConfirmationCommandState{browserCookie: cookie, synchronizer: form}
	}
	return c, nil
}

// SAMLIDPConfirmationFeature returns a detached structural projection of the
// exact joint-custody command. It carries neither submitted credential and
// cannot reconstruct either. Use only in the selected trusted native adapter;
// generic Feature deliberately rejects this command.
func (c Command) SAMLIDPConfirmationFeature() (FeatureCommandSpec, bool) {
	if !c.isSAMLIDPConfirmation() {
		return FeatureCommandSpec{}, false
	}
	return cloneFeatureSpec(c.feature.spec), true
}

// SAMLIDPConfirmationCustody lends both original values to the trusted native
// comparison owner without granting authority. Zero, ordinary and mixed
// commands return zero values and false. Immutable commands support concurrent
// reads; discard borrowed copies after use and never log or persist Token().
func (c Command) SAMLIDPConfirmationCustody() (browserCookie, synchronizer authentication.BearerCredential, ok bool) {
	if !c.isSAMLIDPConfirmation() {
		return authentication.BearerCredential{}, authentication.BearerCredential{}, false
	}
	state := c.feature.samlIDPConfirmation()
	return state.browserCookie, state.synchronizer, true
}

func samlIDPConfirmationOperation(operation FeatureOperation) bool {
	return operation == (FeatureOperation{
		Owner: "sso/saml", OperationID: "identity.sso.saml-idp-init", SchemaID: "sso-enterprise-saml-idp-init-v1",
		SchemaVersion: 1, RecordRequirement: FeatureRecordRequired, SubjectRequirement: FeatureSubjectUser,
	})
}

func (c Command) isSAMLIDPConfirmation() bool {
	f := c.feature
	if f == nil || f.samlIDPConfirmation == nil || !samlIDPConfirmationOperation(f.spec.Operation) {
		return false
	}
	return c.create == nil && c.update == nil && c.profile == nil && c.status == nil && c.unlink == nil && c.link == nil &&
		c.accountCounters == nil && c.linkPreparation == nil && c.unlinkPreparation == nil && c.identifier == nil &&
		c.identifierProof == nil && c.privacy == nil && c.privacyProof == nil && f.code == nil && f.recovery == nil &&
		f.preAuthCookie == nil && f.sessionToken == nil && f.passwordHash == nil && f.passwordChange == nil &&
		f.passwordReset == nil && f.passwordResetInput == nil && f.passwordSignin == nil && f.passwordSignup == nil &&
		f.passwordSignupInput == nil && f.phonePasswordReset == nil
}
