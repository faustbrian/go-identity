package identity

import (
	"slices"
	"time"

	"github.com/faustbrian/go-authentication/v2"
)

// AccountUnlinkPreparationCommand freezes explicit self-unlink intent before
// its canonical one-use child grant exists. Primary is original password-proof
// metadata, not authenticated authority. The native password owner must verify
// the actual signed record, exact session and current credential/factor policy.
// Counters retain their original primary time; no copy can renew freshness.
// The selected preparation profile is single-factor password only. It neither
// downgrades an enrolled factor nor substitutes recovery or provider proof.
type AccountUnlinkPreparationCommand struct {
	Binding        CommandBinding
	Change         AccountUnlinkChange
	SessionID      string
	SessionVersion uint64
	RevokeProvider bool
	Counters       AccountUnlinkCounterContext
	Primary        authentication.ReauthenticationProof
	// FactorAuthorityVersion is the original known-empty MFA generation. A
	// retry must use the same generation, even if factors are now empty again.
	FactorAuthorityVersion uint64
	// CSRFCommitment is the native cookie synchronizer's keyed intent digest.
	// Bearer-only composition leaves it zero. This is not CSRF authority.
	CSRFCommitment [32]byte
}

type accountUnlinkPreparationState struct {
	spec    AccountUnlinkPreparationCommand
	custody func() authentication.BearerCredential
}

// NewAccountUnlinkPreparationCommand snapshots exact intent, original proof
// metadata and canonical session-bearer custody. Structural proof validation
// uses its original issuance instant, not a current clock or freshness grant.
// No I/O, signing, issuance, consumption or callback runs here. The durable
// owner must authenticate current original authority, checkpoint generated
// issuer output, and atomically persist/reserve that exact child grant before
// protected execution. Password-proof consumption belongs to the final mutation.
//
// Ordinary unlink and link accessors reject this preparation-only variant;
// a grant-free input cannot silently enter an older execution path. Copies are
// immutable for concurrent readers; input/output counter slices never alias.
func NewAccountUnlinkPreparationCommand(spec AccountUnlinkPreparationCommand, bearer authentication.BearerCredential) (Command, error) {
	if !validAccountUnlinkInput(spec.Binding, spec.Change, spec.SessionID, spec.SessionVersion) || !spec.Counters.valid() || spec.FactorAuthorityVersion == 0 {
		return Command{}, invalidAccountUnlinkPreparation()
	}
	p := spec.Primary
	if p.Proof.Method != "password" || p.Proof.Assurance != authentication.AssuranceSingleFactor {
		return Command{}, invalidAccountUnlinkPreparation()
	}
	// AccountUnlinkConfig caps the consuming age policy at fifteen minutes.
	// Testing at the original issuance instant checks framing only; native
	// current admission must enforce its actual configured age and expiry.
	use := authentication.ReauthenticationUse{
		ProofUse:  authentication.ProofUse{Tenant: string(spec.Binding.TenantID), Subject: string(spec.Binding.UserID), Purpose: "identity.password.verify", Audience: p.Proof.Audience, Now: p.Proof.IssuedAt},
		SessionID: spec.SessionID, SessionVersion: spec.SessionVersion,
		Action: "identity.account.unlink", MaximumAge: 15 * time.Minute,
	}
	if p.Validate(use) != nil {
		return Command{}, invalidAccountUnlinkPreparation()
	}
	frozen, ok := freezeAccountSessionBearer(bearer)
	if !ok {
		return Command{}, invalidAccountUnlinkPreparation()
	}
	spec.Counters.KeyVersions = slices.Clone(spec.Counters.KeyVersions)
	return Command{unlinkPreparation: &accountUnlinkPreparationState{spec: spec, custody: func() authentication.BearerCredential { return frozen }}}, nil
}

func invalidAccountUnlinkPreparation() error {
	return InvalidInputError{Field: "account_unlink_preparation"}
}

// AccountUnlinkPreparationInput lends independently owned original metadata and
// retained bearer only for this exact variant. Zero, mixed, issued-unlink and
// OAuth-link commands deny. The projection grants no current authorization,
// issuance, consumption, SQL or closure authority. It performs no I/O.
func (c Command) AccountUnlinkPreparationInput() (AccountUnlinkPreparationCommand, authentication.BearerCredential, bool) {
	if c.unlinkPreparation == nil || c.linkPreparation != nil || c.create != nil || c.update != nil || c.profile != nil || c.status != nil || c.unlink != nil || c.link != nil || c.accountCounters != nil || c.identifier != nil || c.identifierProof != nil || c.feature != nil || c.privacy != nil || c.privacyProof != nil {
		return AccountUnlinkPreparationCommand{}, authentication.BearerCredential{}, false
	}
	spec := c.unlinkPreparation.spec
	spec.Counters.KeyVersions = slices.Clone(spec.Counters.KeyVersions)
	return spec, c.unlinkPreparation.custody(), true
}
