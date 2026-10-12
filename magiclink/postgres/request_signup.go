package magiclinkpostgres

import (
	"context"
	"fmt"
	"slices"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/magiclink"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// SignupConfig freezes prospective account schema and kernel retirement policy.
// It is trusted server configuration, never an anonymous request field. The
// request allocates IDs only in acknowledged generation; no account is created
// until the original link is consumed under mailbox, risk and current authority.
// Construction copies retained keys. Do not log or export configuration.
type SignupConfig struct {
	SchemaID      string
	SchemaVersion uint32
	Domain        kernel.MagicLinkRegistrationDomainConfig
}

// Format redacts retained identifier keys and configuration.
func (SignupConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("magiclinkpostgres.SignupConfig(redacted)"))
}

// MarshalJSON prevents implicit export of key-bearing configuration.
func (SignupConfig) MarshalJSON() ([]byte, error) { return nil, invalid() }

type signupProfile struct {
	Schema, Comparison string
	SchemaVersion      uint32
	MailboxVersion     uint64
	CurrentKeyVersion  uint32
	RetainedVersions   []uint32
}

func (c SignupConfig) profile() *signupProfile {
	versions := make([]uint32, 0, len(c.Domain.RetainedIdentifierKeys))
	for version := range c.Domain.RetainedIdentifierKeys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return &signupProfile{c.SchemaID, c.Domain.ComparisonProfile, c.SchemaVersion, c.Domain.EmailPossessionPolicyVersion, c.Domain.CurrentIdentifierKeyVersion, versions}
}

// Called only by original acknowledged generation after private preparation
// selection. Future IDs are not current user/factor authority. The complete
// intent then travels through the existing encrypted original-output journal.
func (p *requestPhase) prepareProspective(ctx context.Context, generation uint64) error {
	if ctx == nil || ctx.Err() != nil || p == nil || p.service == nil || p.service.config == nil || generation == 0 || !p.prospectiveAvailable || p.selected.prospective != nil || !p.selected.recipient.Suppressed || p.selected.factor != 0 || p.request.Intent != magiclink.SignupIfAllowed {
		return invalid()
	}
	c := p.service.config().Signup
	original, ok := p.original.Feature()
	if c == nil || !ok || original.Operation != requestOperation() || p.canonical != p.selected.recipient.Query.CanonicalValue {
		return invalid()
	}
	user, err := identity.NewSubjectID()
	if err != nil {
		return err
	}
	id, err := identity.NewSubjectID()
	if err != nil {
		return err
	}
	b := original.Binding
	b.OperationID, b.AnonymousFlowID, b.UserID = "identity.user.create", "", identity.UserID(user)
	b.SchemaID, b.SchemaVersion = c.SchemaID, c.SchemaVersion
	intent := kernel.MagicLinkRegistrationIntent{Creation: identity.CreateUserCommand{Binding: b, Status: identity.StatusActive}, Identifier: identity.Identifier{ID: identity.IdentifierID(id), UserID: identity.UserID(user), Kind: identity.IdentifierEmail, CanonicalValue: p.canonical, DisplayValue: string(p.request.Email), Version: 1}, ComparisonProfile: c.Domain.ComparisonProfile, EmailPossessionPolicyVersion: c.Domain.EmailPossessionPolicyVersion}
	if _, err := kernel.MagicLinkRegistrationDigest(intent); err != nil {
		return err
	}
	p.selected.prospective = &intent
	return nil
}
