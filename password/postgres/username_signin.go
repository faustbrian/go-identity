package passwordpostgres

import (
	"context"
	"errors"
	"strconv"

	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/username"
)

func (s *SigninService) canonicalSigninIdentifier(ctx context.Context, raw identifier.Input) (string, error) {
	if s.c.Username != nil {
		name, err := s.c.Username.Canonicalize(ctx, string(raw))
		if err != nil {
			return string(raw), err
		}
		return name.Record().Canonical, nil
	}
	address, err := s.address.Parse(email.AddressInput(raw))
	if err != nil {
		return string(raw), err
	}
	return address.Canonical().Record().Value, nil
}

// A username is neither a delivery channel nor evidence of a verified mailbox.
// Resolve both actual database records independently, and retain their complete
// original epochs. The protected Work fences both before any commit.
func (s *SigninService) resolveUsernameSignin(ctx context.Context, tenant identity.TenantID, canonical string) (kernel.UsernameRecord, kernel.RecipientRecord, error) {
	query := kernel.UsernameQuery{TenantID: tenant, CanonicalValue: canonical, NormalizationProfile: string(username.ProfileID), NormalizationVersion: username.ProfileVersion}
	name, err := s.domain.ResolveUsername(ctx, query)
	if err != nil {
		return name, kernel.RecipientRecord{}, err
	}
	neutral := kernel.RecipientRecord{Suppressed: true}
	if name.Suppressed {
		return name, neutral, nil
	}
	state, err := s.domain.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: tenant, UserID: name.User.ID, MaximumIdentifiers: 128})
	if errors.Is(err, identity.ErrUserAbsent) {
		return name, neutral, nil
	}
	if err != nil {
		return name, kernel.RecipientRecord{}, err
	}
	if state.User != name.User || state.AuthorityVersion != name.IdentifierAuthorityVersion {
		return name, neutral, nil
	}
	for _, i := range state.Identifiers {
		// Registration confirmation verifies an email without establishing a
		// primary address. Match the password signin requirement of a verified
		// mailbox; making it primary is a separate managed-email operation.
		if i.Kind != identity.IdentifierEmail || !i.Verified {
			continue
		}
		recipient, err := s.domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: tenant, Kind: identity.IdentifierEmail, CanonicalValue: i.CanonicalValue, Eligibility: kernel.RecipientVerified})
		if err != nil {
			return name, kernel.RecipientRecord{}, err
		}
		if recipient.Suppressed || recipient.User != name.User || recipient.Identifier.ID != i.ID || recipient.UserAuthorityVersion != name.UserAuthorityVersion || recipient.IdentifierAuthorityVersion != name.IdentifierAuthorityVersion || recipient.CredentialAuthorityVersion != name.CredentialAuthorityVersion {
			return name, neutral, nil
		}
		return name, recipient, nil
	}
	return name, neutral, nil
}

func usernameSigninFields(r kernel.UsernameRecord) []identity.FeatureField {
	text := func(name, value string) identity.FeatureField {
		return identity.FeatureField{Name: "password.username." + name, Value: identity.FeatureValue{Kind: identity.FeatureText, Text: value}}
	}
	return []identity.FeatureField{text("identifier", string(r.Identifier.ID)), text("canonical", r.Identifier.CanonicalValue), text("profile", r.Identifier.NormalizationProfile), text("profile-version", strconv.FormatUint(uint64(r.Identifier.NormalizationVersion), 10)), text("identifier-version", strconv.FormatUint(r.Identifier.Version, 10))}
}

func (p *signinPhase) validateUsernameFields() error {
	if p.operation.OperationID != "identity.username.signin" {
		if p.username != (kernel.UsernameRecord{}) {
			return password.ErrPasswordWork
		}
		return nil
	}
	if p.username.Validate() != nil || p.username.Suppressed || p.username.User != p.recipient.User || p.username.UserAuthorityVersion != p.recipient.UserAuthorityVersion || p.username.IdentifierAuthorityVersion != p.recipient.IdentifierAuthorityVersion || p.username.CredentialAuthorityVersion != p.recipient.CredentialAuthorityVersion || p.factorVersion == 0 {
		return password.ErrPasswordWork
	}
	return nil
}
