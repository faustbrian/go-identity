package postgres

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const upgradeGuestDigestField = "anonymous.guest-session.digest"
const upgradeResultDigestField = "session.upgrade-result.digest"

// AnonymousUpgradeSessionFields binds both complete original guest and
// prospective permanent records through the existing canonical session codec.
// Three flattened sessions exceed the shared 128-field command limit; retain
// the target's required source-session vocabulary and bind these two records by
// domain-separated commitments instead. This is not a JSON escape or authority:
// the native owner's authenticated preparation must retain the complete records,
// prove possession/current owners and compare them again inside sole Work.
// No bearer or positive-validity lease is encoded. Returned fields are owned.
func AnonymousUpgradeSessionFields(guest, permanent session.Session) ([]identity.FeatureField, error) {
	g, ge := guest.Bindings()
	p, pe := permanent.Bindings()
	if ge != nil || pe != nil || g.TenantID != p.TenantID || g.UserID == p.UserID || g.Authentication.Kind != session.AuthenticationAnonymous || p.Authentication.Kind != session.AuthenticationVerified || p.Authentication.Proof.Method != "password" || p.Authentication.Proof.Assurance != authentication.AssuranceSingleFactor || p.Authentication.Proof.Purpose != "session-issue" || p.Version != 1 || p.FamilyVersion != 1 || !p.LastActivityAt.Equal(p.IssuedAt) {
		return nil, session.ErrInvalidSessionCommand
	}
	gr, _ := g.Remember.Bindings()
	pr, _ := p.Remember.Bindings()
	if gr != pr {
		return nil, session.ErrInvalidSessionCommand
	}
	for _, r := range []session.Session{guest, permanent} {
		s, _ := r.Bindings()
		a, err := s.Authority.Bindings()
		_, continued := r.CredentialContinuation()
		if err != nil || a.Organization.Present || a.Factor.Present || a.Passkey.Present || continued || r.MFAAuthentication() != (session.MFAAuthentication{}) {
			return nil, session.ErrInvalidSessionCommand
		}
	}
	gd, err := anonymousUpgradeSessionDigest("guest", guest)
	if err != nil {
		return nil, err
	}
	pd, err := anonymousUpgradeSessionDigest("result", permanent)
	if err != nil {
		return nil, err
	}
	return []identity.FeatureField{
		{Name: upgradeGuestDigestField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: gd[:]}},
		{Name: upgradeResultDigestField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: pd[:]}},
	}, nil
}

func anonymousUpgradeSessionDigest(role string, record session.Session) ([32]byte, error) {
	wire, _, err := encodeRecord(record)
	if err != nil {
		return [32]byte{}, session.ErrInvalidSessionCommand
	}
	h := sha256.New()
	_, _ = h.Write([]byte("identity/session/anonymous-upgrade/" + role + "/v1\x00"))
	_, _ = h.Write(wire)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// ValidateAnonymousUpgradeSessionIntent compares complete retained records to
// their exact closed command commitments without IO, parsing or freshness
// renewal. Unknown fields in these two owned namespaces deny. Target credential
// and guest possession/current authority must still be checked by their native
// owners. This cannot reconstruct records, authenticate or authorize issuance.
func ValidateAnonymousUpgradeSessionIntent(command identity.Command, guest, permanent session.Session) error {
	f, ok := command.Feature()
	op := identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	g, ge := guest.Bindings()
	p, pe := permanent.Bindings()
	if !ok || ge != nil || pe != nil || f.Operation != op || f.Binding.ValidateFor(op) != nil || f.Binding.TenantID != g.TenantID || f.Binding.UserID != p.UserID || f.Binding.RecordID != string(g.UserID) || f.Binding.ActorKind != authorization.SubjectUser || string(f.Binding.ActorID) != string(p.UserID) {
		return session.ErrInvalidSessionCommand
	}
	expected, err := AnonymousUpgradeSessionFields(guest, permanent)
	if err != nil {
		return err
	}
	matched := 0
	for _, field := range f.Fields {
		if !strings.HasPrefix(field.Name, "anonymous.guest-session.") && !strings.HasPrefix(field.Name, "session.upgrade-result.") {
			continue
		}
		found := false
		for _, want := range expected {
			if field.Name != want.Name {
				continue
			}
			if field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 || subtle.ConstantTimeCompare(field.Value.Bytes, want.Value.Bytes) != 1 {
				return session.ErrInvalidSessionCommand
			}
			found = true
			matched++
		}
		if !found {
			return session.ErrInvalidSessionCommand
		}
	}
	if matched != len(expected) {
		return session.ErrInvalidSessionCommand
	}
	return nil
}
