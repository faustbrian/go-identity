package postgres

import (
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// MapUpdateRequest binds exact source, label, original exclusive deadline and
// transport into the sole kernel intent. It neither restores opaque custody
// nor authorizes execution. The native executor must validate the original
// request against its exact authenticating reader before reservation/commit.
func MapUpdateRequest(request session.UpdateCommandRequest) (identity.Command, error) {
	command, ok := request.Command()
	u, update := command.Update()
	if !ok || !update || !sessionReadTime(request.ValidUntil()) || request.Transport() != session.CredentialCookie && request.Transport() != session.CredentialBearer {
		return identity.Command{}, session.ErrInvalidSessionCommand
	}
	mapped, err := mapSessionRecord(u.Binding, session.UpdateOperation(), u.Source)
	if err != nil {
		return identity.Command{}, err
	}
	p, _ := mapped.Feature()
	p.Fields = append(p.Fields,
		identity.FeatureField{Name: "metadata.label", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: u.DeviceLabel}},
		identity.FeatureField{Name: "caller.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: request.ValidUntil().UTC().Format(storedTimeLayout)}},
		identity.FeatureField{Name: "caller.transport", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(request.Transport())}},
	)
	result, err := identity.NewFeatureCommand(p)
	if err != nil {
		return identity.Command{}, err
	}
	if _, _, _, err = nativeUpdateIntent(result); err != nil {
		return identity.Command{}, err
	}
	return result, nil
}

// Structural reconstruction never resets the original admission. The core
// constructor derives the sole allowed successor, so mapped fields cannot
// override authentication, activity, lookup or unrelated authority.
func nativeUpdateIntent(command identity.Command) (session.SessionCommand, time.Time, session.CredentialKind, error) {
	fail := func() (session.SessionCommand, time.Time, session.CredentialKind, error) {
		return session.SessionCommand{}, time.Time{}, 0, session.ErrInvalidSessionCommand
	}
	p, ok := command.Feature()
	if !ok || p.Operation != session.UpdateOperation() {
		return fail()
	}
	source := p
	source.Fields = nil
	values := make(map[string]identity.FeatureValue, 3)
	for _, f := range p.Fields {
		if strings.HasPrefix(f.Name, "metadata.") || strings.HasPrefix(f.Name, "caller.") {
			values[f.Name] = f.Value
		} else {
			source.Fields = append(source.Fields, f)
		}
	}
	mapped, err := identity.NewFeatureCommand(source)
	if err != nil {
		return fail()
	}
	b, original, err := nativeSessionRecord(mapped, session.UpdateOperation())
	if err != nil || len(values) != 3 {
		return fail()
	}
	label, l := values["metadata.label"]
	deadline, d := values["caller.valid-until"]
	transport, k := values["caller.transport"]
	until, err := time.Parse(storedTimeLayout, deadline.Text)
	if !l || !d || !k || label.Kind != identity.FeatureText || deadline.Kind != identity.FeatureText || transport.Kind != identity.FeatureUint64 || err != nil || !sessionReadTime(until) || until.UTC().Format(storedTimeLayout) != deadline.Text || transport.Uint64 != uint64(session.CredentialCookie) && transport.Uint64 != uint64(session.CredentialBearer) {
		return fail()
	}
	native, err := session.NewUpdateCommand(b, original, label.Text)
	if err != nil {
		return fail()
	}
	s, _ := original.Bindings()
	life, err := original.Lifetime(s.LastActivityAt)
	if err != nil || !until.After(s.IssuedAt) || until.After(life.ExpiresAt) {
		return fail()
	}
	return native, until, session.CredentialKind(transport.Uint64), nil
}
