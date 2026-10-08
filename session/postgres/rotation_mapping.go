package postgres

import (
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// MapRotationRequest binds the complete original record, exact permitted
// successor, original exclusive admission and transport to the keyed command
// intent. It performs no IO and grants no execution authority. The owned
// executor must validate the opaque request against its configured reader
// before reservation and commit; this projection cannot replace that custody.
// Successor deltas use the same canonical scalar vocabulary as the source,
// avoiding a second arbitrary JSON record or duplicated authority vector.
func MapRotationRequest(request session.RotationRequest) (identity.Command, error) {
	command, ok := request.Command()
	r, rotation := command.Rotation()
	if !ok || !rotation || !sessionReadTime(request.ValidUntil()) || (request.Transport() != session.CredentialCookie && request.Transport() != session.CredentialBearer) {
		return identity.Command{}, session.ErrInvalidSessionCommand
	}
	mapped, err := mapSessionRecord(r.Binding, session.RotateOperation(), r.Source)
	if err != nil {
		return identity.Command{}, err
	}
	next, _ := r.Successor.Bindings()
	projection, _ := mapped.Feature()
	projection.Fields = append(projection.Fields,
		identity.FeatureField{Name: "successor.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: next.Version}},
		identity.FeatureField{Name: "successor.lookup.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(next.Lookup.KeyVersion)}},
		identity.FeatureField{Name: "successor.lookup.digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: next.Lookup.Sum[:]}},
		identity.FeatureField{Name: "successor.activity", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: next.LastActivityAt.UTC().Format(storedTimeLayout)}},
		identity.FeatureField{Name: "caller.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: request.ValidUntil().UTC().Format(storedTimeLayout)}},
		identity.FeatureField{Name: "caller.transport", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(request.Transport())}},
	)
	projection.Fields = appendCSRFFields(projection.Fields, "successor.", r.Successor)
	result, err := identity.NewFeatureCommand(projection)
	if err != nil {
		return identity.Command{}, err
	}
	if _, _, _, err = nativeRotationIntent(result); err != nil {
		return identity.Command{}, err
	}
	return result, nil
}

// Reconstruction grants no custody and cannot refresh the original deadline.
// Only the four permitted successor deltas are admitted. All other values are
// inherited unchanged from the exact source, including historical sign-in proof.
func nativeRotationIntent(command identity.Command) (session.SessionCommand, time.Time, session.CredentialKind, error) {
	fail := func() (session.SessionCommand, time.Time, session.CredentialKind, error) {
		return session.SessionCommand{}, time.Time{}, 0, session.ErrInvalidSessionCommand
	}
	projection, ok := command.Feature()
	if !ok || projection.Operation != session.RotateOperation() {
		return fail()
	}
	source := projection
	source.Fields = nil
	deltas := make(map[string]identity.FeatureValue, 6)
	for _, f := range projection.Fields {
		if strings.HasPrefix(f.Name, "successor.") || strings.HasPrefix(f.Name, "caller.") {
			deltas[f.Name] = f.Value
		} else {
			source.Fields = append(source.Fields, f)
		}
	}
	mapped, err := identity.NewFeatureCommand(source)
	if err != nil {
		return fail()
	}
	b, original, err := nativeSessionRecord(mapped, session.RotateOperation())
	if err != nil {
		return fail()
	}
	valid := true
	take := func(name string, kind identity.FeatureKind) identity.FeatureValue {
		value, exists := deltas[name]
		delete(deltas, name)
		if !exists || value.Kind != kind {
			valid = false
		}
		return value
	}
	instant := func(name string) time.Time {
		raw := take(name, identity.FeatureText).Text
		value, err := time.Parse(storedTimeLayout, raw)
		if err != nil || !sessionReadTime(value) || value.UTC().Format(storedTimeLayout) != raw {
			valid = false
		}
		return value
	}
	next, _ := original.Bindings()
	next.Version = take("successor.version", identity.FeatureUint64).Uint64
	key := take("successor.lookup.version", identity.FeatureUint64).Uint64
	if key == 0 || key > uint64(^uint32(0)) {
		valid = false
	}
	next.Lookup.KeyVersion = uint32(key)
	digest := take("successor.lookup.digest", identity.FeatureBytes).Bytes
	if len(digest) != len(next.Lookup.Sum) {
		valid = false
	} else {
		copy(next.Lookup.Sum[:], digest)
	}
	next.LastActivityAt = instant("successor.activity")
	until := instant("caller.valid-until")
	kind := take("caller.transport", identity.FeatureUint64).Uint64
	if kind != uint64(session.CredentialCookie) && kind != uint64(session.CredentialBearer) {
		valid = false
	}
	if !valid || !until.After(next.LastActivityAt) || until.After(next.LastActivityAt.Add(20*time.Second)) {
		return fail()
	}
	vector, _ := next.Authority.Bindings()
	vector.Session.Version = next.Version
	next.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		return fail()
	}
	successor, err := sessionFromCSRFFields(deltas, "successor.", next)
	if err != nil || len(deltas) != 0 {
		return fail()
	}
	native, err := session.NewRotateCommand(b, original, successor)
	if err != nil {
		return fail()
	}
	life, err := successor.Lifetime(next.LastActivityAt)
	if err != nil || until.After(life.ExpiresAt) {
		return fail()
	}
	return native, until, session.CredentialKind(kind), nil
}
