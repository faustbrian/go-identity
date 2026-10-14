package postgres

import (
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// MapRevokeSetRequest freezes the exact original source, disposition, whole-set
// bound and unchanged exclusive admission deadline in the existing keyed intent.
// This is structural mapping, never authentication or execution permission.
// Only the owned executor may admit the opaque request from its exact reader.
// No caller-selected target, bearer or arbitrary JSON enters the command.
func MapRevokeSetRequest(request session.RevokeSetRequest) (identity.Command, error) {
	command, ok := request.Command()
	set, targeted := command.RevokeSet()
	if !ok || !targeted || !sessionReadTime(request.ValidUntil()) {
		return identity.Command{}, session.ErrInvalidSessionCommand
	}
	op := session.RevokeOtherOperation()
	if set.Binding.OperationID == session.RevokeAllOperation().OperationID {
		op = session.RevokeAllOperation()
	}
	mapped, err := mapSessionRecord(set.Binding, op, set.Caller)
	if err != nil {
		return identity.Command{}, err
	}
	projection, _ := mapped.Feature()
	projection.Fields = append(projection.Fields,
		identity.FeatureField{Name: "set.maximum", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(set.MaximumSessions)}},
		identity.FeatureField{Name: "set.include-current", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: set.IncludeCurrent}},
		identity.FeatureField{Name: "caller.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: request.ValidUntil().UTC().Format(storedTimeLayout)}},
	)
	return identity.NewFeatureCommand(projection)
}

func nativeRevokeSet(command identity.Command) (session.SessionCommand, time.Time, error) {
	fail := func() (session.SessionCommand, time.Time, error) {
		return session.SessionCommand{}, time.Time{}, session.ErrInvalidSessionCommand
	}
	p, ok := command.Feature()
	if !ok || p.Operation != session.RevokeOtherOperation() && p.Operation != session.RevokeAllOperation() {
		return fail()
	}
	source := p
	source.Fields = nil
	var maximum uint64
	var include bool
	var until time.Time
	count := 0
	for _, f := range p.Fields {
		switch f.Name {
		case "set.maximum":
			if f.Value.Kind != identity.FeatureUint64 {
				return fail()
			}
			maximum = f.Value.Uint64
			count++
		case "set.include-current":
			if f.Value.Kind != identity.FeatureBool {
				return fail()
			}
			include = f.Value.Bool
			count++
		case "caller.valid-until":
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			var err error
			until, err = time.Parse(storedTimeLayout, f.Value.Text)
			if err != nil || !sessionReadTime(until) || until.UTC().Format(storedTimeLayout) != f.Value.Text {
				return fail()
			}
			count++
		default:
			source.Fields = append(source.Fields, f)
		}
	}
	if count != 3 || maximum < 1 || maximum > 100000 || p.Operation == session.RevokeOtherOperation() && include {
		return fail()
	}
	mapped, err := identity.NewFeatureCommand(source)
	if err != nil {
		return fail()
	}
	b, record, err := nativeSessionRecord(mapped, p.Operation)
	if err != nil {
		return fail()
	}
	spec, _ := record.Bindings()
	life, err := record.Lifetime(spec.LastActivityAt)
	remember, _ := spec.Remember.Bindings()
	freshUntil := spec.Authentication.Proof.IssuedAt.Add(remember.FreshFor)
	if err != nil || !until.After(spec.LastActivityAt) || until.After(life.ExpiresAt) || until.After(freshUntil) {
		return fail()
	}
	var native session.SessionCommand
	if p.Operation == session.RevokeAllOperation() {
		native, err = session.NewRevokeAllCommand(b, record, include, uint32(maximum))
	} else {
		native, err = session.NewRevokeOtherCommand(b, record, uint32(maximum))
	}
	if err != nil {
		return fail()
	}
	return native, until, nil
}
