package postgres

import (
	"bytes"
	"context"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

type revokeSource struct {
	record session.Session
	until  time.Time
	csrf   bool
}

// MapRevokeOneRequest freezes both original caller and target, including the
// caller's unchanged exclusive deadline, in the existing keyed command intent.
// It performs no IO or authentication. The owned executor must validate opaque
// request custody against its configured SessionService before reservation;
// this structural projection cannot replace that request or grant permission.
func MapRevokeOneRequest(request session.RevokeOneRequest) (identity.Command, error) {
	native, ok := request.Command()
	one, targeted := native.RevokeOne()
	if !ok || !targeted || !sessionReadTime(request.ValidUntil()) {
		return identity.Command{}, session.ErrInvalidSessionCommand
	}
	target, err := MapCommand(native)
	if err != nil {
		return identity.Command{}, err
	}
	caller, err := mapSessionRecord(one.Binding, session.RevokeOneOperation(), request.Caller())
	if err != nil {
		return identity.Command{}, err
	}
	projection, _ := target.Feature()
	source, _ := caller.Feature()
	for _, f := range source.Fields {
		f.Name = "caller." + f.Name
		projection.Fields = append(projection.Fields, f)
	}
	projection.Fields = append(projection.Fields, identity.FeatureField{Name: "caller.valid-until", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: request.ValidUntil().UTC().Format(storedTimeLayout)}})
	if _, strict := request.CSRFToken(); strict {
		projection.Fields = append(projection.Fields, identity.FeatureField{Name: "caller.csrf-required", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
	}
	return identity.NewFeatureCommand(projection)
}

// Decode two closed scalar records without weakening the original target-only
// contributor contract. A partially declared caller never becomes legacy mode.
func nativeRevokeIntent(command identity.Command) (session.SessionCommand, *revokeSource, error) {
	fail := func() (session.SessionCommand, *revokeSource, error) {
		return session.SessionCommand{}, nil, session.ErrInvalidSessionCommand
	}
	projection, ok := command.Feature()
	if !ok || projection.Operation != session.RevokeOneOperation() {
		return fail()
	}
	target := projection
	target.Fields = nil
	caller := projection
	caller.Fields = nil
	var until time.Time
	hasUntil := false
	csrf := false
	for _, f := range projection.Fields {
		if f.Name == "caller.csrf-required" {
			if f.Value.Kind != identity.FeatureBool || !f.Value.Bool {
				return fail()
			}
			csrf = true
		} else if f.Name == "caller.valid-until" {
			if f.Value.Kind != identity.FeatureText {
				return fail()
			}
			var err error
			until, err = time.Parse(storedTimeLayout, f.Value.Text)
			if err != nil || !sessionReadTime(until) || until.UTC().Format(storedTimeLayout) != f.Value.Text {
				return fail()
			}
			hasUntil = true
		} else if strings.HasPrefix(f.Name, "caller.") {
			f.Name = strings.TrimPrefix(f.Name, "caller.")
			caller.Fields = append(caller.Fields, f)
		} else {
			target.Fields = append(target.Fields, f)
		}
	}
	targetCommand, err := identity.NewFeatureCommand(target)
	if err != nil {
		return fail()
	}
	b, record, err := nativeSessionRecord(targetCommand, session.RevokeOneOperation())
	if err != nil {
		return fail()
	}
	native, err := session.NewRevokeOneCommand(b, record)
	if err != nil {
		return fail()
	}
	if len(caller.Fields) == 0 && !hasUntil {
		if csrf {
			return fail()
		}
		return native, nil, nil
	}
	if !hasUntil {
		return fail()
	}
	sourceCommand, err := identity.NewFeatureCommand(caller)
	if err != nil {
		return fail()
	}
	_, source, err := nativeSessionRecord(sourceCommand, session.RevokeOneOperation())
	if err != nil {
		return fail()
	}
	spec, _ := source.Bindings()
	dest, _ := record.Bindings()
	if spec.Audience != dest.Audience || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(spec.UserID) {
		return fail()
	}
	if spec.SessionID == dest.SessionID {
		a, _, _ := encodeRecord(source)
		z, _, _ := encodeRecord(record)
		if !bytes.Equal(a, z) {
			return fail()
		}
	}
	life, err := source.Lifetime(spec.LastActivityAt)
	if err != nil || !until.After(spec.LastActivityAt) || until.After(life.ExpiresAt) {
		return fail()
	}
	if csrf {
		if _, err := source.CSRFState().Bindings(); err != nil {
			return fail()
		}
	}
	return native, &revokeSource{record: source, until: until, csrf: csrf}, nil
}

func (r *Repository) requireRevokeSource(ctx context.Context, w kernel.Work, b identity.CommandBinding, target session.Session, source *revokeSource) error {
	if ctx == nil {
		return session.ErrInvalidSessionCommand
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximumDuration)
	defer cancel()
	spec, _ := source.record.Bindings()
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(*r.issueAdmission), source.record, b, spec.SessionID, spec.Version)
	if err != nil {
		return err
	}
	if err = w.RequireActiveDirectoryAuthority(ctx, r, directory); err != nil {
		return err
	}
	if _, err = w.RequireActiveCredential(ctx, r, credential); err != nil {
		return err
	}
	if err = w.RequireActiveUserAuthorization(ctx, r, policy); err != nil {
		return err
	}
	destination, _ := target.Bindings()
	// Lock both session rows in one deterministic order before any shared source
	// lock. Cross-revocation must not hold A SHARE while waiting for B UPDATE.
	rows, err := w.Query(ctx, `SELECT session_id FROM `+r.schema+`.sessions WHERE tenant_id=$1 AND user_id=$2 AND session_id IN ($3,$4) ORDER BY session_id FOR UPDATE`, string(b.TenantID), string(b.UserID), spec.SessionID, destination.SessionID)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		count++
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	want := 2
	if spec.SessionID == destination.SessionID {
		want = 1
	}
	if count != want {
		return identity.ForbiddenError{}
	}
	if err = RequireSession(ctx, w, Config{Schema: strings.Trim(r.schema, "\""), MaximumDuration: r.maximumDuration}, source.record); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if !now.Before(source.until) || source.until.After(now.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	return nil
}
