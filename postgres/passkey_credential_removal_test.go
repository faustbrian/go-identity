package postgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPasskeyRemovalLateCancellationPoisonsWork(t *testing.T) {
	// Exercise the final boundary after successful row validation, independently
	// of SQL cancellation. Work's original lifetime is deliberately still live.
	w := Work{state: &workState{ctx: context.Background()}}
	ctx, cancel := context.WithCancel(context.Background())
	if err := w.usable(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := w.finishPasskeyRemovalCheck(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("late child cancellation lost", err)
	}
	if err := w.usable(); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored late cancellation left Work usable", err)
	}
}

func TestPasskeyCredentialRemovalBindsOriginalReferenceAndEpochs(t *testing.T) {
	c := identity.CredentialRef{ID: "passkey", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPasskey, Owner: "passkey", Version: 7}
	a := UserAuthorityAdmission{UserAuthorityVersion: 11, IdentifierAuthorityVersion: 13, CredentialAuthorityVersion: 17}
	fields, err := PasskeyCredentialRemovalFields(c, a)
	if err != nil {
		t.Fatal(err)
	}
	s := identity.FeatureCommandSpec{Binding: identity.CommandBinding{TenantID: c.TenantID, UserID: c.UserID, RecordID: string(c.ID)}, Fields: fields}
	if !passkeyCredentialRemovalMatches(s, c, a) {
		t.Fatal("original removal reference and independent epochs were lost")
	}
	for _, mode := range []string{"tenant", "user", "reference", "missing", "duplicate", "unknown", "version", "epoch", "kind", "extra-bytes", "extra-bool"} {
		t.Run(mode, func(t *testing.T) {
			candidate := s
			candidate.Fields = append([]identity.FeatureField(nil), fields...)
			switch mode {
			case "tenant":
				candidate.Binding.TenantID = "other"
			case "user":
				candidate.Binding.UserID = "other"
			case "reference":
				candidate.Binding.RecordID = "other"
			case "missing":
				candidate.Fields = candidate.Fields[:len(fields)-1]
			case "duplicate":
				candidate.Fields = append(candidate.Fields, fields[0])
			case "unknown":
				candidate.Fields = append(candidate.Fields, identity.FeatureField{Name: "passkey-removal-reference.unselected", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
			case "version":
				candidate.Fields[5].Value.Uint64++
			case "epoch":
				candidate.Fields[len(fields)-1].Value.Uint64++
			case "kind":
				candidate.Fields[0].Value.Kind = identity.FeatureBytes
			case "extra-bytes":
				candidate.Fields[0].Value.Bytes = []byte{}
			case "extra-bool":
				candidate.Fields[0].Value.Bool = true
			}
			if passkeyCredentialRemovalMatches(candidate, c, a) {
				t.Fatal("substituted removal input accepted")
			}
		})
	}
	for _, mode := range []string{"owner", "kind", "zero-version", "overflow", "zero-user", "zero-identifier", "zero-credential"} {
		credential, authority := c, a
		switch mode {
		case "owner":
			credential.Owner = "webauthn"
		case "kind":
			credential.Kind = identity.CredentialPassword
		case "zero-version":
			credential.Version = 0
		case "overflow":
			credential.Version = ^uint64(0)
		case "zero-user":
			authority.UserAuthorityVersion = 0
		case "zero-identifier":
			authority.IdentifierAuthorityVersion = 0
		case "zero-credential":
			authority.CredentialAuthorityVersion = 0
		}
		if got, err := PasskeyCredentialRemovalFields(credential, authority); err == nil || got != nil {
			t.Fatal("invalid removal reference returned intent", mode)
		}
	}
	if err := (Work{}).RemovePasskeyCredential(context.Background(), nil, identity.Command{}, c, a); err == nil {
		t.Fatal("zero Work admitted removal")
	}
	if err := (Work{}).CheckRemovedPasskeyCredential(context.Background(), nil, identity.Command{}, c, a); err == nil {
		t.Fatal("zero Work admitted removed successor")
	}
}
