package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func TestPasskeyCredentialCreationBindsOriginalReferenceAndEpochs(t *testing.T) {
	c := identity.CredentialRef{ID: "passkey", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPasskey, Owner: "passkey", Version: 1}
	for _, version := range []uint64{1, 1<<53 + 1, 1 << 63, ^uint64(0)} {
		a := UserAuthorityAdmission{UserAuthorityVersion: version, IdentifierAuthorityVersion: 7, CredentialAuthorityVersion: 11}
		fields, err := PasskeyCredentialCreationFields(c, a)
		if err != nil {
			t.Fatal(err)
		}
		s := identity.FeatureCommandSpec{Binding: identity.CommandBinding{TenantID: c.TenantID, UserID: c.UserID, RecordID: string(c.ID)}, Fields: fields}
		if !passkeyCredentialCreationMatches(s, c, a) {
			t.Fatal("original full-width independent authority was lost")
		}
		for _, mode := range []string{"tenant", "user", "reference", "missing", "duplicate", "unknown", "changed-epoch", "wrong-kind", "extra-bytes", "extra-time", "extra-bool", "extra-int"} {
			t.Run(mode, func(t *testing.T) {
				candidate := s
				candidate.Fields = append([]identity.FeatureField(nil), fields...)
				switch mode {
				case "tenant":
					candidate.Binding.TenantID = "foreign"
				case "user":
					candidate.Binding.UserID = "foreign"
				case "reference":
					candidate.Binding.RecordID = "foreign"
				case "missing":
					candidate.Fields = candidate.Fields[:len(fields)-1]
				case "duplicate":
					candidate.Fields = append(candidate.Fields, fields[0])
				case "unknown":
					candidate.Fields = append(candidate.Fields, identity.FeatureField{Name: "passkey-reference.unselected", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
				case "changed-epoch":
					candidate.Fields[len(fields)-1].Value.Uint64++
				case "wrong-kind":
					candidate.Fields[0].Value.Kind = identity.FeatureBytes
				case "extra-bytes":
					candidate.Fields[0].Value.Bytes = []byte{}
				case "extra-time":
					candidate.Fields[0].Value.Time = time.Unix(1, 0)
				case "extra-bool":
					candidate.Fields[0].Value.Bool = true
				case "extra-int":
					candidate.Fields[0].Value.Int64 = 1
				}
				if passkeyCredentialCreationMatches(candidate, c, a) {
					t.Fatal("substituted or noncanonical original input accepted")
				}
			})
		}
	}
	for _, mode := range []string{"owner", "kind", "version", "zero-user", "zero-identifier", "zero-credential"} {
		credential, authority := c, UserAuthorityAdmission{1, 7, 11}
		switch mode {
		case "owner":
			credential.Owner = "webauthn"
		case "kind":
			credential.Kind = identity.CredentialPassword
		case "version":
			credential.Version = 2
		case "zero-user":
			authority.UserAuthorityVersion = 0
		case "zero-identifier":
			authority.IdentifierAuthorityVersion = 0
		case "zero-credential":
			authority.CredentialAuthorityVersion = 0
		}
		if fields, err := PasskeyCredentialCreationFields(credential, authority); err == nil || fields != nil {
			t.Fatal("invalid initial reference returned intent", mode)
		}
	}
	if err := (Work{}).CreatePasskeyCredential(context.Background(), nil, identity.Command{}, c, UserAuthorityAdmission{1, 7, 11}); err == nil {
		t.Fatal("zero Work admitted initial credential creation")
	}
}
