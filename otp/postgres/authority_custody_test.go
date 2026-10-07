package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	authority "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

func TestPreAuthOriginalAuthorityCustody(t *testing.T) {
	c, old, plan, flow, cookie := admissionFixture(t, time.Now().UTC())
	attempt, err := c.restoreAttempt(old, plan)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := old.Feature()
	fields := spec.Fields[:0]
	for _, f := range spec.Fields {
		if !otpField(f.Name) {
			fields = append(fields, f)
		}
	}
	spec.Fields = fields
	original := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: spec.Binding.TenantID}, GlobalVersion: 2, TenantVersion: 3}}
	bearer, _ := old.PreAuthCookie()
	command, gotPlan, err := c.MapPreAuthWithAuthority(context.Background(), attempt, 3, spec, bearer, original)
	if err != nil || gotPlan != plan {
		t.Fatal("authority mapping changed original plan", err)
	}
	if got, ok := command.PreAuthCookie(); !ok || got.Token() != cookie {
		t.Fatal("lost original cookie")
	}
	profile, _ := newPreAuthProfile(sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, map[uint32][]byte{3: bytes.Repeat([]byte{0x56}, 32)})
	gotFlow, err := c.authenticatePreAuth(context.Background(), profile, command, plan)
	want, _ := flow.Bindings()
	got, _ := gotFlow.Bindings()
	if err != nil || got != want {
		t.Fatal("authority custody broke original flow authentication")
	}
}

func TestAttemptAuthorityUserAndMalformedProfiles(t *testing.T) {
	c, _ := NewAttemptCodec(codecConfig())
	attempt, spec := mappedAttempt(t, otp.PurposeSignin, false)
	original := AttemptAuthority{
		Directory:            kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3},
		Credential:           identity.CredentialRef{ID: "credential", TenantID: "tenant", UserID: "user", Kind: identity.CredentialPassword, Owner: "identity/password", Version: ^uint64(0)},
		UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6,
		UserAuthorization: kernel.UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, Version: 7},
	}
	command, _, err := c.MapWithAuthority(context.Background(), attempt, 3, spec, original)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := command.Feature()
	got, err := c.restoreAuthority(metadata)
	if err != nil || got != original {
		t.Fatal("complete original user expectations changed")
	}
	for _, change := range []func(*AttemptAuthority){
		func(a *AttemptAuthority) { a.Directory.Query.TenantID = "other" },
		func(a *AttemptAuthority) { a.Directory.Query.GlobalAuthorityID = "" },
		func(a *AttemptAuthority) { a.Directory.GlobalVersion = 0 },
		func(a *AttemptAuthority) { a.Directory.TenantVersion = 0 },
		func(a *AttemptAuthority) { a.UserAuthorization = kernel.UserAuthorizationAdmission{} },
		func(a *AttemptAuthority) { a.UserAuthorization.Scope.SubjectID = "actor" },
		func(a *AttemptAuthority) { a.UserAuthorization.Scope.TenantID = "other" },
		func(a *AttemptAuthority) { a.UserAuthorization.Version = 0 },
		func(a *AttemptAuthority) { a.Credential.UserID = "other" },
		func(a *AttemptAuthority) { a.Credential.Owner = "other" },
		func(a *AttemptAuthority) { a.UserAuthorityVersion = 0 },
		func(a *AttemptAuthority) { a.IdentifierAuthorityVersion = 0 },
		func(a *AttemptAuthority) { a.CredentialAuthorityVersion = 0 },
	} {
		altered := original
		change(&altered)
		out, p, err := c.MapWithAuthority(context.Background(), attempt, 3, spec, altered)
		if !errors.Is(err, ErrInvalidCommand) || p != (kernel.OTPAttemptPlan{}) {
			t.Fatal("invalid authority accepted")
		}
		if _, ok := out.Feature(); ok {
			t.Fatal("failed mapping retained custody")
		}
	}
	anonymous, anonSpec := mappedAttempt(t, otp.PurposeSignin, true)
	if _, _, err := c.MapWithAuthority(context.Background(), anonymous, 3, anonSpec, original); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("anonymous profile accepted user authority")
	}
	if !strings.Contains(fmt.Sprintf("%#v", original), "redacted") {
		t.Fatal("authority exported to diagnostics")
	}
	if _, err := json.Marshal(original); err == nil {
		t.Fatal("authority serialized")
	}
}

func TestPasswordlessAuthorityRetainsIndependentUserEpochs(t *testing.T) {
	c, _ := NewAttemptCodec(codecConfig())
	a, spec := mappedAttempt(t, otp.PurposeSignin, false)
	original := AttemptAuthority{
		Directory:            kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: "tenant"}, GlobalVersion: 2, TenantVersion: 3},
		UserAuthorization:    kernel.UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", PolicyNamespace: "users", SubjectID: "user"}, Version: 7},
		UserAuthorityVersion: 4, IdentifierAuthorityVersion: 5, CredentialAuthorityVersion: 6,
	}
	command, _, err := c.MapWithAuthority(context.Background(), a, 3, spec, original)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := command.Feature()
	got, err := c.restoreAuthority(metadata)
	if err != nil || got != original {
		t.Fatal("passwordless command lost independent user epochs")
	}
	for _, epoch := range []*uint64{&original.UserAuthorityVersion, &original.IdentifierAuthorityVersion, &original.CredentialAuthorityVersion} {
		saved := *epoch
		*epoch = 0
		if _, _, err := c.MapWithAuthority(context.Background(), a, 3, spec, original); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("missing passwordless user epoch accepted")
		}
		*epoch = saved
	}
}

func TestAttemptOriginalAuthorityCustody(t *testing.T) {
	c, _ := NewAttemptCodec(codecConfig())
	attempt, spec := mappedAttempt(t, otp.PurposeSignin, true)
	original := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{
		Query:         kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: spec.Binding.TenantID},
		GlobalVersion: ^uint64(0), TenantVersion: 17,
	}}
	command, plan, err := c.MapWithAuthority(context.Background(), attempt, 3, spec, original)
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ := command.Feature()
	restarted, _ := NewAttemptCodec(codecConfig())
	got, err := restarted.restoreAuthority(metadata)
	if err != nil || got != original {
		t.Fatal("original authority did not survive restart")
	}
	if _, err := restarted.restoreAttempt(command, plan); err != nil {
		t.Fatal(err)
	}
	original.Directory.TenantVersion++
	got, err = restarted.restoreAuthority(metadata)
	if err != nil || got.Directory.TenantVersion != 17 {
		t.Fatal("caller mutation renewed authority")
	}
	legacy, _, err := c.Map(context.Background(), attempt, 3, spec)
	if err != nil {
		t.Fatal(err)
	}
	old, _ := legacy.Feature()
	if _, err := c.restoreRecord(old); err != nil {
		t.Fatal("legacy custody broken")
	}
	if _, err := c.restoreAuthority(old); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("legacy record invented authority")
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) {
			for i := range s.Fields {
				if s.Fields[i].Name == "otp.attempt-custody" {
					s.Fields[i].Value.Bytes[len(s.Fields[i].Value.Bytes)-1] ^= 1
				}
			}
		},
	} {
		altered, _ := command.Feature()
		change(&altered)
		if _, err := c.restoreAuthority(altered); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("modified authority custody accepted")
		}
	}
}

func TestAuthorityRecordRejectsTruncationAndTrailingData(t *testing.T) {
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	attempt, spec := mappedAttempt(t, otp.PurposeSignin, true)
	record, err := issuer.SealForCommand(attempt)
	if err != nil {
		t.Fatal(err)
	}
	original := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: spec.Binding.TenantID}, GlobalVersion: 2, TenantVersion: 3}}
	inner := encodeAttemptRecord(record)
	wire := encodeAuthorityRecord(inner, original)
	for i := len(authorityRecordPrefix); i < len(wire); i++ {
		if _, _, err := decodeAuthorityRecord(wire[:i], spec.Binding); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("truncated authority record accepted")
		}
	}
	if _, _, err := decodeAuthorityRecord(append(bytes.Clone(wire), 0), spec.Binding); !errors.Is(err, ErrInvalidCommand) {
		t.Fatal("trailing authority bytes accepted")
	}
	// Two absent-profile tags are the last bytes of this anonymous record.
	for _, offset := range []int{len(wire) - 1, len(wire) - 2} {
		changed := bytes.Clone(wire)
		changed[offset] = 2
		if _, _, err := decodeAuthorityRecord(changed, spec.Binding); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("unknown authority tag accepted")
		}
	}
	data, got, err := decodeAuthorityRecord(wire, spec.Binding)
	if err != nil || !bytes.Equal(data, inner) || got == nil || *got != original {
		t.Fatal("canonical authority record changed")
	}
}

func FuzzAuthorityRecord(f *testing.F) {
	issuer, _ := otp.NewAttemptIssuer(7, [32]byte{0x31})
	attempt, spec := mappedAttempt(f, otp.PurposeSignin, true)
	record, _ := issuer.SealForCommand(attempt)
	original := AttemptAuthority{Directory: kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "deployment", TenantID: spec.Binding.TenantID}, GlobalVersion: 2, TenantVersion: 3}}
	f.Add(encodeAuthorityRecord(encodeAttemptRecord(record), original))
	f.Add([]byte(authorityRecordPrefix))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 16384 {
			return
		}
		_, a, err := decodeAuthorityRecord(wire, spec.Binding)
		if err == nil && a != nil && a.validate(spec.Binding) != nil {
			t.Fatal("invalid authority escaped decoding")
		}
		if err != nil && a != nil {
			t.Fatal("failed decoding retained authority")
		}
	})
}
