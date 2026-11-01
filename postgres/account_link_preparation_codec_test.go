package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestAccountLinkPreparationCodecBindsOriginalCustodyAndFinalRootScope(t *testing.T) {
	finalCommand := recordLink(t, identity.AccountLinkExplicit, nil, nil, "proof-key")
	final, ok := finalCommand.LinkAccount()
	if !ok {
		t.Fatal("final canonical link fixture unavailable")
	}
	finalClaim := encodedRecord(t, finalCommand)
	input := identity.AccountLinkPreparationCommand{Binding: final.Binding, ProviderID: "configured-oidc", ProviderConfigVersion: 1,
		FlowID: "flow-a", FlowFingerprint: [32]byte{1}, SessionID: final.SessionID, SessionVersion: final.SessionVersion,
		Counters: identity.AccountLinkCounterContext{Network: "192.0.2.15", PreparedAt: time.Unix(1000, 0).UTC(), KeyVersions: []uint32{9, 7}}}
	code := []byte("synthetic-authorization-code+/= :")
	state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	bearer := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	mapOriginal := func(spec identity.AccountLinkPreparationCommand, code []byte, state, bearer string) identity.Command {
		t.Helper()
		callback, err := identity.NewOAuthCallbackInput(code, state, identity.OAuthCallbackLimits{MaxCodeBytes: 16384, StateBytes: 32})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(callback.Destroy)
		command, err := identity.NewAccountLinkPreparationCommand(spec, callback, authentication.NewBearerCredential(bearer))
		if err != nil {
			t.Fatal(err)
		}
		return command
	}
	original := mapOriginal(input, code, state, bearer)
	claim, err := prepareClaim(original, [32]byte{1})
	if err != nil {
		t.Fatal("native claim rejects original pre-exchange root intent", err)
	}
	if !bytes.Equal(claim.safeFields, finalClaim.safeFields) || claim.commandID != finalClaim.commandID || claim.tenant != finalClaim.tenant || claim.purpose != finalClaim.purpose || claim.feature != nil {
		t.Fatal("preparation invented a different claim scope or feature owner")
	}
	if bytes.Equal(claim.canonical, finalClaim.canonical) {
		t.Fatal("original request and generated link proof have indistinguishable claims")
	}
	repeated, err := prepareClaim(mapOriginal(input, code, state, bearer), [32]byte{1})
	if err != nil || !bytes.Equal(claim.canonical, repeated.canonical) {
		t.Fatal("same original request changed retained-key claim", err)
	}
	for _, secret := range [][]byte{code, []byte(state), []byte(bearer), []byte(input.Counters.Network)} {
		if bytes.Contains(claim.canonical, secret) || bytes.Contains(claim.safeFields, secret) {
			t.Fatal("original private input persisted in canonical or collision metadata")
		}
	}
	for _, change := range []func(*identity.AccountLinkPreparationCommand, *[]byte, *string, *string){
		func(_ *identity.AccountLinkPreparationCommand, code *[]byte, _, _ *string) {
			*code = []byte("changed-authorization-code")
		},
		func(_ *identity.AccountLinkPreparationCommand, _ *[]byte, state, _ *string) {
			*state = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
		},
		func(_ *identity.AccountLinkPreparationCommand, _ *[]byte, _, bearer *string) {
			*bearer = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
		},
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) {
			s.ProviderID = "other-provider"
		},
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) { s.ProviderConfigVersion++ },
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) { s.FlowID = "other-flow" },
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) { s.FlowFingerprint[0]++ },
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) {
			s.SessionID = "other-session"
		},
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) { s.SessionVersion++ },
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) {
			s.Counters.Network = "192.0.2.16"
		},
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) {
			s.Counters.PreparedAt = s.Counters.PreparedAt.Add(time.Microsecond)
		},
		func(s *identity.AccountLinkPreparationCommand, _ *[]byte, _, _ *string) {
			s.Counters.KeyVersions = []uint32{9}
		},
	} {
		spec, selectedCode, selectedState, selectedBearer := input, code, state, bearer
		change(&spec, &selectedCode, &selectedState, &selectedBearer)
		changed, err := prepareClaim(mapOriginal(spec, selectedCode, selectedState, selectedBearer), [32]byte{1})
		if err != nil || bytes.Equal(claim.canonical, changed.canonical) || !bytes.Equal(claim.safeFields, changed.safeFields) {
			t.Fatal("original input omitted from immutable claim or changed root collision scope", err)
		}
	}
	rotated, err := prepareClaim(original, [32]byte{2})
	if err != nil || bytes.Equal(rotated.canonical, claim.canonical) {
		t.Fatal("original custody is not keyed by retained claim key", err)
	}
	if capabilityReservationCommand(original, CommandPlan{}) {
		t.Fatal("original callback enabled unsupported ordinary reservation")
	}
	_, callback, _, _ := original.AccountLinkPreparationInput()
	callback.Destroy()
	if _, err := prepareClaim(original, [32]byte{1}); err == nil {
		t.Fatal("destroyed original custody accepted for claim reconstruction")
	}
	if err := callback.Use(context.Background(), func(context.Context, []byte, []byte) error {
		t.Fatal("native codec resurrected destroyed custody")
		return nil
	}); err == nil {
		t.Fatal("destroyed custody usable")
	}
}
