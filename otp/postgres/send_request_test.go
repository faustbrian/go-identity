package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestOriginalSendCommandIsStableAndRequiresOriginalBearer(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		originalSendCommandVariant(t, authenticated)
	}
}

func originalSendCommandVariant(t *testing.T, authenticated bool) {
	t.Helper()
	phase, generated, _ := issuancePhaseFixture(t)
	store := phase.store
	if !authenticated {
		store, _, _ = nativeContributorFixture(t)
		codec, challenge, spec, bearer, authority := issuanceCustodyFixture(t, false)
		store.codec = codec
		var err error
		generated, err = codec.MapIssuancePreAuth(context.Background(), challenge, spec, bearer, authority)
		if err != nil {
			t.Fatal(err)
		}
	}
	custody, _, err := store.authenticateIssuance(context.Background(), generated)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := custody.challenge.Bindings()
	request := sendRequestRecord{continuation: s.Continuation, policy: s.Policy, authority: custody.authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt}
	spec, _ := generated.Feature()
	bearer, _ := generated.SessionToken()
	if !authenticated {
		bearer, _ = generated.PreAuthCookie()
	}
	first, err := store.mapSendRequest(context.Background(), request, spec.Binding, bearer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.mapSendRequest(context.Background(), request, spec.Binding, bearer)
	if err != nil {
		t.Fatal(err)
	}
	one, _ := first.Feature()
	two, _ := second.Feature()
	if !reflect.DeepEqual(one, two) {
		t.Fatal("retry remapped original command intent")
	}
	if _, ok := first.OneTimeCode(); ok {
		t.Fatal("preparation request acquired submitted-code custody")
	}
	if _, _, err := store.authenticateSendRequest(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	wrong := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x79}, 32)))
	if _, err := store.mapSendRequest(context.Background(), request, spec.Binding, wrong); err == nil {
		t.Fatal("original request accepted invented bearer possession")
	}
	if _, _, err := store.authenticateIssuance(context.Background(), first); err == nil {
		t.Fatal("pre-generation request became generated issuance")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.mapSendRequest(ctx, request, spec.Binding, bearer); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled mapping lost cancellation", err)
	}
	if _, _, err := store.authenticateSendRequest(ctx, first); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled restoration lost cancellation", err)
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Name = "otp.issue-custody" },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Bytes[len(s.Fields[0].Value.Bytes)-1] ^= 1 },
	} {
		x, _ := first.Feature()
		change(&x)
		var altered identity.Command
		if authenticated {
			altered, err = identity.NewFeatureSessionCommand(x, bearer)
		} else {
			altered, err = identity.NewFeaturePreAuthCommand(x, bearer)
		}
		if err != nil {
			continue
		}
		if _, _, err := store.authenticateSendRequest(context.Background(), altered); err == nil {
			t.Fatal("unsupported original request schema admitted")
		}
	}
}
