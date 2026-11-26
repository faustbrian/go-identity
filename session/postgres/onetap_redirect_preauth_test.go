package postgres

import (
	"bytes"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func oneTapRedirectStorageFixture(t *testing.T) (identity.CommandBinding, session.PreAuthTransaction, session.PreAuthProviderBinding) {
	t.Helper()
	b, popup, provider := oneTapStorageFixture(t)
	projection, err := popup.ProviderBindings()
	if err != nil {
		t.Fatal(err)
	}
	provider.Mode = session.PreAuthProviderRedirect
	projection.Provider = provider
	projection.Transaction.Binding.Intent.CallbackURL = projection.Transaction.Binding.Intent.Origin + "/v1/oauth/onetap-redirect"
	record, err := session.NewProviderPreAuthTransaction(projection)
	if err != nil {
		t.Fatal("construct explicit redirect fixture", err)
	}
	return b, record, provider
}

func TestOneTapRedirectPreAuthCanonicalRoundTripAndLegacyIsolation(t *testing.T) {
	_, redirect, selected := oneTapRedirectStorageFixture(t)
	want, err := redirect.ProviderBindings()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := encodePreAuth(redirect)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := decodePreAuth(payload)
	if err != nil {
		t.Fatal("restore exact durable redirect", err)
	}
	got, err := loaded.ProviderBindings()
	if err != nil || got != want {
		t.Fatal("redirect lost original endpoint, mode, RememberPolicy or deadline", err)
	}
	again, err := encodePreAuth(loaded)
	if err != nil || !bytes.Equal(payload, again) {
		t.Fatal("redirect bytes changed across restart", err)
	}
	if _, err := selectedPreAuthProjection(loaded, session.PreAuthProviderBinding{}); err == nil {
		t.Fatal("ordinary projection dropped redirect binding")
	}
	popup := selected
	popup.Mode = session.PreAuthProviderCallback
	if _, err := selectedPreAuthProjection(loaded, popup); err == nil {
		t.Fatal("popup selection accepted redirect")
	}
	for _, corrupted := range [][]byte{
		bytes.Replace(payload, []byte(`"Mode":2`), []byte(`"Mode":0`), 1),
		bytes.Replace(payload, []byte(`"Mode":2`), []byte(`"Mode":1`), 1),
		bytes.Replace(payload, []byte(`"Mode":2`), []byte(`"Mode":3`), 1),
		bytes.Replace(payload, []byte(want.Transaction.Binding.Intent.CallbackURL), []byte("https://foreign.test/v1/oauth/onetap-redirect"), 1),
		bytes.Replace(payload, []byte(want.Transaction.Binding.Intent.CallbackURL), nil, 1),
		append(bytes.Clone(payload), ' '),
	} {
		if bytes.Equal(corrupted, payload) {
			t.Fatal("corruption fixture did not change the original")
		}
		if _, err := decodePreAuth(corrupted); err == nil {
			t.Fatal("invalid or noncanonical redirect restored as original evidence")
		}
	}

	_, callback, _ := oneTapStorageFixture(t)
	for _, original := range []session.PreAuthTransaction{testPreAuth(t, time.Date(2026, 11, 27, 0, 0, 0, 1, time.UTC)), callback} {
		before, err := encodePreAuth(original)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := decodePreAuth(before)
		if err != nil {
			t.Fatal("existing ordinary/popup bytes rejected", err)
		}
		after, err := encodePreAuth(restored)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("existing ordinary/popup bytes changed", err)
		}
		if _, err := selectedPreAuthProjection(restored, selected); err == nil {
			t.Fatal("redirect selection accepted ordinary/popup history")
		}
	}
}

func TestOneTapRedirectStartCommitmentRejectsModeEndpointAndLifetimeSubstitution(t *testing.T) {
	b, record, selected := oneTapRedirectStorageFixture(t)
	field, err := OneTapStartPreAuthField(record)
	if err != nil {
		t.Fatal("redirect start cannot commit the prepared browser flow", err)
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: kernel.OneTapStartOperation(), Fields: []identity.FeatureField{field}})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateOneTapStartPreAuth(b, command, record, selected); err != nil {
		t.Fatal("exact selected redirect start was rejected", err)
	}
	for _, test := range []struct {
		name   string
		change func(*session.ProviderPreAuthTransactionSpec)
	}{
		{"endpoint", func(p *session.ProviderPreAuthTransactionSpec) {
			p.Transaction.Binding.Intent.CallbackURL = p.Transaction.Binding.Intent.Origin + "/another-endpoint"
		}},
		{"popup mode", func(p *session.ProviderPreAuthTransactionSpec) {
			p.Provider.Mode = session.PreAuthProviderCallback
			p.Transaction.Binding.Intent.CallbackURL = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			projection, _ := record.ProviderBindings()
			test.change(&projection)
			changed, err := session.NewProviderPreAuthTransaction(projection)
			if err != nil {
				t.Fatal(err)
			}
			changedField, err := OneTapStartPreAuthField(changed)
			if err != nil || bytes.Equal(field.Value.Bytes, changedField.Value.Bytes) || validateOneTapStartPreAuth(b, command, changed, projection.Provider) == nil {
				t.Fatal("different valid mode or endpoint borrowed original start commitment", err)
			}
		})
	}
	for _, delta := range []time.Duration{-time.Nanosecond, time.Nanosecond} {
		projection, _ := record.ProviderBindings()
		projection.Transaction.Binding.ExpiresAt = projection.Transaction.Binding.ExpiresAt.Add(delta)
		changed, err := session.NewProviderPreAuthTransaction(projection)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OneTapStartPreAuthField(changed); err == nil {
			t.Fatal("redirect start changed the exact five-minute lifetime")
		}
	}
}
