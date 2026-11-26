package postgres

import (
	"bytes"
	"testing"
	"time"

	authorization "github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

func oneTapStorageFixture(t *testing.T) (identity.CommandBinding, session.PreAuthTransaction, session.PreAuthProviderBinding) {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	base, err := testPreAuth(t, time.Now().UTC().Truncate(time.Microsecond)).Bindings()
	if err != nil {
		t.Fatal(err)
	}
	op := kernel.OneTapStartOperation()
	base.Binding.ID = identity.PreAuthTransactionID(id)
	base.Binding.Intent.Action, base.Binding.Intent.CallbackURL = op.OperationID, ""
	base.Binding.Intent.Origin = "https://identity.test"
	base.Binding.Intent.IdentifierBinding = [32]byte{}
	copy(base.Cookie.Sum[:], string(id))
	provider := session.PreAuthProviderBinding{ProviderID: "google", ClientID: "fixture-client", ProviderVersion: 7, Mode: session.PreAuthProviderCallback}
	record, err := session.NewProviderPreAuthTransaction(session.ProviderPreAuthTransactionSpec{Transaction: base, Provider: provider})
	if err != nil {
		t.Fatal(err)
	}
	return identity.CommandBinding{CommandID: id, TenantID: base.Binding.Intent.TenantID, AnonymousFlowID: string(id), RecordID: string(id), ActorID: "onetap-service", ActorKind: authorization.SubjectServiceAccount, PolicyID: base.Binding.Intent.PolicyID, PolicyVersion: base.Binding.Intent.PolicyVersion, CorrelationID: string(id), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion}, record, provider
}

func TestOneTapStartPreAuthFieldBindsTheCompletePreparedFlow(t *testing.T) {
	b, record, provider := oneTapStorageFixture(t)
	field, err := OneTapStartPreAuthField(record)
	if err != nil || field.Name != "preauth.commitment" || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
		t.Fatal("missing exact browser flow commitment", err)
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: kernel.OneTapStartOperation(), Fields: []identity.FeatureField{field}})
	if err != nil {
		t.Fatal(err)
	}
	if err = validateOneTapStartPreAuth(b, command, record, provider); err != nil {
		t.Fatal("exact prepared flow rejected", err)
	}
	projection, err := record.ProviderBindings()
	if err != nil {
		t.Fatal(err)
	}
	projection.Transaction.Binding.Intent.Nonce[0] ^= 0x20
	changed, err := session.NewProviderPreAuthTransaction(projection)
	if err != nil {
		t.Fatal(err)
	}
	changedField, err := OneTapStartPreAuthField(changed)
	if err != nil || bytes.Equal(changedField.Value.Bytes, field.Value.Bytes) || validateOneTapStartPreAuth(b, command, changed, provider) == nil {
		t.Fatal("same-scope flow substitution retained the original custody", err)
	}
	provider.ProviderVersion++
	if validateOneTapStartPreAuth(b, command, record, provider) == nil {
		t.Fatal("a different selected provider version matched")
	}
	if err := StageOneTapStartPreAuth(t.Context(), kernel.Work{}, nil, command, Config{}, record, provider); err == nil {
		t.Fatal("empty Work staged browser state")
	}
	if result, err := RecoverOneTapStartPreAuth(t.Context(), kernel.RecoveryWork{}, nil, Config{}); err == nil || result != kernel.RecoveryUnknown {
		t.Fatal("empty recovery Work disclosed browser state")
	}
}
