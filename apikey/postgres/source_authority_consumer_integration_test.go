//go:build integration

package postgres_test

import (
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
)

func authenticatedSourceBinding(t *testing.T, f nativeConsumerFixture, service *apikeypg.Service) apikey.SourceAuthorityBinding {
	t.Helper()
	key, _ := identity.NewIdempotencyKey([]byte("source-authority-original-create"))
	issued, err := service.Create(f.ctx, apikey.CreateRequest{Authentication: f.caller, IdempotencyKey: key, Name: "exchange-source", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), Network: "192.0.2.1"})
	if err != nil {
		t.Fatal("actual modern user key issuance failed", err)
	}
	record, ok := issued.Record()
	if !ok {
		t.Fatal("actual issued source record absent")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal("known committed source was not delivered", err)
	}
	secret, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal("actual issued source format rejected", err)
	}
	verified, err := service.VerifyAndConsume(f.ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: baselineTenant, ConfigurationID: record.ConfigurationID, ConfigurationRevision: record.ConfigurationRevision, Candidate: record.ID, Secret: secret, RequiredPermissions: []string{"invoice.read"}})
	if err != nil || verified.Validate() != nil || verified.Result == nil {
		t.Fatal("actual native source bearer authentication failed", err)
	}
	binding, err := apikey.NewSourceAuthorityBinding(*verified.Result, f.config.Configuration, time.Now().UTC())
	if err != nil {
		t.Fatal("actual verified source binding failed", err)
	}
	// Only nonsecret immutable bindings leave this fixture helper. Observation
	// has no bearer argument and cannot silently verify/debit another attempt.
	return binding
}

func TestNativeSourceAuthorityIssuedKeyCurrentPolicyAndRevocation(t *testing.T) {
	f := setupNativeConsumer(t)
	service, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal("actual API-key source owner composition failed", err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal("actual source configuration initialization failed", err)
	}
	binding := authenticatedSourceBinding(t, f, service)
	var before int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.command_effects`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	current, err := service.ObserveSourceAuthority(f.ctx, binding)
	if err != nil || current.Validate(binding, f.config.Configuration, time.Now().UTC()) != nil || current.Owner.Spec().UserID != f.user || current.Record.RootID != binding.RootID || current.Record.AuthorityVersion != binding.AuthorityVersion || !slices.Equal(current.Grant, binding.Grant) {
		t.Fatal("secret-free current observation lost real source authority", err)
	}
	f.deniedGrant.Store(true)
	narrowed, err := service.ObserveSourceAuthority(f.ctx, binding)
	f.deniedGrant.Store(false)
	if err != nil || !slices.Equal(narrowed.Grant, []string{"invoice.read"}) || narrowed.Record.RootVersion != binding.RootVersion {
		t.Fatal("source observation retained removed permissions or mutated the root", err)
	}
	var after int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM identity_api_keys.command_effects`).Scan(&after); err != nil || after != before {
		t.Fatal("source validity observation journaled another verification or mutation", err)
	}
	foreign := binding
	foreign.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: baselineTenant, Kind: apikey.OwnerUser, UserID: "foreign-user", Version: binding.Owner.Version()})
	if out, err := service.ObserveSourceAuthority(f.ctx, foreign); err == nil || out.Record.ID != "" || len(out.Grant) != 0 {
		t.Fatal("source authority disclosed another owner's key", err)
	}
	metadataKey, _ := identity.NewIdempotencyKey([]byte("source-original-name-only-update"))
	renamed, err := service.Update(f.ctx, apikey.UpdateRequest{Authentication: f.caller, IdempotencyKey: metadataKey, KeyID: binding.KeyID, ExpectedVersion: current.Record.Version, Name: "renamed-source", Permissions: slices.Clone(current.Record.Grant), Network: "192.0.2.1"})
	if err != nil || renamed.Record == nil || renamed.Record.AuthorityVersion != binding.AuthorityVersion {
		t.Fatal("actual metadata-only update changed source credential authority", err)
	}
	current, err = service.ObserveSourceAuthority(f.ctx, binding)
	if err != nil || current.Record.Name != "renamed-source" || current.Record.RootVersion != binding.RootVersion {
		t.Fatal("metadata-only update invalidated an unchanged source root", err)
	}
	requestKey, _ := identity.NewIdempotencyKey([]byte("source-authority-original-revoke"))
	result, err := service.Revoke(f.ctx, apikey.Revocation{Authentication: f.caller, IdempotencyKey: requestKey, KeyID: binding.KeyID, ExpectedVersion: current.Record.Version, Network: "192.0.2.1"})
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual original source revocation failed", err)
	}
	if out, err := service.ObserveSourceAuthority(f.ctx, binding); err == nil || out.Record.ID != "" || len(out.Grant) != 0 {
		t.Fatal("revoked original root retained source authority", err)
	}
}
