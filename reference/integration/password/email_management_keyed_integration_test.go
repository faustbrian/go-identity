//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/email"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func testNativeKeyedEmailManagement(t *testing.T, ctx context.Context, pool *database.Pool, native *passwordpg.EmailManagementService, config passwordpg.ReauthenticationConfig, nativeConfig passwordpg.EmailManagementConfig, envelopeKeys *keyring.Provider, request passwordpg.EmailManagementRequest, unavailable *atomic.Bool) {
	t.Helper()
	var history migrations.Source = kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 23}
	history = kernel.RequestKeyPreparationMigrationSource{Base: history, Version: 24}
	items, err := history.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range items {
		if row.Version() >= 23 {
			if _, err := pool.Raw().Exec(ctx, row.UpSQL()); err != nil {
				t.Fatal(err)
			}
		}
	}
	keys, err := kernel.NewRequestKeyConfig("managed-email", [32]byte{91}, *config.Coordinator.QueryPolicy)
	if err != nil {
		t.Fatal(err)
	}
	keyedConfig, err := passwordpg.NewKeyedEmailManagementConfig(keys, [32]byte{92})
	if err != nil {
		t.Fatal(err)
	}
	service, err := passwordpg.NewKeyedEmailManagementService(native, keyedConfig)
	if err != nil {
		t.Fatal(err)
	}
	request.Primary.CommandID, request.Primary.AddressID = "", ""
	key, _ := identity.NewIdempotencyKey([]byte("managed-original-request"))
	rateUser, rateAddress, err := service.RequestRateSource(ctx, request, key, false)
	if err != nil || string(rateUser) != string(request.Primary.Caller.Request.Subject.ID) || rateAddress != "New@example.test" {
		t.Fatal("fresh keyed rate metadata", err)
	}
	var mapped int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.request_key_mappings`).Scan(&mapped); err != nil || mapped != 0 {
		t.Fatal("rate projection allocated a request mapping", err)
	}
	type attempt struct {
		result passwordpg.EmailManagementResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan attempt, 4)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			<-start
			result, err := service.VerificationSend(ctx, request, key)
			results <- attempt{result, err}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	for attempt := range results {
		if attempt.err != nil && attempt.result.AddressID != "" {
			t.Fatal("failed concurrent mapping disclosed a target")
		}
		if attempt.err == nil && attempt.result.Outcome != identity.CommitOutcomeCommitted && attempt.result.AddressID != "" {
			t.Fatal("pending concurrent mapping disclosed a target")
		}
	}
	result, err := service.VerificationSend(ctx, request, key)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.CommandID == "" || result.AddressID == "" || result.IdentifierVersion != 1 {
		t.Fatal("keyed native add did not converge", result.Outcome, err)
	}
	// Replay must not need the spent primary proof, current identifier epoch or
	// live provider. Reconstructing the service simulates process-local state loss.
	unavailable.Store(true)
	defer unavailable.Store(false)
	service, err = passwordpg.NewKeyedEmailManagementService(native, keyedConfig)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.VerificationSend(ctx, request, key)
	if err != nil || replay != result {
		t.Fatal("original keyed result not restored", replay.Outcome, err)
	}
	user, address, err := service.RequestRateSource(ctx, request, key, false)
	if err != nil || user != rateUser || address != rateAddress {
		t.Fatal("spent-proof rate metadata required live source or provider", err)
	}
	workflow, err := passwordpg.NewEmailRequestWorkflow(service)
	if err != nil {
		t.Fatal(err)
	}
	var portable email.VerificationSendService = workflow
	callback, err := url.Parse(request.CallbackURL)
	if err != nil {
		t.Fatal(err)
	}
	caller := request.Primary.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(config.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Tenant = authorization.TenantID(request.Primary.TenantID)
	caller.Request.Action = "identity.email.verification-send"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(caller.Request.Subject.ID)}
	portableRequest := email.VerificationSendRequest{TenantID: request.Primary.TenantID, Address: request.Address, Callback: *callback, IdempotencyKey: key, Primary: email.RequestPrimary{Session: request.Primary.Session, Proof: request.Primary.Proof}, Caller: caller, Network: request.Network}
	portableResult, err := portable.VerificationSend(ctx, portableRequest)
	if err != nil || portableResult.Validate() != nil || portableResult.CommandID != result.CommandID || portableResult.AddressID != result.AddressID || portableResult.DeliveryState != delivery.StateQueued {
		t.Fatal("portable request lost original committed custody", portableResult.Outcome, err)
	}
	// Reusing a key name must not make a differently signed original record
	// eligible. Replay grants no mutation authority, but still needs valid custody.
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	rotated := config
	rotated.SigningKey, err = passwordpg.NewReauthenticationSigningKey("evidence-1", private)
	if err != nil {
		t.Fatal(err)
	}
	rotated.VerificationKeys = map[string]ed25519.PublicKey{"evidence-1": private.Public().(ed25519.PublicKey)}
	clear(private)
	rotatedSource, err := passwordpg.NewReauthenticationService(pool, rotated)
	if err != nil {
		t.Fatal(err)
	}
	rotatedPrimary, err := passwordpg.NewEmailPrimarySource(rotatedSource, passwordpg.EmailPrimaryConfig{Action: "identity.email.verification-send", Audience: "email-management", MaximumAge: 2 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	rotatedNative, err := passwordpg.NewEmailManagementService(rotatedPrimary, nativeConfig, envelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	rotatedService, err := passwordpg.NewKeyedEmailManagementService(rotatedNative, keyedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := rotatedService.VerificationSend(ctx, request, key); err == nil || out.AddressID != "" {
		t.Fatal("ineligible original signer disclosed keyed custody", out.Outcome, err)
	}
	changed := request
	changed.Address = "different@example.test"
	if user, address, err := service.RequestRateSource(ctx, changed, key, false); err == nil || user != "" || address != "" {
		t.Fatal("changed intent disclosed rate metadata")
	}
	conflict, err := service.VerificationSend(ctx, changed, key)
	var want identity.ConflictError
	if !errors.As(err, &want) || conflict.Outcome != identity.CommitOutcomeConflict || conflict.AddressID != "" {
		t.Fatal("changed mailbox did not conflict", conflict.Outcome, err)
	}
	var addresses, links, messages int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.identifiers WHERE tenant_id=$1 AND identifier_id=$2),(SELECT count(*) FROM capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$3),(SELECT count(*) FROM identity.delivery_intents WHERE tenant_id=$1)`, string(request.Primary.TenantID), string(result.AddressID), string(result.CommandID)).Scan(&addresses, &links, &messages); err != nil || addresses != 1 || links != 1 || messages != 1 {
		t.Fatal("keyed retry duplicated effects", addresses, links, messages, err)
	}
	var ciphertext []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT request_preparation_ciphertext FROM identity.request_key_mappings WHERE namespace='managed-email'`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(request.Primary.Proof)
	if bytes.Contains(ciphertext, []byte(request.Primary.Session.Token())) || bytes.Contains(ciphertext, proof) || bytes.Contains(ciphertext, []byte(request.Address)) {
		t.Fatal("request mapping leaked source or personal input")
	}
	clear(proof)
	ciphertext[len(ciphertext)/2] ^= 1
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.request_key_mappings SET request_preparation_ciphertext=$1 WHERE namespace='managed-email'`, ciphertext); err == nil {
		t.Fatal("original request mapping allowed ciphertext replacement")
	}
	clear(ciphertext)
	if restored, err := service.VerificationSend(ctx, request, key); err != nil || restored != result {
		t.Fatal("rejected mapping tamper changed original result", restored.Outcome, err)
	}
}
