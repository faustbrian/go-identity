//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

// The RP rows are encrypted storage fixtures, not completed browser/protocol
// admission. Selection must neither authenticate them nor mutate their custody.
func TestCallbackOperationSelectsStoredIntentWithoutBrowserFallback(t *testing.T) {
	ctx, phase, out, _, request, pool, _ := storedRPCallbackFixture(t, 0)
	owner := phase.service
	op, err := owner.CallbackOperation(ctx, request.TenantID, request.Callback)
	if err != nil || op != "identity.account.link-start" {
		t.Fatal("link state did not retain its native operation", err)
	}
	profile := request.Callback.Profile()
	state := bytes.Repeat([]byte{27}, 32)
	command := bytes.Repeat([]byte{28}, 16)
	transaction := base64.RawURLEncoding.EncodeToString(command)
	c := owner.config()
	digest := rpStateDigest(c.StateKeys[c.CurrentStateKeyVersion], c.CurrentStateKeyVersion, request.TenantID, profile.ID, state)
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.oauth.signin-start',$3,1,$4)`, command, string(request.TenantID), bytes.Repeat([]byte{29}, 32), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.oauth.signin-start')`, command, string(request.TenantID)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `INSERT INTO oauth_rp.transactions(tenant_id,transaction_id,origin_command_id,operation,preauth_id,provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,state_key_version,state_digest,pkce_key_version,pkce_commitment,pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version)
 SELECT tenant_id,$2,$3,'identity.oauth.signin-start','original-flow',provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,$4,$5,pkce_key_version,pkce_commitment,pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version FROM oauth_rp.transactions WHERE tenant_id=$1 AND transaction_id=$6`, string(request.TenantID), transaction, command, c.CurrentStateKeyVersion, digest[:], phase.input.binding().RecordID); err != nil {
		t.Fatal(err)
	}
	parsed, err := oauth.ParseQueryCallback(ctx, (url.Values{"code": {"original-code"}, "state": {base64.RawURLEncoding.EncodeToString(state)}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Destroy()
	op, err = owner.CallbackOperation(ctx, request.TenantID, parsed)
	if err != nil || op != "identity.oauth.signin-start" {
		t.Fatal("signin state was not selected independently of ambient cookies", err)
	}
	for name, tenant := range map[string]identity.TenantID{"foreign": "other-tenant", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			if operation, err := owner.CallbackOperation(ctx, tenant, parsed); operation != "" || err == nil {
				t.Fatal("unmatched state selected an operation")
			}
		})
	}
	denied, err := oauth.ParseQueryCallback(ctx, (url.Values{"error": {"access_denied"}, "state": {base64.RawURLEncoding.EncodeToString(state)}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Destroy()
	if operation, err := owner.CallbackOperation(ctx, request.TenantID, denied); err != nil || operation != op {
		t.Fatal("provider denial lost its original operation", err)
	}
	var pkce, proof []byte
	var version string
	if err := pool.Raw().QueryRow(ctx, `SELECT pkce_ciphertext,state_proof_ciphertext,version::text FROM oauth_rp.transactions WHERE tenant_id=$1 AND transaction_id=$2`, string(request.TenantID), transaction).Scan(&pkce, &proof, &version); err != nil || !bytes.Equal(pkce, out.PKCECiphertext) || !bytes.Equal(proof, out.StateProofCiphertext) || version != "1" {
		t.Fatal("routing changed state or released/consumed stored custody", err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE oauth_rp.transactions SET pkce_ciphertext=NULL,state_proof_ciphertext=NULL,version=2,secrets_erased_at=clock_timestamp() WHERE tenant_id=$1 AND transaction_id=$2`, string(request.TenantID), transaction); err != nil {
		t.Fatal(err)
	}
	if operation, err := owner.CallbackOperation(ctx, request.TenantID, parsed); err != nil || operation != op {
		t.Fatal("erased retry metadata lost its original route", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if operation, err := owner.CallbackOperation(canceled, request.TenantID, parsed); operation != "" || err == nil {
		t.Fatal("canceled routing returned a selection")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE oauth_rp.transactions SET issued_at=clock_timestamp()-interval '20 minutes',expires_at=clock_timestamp()-interval '15 minutes',secrets_erased_at=clock_timestamp()-interval '16 minutes' WHERE tenant_id=$1 AND transaction_id=$2`, string(request.TenantID), transaction); err != nil {
		t.Fatal(err)
	}
	if operation, err := owner.CallbackOperation(ctx, request.TenantID, parsed); operation != "" || err == nil {
		t.Fatal("expired state selected a live operation")
	}
}
