//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	database "github.com/faustbrian/go-postgres"
)

// This proves the actual encrypted RP lookup/erasure boundary. The user and
// originating command below are storage fixtures, not a completed native start,
// active session admission, capability reservation or business-journey proof.
func storedRPCallbackFixture(t *testing.T, clockOffset time.Duration) (context.Context, *rpStartPhase, rpStartOutput, kernel.CapabilityIssuancePlan, oauth.CallbackRequest, *database.Pool, time.Time) {
	t.Helper()
	ctx, db := rpMigrationDatabase(t)
	p, _, request, clock := rpCallbackInputFixture(t)
	var primary time.Time
	if db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&primary) != nil {
		t.Fatal("primary clock unavailable")
	}
	primary = primary.UTC().Add(clockOffset)
	shift := primary.Sub(*clock)
	*clock = primary
	original, err := p.originalSession()
	if err != nil {
		t.Fatal(err)
	}
	spec, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.IssuedAt, spec.LastActivityAt = spec.IssuedAt.Add(shift), spec.LastActivityAt.Add(shift)
	spec.Authentication.Proof.IssuedAt = spec.Authentication.Proof.IssuedAt.Add(shift)
	spec.Authentication.Proof.ExpiresAt = spec.Authentication.Proof.ExpiresAt.Add(shift)
	original, err = session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	p.input.Session, err = sessionpg.OriginalSessionFields(original)
	if err != nil {
		t.Fatal(err)
	}
	p.input.Started, p.input.ValidUntil = primary, primary.Add(20*time.Second)
	wire, err := p.generateOutput(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	out, _, plan, err := p.restoreOutput(ctx, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	profile := out.Binding.Provider
	request.Callback, err = oauth.ParseQueryCallback(ctx, (url.Values{"code": {"synthetic-original-code"}, "state": {out.Binding.State}, "iss": {profile.Issuer}}).Encode(), profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(request.Callback.Destroy)
	history, err := (MigrationSource{Schema: "oauth_rp", Version: 100}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("RP migration unavailable")
	}
	if _, err := db.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("RP installation failed")
	}
	pool, err := database.Connect(ctx, database.Config{DSN: db.Config().ConnString(), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		// pgx ConnString retains the originally parsed DSN even after the
		// fixture selects its isolated database in ConnConfig.Database.
		c.ConnConfig.Database = db.Config().Database
		return nil
	}})
	if err != nil {
		t.Fatal("owned primary pool unavailable")
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(bounded) != nil {
			t.Error("owned pool cleanup failed")
		}
	})
	var selectedDatabase string
	if pool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&selectedDatabase) != nil || selectedDatabase != db.Config().Database {
		t.Fatal("pool escaped the fixture-owned database")
	}
	c := p.service.config()
	c.Schema = "oauth_rp"
	p.service.config = func() LinkServiceConfig { return c }
	p.service.pool = pool
	b := p.input.binding()
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1)`, string(b.TenantID), string(b.UserID)); err != nil {
		t.Fatal("user storage fixture failed")
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`, id, string(b.TenantID), b.OperationID, bytes.Repeat([]byte{1}, 32), []byte{1}); err != nil {
		t.Fatal("origin storage claim failed")
	}
	if _, err := db.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,$3)`, id, string(b.TenantID), b.OperationID); err != nil {
		t.Fatal("origin storage command failed")
	}
	v := out.Binding
	if _, err := db.Exec(ctx, `INSERT INTO oauth_rp.transactions(tenant_id,transaction_id,origin_command_id,operation,user_id,session_id,session_version,provider_id,configuration_version,issuer,client_id,redirect_uri,response_mode,state_key_version,state_digest,pkce_key_version,pkce_commitment,pkce_ciphertext,state_proof_ciphertext,binding_ciphertext,issued_at,expires_at,version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'query',$13,$14,$15,$16,$17,$18,$19,$20,$21,1)`, string(b.TenantID), b.RecordID, id, b.OperationID, string(b.UserID), spec.SessionID, spec.Version, profile.ID, profile.Version, profile.Issuer, profile.ClientID, profile.RedirectURI, v.StateKeyVersion, v.StateDigest[:], v.PKCEKeyVersion, v.PKCECommitment[:], out.PKCECiphertext, out.StateProofCiphertext, out.BindingCiphertext, v.IssuedAt, v.ExpiresAt); err != nil {
		t.Fatal("encrypted RP storage fixture failed")
	}
	return ctx, p, out, plan, request, pool, primary
}

func TestRPCallbackPrimaryLookupAndTerminalErasure(t *testing.T) {
	ctx, p, out, plan, request, pool, primary := storedRPCallbackFixture(t, 0)
	db := pool.Raw()
	b := p.input.binding()
	profile := out.Binding.Provider
	v := out.Binding
	flow, err := p.service.loadRPLinkCallback(ctx, request)
	if err != nil || flow.erased || flow.statePlan != plan.Grants[0] || !bytes.Equal(flow.pkce.ciphertext, out.PKCECiphertext) || flow.loadedAt.Before(primary) {
		flow.destroy()
		t.Fatal("primary lookup lost original custody", err)
	}
	flow.destroy()
	rateSource, err := p.service.CallbackRateSource(ctx, request)
	if err != nil || rateSource.ProviderID != profile.ID || rateSource.TransactionID != b.RecordID || rateSource.Lifetime != v.ExpiresAt.Sub(v.IssuedAt) {
		t.Fatal("rate attribution lost its authenticated original transaction", err)
	}
	if _, err := db.Exec(ctx, `UPDATE oauth_rp.transactions SET pkce_ciphertext=NULL,state_proof_ciphertext=NULL,version=2,secrets_erased_at=clock_timestamp() WHERE tenant_id=$1 AND transaction_id=$2`, string(b.TenantID), b.RecordID); err != nil {
		t.Fatal("terminal erasure failed")
	}
	retained, err := p.service.loadRPLinkCallback(ctx, request)
	defer retained.destroy()
	if err != nil || !retained.erased || retained.statePlan != plan.Grants[0] || len(retained.pkce.ciphertext) != 0 || retained.stateProof != (capability.Proof{}) {
		t.Fatal("erased RP either lost retry metadata or recreated exchange authority", err)
	}
	replayRate, err := p.service.CallbackRateSource(ctx, request)
	if err != nil || replayRate != rateSource {
		t.Fatal("terminal retry changed original rate bucket or lifetime", err)
	}
	foreign := request
	foreign.Session = auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32)))
	if flow, err := p.service.loadRPLinkCallback(ctx, foreign); err == nil {
		flow.destroy()
		t.Fatal("erased metadata disclosed to another browser subject")
	}
	if _, err := p.service.CallbackRateSource(ctx, foreign); err == nil {
		t.Fatal("rate source accepted a foreign browser after erasure")
	}
}
