//go:build integration

package passwordpostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
)

// Fault only the final protected transaction: request issuance, retained hash
// preparation and reservation still use the real unmodified PostgreSQL owners.
func testResetCompletionDisconnect(t *testing.T, ctx context.Context, service *ResetService, keys *keyring.Provider, mail resetRequestDeliveryPreparation, mailCrypto *envelope.Service, request password.ResetRequestRequest, signin *SigninService, signinConfig SigninConfig) {
	for _, before := range []bool{true, false} {
		name := "after-commit"
		if before {
			name = "before-commit"
		}
		t.Run(name, func(t *testing.T) {
			issued := request
			issued.CommandID, _ = identity.NewCommandID()
			issued.Caller = request.Caller.Clone()
			issued.Caller.CorrelationID = string(issued.CommandID)
			issued.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("synthetic-reset-completion-" + name))
			ack, err := service.ResetRequest(ctx, issued)
			if err != nil || !ack.Accepted {
				t.Fatal("completion disconnect original issuance", err)
			}
			proof := captureResetDelivery(t, ctx, service.pool, mail, service.config().Coordinator, string(request.Identifier), mailCrypto)
			defer proof.Transfer(context.Background(), func(context.Context, []byte) error { return nil })
			id, _ := identity.NewCommandID()
			caller := request.Caller.Clone()
			caller.CorrelationID = string(id)
			caller.Request.Action = authorization.Action(resetOperation().OperationID)
			caller.Request.Resource = authorization.Resource{Type: "identity.user"}
			user, credential, grant, _, err := service.ResetCompletionRateSource(ctx, proof, caller)
			if err != nil {
				t.Fatal("completion disconnect original scope", err)
			}
			caller.Request.Resource.ID = authorization.ResourceID(user)
			config := service.config()
			config.Coordinator.LeaseDuration = 500 * time.Millisecond
			collected := 0
			if config.CollectReset != nil {
				collect := config.CollectReset
				config.CollectReset = func(ctx context.Context, binding identity.CommandBinding, challenge string, c risk.Context, secret primitive.Secret) ([]risk.Signal, error) {
					collected++
					return collect(ctx, binding, challenge, c, secret)
				}
			} else {
				collect := config.Screening.Collect
				config.Screening.Collect = func(ctx context.Context, c risk.Context, secret primitive.Secret) ([]risk.Signal, error) {
					collected++
					return collect(ctx, c, secret)
				}
			}
			fault := &signinCommitFault{before: before, marker: "INSERT INTO identity_password.replacements"}
			pool, err := database.Connect(ctx, database.Config{DSN: service.pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
			if err != nil {
				t.Fatal("completion disconnect pool unavailable")
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if pool.Close(cleanup) != nil {
					t.Error("completion disconnect pool cleanup")
				}
			}()
			interrupted, err := NewResetService(pool, config, keys)
			if err != nil {
				t.Fatal("completion disconnect service", err)
			}
			restarted, err := NewResetService(service.pool, config, keys)
			if err != nil {
				t.Fatal("completion restarted service", err)
			}
			repository, err := NewRepository(service.pool, config.Repository)
			if err != nil {
				t.Fatal(err)
			}
			key := password.CredentialKey{TenantID: request.TenantID, SubjectID: identity.UserID(user)}
			predecessor, err := repository.ReadPasswordCredential(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			if login, err := resetTestSignin(t, ctx, service.pool, signin, signinConfig, string(request.Identifier), []byte("synthetic-full-public-reset")); err != nil || login.State != auth.SignInStateAuthenticated {
				t.Fatal("completion disconnect predecessor signin", err)
			}
			sessions := pgx.Identifier{config.Session.Schema, "sessions"}.Sanitize()
			resetEffects := pgx.Identifier{config.Session.Schema, "password_resets"}.Sanitize()
			var activeBefore int
			if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM `+sessions+` WHERE tenant_id=$1 AND user_id=$2 AND state='active'`, request.TenantID, user).Scan(&activeBefore); err != nil || activeBefore == 0 {
				t.Fatal("completion disconnect lacks active predecessor sessions", err)
			}
			secret, _ := primitive.NewSecret([]byte("synthetic-disconnected-reset-password"))
			defer secret.Destroy()
			original, err := interrupted.ResetComplete(ctx, password.ResetCompleteRequest{TenantID: request.TenantID, CommandID: id, Token: proof, NewPassword: secret, Caller: caller, Origin: request.Origin, Network: request.Network, Device: request.Device})
			if err == nil || !fault.hit.Load() || original.CommandID != id || original.Outcome != identity.CommitOutcomeUnknown || original.Validate() != nil || collected != 1 {
				t.Fatal("completion disconnect fabricated commitment or lost original identity", err)
			}
			command, _ := base64.RawURLEncoding.DecodeString(string(id))
			want, outcome := 1, identity.CommitOutcomeCommitted
			if before {
				want, outcome = 0, identity.CommitOutcomeNotCommitted
			}
			assertEffects := func(wantAudit, wantAuditOutcome int) {
				t.Helper()
				var replacements, resets, uses, active, audits, auditOutcome, events, revoked int
				err := service.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.replacements WHERE command_id=$1),(SELECT count(*) FROM `+resetEffects+` WHERE command_id=$1),(SELECT uses FROM capability_identity_one_use WHERE capability_id=$2),(SELECT count(*) FROM `+sessions+` WHERE tenant_id=$3 AND user_id=$4 AND state='active'),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT COALESCE(max(r.outcome),0) FROM audit.records r JOIN audit.identity_command_bindings b ON b.event_id=r.record_id WHERE b.command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT COALESCE(sum(revoked_count),0) FROM `+resetEffects+` WHERE command_id=$1)`, command, grant, request.TenantID, user).Scan(&replacements, &resets, &uses, &active, &audits, &auditOutcome, &events, &revoked)
				wantActive, wantRevoked := activeBefore, 0
				if !before {
					wantActive, wantRevoked = 0, activeBefore
				}
				if err != nil || replacements != want || resets != want || uses != want || active != wantActive || revoked != wantRevoked || audits != wantAudit || auditOutcome != wantAuditOutcome || events != want {
					t.Fatal("completion disconnect split credential/proof/session/audit/lifecycle effects", err)
				}
				material, err := repository.ReadPasswordCredential(ctx, key)
				if err != nil || material.Authority().Credential.Version != predecessor.Authority().Credential.Version+uint64(want) || material.Authority().AuthorityVersion != predecessor.Authority().AuthorityVersion+uint64(want) {
					t.Fatal("completion disconnect changed credential successors", err)
				}
				if before && material.EncodedHash().String() != predecessor.EncodedHash().String() {
					t.Fatal("completion rollback replaced verifier")
				}
			}
			assertEffects(want, want)
			query := identity.RecoveryQuery{CommandID: id, TenantID: request.TenantID, UserID: identity.UserID(user), ActorID: identity.ActorID(signinTestActor), ActorKind: authorization.SubjectServiceAccount, OperationID: resetOperation().OperationID, RecordID: string(credential)}
			bounded, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			var terminal password.ResetCompleteResult
			for {
				result, err := restarted.RecoverResetComplete(bounded, query, caller)
				if result.Outcome == outcome {
					var unavailable identity.UnavailableError
					if result.CommandID != id || result.Validate() != nil || (!before && err != nil) || (before && !errors.As(err, &unavailable)) || collected != 1 {
						t.Fatal("completion recovery changed original result or regenerated", err)
					}
					terminal = result
					break
				}
				select {
				case <-bounded.Done():
					t.Fatal("completion disconnect outcome unresolved", err)
				case <-ticker.C:
				}
			}
			for i := 0; i < 2; i++ {
				result, err := restarted.RecoverResetComplete(ctx, query, caller)
				if result != terminal || (!before && err != nil) || collected != 1 {
					t.Fatal("repeated completion recovery changed original effects", err)
				}
				auditOutcome := 1
				if before {
					auditOutcome = 2
				}
				assertEffects(1, auditOutcome)
			}
			if !before {
				if terminal.CredentialVersion != predecessor.Authority().Credential.Version+1 || !terminal.SessionsRevoked {
					t.Fatal("recovered completion lost successors")
				}
				if login, err := resetTestSignin(t, ctx, service.pool, signin, signinConfig, string(request.Identifier), []byte("synthetic-full-public-reset")); err != nil || login.State != auth.SignInStateRejected {
					t.Fatal("recovered completion retained old-password signin", err)
				}
				if login, err := resetTestSignin(t, ctx, service.pool, signin, signinConfig, string(request.Identifier), []byte("synthetic-disconnected-reset-password")); err != nil || login.State != auth.SignInStateAuthenticated {
					t.Fatal("recovered completion cannot use replacement password", err)
				}
			}
		})
	}
}
