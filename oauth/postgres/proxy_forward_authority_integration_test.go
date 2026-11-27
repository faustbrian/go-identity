//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestProxyForwardInvalidatedAuthorityAfterGenerationMarkerCannotOpenPKCE(t *testing.T) {
	for _, test := range []struct {
		name string
		sql  string
	}{
		{"global compromise epoch", `UPDATE identity.global_authorities SET version=version+1 WHERE authority_id=$1 AND version=1`},
		{"tenant authority epoch", `UPDATE identity.tenant_authorities SET version=version+1 WHERE tenant_id=$1 AND version=1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newProxyForwardIntegration(t, false)
			callbackID, err := base64.RawURLEncoding.DecodeString(string(f.locator.CallbackCommand))
			if err != nil {
				t.Fatal("decode original callback command", err)
			}
			trace := &proxyForwardAuthorityCommitTrace{}
			trace.invalidate = func(ctx context.Context) error {
				var marked bool
				if err := f.pool.Raw().QueryRow(ctx, `SELECT state='pending' AND preparation_started_generation=generation AND preparation_ciphertext IS NULL
FROM identity.commands WHERE command_id=$1`, callbackID).Scan(&marked); err != nil {
					return err
				}
				if !marked {
					return errors.New("generation marker was not independently visible at commit acknowledgement")
				}
				authority := f.service.config.GlobalAuthorityID
				if test.name == "tenant authority epoch" {
					authority = string(f.locator.Tenant)
				}
				tag, err := f.pool.Raw().Exec(ctx, test.sql, authority)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return errors.New("original directory authority epoch was not advanced exactly once")
				}
				return nil
			}
			traced, err := database.Connect(f.ctx, database.Config{
				DSN: f.pool.Raw().Config().ConnString(), MaxConns: 2,
				Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
					c.ConnConfig.Tracer = trace
					return nil
				},
			})
			if err != nil {
				t.Fatal("open traced fixture-owned runtime pool", err)
			}
			t.Cleanup(func() {
				ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := traced.Close(ctx); err != nil {
					t.Error("close traced runtime pool", err)
				}
			})
			directory, err := kernel.NewRepository(traced, kernel.Config{MaximumDuration: f.service.config.MaximumDuration})
			if err != nil {
				t.Fatal("real traced directory repository", err)
			}
			// The public constructor intentionally discards raw envelope keys and
			// capability configuration. Preserve its validated owning services.
			service := *f.service
			service.pool, service.directory = traced, directory
			calls := 0
			verifierReached := false
			generate := func(_ context.Context, original oauthproxy.OriginalCallback) (oauthproxy.CallbackPrepared, error) {
				calls++
				verifierReached = verifierReached || original.Verifier.Challenge() != ""
				return oauthproxy.CallbackPrepared{}, oauthproxy.CallbackReconcile
			}
			for attempt := range 2 {
				if err := service.ExecuteOAuthProxyForward(f.ctx, f.lookup, generate); !errors.Is(err, oauthproxy.CallbackReconcile) {
					t.Errorf("attempt %d did not fail closed for the invalidated original authority: %v", attempt, err)
				}
				var pending, reserved, started bool
				var audits, events, users, accounts, sessions int
				err := f.pool.Raw().QueryRow(f.ctx, `SELECT
 (SELECT version=1 AND outcome IS NULL AND handoff_ciphertext IS NULL FROM onetap_oauth.proxy_transactions),
 (SELECT state='reserved' AND uses=0 AND command_id=$2 FROM public.capability_identity_one_use),
 (SELECT state='pending' AND preparation_started_generation=generation AND preparation_ciphertext IS NULL FROM identity.commands WHERE command_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
 (SELECT count(*) FROM identity.users),
 (SELECT count(*) FROM identity.accounts),
 (SELECT count(*) FROM onetap_sessions.sessions)`, callbackID, string(f.locator.CallbackCommand)).Scan(
					&pending, &reserved, &started, &audits, &events, &users, &accounts, &sessions)
				if err != nil || !pending || !reserved || !started || audits != 0 || events != 0 || users != 0 || accounts != 0 || sessions != 0 {
					t.Errorf("attempt %d disclosed a handoff or settled invalidated generation: pending=%t reserved=%t started=%t audits=%d events=%d users=%d accounts=%d sessions=%d: %v",
						attempt, pending, reserved, started, audits, events, users, accounts, sessions, err)
				}
				if calls != 0 {
					t.Errorf("attempt %d invoked generation after acknowledged authority invalidation: calls=%d verifier_reached=%t", attempt, calls, verifierReached)
				}
			}
			trace.mu.Lock()
			markers, commits, invalidations, traceErr := trace.markers, trace.commits, trace.invalidations, trace.err
			trace.mu.Unlock()
			if markers != 1 || commits != 1 || invalidations != 1 || traceErr != nil {
				t.Fatalf("authority invalidation did not occur at the exact acknowledged generation marker: markers=%d commits=%d invalidations=%d: %v", markers, commits, invalidations, traceErr)
			}
		})
	}
}

type proxyForwardAuthorityTraceQuery uint8

const (
	proxyForwardAuthorityOtherQuery proxyForwardAuthorityTraceQuery = iota
	proxyForwardAuthorityMarkerQuery
	proxyForwardAuthorityCommitQuery
	proxyForwardAuthorityRollbackQuery
)

type proxyForwardAuthorityTraceKey struct{}

type proxyForwardAuthorityCommitTrace struct {
	mu            sync.Mutex
	marked        *pgx.Conn
	markers       int
	commits       int
	invalidations int
	err           error
	invalidate    func(context.Context) error
}

func (*proxyForwardAuthorityCommitTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	kind := proxyForwardAuthorityOtherQuery
	switch strings.TrimSpace(data.SQL) {
	case `UPDATE identity.commands SET preparation_started_generation=generation WHERE command_id=$1 AND tenant_id=$2 AND purpose=$3 AND preparation_started_generation IS NULL AND preparation_ciphertext IS NULL`:
		kind = proxyForwardAuthorityMarkerQuery
	case "commit", "COMMIT":
		kind = proxyForwardAuthorityCommitQuery
	case "rollback", "ROLLBACK":
		kind = proxyForwardAuthorityRollbackQuery
	}
	return context.WithValue(ctx, proxyForwardAuthorityTraceKey{}, kind)
}

func (trace *proxyForwardAuthorityCommitTrace) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	kind, _ := ctx.Value(proxyForwardAuthorityTraceKey{}).(proxyForwardAuthorityTraceQuery)
	trace.mu.Lock()
	if kind == proxyForwardAuthorityMarkerQuery && data.Err == nil && data.CommandTag.RowsAffected() == 1 {
		trace.markers++
		trace.marked = conn
		trace.mu.Unlock()
		return
	}
	if trace.marked != conn {
		trace.mu.Unlock()
		return
	}
	trace.marked = nil
	if kind != proxyForwardAuthorityCommitQuery || data.Err != nil || data.CommandTag.String() != "COMMIT" {
		trace.err = errors.New("generation marker was not immediately followed by an acknowledged commit")
		trace.mu.Unlock()
		return
	}
	trace.commits++
	trace.mu.Unlock()

	// pgx has received COMMIT, but its caller cannot resume generation until
	// this callback returns. The independent admin pool observes real commit
	// visibility and advances authority without retaining a runtime SQL lock.
	err := trace.invalidate(ctx)
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if err != nil {
		trace.err = err
		return
	}
	trace.invalidations++
}
