//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

func TestOAuthProxyRetirementHistoryReadsOnlyCommittedLocalOriginal(t *testing.T) {
	ctx, pool, _ := newAccountAuthorityStore(t)
	_, err := pool.Raw().Exec(ctx, `WITH ids AS (
 SELECT decode('aa'||lpad(to_hex(i),30,'0'),'hex') id,
 CASE WHEN i<=16000 THEN 'tenant-a' ELSE 'tenant-'||(i%40)::text END tenant,
 CASE WHEN i%2=0 THEN 'identity.oauth.proxy-start' ELSE 'identity.oauth.signin-start' END purpose
 FROM generate_series(1,20000) i
), claims AS (
 INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT id,tenant,purpose,decode(repeat('71',32),'hex'),1,'\xa0'::bytea FROM ids
 RETURNING command_id,tenant_id,purpose
)
INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT command_id,tenant_id,purpose FROM claims;
ANALYZE identity.commands; ANALYZE identity.identity_command_id_claims`)
	if err != nil {
		t.Fatal("populate skewed local command history", err)
	}
	for _, preview := range []bool{false, true} {
		for _, state := range []string{"committed", "pending", "aborted", "missing"} {
			name := "production/" + state
			if preview {
				name = "preview/" + state
			}
			t.Run(name, func(t *testing.T) {
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				scope, origin, plan, fp, safe, wire := proxyRetirementHistoryFixture(t, preview)
				id, err := base64.RawURLEncoding.Strict().DecodeString(string(scope.OriginCommandID))
				if err != nil {
					t.Fatal(err)
				}
				if state != "missing" {
					seedOAuthProxyRetirementHistory(t, ctx, tx, id, origin, fp, safe, wire, state)
				}
				kind := OAuthProxyRetireProduction
				if preview {
					kind = OAuthProxyRetirePreview
				}
				w, owner, _ := proxyRetirementWork(t, kind)
				b := proxyRetirementBinding()
				b.TenantID, b.CorrelationID = scope.TenantID, string(scope.OriginCommandID)
				b.CommandID, err = identity.NewCommandID()
				if err != nil {
					t.Fatal(err)
				}
				command, err := NewOAuthProxyOriginRetirementCommand(b, kind, scope.SourceCommandID, scope.SourceVersion)
				if err != nil {
					t.Fatal(err)
				}
				w.state.ctx, w.state.tx, w.state.binding, w.state.featureApplyCommand = ctx, tx, b, &command
				w.state.execution.reservation.plan.binding = b
				grant, err := w.OAuthProxyOriginRetirementGrant(ctx, owner, command)
				if state == "committed" {
					if err != nil || grant != plan.CapabilityIssuance.Grants[0] {
						t.Fatal("committed history did not recover exact original grant", err)
					}
				} else if err == nil || grant != (CapabilityPlan{}) || w.state.failed == nil {
					t.Fatal("unsettled or absent history returned retirement custody", err)
				}
				measureOAuthProxyRetirementHistory(t, ctx, tx, id, origin, state == "committed")
			})
		}
	}
}

func seedOAuthProxyRetirementHistory(t *testing.T, ctx context.Context, tx pgx.Tx, id []byte, b identity.CommandBinding, fp [32]byte, safe, wire []byte, state string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,$3,$4,1,$5)`,
		id, string(b.TenantID), b.OperationID, fp[:], safe); err != nil {
		t.Fatal("seed retained command claim", err)
	}
	var class, receipt, resultVersion any
	if state != "pending" {
		class, receipt, resultVersion = "denied", []byte{0xa0}, 1
		if state == "committed" {
			class = "committed"
		}
	}
	const insert = `WITH ts AS(SELECT clock_timestamp() AS now)
INSERT INTO identity.commands(command_id,tenant_id,purpose,command_plan,state,generation,attempt,lease_owner,lease_until,heartbeat_at,created_at,updated_at,terminal_at,terminal_class,result_version,result)
SELECT $1,$2,$3,$4,$5,1,1,decode(repeat('11',16),'hex'),now+interval '1 minute',now,now,now,CASE WHEN $5='pending' THEN NULL ELSE now END,$6,$7,$8 FROM ts`
	if _, err := tx.Exec(ctx, insert, id, string(b.TenantID), b.OperationID, wire, state, class, resultVersion, receipt); err != nil {
		t.Fatal("seed native terminal or pending journal shape", err)
	}
}

func measureOAuthProxyRetirementHistory(t *testing.T, ctx context.Context, tx pgx.Tx, id []byte, b identity.CommandBinding, found bool) {
	t.Helper()
	args := []any{id, string(b.TenantID), b.OperationID}
	rows, err := tx.Query(ctx, `EXPLAIN(ANALYZE,BUFFERS,TIMING OFF) `+oauthProxyRetirementGrantSQL, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if rows.Err() != nil || strings.Contains(plan.String(), "Seq Scan") || !strings.Contains(plan.String(), "Index Cond") {
		t.Fatal("expected a bounded original-command lookup", plan.String(), rows.Err())
	}
	start := time.Now()
	for range 12 {
		var safe, fingerprint, wire []byte
		err := tx.QueryRow(ctx, oauthProxyRetirementGrantSQL, args...).Scan(&safe, &fingerprint, &wire)
		if found && err != nil || !found && err != pgx.ErrNoRows {
			t.Fatal("unexpected history measurement result", err)
		}
	}
	t.Logf("20k skewed local rows; native []byte,string,string; 12 warm SELECTs total=%s\n%s", time.Since(start), plan.String())
}
