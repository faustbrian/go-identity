//go:build integration

package postgres

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5"
)

func TestSSOSAMLIDPLogoutExactQueriesAtSameUserScale(t *testing.T) {
	f := newSSOSessionAccessFixture(t, "sso-saml")
	installSAMLIDPLogoutEffectTestHistory(t, f)
	effect, err := NewSSOSAMLIDPLogoutEffect(f.repository)
	if err != nil {
		t.Fatal(err)
	}
	targets := []kernel.SSOSAMLIDPLogoutTarget{seedSAMLIDPLogoutEffectTestIssuance(t, f, f.record, "identity.sso.saml-acs")}
	for i := 1; i < kernel.MaxSSOSAMLIDPLogoutTargets; i++ {
		record, _ := addSAMLIDPLogoutEffectTestSession(t, f, fmt.Sprintf("query-selected-%03d", i), fmt.Sprintf("query-selected-family-%03d", i))
		purpose := "identity.sso.saml-acs"
		if i%2 == 1 {
			purpose = "identity.sso.saml-idp-init"
		}
		targets = append(targets, seedSAMLIDPLogoutEffectTestIssuance(t, f, record, purpose))
	}
	seedSAMLIDPLogoutQueryDistractors(t, f)
	for _, table := range []string{"sessions", "families", "session_issuances", "saml_idp_logout_revocations"} {
		if _, err := f.pool.Raw().Exec(f.ctx, "ANALYZE session_store."+table); err != nil {
			t.Fatal("refresh disposable fixture statistics", err)
		}
	}
	var engine, indexes string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version(),(SELECT string_agg(indexdef,E'\n' ORDER BY tablename,indexname) FROM pg_indexes WHERE schemaname='session_store' AND tablename IN ('sessions','families','session_issuances','saml_idp_logout_revocations'))`).Scan(&engine, &indexes); err != nil {
		t.Fatal(err)
	}
	t.Logf("engine=%s; 20000 same-tenant/same-user distractors plus 128 real selected sessions; native production SQL/binding types; isolated warm serial execution, not production contention or end-to-end latency; indexes:\n%s", engine, indexes)
	for _, lock := range []bool{true, false} {
		for _, matches := range []int{0, 1, 16} {
			name := fmt.Sprintf("targets/lock=%t/matches=%d-of-16", lock, matches)
			keys := make([]struct {
				Session  string `json:"session_id"`
				Issuance string `json:"issuance_hex"`
			}, 16)
			for i := range keys {
				keys[i].Session = fmt.Sprintf("missing-query-target-%03d", i)
				keys[i].Issuance = hex.EncodeToString(mustCommandBytes(t, targets[i].IssuanceCommandID))
				if i < matches {
					keys[i].Session = targets[i].SessionID
				}
			}
			encoded, err := json.Marshal(keys)
			if err != nil {
				t.Fatal(err)
			}
			args := []any{"guest-tenant", "enterprise-user", string(encoded), kernel.SSOSAMLSigninOperation().OperationID, kernel.SSOSAMLIDPConfirmationOperation().OperationID}
			t.Run(name, func(t *testing.T) {
				measureSAMLIDPLogoutQuery(t, f, name, effect.targetRowsSQL(lock), args, matches, "")
			})
		}
	}
	for _, matches := range []int{0, 1, kernel.MaxSSOSAMLIDPLogoutTargets} {
		name := fmt.Sprintf("update/matches=%d-of-128", matches)
		ids := make([]string, len(targets))
		for i := range ids {
			ids[i] = fmt.Sprintf("missing-query-target-%03d", i)
			if i < matches {
				ids[i] = targets[i].SessionID
			}
		}
		encoded, err := json.Marshal(ids)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(name, func(t *testing.T) {
			measureSAMLIDPLogoutQuery(t, f, name, effect.updateTargetsSQL(), []any{"guest-tenant", "enterprise-user", string(encoded)}, matches, "session")
		})
	}
	var receiptID []byte
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT command_id FROM session_store.saml_idp_logout_revocations WHERE tenant_id='guest-tenant' ORDER BY command_id LIMIT 1`).Scan(&receiptID); err != nil {
		t.Fatal(err)
	}
	for _, hit := range []bool{true, false} {
		id, matches := receiptID, 1
		if !hit {
			id, matches = mustCommandBytes(t, newSAMLIDPLogoutEffectTestCommandID(t)), 0
		}
		name := fmt.Sprintf("receipt/hit=%t", hit)
		t.Run(name, func(t *testing.T) {
			measureSAMLIDPLogoutQuery(t, f, name, effect.evidenceSQL(), []any{"guest-tenant", id}, matches, "")
		})
	}
	var revoked int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM session_store.sessions WHERE tenant_id='guest-tenant' AND state='revoked'`).Scan(&revoked); err != nil || revoked != 0 {
		t.Fatal("measured updates escaped their rolled-back transactions", revoked, err)
	}
	intent := kernel.SSOSAMLIDPLogoutIntent{OrganizationID: "selected-org", ProviderID: "selected-provider", RequestDigest: [32]byte{1}, ValidUntil: time.Now().UTC().Add(20 * time.Second).Truncate(time.Microsecond), Targets: targets}
	binding, command := newSAMLIDPLogoutEffectTestCommand(t, intent)
	owner := &samlIDPLogoutEffectTestOwner{effect: effect, command: command, intent: intent}
	coordinator, plan := prepareSAMLIDPLogoutEffectTest(t, f, owner, binding)
	reservation, _, err := coordinator.ReserveCommand(f.ctx, binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	id, bindingDigest := revocationEvidence(binding, kernel.SSOSAMLIDPLogoutLifecycle())
	intentDigest, err := samlIDPLogoutIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("receipt/insert", func(t *testing.T) {
		measureSAMLIDPLogoutQuery(t, f, "receipt/insert", effect.insertEvidenceSQL(), []any{string(binding.TenantID), id, binding.OperationID, string(binding.UserID), bindingDigest[:], intentDigest[:], len(targets)}, 1, "receipt")
	})
	started := time.Now()
	w, err := coordinator.Begin(f.ctx, reservation)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Abort(w, identity.UnavailableError{})
	result, err := coordinator.ApplyFeature(f.ctx, w, command)
	if err != nil {
		t.Fatal(err)
	}
	result, err = coordinator.Commit(w, result)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("owning operation did not commit all eight target pages", result.Outcome, err)
	}
	t.Logf("full 128-target owning PostgreSQL transaction: %s (coordinator Begin, mutation, final checks, audit/outbox and Commit; excludes provider verification and reservation)", time.Since(started))
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM session_store.sessions WHERE tenant_id='guest-tenant' AND state='revoked'`).Scan(&revoked); err != nil || revoked != len(targets) {
		t.Fatal("owning operation revoked the wrong number of sessions", revoked, err)
	}
}

func seedSAMLIDPLogoutQueryDistractors(t *testing.T, f ssoSessionAccessFixture) {
	t.Helper()
	// Distractors retain native row widths and indexed identity distribution.
	// Only the 128 selected records use the fully reconstructed session fixture;
	// bulk distractor payloads are storage-shaped, not authentication evidence.
	queries := []string{
		`INSERT INTO session_store.families(tenant_id,family_id,user_id,version,state,issued_at)
 SELECT s.tenant_id,'query-distractor-family-'||g,s.user_id,1,'active',f.issued_at
 FROM session_store.sessions s JOIN session_store.families f USING(tenant_id,family_id,user_id)
 CROSS JOIN generate_series(1,20000) g WHERE s.tenant_id='guest-tenant' AND s.session_id='enterprise-access'`,
		`INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record)
 SELECT tenant_id,'query-distractor-'||g,user_id,'query-distractor-family-'||g,1,1,'active',digest_version,
 sha256(convert_to('query-distractor-'||g,'UTF8')),expires_at,
 jsonb_set(record||jsonb_build_object('SessionID','query-distractor-'||g,'FamilyID','query-distractor-family-'||g),'{CSRF,Binding,SessionID}',to_jsonb('query-distractor-'||g))
 FROM session_store.sessions CROSS JOIN generate_series(1,20000) g WHERE tenant_id='guest-tenant' AND session_id='enterprise-access'`,
		`INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
 SELECT decode(md5('query-issuance-'||g),'hex'),'guest-tenant','identity.sso.saml-acs',decode(repeat('01',32),'hex'),1,decode('01','hex') FROM generate_series(1,20000) g
 UNION ALL SELECT decode(md5('query-receipt-'||g),'hex'),'guest-tenant','identity.sso.saml-slo',decode(repeat('01',32),'hex'),1,decode('01','hex') FROM generate_series(1,20000) g`,
		`INSERT INTO identity.commands(command_id,tenant_id,purpose)
 SELECT decode(md5('query-issuance-'||g),'hex'),'guest-tenant','identity.sso.saml-acs' FROM generate_series(1,20000) g
 UNION ALL SELECT decode(md5('query-receipt-'||g),'hex'),'guest-tenant','identity.sso.saml-slo' FROM generate_series(1,20000) g`,
		`INSERT INTO session_store.session_issuances(tenant_id,command_id,purpose,user_id,session_id,family_id,binding_digest,record_digest)
 SELECT 'guest-tenant',decode(md5('query-issuance-'||g),'hex'),'identity.sso.saml-acs','enterprise-user','query-distractor-'||g,'query-distractor-family-'||g,decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex') FROM generate_series(1,20000) g`,
		`INSERT INTO session_store.saml_idp_logout_revocations(tenant_id,command_id,purpose,user_id,binding_digest,intent_digest,target_count)
 SELECT 'guest-tenant',decode(md5('query-receipt-'||g),'hex'),'identity.sso.saml-slo','enterprise-user',decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),16 FROM generate_series(1,20000) g`,
	}
	for _, query := range queries {
		if _, err := f.pool.Raw().Exec(f.ctx, query); err != nil {
			t.Fatal("populate bounded same-user SQL evidence fixture", err)
		}
	}
}

type samlIDPLogoutQueryPlan struct {
	NodeType       string                   `json:"Node Type"`
	Relation       string                   `json:"Relation Name"`
	Index          string                   `json:"Index Name"`
	ActualRows     float64                  `json:"Actual Rows"`
	ActualLoops    float64                  `json:"Actual Loops"`
	RemovedFilter  float64                  `json:"Rows Removed by Filter"`
	RemovedRecheck float64                  `json:"Rows Removed by Index Recheck"`
	Plans          []samlIDPLogoutQueryPlan `json:"Plans"`
}

func measureSAMLIDPLogoutQuery(t *testing.T, f ssoSessionAccessFixture, name, query string, args []any, matches int, mutation string) {
	t.Helper()
	var types []string
	for _, arg := range args {
		types = append(types, fmt.Sprintf("%T", arg))
	}
	t.Logf("case=%s native_go_types=%v SQL=%s", name, types, query)
	for sample := 0; sample < 3; sample++ {
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer tx.Rollback(f.ctx)
			if _, err := tx.Exec(f.ctx, `SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='1s'`); err != nil {
				t.Fatal(err)
			}
			var encoded []byte
			start := time.Now()
			bindings := append([]any{pgx.QueryExecModeExec}, args...)
			if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, bindings...).Scan(&encoded); err != nil {
				t.Fatal("explain exact native SQL and bindings", err)
			}
			elapsed := time.Since(start)
			var result []struct {
				Plan          samlIDPLogoutQueryPlan
				PlanningTime  float64 `json:"Planning Time"`
				ExecutionTime float64 `json:"Execution Time"`
			}
			if err := json.Unmarshal(encoded, &result); err != nil || len(result) != 1 {
				t.Fatal("decode measured JSON plan", err)
			}
			plan := result[0]
			switch mutation {
			case "session":
				var revoked int
				if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM session_store.sessions WHERE tenant_id='guest-tenant' AND state='revoked'`).Scan(&revoked); err != nil || revoked != matches {
					t.Fatal("measured update changed the wrong number of rows", revoked, matches, err)
				}
			case "receipt":
				var receipts int
				if err := tx.QueryRow(f.ctx, `SELECT count(*) FROM session_store.saml_idp_logout_revocations WHERE tenant_id=$1 AND command_id=$2`, args[0], args[1]).Scan(&receipts); err != nil || receipts != matches {
					t.Fatal("measured insert did not retain the exact local receipt", receipts, matches, err)
				}
			default:
				if plan.Plan.ActualRows != float64(matches) {
					t.Fatal("query returned the wrong number of matching rows", plan.Plan.ActualRows, matches)
				}
			}
			var scans []string
			var visit func(samlIDPLogoutQueryPlan)
			visit = func(node samlIDPLogoutQueryPlan) {
				if node.Relation != "" && strings.Contains(node.NodeType, "Scan") {
					examined := (node.ActualRows + node.RemovedFilter + node.RemovedRecheck) * node.ActualLoops
					scans = append(scans, fmt.Sprintf("%s:%s:%s rows=%g loops=%g examined=%g", node.Relation, node.NodeType, node.Index, node.ActualRows, node.ActualLoops, examined))
				}
				for _, child := range node.Plans {
					visit(child)
				}
			}
			visit(plan.Plan)
			t.Logf("case=%s sample=%d returned=%g planning_ms=%g execution_ms=%g client_explain=%s scans=%v; scan examination is per-node rows plus filtered/rechecked rows multiplied by loops, not summed inclusive parent work", name, sample, plan.Plan.ActualRows, plan.PlanningTime, plan.ExecutionTime, elapsed, scans)
			t.Logf("case=%s sample=%d exact_json_plan=%s", name, sample, encoded)
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal("rollback measured statement and release locks", err)
			}
		}()
	}
}
