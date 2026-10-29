//go:build integration

package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
)

func TestMetadataSparseOwnerAccessPath(t *testing.T) {
	f := setupNativeConsumer(t)
	config := metadataPolicy(t, f.config, metadataConsumerPolicy{base: &baselineEvaluator{}})
	service, err := apikeypg.NewService(f.pool, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	template := metadataIssue(t, f, service, f.caller, "planner-only-template")
	_, sparse := f.register()
	// Representative planner data only: genuine native schema and user owners,
	// with canonical metadata copied to distinct IDs. These synthetic lookup
	// digests are never verified or used as credential/consumer acceptance proof.
	_, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_api_keys.keys(tenant_id,configuration_id,key_id,user_id,pepper_version,lookup_digest,record)
 SELECT tenant_id,configuration_id,'plan-'||lpad(n::text,22,'0'),
 CASE WHEN n%1000=0 THEN $4 ELSE user_id::text END,pepper_version,
 decode(md5(n::text)||md5(n::text),'hex'),
 convert_to(replace(replace(convert_from(record,'UTF8'),$3,'plan-'||lpad(n::text,22,'0')),user_id::text,CASE WHEN n%1000=0 THEN $4 ELSE user_id::text END),'UTF8')
 FROM identity_api_keys.keys CROSS JOIN generate_series(1,20000) n
 WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, baselineTenant, config.Configuration.Spec().ID, string(template.ID), string(sparse))
	if err != nil {
		t.Fatal("bounded representative sparse-owner planner fixture", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE identity_api_keys.keys`); err != nil {
		t.Fatal(err)
	}
	var collation string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT c.collname FROM pg_attribute a JOIN pg_collation c ON c.oid=a.attcollation WHERE a.attrelid='identity_api_keys.keys'::regclass AND a.attname='key_id'`).Scan(&collation); err != nil || collation != "C" {
		t.Fatal("native key domain lost its actual C collation", err)
	}
	query := `EXPLAIN(ANALYZE,BUFFERS) SELECT key_id,configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND user_id=$2 AND configuration_id=ANY($3::text[]) AND key_id COLLATE "C">$4 ORDER BY key_id COLLATE "C" LIMIT $5`
	showPlan := func(label, sql string, user string, ids []string) {
		t.Helper()
		rows, err := f.pool.Raw().Query(f.ctx, sql, baselineTenant, user, ids, "", 11)
		if err != nil {
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plan.WriteString(line)
			plan.WriteByte('\n')
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s:\n%s", label, plan.String())
	}
	for sample := 0; sample < 2; sample++ {
		showPlan("baseline: actual native schema, 20000 planner rows, sparse owner 20, limit 11, C key domain", query, string(sparse), []string{config.Configuration.Spec().ID})
	}
	metadataPlannerWriteWork(t, f, template, "before metadata index")
	installMetadataPages(t, f, false)
	metadataPlannerWriteWork(t, f, template, "after partial metadata index")
	for sample := 0; sample < 2; sample++ {
		showPlan("candidate: partial exact owner/configuration/key index", query, string(sparse), []string{config.Configuration.Spec().ID})
	}
	lateral := `EXPLAIN(ANALYZE,BUFFERS) SELECT key_id,configuration_id,record FROM unnest($3::text[]) AS selected(id) CROSS JOIN LATERAL
 (SELECT key_id,configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND user_id=$2 AND configuration_id=selected.id AND key_id COLLATE "C">$4 ORDER BY key_id COLLATE "C" LIMIT $5) AS page
 ORDER BY key_id COLLATE "C" LIMIT $5`
	for sample := 0; sample < 2; sample++ {
		showPlan("candidate: per-configuration bounded lateral query", lateral, string(sparse), []string{config.Configuration.Spec().ID, "absent-profile"})
		showPlan("candidate: dense owner page bounded per configuration", lateral, string(f.user), []string{config.Configuration.Spec().ID, "absent-profile"})
	}
	metadataPreparedPlan(t, f, strings.TrimPrefix(lateral, "EXPLAIN(ANALYZE,BUFFERS) "), string(sparse), string(f.user), []string{config.Configuration.Spec().ID})
	var tableBytes, allIndexes, candidateBytes int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_size('identity_api_keys.keys'),pg_indexes_size('identity_api_keys.keys'),pg_relation_size('identity_api_keys.identity_api_keys_metadata_user_page')`).Scan(&tableBytes, &allIndexes, &candidateBytes); err != nil {
		t.Fatal(err)
	}
	t.Logf("measured bytes: native key heap=%d all retained indexes including candidate=%d candidate=%d; 20001 rows; no production frequency/growth claim", tableBytes, allIndexes, candidateBytes)
	got, err := metadataReader(t, service).List(f.ctx, apikey.ListRequest{Authentication: f.caller, ConfigurationIDs: []string{config.Configuration.Spec().ID}, Limit: 1})
	if err != nil || len(got.Records) != 1 {
		t.Fatal("actual caller query failed on representative native data", err)
	}
}

func metadataPlannerWriteWork(t *testing.T, f nativeConsumerFixture, template apikey.Record, label string) {
	t.Helper()
	statements := []string{
		`EXPLAIN(ANALYZE,BUFFERS,WAL) INSERT INTO identity_api_keys.keys(tenant_id,configuration_id,key_id,user_id,pepper_version,lookup_digest,record)
 SELECT tenant_id,configuration_id,'write-plan-'||lpad(n::text,22,'0'),user_id,pepper_version,
 decode(md5(n::text)||md5(n::text),'hex'),convert_to(replace(convert_from(record,'UTF8'),$2,'write-plan-'||lpad(n::text,22,'0')),'UTF8')
 FROM identity_api_keys.keys CROSS JOIN generate_series(50001,51000) n WHERE tenant_id=$1 AND key_id=$2`,
		`EXPLAIN(ANALYZE,BUFFERS,WAL) UPDATE identity_api_keys.keys SET record=record WHERE tenant_id=$1 AND key_id=$2`,
	}
	for _, sql := range statements {
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := tx.Query(f.ctx, sql, baselineTenant, string(template.ID))
		if err != nil {
			_ = tx.Rollback(f.ctx)
			t.Fatal(err)
		}
		var plan strings.Builder
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				rows.Close()
				_ = tx.Rollback(f.ctx)
				t.Fatal(err)
			}
			plan.WriteString(line + "\n")
		}
		err = rows.Err()
		rows.Close()
		if rollback := tx.Rollback(f.ctx); err != nil || rollback != nil {
			t.Fatal("bounded planner write experiment did not roll back", err, rollback)
		}
		t.Logf("%s; isolated 1000-row insert or one unchanged-index-column record update, rolled back; instrumentation is not production throughput:\n%s", label, plan.String())
	}
}

func metadataPreparedPlan(t *testing.T, f nativeConsumerFixture, sql, sparse, dense string, ids []string) {
	t.Helper()
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_, _ = connection.Exec(cleanup, `RESET plan_cache_mode`)
		_ = connection.Conn().Deallocate(cleanup, "metadata_selected_page")
	}()
	if _, err := connection.Conn().Prepare(f.ctx, "metadata_selected_page", sql); err != nil {
		t.Fatal("actual pgx/server-side preparation", err)
	}
	for sample := 0; sample < 8; sample++ {
		owner := sparse
		if sample%2 != 0 {
			owner = dense
		}
		rows, err := connection.Query(f.ctx, "metadata_selected_page", baselineTenant, owner, ids, "", 11)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for rows.Next() {
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil || count != 11 {
			t.Fatal("normal prepared sparse/dense owner page changed its bound", err)
		}
	}
	var generic, custom int64
	if err := connection.QueryRow(f.ctx, `SELECT generic_plans,custom_plans FROM pg_prepared_statements WHERE name='metadata_selected_page'`).Scan(&generic, &custom); err != nil {
		t.Fatal(err)
	}
	t.Logf("normal pgx prepared execution: mode=%v, eight alternating sparse/dense pages, server generic_plans=%d custom_plans=%d", f.pool.Raw().Config().ConnConfig.DefaultQueryExecMode, generic, custom)
	for _, mode := range []string{"auto", "force_generic_plan", "force_custom_plan"} {
		if _, err := connection.Exec(f.ctx, "SET plan_cache_mode="+mode); err != nil {
			t.Fatal(err)
		}
		for _, owner := range []string{sparse, dense} {
			// PostgreSQL quotes actual parameter values; utility EXPLAIN EXECUTE
			// does not bind client placeholders itself. No manual SQL quoting.
			var explain string
			if err := connection.QueryRow(f.ctx, `SELECT format('EXPLAIN(ANALYZE,BUFFERS) EXECUTE metadata_selected_page(%L,%L,%L::text[],%L,%s)',$1::text,$2::text,$3::text[],$4::text,$5::int)`, baselineTenant, owner, ids, "", 11).Scan(&explain); err != nil {
				t.Fatal(err)
			}
			rows, err := connection.Query(f.ctx, explain)
			if err != nil {
				t.Fatal(err)
			}
			var plan strings.Builder
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				plan.WriteString(line + "\n")
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("prepared %s (forced modes are diagnostic alternatives, not production execution claims):\n%s", mode, plan.String())
		}
	}
}

func metadataOrganizationPlan(t *testing.T, f nativeConsumerFixture, config apikeypg.ServiceConfig, userRecord, organizationRecord apikey.Record) {
	t.Helper()
	// Planner-only volume follows the genuine organization consumer assertions.
	// Both owner rows and migrations are real; synthetic lookup digests are not
	// verified or counted as issued/imported credential acceptance.
	for _, sample := range []struct {
		record apikey.Record
		count  int
		prefix string
	}{{userRecord, 20000, "org-foreign-"}, {organizationRecord, 20, "org-sparse-"}} {
		_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_api_keys.keys(tenant_id,configuration_id,key_id,user_id,organization_id,pepper_version,lookup_digest,record)
 SELECT tenant_id,configuration_id,$3||lpad(n::text,22,'0'),user_id,organization_id,pepper_version,
 decode(md5($3||n::text)||md5($3||n::text),'hex'),convert_to(replace(convert_from(record,'UTF8'),$2,$3||lpad(n::text,22,'0')),'UTF8')
 FROM identity_api_keys.keys CROSS JOIN generate_series(1,$4::int) n WHERE tenant_id=$1 AND key_id=$2`, baselineTenant, string(sample.record.ID), sample.prefix, sample.count)
		if err != nil {
			t.Fatal("bounded organization sparse-owner planner fixture", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE identity_api_keys.keys`); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, err := tx.Exec(f.ctx, `SET LOCAL lock_timeout='1s'; DROP INDEX identity_api_keys.identity_api_keys_metadata_org_page`); err != nil {
		t.Fatal(err)
	}
	baseline := `EXPLAIN(ANALYZE,BUFFERS) SELECT key_id,configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2 AND configuration_id=ANY($3::text[]) AND key_id COLLATE "C">$4 ORDER BY key_id COLLATE "C" LIMIT $5`
	rows, err := tx.Query(f.ctx, baseline, baselineTenant, string(organizationRecord.Owner.Spec().OrganizationID), []string{config.Configuration.Spec().ID}, "", 11)
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	err = rows.Err()
	rows.Close()
	if rollback := tx.Rollback(f.ctx); err != nil || rollback != nil {
		t.Fatal(err, rollback)
	}
	t.Logf("organization baseline: actual native schema, 20000 foreign user-owned rows and 21 selected organization keys, limit11, optional index omitted transactionally:\n%s", plan.String())
	lateral := `EXPLAIN(ANALYZE,BUFFERS) SELECT key_id,configuration_id,record FROM unnest($3::text[]) AS selected(id) CROSS JOIN LATERAL
 (SELECT key_id,configuration_id,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND organization_id=$2 AND configuration_id=selected.id AND key_id COLLATE "C">$4 ORDER BY key_id COLLATE "C" LIMIT $5) AS page
 ORDER BY key_id COLLATE "C" LIMIT $5`
	for sample := 0; sample < 2; sample++ {
		rows, err := f.pool.Raw().Query(f.ctx, lateral, baselineTenant, string(organizationRecord.Owner.Spec().OrganizationID), []string{config.Configuration.Spec().ID, config.LegacyConfiguration.Spec().ID}, "", 11)
		if err != nil {
			t.Fatal(err)
		}
		plan.Reset()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			plan.WriteString(line + "\n")
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("organization candidate: actual independent partial organization index and exact per-configuration limited query, sample%d:\n%s", sample+1, plan.String())
	}
}
