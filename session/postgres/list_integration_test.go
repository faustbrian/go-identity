//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// Use the actually delivered cookie and full kernel/authentication owners, not
// a test replacement for SessionReader or an application-written page store.
func testPublicSessionList(t *testing.T, ctx context.Context, pool *database.Pool, input session.GetRequest, original session.Session, config SessionServiceConfig) {
	t.Helper()
	spec, _ := original.Bindings()
	native, err := NewRepository(pool, config.Repository)
	if err != nil {
		t.Fatal(err)
	}
	fixtureIDs := []string{"list-active-a", "list-expired-b", "list-revoked-c", "list-other-audience-d", "list-family-revoked-e"}
	for i, id := range fixtureIDs {
		s := spec
		s.SessionID, s.FamilyID = id, "family-"+id
		s.Lookup.Sum[0] = byte(i + 50)
		if i == 1 {
			s.IssuedAt = s.IssuedAt.Add(-24 * time.Hour)
			s.LastActivityAt = s.LastActivityAt.Add(-24 * time.Hour)
			s.Authentication.Proof.IssuedAt = s.Authentication.Proof.IssuedAt.Add(-24 * time.Hour)
			s.Authentication.Proof.ExpiresAt = s.Authentication.Proof.ExpiresAt.Add(-24 * time.Hour)
		}
		if i == 3 {
			s.Audience = "another-service"
			s.Authentication.Proof.Audience = s.Audience
		}
		keys, e := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
		if e != nil {
			t.Fatal(e)
		}
		a, _ := s.Authority.Bindings()
		a.Session.ScopeKey, a.SessionFamily.ScopeKey = keys.Session, keys.Family
		s.Authority, e = session.NewAuthoritySnapshot(a)
		if e != nil {
			t.Fatal(e)
		}
		record, e := session.NewSession(s)
		if e != nil {
			t.Fatal(e)
		}
		payload, expiry, e := encodeRecord(record)
		if e != nil {
			t.Fatal(e)
		}
		state, familyState := "active", "active"
		if i == 2 {
			state = "revoked"
		}
		if i == 4 {
			familyState = "revoked"
		}
		if _, e = pool.Raw().Exec(ctx, `INSERT INTO session_store.families(tenant_id,user_id,family_id,version,state,issued_at) VALUES($1,$2,$3,$4::numeric,$5,$6)`, string(s.TenantID), string(s.UserID), s.FamilyID, strconv.FormatUint(s.FamilyVersion, 10), familyState, s.IssuedAt.UTC().Format(storedTimeLayout)); e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Raw().Exec(ctx, `INSERT INTO session_store.sessions(tenant_id,user_id,session_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9,$10,$11)`, string(s.TenantID), string(s.UserID), s.SessionID, s.FamilyID, strconv.FormatUint(s.Version, 10), strconv.FormatUint(s.FamilyVersion, 10), state, int64(s.Lookup.KeyVersion), s.Lookup.Sum[:], expiry, payload); e != nil {
			t.Fatal(e)
		}
		defer func(id, family string) {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if _, e := pool.Raw().Exec(cleanup, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2;`, string(spec.TenantID), id); e != nil {
				t.Error("fixture cleanup")
			}
			if _, e := pool.Raw().Exec(cleanup, `DELETE FROM session_store.families WHERE tenant_id=$1 AND family_id=$2;`, string(spec.TenantID), family); e != nil {
				t.Error("fixture cleanup")
			}
		}(id, s.FamilyID)
	}
	listing := ListServiceConfig{Sessions: config, Listing: session.ListConfig{Authorization: revokeQueryPolicy{}, PolicyRevision: 1, MaximumDuration: 2 * time.Second}}
	service, err := NewListService(pool, listing)
	if err != nil {
		t.Fatal(err)
	}
	request := session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "native-list", Limit: 2}
	collect := func(include bool) map[string]session.Device {
		t.Helper()
		request.Cursor, request.IncludeInactive = "", include
		all := map[string]session.Device{}
		for n := 0; n < 100; n++ {
			out, e := service.List(ctx, request)
			if e != nil || len(out.Sessions) > 2 {
				t.Fatal("native list", e)
			}
			for _, d := range out.Sessions {
				if _, exists := all[d.SessionID]; exists {
					t.Fatal("duplicate cursor row")
				}
				if d.LastSeenAt.Location() != time.UTC || d.ExpiresAt.Location() != time.UTC {
					t.Fatal("UTC projection")
				}
				all[d.SessionID] = d
			}
			if out.NextCursor == "" {
				return all
			}
			request.Cursor = out.NextCursor
		}
		t.Fatal("unbounded continuation")
		return nil
	}
	active := collect(false)
	if !active[spec.SessionID].Current || active["list-active-a"].SessionID == "" {
		t.Fatal("issued current/active session absent")
	}
	for _, id := range fixtureIDs[1:] {
		if _, ok := active[id]; ok {
			t.Fatal("inactive/foreign audience escaped", id)
		}
	}
	all := collect(true)
	for _, id := range []string{"list-expired-b", "list-revoked-c", "list-family-revoked-e"} {
		if !all[id].Inactive {
			t.Fatal("retained tombstone/expiry absent", id)
		}
	}
	if _, ok := all["list-other-audience-d"]; ok {
		t.Fatal("foreign audience escaped")
	}
	t.Run("primary bounds scopes and cancel", func(t *testing.T) {
		q := session.SessionPageQuery{TenantID: spec.TenantID, UserID: spec.UserID, Audience: spec.Audience, Limit: 1}
		first, e := native.ReadSessionPage(ctx, q)
		if e != nil || len(first.Entries) != 1 || !first.HasMore {
			t.Fatal("raw page bound", e)
		}
		b, _ := first.Entries[0].Session.Bindings()
		q.AfterSessionID = b.SessionID
		next, e := native.ReadSessionPage(ctx, q)
		if e != nil || len(next.Entries) != 1 {
			t.Fatal("raw next page", e)
		}
		b2, _ := next.Entries[0].Session.Bindings()
		if b2.SessionID <= b.SessionID {
			t.Fatal("exclusive bytewise ordering")
		}
		for _, change := range []func(*session.SessionPageQuery){func(q *session.SessionPageQuery) { q.TenantID = "foreign" }, func(q *session.SessionPageQuery) { q.UserID = "foreign" }, func(q *session.SessionPageQuery) { q.Audience = "foreign" }} {
			other := q
			change(&other)
			page, e := native.ReadSessionPage(ctx, other)
			if e != nil || len(page.Entries) != 0 || page.HasMore {
				t.Fatal("scope isolation", e)
			}
		}
		for _, limit := range []uint16{0, 101} {
			q.Limit = limit
			if page, e := native.ReadSessionPage(ctx, q); e == nil || len(page.Entries) != 0 {
				t.Fatal("invalid page limit")
			}
		}
		q.Limit = 1
		canceled, stop := context.WithCancel(ctx)
		stop()
		var ce identity.CancelledError
		if page, e := native.ReadSessionPage(canceled, q); !errors.As(e, &ce) || len(page.Entries) != 0 {
			t.Fatal("page cancellation", e)
		}
	})
	t.Run("current policy and primary outage deny disclosure", func(t *testing.T) {
		denied := listing
		denied.Listing.Authorization = issueDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
		})
		s, e := NewListService(pool, denied)
		if e != nil {
			t.Fatal(e)
		}
		request.Cursor = ""
		if out, e := s.List(ctx, request); e == nil || len(out.Sessions) != 0 {
			t.Fatal("policy denial disclosed")
		}
		if _, e := pool.Raw().Exec(ctx, `ALTER TABLE session_store.families RENAME TO hidden_list_families`); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := pool.Raw().Exec(ctx, `ALTER TABLE session_store.hidden_list_families RENAME TO families`); e != nil {
				t.Error("restore primary fixture")
			}
		}()
		if out, e := service.List(ctx, request); e == nil || len(out.Sessions) != 0 || out.NextCursor != "" {
			t.Fatal("outage disclosed")
		}
	})
	t.Run("index supports audience-scoped keyset", func(t *testing.T) {
		var plan string
		// Explain through one acquired connection so the setting cannot depend on pool routing.
		conn, e := pool.Acquire(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Release()
		var indexValid bool
		if e = conn.QueryRow(ctx, `SELECT indisvalid AND indisready FROM pg_index WHERE indexrelid='session_store.session_owner_audience_order'::regclass`).Scan(&indexValid); e != nil || !indexValid {
			t.Fatal("missing usable audience index", e)
		}
		// Earlier native lifecycle cases can change the fixture cardinality.
		// Plan against current table statistics, not the empty-install estimate.
		if _, e = conn.Exec(ctx, `ANALYZE session_store.sessions`); e != nil {
			t.Fatal(e)
		}
		if _, e = conn.Exec(ctx, `SET enable_seqscan=off`); e != nil {
			t.Fatal(e)
		}
		defer conn.Exec(ctx, `RESET enable_seqscan`)
		rows, e := conn.Query(ctx, `EXPLAIN SELECT session_id FROM session_store.sessions WHERE tenant_id=$1 AND user_id=$2 AND (record->>'Audience') COLLATE "C"=$3 AND session_id>$4 ORDER BY session_id LIMIT 3`, string(spec.TenantID), string(spec.UserID), spec.Audience, "")
		if e != nil {
			t.Fatal(e)
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if e = rows.Scan(&line); e != nil {
				t.Fatal(e)
			}
			plan += line + "\n"
		}
		if e = rows.Err(); e != nil {
			t.Fatal(e)
		}
		// When every fixture record shares an audience, PostgreSQL may choose
		// the smaller owner-order index. Both retain scoped keyset execution;
		// the audience index must exist but its name is not an optimizer API.
		if !strings.Contains(plan, "Index Scan") || !strings.Contains(plan, "Index Cond:") || !strings.Contains(plan, "tenant_id") || !strings.Contains(plan, "user_id") || !strings.Contains(plan, "session_id") {
			t.Fatal("missing scoped indexed keyset", fmt.Sprint(plan))
		}
	})
	t.Run("corrupt indexed record denies entire page", func(t *testing.T) {
		var originalExpiry string
		if e := pool.Raw().QueryRow(ctx, `SELECT expires_at FROM session_store.sessions WHERE tenant_id=$1 AND session_id='list-active-a'`, string(spec.TenantID)).Scan(&originalExpiry); e != nil {
			t.Fatal(e)
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET expires_at='2000-01-01T00:00:00.000000000Z' WHERE tenant_id=$1 AND session_id='list-active-a'`, string(spec.TenantID)); e != nil {
			t.Fatal(e)
		}
		defer func() {
			if _, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET expires_at=$1 WHERE tenant_id=$2 AND session_id='list-active-a'`, originalExpiry, string(spec.TenantID)); e != nil {
				t.Error("restore corrupted fixture")
			}
		}()
		page, e := native.ReadSessionPage(ctx, session.SessionPageQuery{TenantID: spec.TenantID, UserID: spec.UserID, Audience: spec.Audience, Limit: 100})
		if !errors.Is(e, ErrInvalidRecord) || len(page.Entries) != 0 || page.HasMore {
			t.Fatal("partial corrupt page disclosed", e)
		}
		request.Cursor, request.Limit = "", 100
		if out, e := service.List(ctx, request); e == nil || len(out.Sessions) != 0 || out.NextCursor != "" {
			t.Fatal("public corrupt page disclosed")
		}
	})
}
