//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

type providerAuthorityEvent struct {
	command identity.CommandID
	key     ProviderAuthorityKey
	enabled bool
}

func providerAuthorityFixture(t *testing.T) (context.Context, *database.Pool, *ProviderAuthority, *ProviderAuthorityOperator, ProviderAuthorityKey) {
	t.Helper()
	ctx, pool, config, _ := oneTapStartIntegrationFixture(t)
	history, err := (ProviderAuthorityMigrationSource{Schema: config.Schema, Version: 42}).Load(ctx)
	if err != nil || len(history) != 1 {
		t.Fatal("load additive shared provider authority migration", len(history), err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("begin provider authority migration", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, history[0].UpSQL()); err != nil {
		t.Fatal("install provider authority after existing OAuth history", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("commit provider authority migration", err)
	}
	authority, err := NewProviderAuthority(pool, config.Schema, time.Second)
	if err != nil {
		t.Fatal("construct primary-backed provider reader", err)
	}
	operator, err := NewProviderAuthorityOperator(authority, config.Issuance.ActorID)
	if err != nil {
		t.Fatal("construct explicitly identified provider operator", err)
	}
	key := ProviderAuthorityKey{TenantID: config.TenantID, ProviderID: "example-oidc"}
	return ctx, pool, authority, operator, key
}

func providerAuthorityCommand(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal("new provider operator command", err)
	}
	return id
}

func providerAuthorityAssertState(t *testing.T, ctx context.Context, authority *ProviderAuthority, key ProviderAuthorityKey, want ProviderAuthorityState) {
	t.Helper()
	got, err := authority.Current(ctx, key)
	if err != nil || got != want {
		t.Fatal("durable provider state differs", got, want, err)
	}
}

func providerAuthorityAssertEvents(t *testing.T, ctx context.Context, pool *database.Pool, events ...providerAuthorityEvent) {
	t.Helper()
	var audits, messages int
	if err := pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM audit.records),
 (SELECT count(*) FROM public.outbox_messages)`).Scan(&audits, &messages); err != nil || audits != len(events) || messages != len(events) {
		t.Fatal("provider transitions did not conserve one audit and one outbox message each", audits, messages, len(events), err)
	}
	for _, event := range events {
		action, topic := "identity.oauth.provider.configure", "social_provider.configuration_changed.v1"
		if !event.enabled {
			action, topic = "identity.oauth.provider.disable", "social_provider.disabled.v1"
		}
		var correlated, matching, published int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER (
 WHERE tenant_id=$2 AND actor_id=$3 AND subject_id=$4 AND action=$5)
 FROM audit.records WHERE correlation_id=$1`, string(event.command), string(event.key.TenantID), oneTapStartActor, event.key.ProviderID, action).Scan(&correlated, &matching); err != nil || correlated != 1 || matching != 1 {
			t.Fatal("provider audit lost exact command, actor, tenant, provider or action", correlated, matching, err)
		}
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.outbox_messages
 WHERE id=$1 AND topic=$2 AND payload_version=1 AND state='pending'`, string(event.command), topic).Scan(&published); err != nil || published != 1 {
			t.Fatal("provider lifecycle message lost exact command identity or topic", published, err)
		}
	}
}

func TestProviderAuthoritySharedReadersObserveDisableAndExactLatestRetry(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	reader, err := NewProviderAuthority(pool, "onetap_oauth", time.Second)
	if err != nil {
		t.Fatal("construct independent reader before any provider change", err)
	}
	if state, err := reader.Current(ctx, key); err == nil || state.Enabled {
		t.Fatal("unconfigured provider did not fail closed", state, err)
	}
	configure := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 0, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	for attempt := range 2 {
		state, err := operator.Apply(ctx, configure)
		if err != nil || state != configure.Next {
			t.Fatal("initial configuration or exact retry changed result", attempt, state, err)
		}
	}
	configured := providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true}
	providerAuthorityAssertState(t, ctx, reader, key, configure.Next)
	providerAuthorityAssertEvents(t, ctx, pool, configured)

	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3, Enabled: false}, CommandID: providerAuthorityCommand(t),
	}
	state, err := operator.Apply(ctx, disable)
	if err != nil || state != disable.Next {
		t.Fatal("disable did not compare and advance live provider version", state, err)
	}
	providerAuthorityAssertState(t, ctx, reader, key, disable.Next)
	providerAuthorityAssertState(t, ctx, authority, key, disable.Next)

	restarted, err := NewProviderAuthorityOperator(reader, oneTapStartActor)
	if err != nil {
		t.Fatal("restart provider operator without recreating live reader", err)
	}
	state, err = restarted.Apply(ctx, disable)
	if err != nil || state != disable.Next {
		t.Fatal("latest committed disable was not durably retryable", state, err)
	}
	disabled := providerAuthorityEvent{command: disable.CommandID, key: key, enabled: false}
	providerAuthorityAssertEvents(t, ctx, pool, configured, disabled)
	if state, err := restarted.Apply(ctx, configure); err == nil || state.Enabled {
		t.Fatal("old configuration retry revived a disabled provider", state, err)
	}
	substituted := disable
	substituted.CommandID = providerAuthorityCommand(t)
	if _, err := restarted.Apply(ctx, substituted); err == nil {
		t.Fatal("same target version with another command was accepted as an exact retry")
	}
	for name, altered := range map[string]ProviderAuthorityChange{
		"changed predecessor": {Key: key, ExpectedVersion: 0, Next: disable.Next, CommandID: disable.CommandID},
		"changed profile":     {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 4, Enabled: false}, CommandID: disable.CommandID},
		"changed eligibility": {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3, Enabled: true}, CommandID: disable.CommandID},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := restarted.Apply(ctx, altered); err == nil {
				t.Fatal("changed transition reused a committed command as an exact retry")
			}
		})
	}
	providerAuthorityAssertState(t, ctx, reader, key, disable.Next)
	providerAuthorityAssertEvents(t, ctx, pool, configured, disabled)

	reenable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 8, Next: ProviderAuthorityState{Version: 12, ProfileVersion: 4, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	if state, err := restarted.Apply(ctx, reenable); err != nil || state != reenable.Next {
		t.Fatal("a strictly newer provider configuration could not restore eligibility", state, err)
	}
	providerAuthorityAssertState(t, ctx, reader, key, reenable.Next)
	providerAuthorityAssertEvents(t, ctx, pool, configured, disabled, providerAuthorityEvent{command: reenable.CommandID, key: key, enabled: true})
}

func TestProviderAuthorityCommandIDStaysBoundAfterOutboxRetention(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	initial := ProviderAuthorityChange{Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t)}
	disable := ProviderAuthorityChange{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3}, CommandID: providerAuthorityCommand(t)}
	for _, change := range []ProviderAuthorityChange{initial, disable} {
		if _, err := operator.Apply(ctx, change); err != nil {
			t.Fatal("prepare retained command custody", err)
		}
	}
	// Simulate retention of the one old, synthetic outbox item. Authority must
	// not depend on the lifetime of a notification that may already be gone.
	if tag, err := pool.Raw().Exec(ctx, `DELETE FROM public.outbox_messages WHERE id=$1`, string(initial.CommandID)); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("remove only the fixture's old outbox message", err)
	}
	if state, err := operator.Apply(ctx, initial); err == nil || state != (ProviderAuthorityState{}) {
		t.Fatal("an older command replay returned current authority")
	}
	rebound := ProviderAuthorityChange{Key: key, ExpectedVersion: 8, Next: ProviderAuthorityState{Version: 9, ProfileVersion: 4, Enabled: true}, CommandID: initial.CommandID}
	if state, err := operator.Apply(ctx, rebound); err == nil || state != (ProviderAuthorityState{}) {
		t.Fatal("outbox retention let a used command ID change authority again")
	}
	providerAuthorityAssertState(t, ctx, authority, key, disable.Next)
	var audits, republished int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM audit.records WHERE correlation_id=$1),
 (SELECT count(*) FROM public.outbox_messages WHERE id=$1)`, string(initial.CommandID)).Scan(&audits, &republished); err != nil || audits != 1 || republished != 0 {
		t.Fatal("rebound command created a second audit or outbox effect", err)
	}
}

func TestProviderAuthorityUnknownAndUnavailableStateFailClosed(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(ctx, configure); err != nil {
		t.Fatal("configure known tenant/provider", err)
	}
	for name, unknown := range map[string]ProviderAuthorityKey{
		"other tenant":     {TenantID: "AAAAAAAAAAAAAAAAAAAAAg", ProviderID: key.ProviderID},
		"other provider":   {TenantID: key.TenantID, ProviderID: "another-oidc"},
		"missing tenant":   {ProviderID: key.ProviderID},
		"missing provider": {TenantID: key.TenantID},
	} {
		t.Run(name, func(t *testing.T) {
			if state, err := authority.Current(ctx, unknown); err == nil || state.Enabled {
				t.Fatal("missing or foreign provider authority became eligible", state, err)
			}
		})
	}
	if _, err := pool.Raw().Exec(ctx, `ALTER TABLE onetap_oauth.provider_authorities RENAME TO provider_authorities_unavailable`); err != nil {
		t.Fatal("make only fixture-owned provider storage unavailable", err)
	}
	if state, err := authority.Current(ctx, key); err == nil || state.Enabled {
		t.Fatal("unavailable primary provider authority reused cached enabled state", state, err)
	}
	providerAuthorityAssertEvents(t, ctx, pool, providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true})
}

func TestProviderAuthorityRejectsInvalidInitialAndNonIncreasingTransitions(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	for name, change := range map[string]ProviderAuthorityChange{
		"initial disabled":    {Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: false}},
		"initial zero":        {Key: key, Next: ProviderAuthorityState{ProfileVersion: 3, Enabled: true}},
		"missing profile":     {Key: key, Next: ProviderAuthorityState{Version: 7, Enabled: true}},
		"missing predecessor": {Key: key, ExpectedVersion: 6, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}},
	} {
		t.Run(name, func(t *testing.T) {
			change.CommandID = providerAuthorityCommand(t)
			if _, err := operator.Apply(ctx, change); err == nil {
				t.Fatal("invalid initial authority was committed")
			}
			if state, err := authority.Current(ctx, key); err == nil || state.Enabled {
				t.Fatal("rejected initial authority left eligible state", state, err)
			}
			providerAuthorityAssertEvents(t, ctx, pool)
		})
	}
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(ctx, configure); err != nil {
		t.Fatal("configure initial authority", err)
	}
	for name, change := range map[string]ProviderAuthorityChange{
		"same enabled version":        {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}},
		"disable same version":        {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: false}},
		"older next version":          {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 6, ProfileVersion: 3, Enabled: false}},
		"stale predecessor":           {Key: key, ExpectedVersion: 6, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3, Enabled: false}},
		"insert over existing":        {Key: key, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 4, Enabled: true}},
		"disable substitutes profile": {Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 4, Enabled: false}},
	} {
		t.Run(name, func(t *testing.T) {
			change.CommandID = providerAuthorityCommand(t)
			if _, err := operator.Apply(ctx, change); err == nil {
				t.Fatal("non-increasing or stale provider transition was committed")
			}
			providerAuthorityAssertState(t, ctx, authority, key, configure.Next)
			providerAuthorityAssertEvents(t, ctx, pool, providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true})
		})
	}
}

func TestProviderAuthorityConcurrentChangesHaveOneCASWinner(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(ctx, configure); err != nil {
		t.Fatal("configure predecessor for competing operators", err)
	}
	reader, err := NewProviderAuthority(pool, "onetap_oauth", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewProviderAuthorityOperator(reader, oneTapStartActor)
	if err != nil {
		t.Fatal(err)
	}
	changes := []ProviderAuthorityChange{
		{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3, Enabled: false}, CommandID: providerAuthorityCommand(t)},
		{Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 9, ProfileVersion: 4, Enabled: true}, CommandID: providerAuthorityCommand(t)},
	}
	type result struct {
		index int
		state ProviderAuthorityState
		err   error
	}
	start, results := make(chan struct{}), make(chan result, 2)
	for index, owner := range []*ProviderAuthorityOperator{operator, other} {
		go func(index int, owner *ProviderAuthorityOperator) {
			<-start
			state, err := owner.Apply(ctx, changes[index])
			results <- result{index: index, state: state, err: err}
		}(index, owner)
	}
	close(start)
	winner, successes := -1, 0
	for range changes {
		outcome := <-results
		if outcome.err == nil {
			successes++
			winner = outcome.index
			if outcome.state != changes[outcome.index].Next {
				t.Error("CAS winner returned another provider state", outcome.state)
			}
		}
	}
	if successes != 1 {
		t.Fatal("competing commands did not have exactly one live-version winner", successes)
	}
	committed := changes[winner]
	providerAuthorityAssertState(t, ctx, authority, key, committed.Next)
	providerAuthorityAssertState(t, ctx, reader, key, committed.Next)
	providerAuthorityAssertEvents(t, ctx, pool,
		providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true},
		providerAuthorityEvent{command: committed.CommandID, key: key, enabled: committed.Next.Enabled})
}

func TestProviderAuthorityOutboxFailureRollsBackStateAndAudit(t *testing.T) {
	ctx, pool, authority, operator, key := providerAuthorityFixture(t)
	configure := ProviderAuthorityChange{
		Key: key, Next: ProviderAuthorityState{Version: 7, ProfileVersion: 3, Enabled: true}, CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(ctx, configure); err != nil {
		t.Fatal("configure provider before outbox failure", err)
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE SEQUENCE onetap_oauth.provider_authority_outbox_failure;
 CREATE FUNCTION onetap_oauth.reject_provider_authority_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 PERFORM nextval('onetap_oauth.provider_authority_outbox_failure');
 RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='fixture provider outbox failure'; END $$;
 CREATE TRIGGER provider_authority_outbox_failure BEFORE INSERT ON public.outbox_messages
 FOR EACH ROW WHEN (NEW.topic='social_provider.disabled.v1')
 EXECUTE FUNCTION onetap_oauth.reject_provider_authority_outbox()`); err != nil {
		t.Fatal("install outbox failure in fixture-owned database", err)
	}
	disable := ProviderAuthorityChange{
		Key: key, ExpectedVersion: 7, Next: ProviderAuthorityState{Version: 8, ProfileVersion: 3, Enabled: false}, CommandID: providerAuthorityCommand(t),
	}
	if _, err := operator.Apply(ctx, disable); err == nil {
		t.Fatal("failed outbox insert was reported as a committed disable")
	}
	var fired bool
	if err := pool.Raw().QueryRow(ctx, `SELECT is_called FROM onetap_oauth.provider_authority_outbox_failure`).Scan(&fired); err != nil || !fired {
		t.Fatal("failure did not reach the real existing outbox insert", fired, err)
	}
	providerAuthorityAssertState(t, ctx, authority, key, configure.Next)
	configured := providerAuthorityEvent{command: configure.CommandID, key: key, enabled: true}
	providerAuthorityAssertEvents(t, ctx, pool, configured)
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER provider_authority_outbox_failure ON public.outbox_messages`); err != nil {
		t.Fatal("remove fixture outbox fault", err)
	}
	if state, err := operator.Apply(ctx, disable); err != nil || state != disable.Next {
		t.Fatal("rolled-back disable consumed the command or predecessor", state, err)
	}
	providerAuthorityAssertState(t, ctx, authority, key, disable.Next)
	providerAuthorityAssertEvents(t, ctx, pool, configured, providerAuthorityEvent{command: disable.CommandID, key: key, enabled: false})
}
