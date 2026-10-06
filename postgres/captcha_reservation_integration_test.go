//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

// This independently implemented SQL participant proves the coordinator's
// reservation transaction boundary. It is not production replay derivation,
// provider verification or native risk-store integration evidence.
type sqlCaptchaReservation struct {
	captchaReservationProbe
	retained CaptchaReservationWork
	mode     string
}

func (p *sqlCaptchaReservation) ReserveCaptchaReplay(ctx context.Context, w CaptchaReservationWork) error {
	p.retained = w
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration != 0 {
		return invalidWork()
	}
	if _, err := w.Binding(&sqlCaptchaReservation{}); err == nil {
		return invalidWork()
	}
	spec, _ := b.Command.Feature()
	n, err := w.Exec(ctx, `INSERT INTO identity.captcha_replay_fixture(alias,command_id,fingerprint,generation) VALUES($1,$2,$3,$4::numeric) ON CONFLICT DO NOTHING`, spec.Fields[0].Value.Text, string(spec.Binding.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return p.finish(ctx, w)
}
func (p *sqlCaptchaReservation) RebindCaptchaReplay(ctx context.Context, w CaptchaReservationWork) error {
	p.retained = w
	b, err := w.Binding(p)
	if err != nil || b.PreviousGeneration == 0 {
		return invalidWork()
	}
	spec, _ := b.Command.Feature()
	n, err := w.Exec(ctx, `UPDATE identity.captcha_replay_fixture SET generation=$4::numeric WHERE alias=$1 AND command_id=$2 AND fingerprint=$3 AND generation=$5::numeric`, spec.Fields[0].Value.Text, string(spec.Binding.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), strconv.FormatUint(b.PreviousGeneration, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return p.finish(ctx, w)
}
func (p *sqlCaptchaReservation) finish(ctx context.Context, w CaptchaReservationWork) error {
	switch p.mode {
	case "error":
		return identity.UnavailableError{}
	case "panic":
		panic("private fixture diagnostic")
	case "open-rows":
		_, err := w.Query(ctx, "SELECT 1")
		return err
	case "poison":
		_, _ = w.Exec(ctx, "SELECT 1/0")
		return nil
	case "closure":
		_, _ = w.Exec(ctx, "COMMIT")
		return nil
	}
	_, err := w.DatabaseTime(ctx)
	return err
}

func testCaptchaReplayReservation(t *testing.T, ctx context.Context, pool *database.Pool) {
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE identity.captcha_replay_fixture(alias text PRIMARY KEY,command_id text NOT NULL,fingerprint bytea NOT NULL,generation numeric NOT NULL);CREATE TABLE identity.captcha_domain_fixture(command_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	setup := func(t *testing.T, p *sqlCaptchaReservation, alias string) (*Coordinator, identity.CommandBinding, identity.Command, CommandPlan) {
		t.Helper()
		c, command, plan := captchaReservationFixture(t)
		c.pool = pool
		// Replace only the registered feature instance, before immutable registry
		// construction, so Binding must recognize the invoked instance itself.
		entries := []Contributor{c.registry.state.entries[0].contributor, c.registry.state.entries[1].contributor, c.registry.state.entries[2].contributor, p}
		registry, err := NewContributorRegistry(entries)
		if err != nil {
			t.Fatal(err)
		}
		c.registry = registry
		spec, _ := command.Feature()
		spec.Binding.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		spec.Binding.RecordID = string(spec.Binding.CommandID)
		spec.Fields = []identity.FeatureField{{Name: "alias", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: alias}}}
		command = featureCodecCommand(t, spec)
		plan.Audits[0].BindingDigest = securityAuditScopeDigest(spec.Binding, &spec.Operation, plan.SubjectType, spec.Binding.RecordID, audit.ActorHuman, "identity-feature-audit-binding-v1")
		plan, err = c.PrepareCommandPlan(spec.Binding, command, plan)
		if err != nil {
			t.Fatal(err)
		}
		return c, spec.Binding, command, plan
	}
	t.Run("durable before domain rollback and exact takeover", func(t *testing.T) {
		p := &sqlCaptchaReservation{}
		c, b, command, plan := setup(t, p, "rollback-alias")
		r, _, err := c.ReserveCommand(ctx, b, command, plan)
		if err != nil || r.state == nil {
			t.Fatal("reserve failed", err)
		}
		if _, err := p.retained.Binding(p); err == nil {
			t.Fatal("retained callback authority")
		}
		if _, err := p.retained.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("retained SQL authority")
		}
		w, err := c.Begin(ctx, r)
		if err != nil {
			t.Fatal("domain begin failed", err)
		}
		if _, err := w.Exec(ctx, `INSERT INTO identity.captcha_domain_fixture(command_id) VALUES($1)`, string(b.CommandID)); err != nil {
			t.Fatal(err)
		}
		// No complete domain/effect receipt exists; Abort must prove rollback
		// but leave the independently committed pending alias intact.
		_, _ = c.Abort(w, identity.UnavailableError{})
		var owner string
		var domainRows int
		if err := pool.Raw().QueryRow(ctx, `SELECT command_id,(SELECT count(*) FROM identity.captcha_domain_fixture) FROM identity.captcha_replay_fixture WHERE alias='rollback-alias'`).Scan(&owner, &domainRows); err != nil || owner != string(b.CommandID) || domainRows != 0 {
			t.Fatal("rollback lost winner or preserved domain", err)
		}
		other, ob, oc, op := setup(t, &sqlCaptchaReservation{}, "rollback-alias")
		if loser, _, err := other.ReserveCommand(ctx, ob, oc, op); err == nil || loser.state != nil {
			t.Fatal("pending alias assigned twice")
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
			t.Fatal(err)
		}
		if next, _, err := c.ReserveCommand(ctx, b, command, plan); err != nil || next.state == nil {
			t.Fatal("exact takeover failed", err)
		}
		var commandGeneration, aliasGeneration string
		if err := pool.Raw().QueryRow(ctx, `SELECT c.generation::text,r.generation::text FROM identity.commands c CROSS JOIN identity.captcha_replay_fixture r WHERE c.command_id=$1 AND r.alias='rollback-alias'`, id).Scan(&commandGeneration, &aliasGeneration); err != nil || commandGeneration != "2" || aliasGeneration != "2" {
			t.Fatal("takeover generations diverged", err)
		}
	})
	for _, mode := range []string{"error", "panic", "open-rows", "poison", "closure"} {
		t.Run(mode, func(t *testing.T) {
			p := &sqlCaptchaReservation{mode: mode}
			c, b, command, plan := setup(t, p, mode)
			if r, _, err := c.ReserveCommand(ctx, b, command, plan); err == nil || r.state != nil {
				t.Fatal("unsafe callback reserved", mode)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
			var aliases, claims int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.captcha_replay_fixture WHERE alias=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$2)`, mode, id).Scan(&aliases, &claims); err != nil || aliases != 0 || claims != 0 {
				t.Fatal("partial reservation survived", mode, err)
			}
		})
	}
}
