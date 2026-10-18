//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

type invitationPreparationAdmissionProbe struct {
	invitationIssuanceProbe
	admissions int
}

func (p *invitationPreparationAdmissionProbe) AdmitFeaturePreparation(context.Context, Work, identity.Command) error {
	p.admissions++
	return nil
}

type invitationPreparationCounterProbe struct {
	commandCounterProbe
	deny bool
}

func (*invitationPreparationCounterProbe) CheckCommandCounters(context.Context, CommandCounterAdmissionWork) error {
	return nil
}

func (p *invitationPreparationCounterProbe) ReserveCommandCounters(context.Context, CommandCounterWork) (CommandCounterDisposition, error) {
	if p.deny {
		return CommandCounterDenied, nil
	}
	return CommandCounterAllowed, nil
}

// Real journal SQL proves original admission, denial and restart observation.
// The native probes deliberately generate no grant or delivery; production
// invitation issuance and membership interoperability belong to its consumer.
func testOrganizationInvitationPreparation(t *testing.T, ctx context.Context, pool *database.Pool, repo *Repository) {
	var installed bool
	if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='identity' AND table_name='commands' AND column_name='preparation_declaration')`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		if _, err := pool.Raw().Exec(ctx, counterPreparationSchemaSQL); err != nil {
			t.Fatal(err)
		}
	}
	for _, denied := range []bool{false, true} {
		name := "pending"
		if denied {
			name = "denied"
		}
		t.Run(name, func(t *testing.T) {
			b, p := organizationInvitationSendPlanFixture(t)
			var err error
			b.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			b.TenantID = identity.TenantID("invitation-preparation-" + name)
			owner := &invitationPreparationAdmissionProbe{invitationIssuanceProbe: invitationIssuanceProbe{outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}}}}
			registry, err := NewContributorRegistry([]Contributor{repo, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &invitationPreparationCounterProbe{deny: denied}})
			if err != nil {
				t.Fatal(err)
			}
			config := CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			})}}
			c, err := NewCoordinator(pool, registry, config)
			if err != nil {
				t.Fatal(err)
			}
			p.Contributors = registry.Descriptors()
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{{Name: "organization.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-organization"}}}})
			seed, err := securityMutationAudit(ctx, b, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.RecordID, "protected", true)
			if err != nil {
				t.Fatal(err)
			}
			p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, p.Feature.Operation, p.SubjectType, seed)
			if err != nil {
				t.Fatal(err)
			}
			q, admitted, phase, err := c.prepareFeaturePreparation(command, p)
			if err != nil {
				t.Fatal("original declaration rejected before SQL", err)
			}
			// A code-free original must never become an executable final plan.
			if _, err := registry.admitFeaturePlan(b, admitted.fingerprint, admitted.snapshot()); err == nil {
				t.Fatal("original declaration bypassed final issuance validation")
			}
			r, result, err := c.startFeaturePreparation(ctx, command, q, admitted, phase, [16]byte{1}, false)
			if denied {
				if !errors.As(err, new(identity.ForbiddenError)) || result.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("original counter denial lost its terminal receipt", result.Outcome, err)
				}
			} else if err != nil || result.Outcome != identity.CommitOutcomeInProgress || !r.generate {
				t.Fatal("original preparation never reached acknowledged generation", result.Outcome, err)
			}
			if owner.admissions != 1 {
				t.Fatal("original native admission was skipped")
			}
			// Restart with a rotated current key retains the original declaration.
			config.CurrentFingerprintKeyVersion = 2
			config.RetainedFingerprintKeys[2] = [32]byte{2}
			fresh, err := NewCoordinator(pool, registry, config)
			if err != nil {
				t.Fatal(err)
			}
			query, caller := queryInputs(b)
			record, err := fresh.QueryCommand(ctx, query, caller)
			want := identity.CommitOutcomeInProgress
			if denied {
				want = identity.CommitOutcomeNotCommitted
			}
			if record.Outcome != want || record.Binding != b || denied && !errors.As(err, new(identity.ForbiddenError)) || !denied && err != nil {
				t.Fatal("restart lost original preparation outcome", record.Outcome, err)
			}
			if !denied {
				id, _ := base64.RawURLEncoding.DecodeString(string(b.CommandID))
				if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
					t.Fatal(err)
				}
				recovered, err := fresh.RecoverFeatureCommand(ctx, query, caller)
				if recovered.Outcome != identity.CommitOutcomeNotCommitted || !errors.As(err, new(identity.UnavailableError)) {
					t.Fatal("unattached preparation could not reconcile under journal exclusion", recovered.Outcome, err)
				}
			}
			if owner.admissions != 1 {
				t.Fatal("observation or recovery repeated native admission")
			}
		})
	}
}
