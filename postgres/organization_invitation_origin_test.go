package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
)

func invitationOriginFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan, *invitationIssuanceProbe) {
	t.Helper()
	b, p := organizationInvitationSendPlanFixture(t)
	p.OrganizationInvitationOrigin = &OrganizationInvitationOriginPlan{OrganizationID: "original-organization", OrganizationVersion: 7}
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{{Name: "organization.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "original-organization"}}, {Name: "organization.version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 7}}}})
	owner := &invitationIssuanceProbe{outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}}}
	c, _, _ := coordinatorFixture(t)
	r, err := NewContributorRegistry([]Contributor{&Repository{}, &riskPassiveProbe{registryContributor{p.Contributors[1]}}, &riskPassiveProbe{registryContributor{p.Contributors[2]}}, owner, &magicLinkPreparationCounter{}})
	if err != nil {
		t.Fatal(err)
	}
	c.registry, p.Contributors = r, r.Descriptors()
	return c, command, p, owner
}

func TestInvitationOriginPlanPreservesOriginalCorrelationAndClones(t *testing.T) {
	c, command, p, _ := invitationOriginFixture(t)
	s, _ := command.Feature()
	seed, err := securityMutationAudit(t.Context(), s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, s.Binding.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := c.PrepareFeaturePreparationPlan(command, p)
	if err != nil {
		t.Fatal("original correlated preparation rejected", err)
	}
	original := *frozen.OrganizationInvitationOrigin
	p.OrganizationInvitationOrigin.OrganizationID = "substituted"
	if *frozen.OrganizationInvitationOrigin != original {
		t.Fatal("caller mutated original organization")
	}
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(s.Binding, fp, frozen)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFeaturePlan(s.Binding, fp, wire)
	if err != nil || got.OrganizationInvitationOrigin == nil || *got.OrganizationInvitationOrigin != original {
		t.Fatal("journal lost original organization", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(s.Binding, fp, wire[:i]); err == nil {
			t.Fatal("truncated origin accepted", i)
		}
	}
	if _, err := decodeFeaturePlan(s.Binding, fp, append(bytes.Clone(wire), 0)); err == nil {
		t.Fatal("trailing origin bytes accepted")
	}
	for _, mutate := range []func(*OrganizationInvitationOriginPlan){func(o *OrganizationInvitationOriginPlan) { o.OrganizationID = "other" }, func(o *OrganizationInvitationOriginPlan) { o.OrganizationVersion++ }} {
		bad := got
		bad.OrganizationInvitationOrigin = cloneOrganizationInvitationOrigin(got.OrganizationInvitationOrigin)
		mutate(bad.OrganizationInvitationOrigin)
		if validateOrganizationInvitationOriginCommand(command, bad) == nil {
			t.Fatal("plan organization did not match immutable command")
		}
		if preparationFinalDeclaration(s.Binding, got, bad) {
			t.Fatal("restoration changed original organization")
		}
	}
	legacy := got
	legacy.OrganizationInvitationOrigin = nil
	old, err := encodeFeaturePlan(s.Binding, fp, legacy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(s.Binding, fp, old)
	if err != nil || decoded.OrganizationInvitationOrigin != nil {
		t.Fatal("historical bytes stopped decoding", err)
	}
	// Closed base depth prevents nested origin envelopes and foreign profiles.
	nested := cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText("organization-invitation-origin-v1"), "version": cborUint(1), "organization_id": cborText(original.OrganizationID), "organization_version": cborUint(original.OrganizationVersion)})
	if _, err := decodeFeaturePlan(s.Binding, fp, nested); err == nil {
		t.Fatal("recursive origin envelope accepted")
	}
	for name, mutate := range map[string]func(*CommandPlan){
		"empty organization": func(p *CommandPlan) { p.OrganizationInvitationOrigin.OrganizationID = "" },
		"missing version":    func(p *CommandPlan) { p.OrganizationInvitationOrigin.OrganizationVersion = 0 },
		"oversized organization": func(p *CommandPlan) {
			p.OrganizationInvitationOrigin.OrganizationID = string(bytes.Repeat([]byte{'a'}, 129))
		},
		"alternate profile": func(p *CommandPlan) { p.SignupAcceptance = true },
		"foreign operation": func(p *CommandPlan) {
			f := *p.Feature
			f.Operation = organizationInvitationAcceptOperation()
			p.Feature = &f
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := got
			bad.OrganizationInvitationOrigin = cloneOrganizationInvitationOrigin(got.OrganizationInvitationOrigin)
			mutate(&bad)
			if _, err := encodeFeaturePlan(s.Binding, fp, bad); err == nil {
				t.Fatal("invalid or silently ignored origin accepted")
			}
		})
	}
}

func TestInvitationOriginQueryUsesCurrentPolicyAndExactHistoricalOwner(t *testing.T) {
	for _, variant := range []string{"pending", "aborted", "committed", "legacy", "denied", "foreign-owner", "wrong-tenant", "missing-key", "corrupt"} {
		t.Run(variant, func(t *testing.T) {
			c, command, p, owner := invitationOriginFixture(t)
			s, _ := command.Feature()
			q, caller := queryInputs(s.Binding)
			claim, err := prepareClaim(command, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			fp := [32]byte{1}
			if variant == "legacy" {
				p.OrganizationInvitationOrigin = nil
			}
			if variant == "committed" {
				p.CapabilityIssuance = issuanceTestPlan()
				p.CapabilityIssuance.Grants[0].Purpose = "identity.organization.invitation.accept"
				p.Delivery = deliveryTestPlan()
				p.Delivery.Intents[0].SubjectID, p.Delivery.Intents[0].Purpose = string(s.Binding.UserID), "identity.organization.invitation.accept"
				p.Delivery.Intents[0].ExpiresAt = p.CapabilityIssuance.Grants[0].ExpiresAt
				p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor, p.Delivery.Contributor)
			}
			wire, err := encodeFeaturePlan(s.Binding, fp, p)
			if err != nil {
				t.Fatal(err)
			}
			state, profile := "pending", int16(3)
			now := time.Now().UTC().Truncate(time.Microsecond)
			until := now.Add(time.Second)
			observed := commandObservation{tenant: string(s.Binding.TenantID), purpose: s.Binding.OperationID, scope: claim.safeFields, fingerprint: fp[:], fingerprintKeyVersion: 1, state: &state, until: &until, now: now, preparationProfile: &profile, declaration: wire}
			want := identity.CommitOutcomeInProgress
			if variant == "aborted" || variant == "committed" {
				state, want = "aborted", identity.CommitOutcomeNotCommitted
				version, class := int32(1), "dependency-failure"
				r := identity.CommandResult{Binding: s.Binding, Outcome: want, Feature: &identity.FeatureReceipt{Operation: s.Operation}}
				if variant == "committed" {
					state, class, want, observed.plan = "committed", "committed", identity.CommitOutcomeCommitted, wire
					r.Outcome, r.AuditEventID, r.Feature.AfterVersion = want, "invitation-audit", 1
				}
				observed.resultVersion, observed.class = &version, &class
				observed.result, err = encodeJournalResult(claimRequest{safeFields: claim.safeFields, feature: &s.Operation}, r)
				if err != nil {
					t.Fatal(err)
				}
			}
			policyCalls, reads := 0, 0
			c.queryPolicy = &CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: queryDecision(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				policyCalls++
				outcome := authorization.Allow
				if variant == "denied" {
					outcome = authorization.Deny
				}
				return authorization.Decision{Outcome: outcome, Revision: 9}, nil
			})}
			c.commandRead = func(context.Context, identity.CommandID) (commandObservation, error) { reads++; return observed, nil }
			if variant == "foreign-owner" {
				owner = &invitationIssuanceProbe{}
			}
			if variant == "wrong-tenant" {
				q.TenantID = "other"
				caller = callerForQuery(caller, q)
			}
			if variant == "missing-key" {
				observed.fingerprintKeyVersion = 2
			}
			if variant == "corrupt" {
				observed.declaration = wire[:len(wire)-1]
			}
			origin, record, err := c.QueryOrganizationInvitationOrigin(t.Context(), q, caller, owner)
			valid := variant == "pending" || variant == "aborted" || variant == "committed"
			if valid {
				if origin != *p.OrganizationInvitationOrigin || record.Binding != s.Binding || record.Outcome != want || variant != "aborted" && err != nil || variant == "aborted" && !errors.As(err, new(identity.UnavailableError)) {
					t.Fatal("authorized original history lost", origin, record.Outcome, err)
				}
			} else if err == nil || origin != (OrganizationInvitationOriginPlan{}) || record.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("unowned or unverifiable origin disclosed", err)
			}
			if variant != "foreign-owner" && (policyCalls != 1 || reads != 1) {
				t.Fatal("current query admission/read shape changed")
			}
		})
	}
}

func FuzzOrganizationInvitationOriginPlan(f *testing.F) {
	f.Add([]byte{0xa5})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65536 {
			return
		}
		_, c, p, _ := invitationOriginFixture(t)
		s, _ := c.Feature()
		wire, err := encodeFeaturePlan(s.Binding, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range [][]byte{wire, input} {
			got, err := decodeFeaturePlan(s.Binding, [32]byte{1}, candidate)
			if err != nil {
				continue
			}
			canonical, err := encodeFeaturePlan(s.Binding, [32]byte{1}, got)
			if err != nil || !bytes.Equal(candidate, canonical) {
				t.Fatal("noncanonical origin accepted")
			}
		}
	})
}
