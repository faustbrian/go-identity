//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
)

func TestImpersonationActivationServiceDirectConsumerPostgres(t *testing.T) {
	for _, withdrawal := range []string{"parent-authorization-epoch", "active-grant-revoked"} {
		t.Run(withdrawal, func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			_, cfg, requester, approver := newM24ServiceFixture(t, ctx, pool)
			history := m24Must((ActivationMigrationSource{}).Load(ctx))
			if len(history) != 2 || history[1].Version() != 2 {
				t.Fatal("activation migration did not append version two")
			}
			m24Exec(t, ctx, pool, history[1].UpSQL())

			policy := &m24ActivationAuthorization{legacy: cfg.Authorization.(*m24Authorization)}
			cfg.Authorization = policy
			lookupKey := m24Must(session.NewDigestKey(7, bytes.Repeat([]byte{71}, 32)))
			service := m24Must(NewServiceWithActivation(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
			requestID := m24Must(identity.NewCommandID())
			request := m24Must(service.PrepareRequest(ctx, RequestInput{
				Authentication: requester, CommandID: requestID, Target: "target-user",
				Scope:    m24Must(impersonation.NewScope([]string{"profile.read", "address.read"})),
				Reason:   m24Must(impersonation.NewReason("private support case request")),
				Duration: 10 * time.Minute, Network: "192.0.2.11",
			}))
			if result := m24Must(service.Execute(ctx, request)); result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("request did not commit", result.Outcome)
			}
			approvalID := m24Must(identity.NewCommandID())
			approval := m24Must(service.PrepareApproval(ctx, ApproveInput{
				Authentication: approver, CommandID: approvalID,
				GrantID: impersonation.GrantID(requestID), ExpectedVersion: 1,
				Reason:  m24Must(impersonation.NewReason("private distinct administrator approval")),
				Network: "192.0.2.12",
			}))
			if result := m24Must(service.Execute(ctx, approval)); result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("distinct approval did not commit", result.Outcome)
			}
			assertM24Grant(t, ctx, pool, requestID, "approved", 2, 1)
			assertM24NoSessionIssuance(t, ctx, pool)

			startInput := StartInput{
				Authentication: requester, CommandID: m24Must(identity.NewCommandID()),
				GrantID: impersonation.GrantID(requestID), ExpectedVersion: 2, Network: "192.0.2.11",
			}
			wrongActor := startInput
			wrongActor.Authentication = approver
			if _, err := service.PrepareStart(ctx, wrongActor); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("another authenticated administrator activated the request", err)
			}
			wrongCSRF := startInput
			wrongCSRF.Authentication.CSRF = approver.CSRF
			if _, err := service.PrepareStart(ctx, wrongCSRF); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("requester activated with another administrator's CSRF", err)
			}
			policy.denyApprover = true
			if _, err := service.PrepareStart(ctx, startInput); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("activation omitted the retained approver's current approval policy", err)
			}
			policy.denyApprover = false
			assertM24CommandEffects(t, ctx, pool, startInput.CommandID, 0)
			var before int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.active_grants`).Scan(&before); err != nil || before != 0 {
				t.Fatal("preparation activated a grant", before, err)
			}

			policy.startChecks, policy.approverChecks = 0, 0
			start := m24Must(service.PrepareStart(ctx, startInput))
			binding := m24Must(start.Binding())
			if binding.TenantID != requester.Tenant || binding.ActorID != "request-admin" || binding.UserID != "target-user" || binding.RecordID != string(requestID) || binding.OperationID != "identity.impersonation.start" {
				t.Fatal("activation binding lost authenticated actor or exact requested target")
			}
			policy.legacy.recovery[string(startInput.CommandID)] = binding
			activated := m24Must(service.ExecuteStart(ctx, start))
			if activated.Receipt.Outcome != identity.CommitOutcomeCommitted || activated.Receipt.Binding != binding || activated.Receipt.Feature == nil || activated.Receipt.Feature.BeforeVersion != 2 || activated.Receipt.Feature.AfterVersion != 3 {
				t.Fatal("activation did not commit the approved version as active version three", activated.Receipt.Outcome)
			}
			if policy.startChecks == 0 || policy.approverChecks == 0 {
				t.Fatal("activation did not check exact requester start and retained approver policies")
			}
			bearer := m24Must(activated.Credential.Reveal())
			if _, err := activated.Credential.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
				t.Fatal("activation response disclosed a second bearer", err)
			}
			replayed := m24Must(service.ExecuteStart(ctx, start))
			if !reflect.DeepEqual(replayed.Receipt, activated.Receipt) {
				t.Fatal("activation retry changed its exact committed receipt")
			}
			if _, err := replayed.Credential.Reveal(); err == nil {
				t.Fatal("receipt replay minted or redelivered a derived bearer")
			}
			restarted := m24Must(NewServiceWithActivation(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
			if recovered := m24Must(restarted.Recover(ctx, requester, binding)); !reflect.DeepEqual(recovered, activated.Receipt) {
				t.Fatal("restart recovery did not return the exact activation receipt")
			}
			if _, err := restarted.Recover(ctx, approver, binding); err == nil {
				t.Fatal("approver recovered another administrator's activation")
			}
			assertM24CommandEffects(t, ctx, pool, startInput.CommandID, 1)
			assertM24NoSessionIssuance(t, ctx, pool)
			var activeCount, version int
			var state string
			var startedAt, expiresAt time.Time
			if err := pool.Raw().QueryRow(ctx, `SELECT state,version,started_at,expires_at,(SELECT count(*) FROM identity_impersonation.active_grants) FROM identity_impersonation.active_grants WHERE tenant_id=$1 AND grant_id=$2`, string(requester.Tenant), string(requestID)).Scan(&state, &version, &startedAt, &expiresAt, &activeCount); err != nil || state != "active" || version != 3 || activeCount != 1 {
				t.Fatal("activation did not retain exactly one active lineage", state, version, activeCount, err)
			}

			useInput := UseInput{Tenant: requester.Tenant, Bearer: bearer, Permission: "profile.read"}
			policy.useSubjects = nil
			used := m24Must(service.ValidateUse(ctx, useInput))
			if used.TenantID != requester.Tenant || used.ActorID != "request-admin" || used.TargetID != "target-user" || used.GrantID != impersonation.GrantID(requestID) || used.GrantVersion != 3 || used.Permission != "profile.read" || !used.StartedAt.Equal(startedAt) || !used.ExpiresAt.Equal(expiresAt) {
				t.Fatal("derived credential lost the exact active actor, target, permission or lifetime")
			}
			if !slices.Contains(policy.useSubjects, authorization.SubjectID("request-admin")) || !slices.Contains(policy.useSubjects, authorization.SubjectID("target-user")) {
				t.Fatal("derived use did not authorize both actor and target")
			}
			unlisted := useInput
			unlisted.Permission = "profile.delete"
			if _, err := service.ValidateUse(ctx, unlisted); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("derived credential used an unapproved permission", err)
			}
			for _, denied := range []authorization.SubjectID{"request-admin", "target-user"} {
				policy.deniedUseSubject = denied
				if _, err := service.ValidateUse(ctx, useInput); !errors.Is(err, identity.ForbiddenError{}) {
					t.Fatal("derived credential survived current permission withdrawal", denied, err)
				}
				policy.deniedUseSubject = ""
				if _, err := service.ValidateUse(ctx, useInput); err != nil {
					t.Fatal("permission restoration did not restore otherwise-current derived use", err)
				}
			}

			if withdrawal == "parent-authorization-epoch" {
				m24Exec(t, ctx, pool, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id='m24-tenant' AND subject_id='request-admin'`)
			} else {
				revokedDuringDecision := false
				var revokeError error
				policy.beforeTargetUseAllow = func(decisionContext context.Context) error {
					tag, err := pool.Raw().Exec(decisionContext, `UPDATE identity_impersonation.active_grants SET state='revoked',version=4 WHERE tenant_id=$1 AND grant_id=$2`, string(requester.Tenant), string(requestID))
					if err == nil && tag.RowsAffected() != 1 {
						err = errors.New("in-flight revocation did not update exactly one active grant")
					}
					revokeError = err
					revokedDuringDecision = err == nil
					return err
				}
				if _, err := service.ValidateUse(ctx, useInput); !errors.Is(err, identity.ForbiddenError{}) {
					t.Fatal("derived use accepted an active snapshot revoked during its final permission decision", err)
				}
				if revokeError != nil || !revokedDuringDecision || policy.beforeTargetUseAllow != nil {
					t.Fatal("target permission callback did not commit its one-shot revocation", revokeError)
				}
			}
			if _, err := service.ValidateUse(ctx, useInput); !errors.Is(err, identity.ForbiddenError{}) {
				t.Fatal("derived use remained authorized after authority withdrawal", withdrawal, err)
			}
			assertM24CommandEffects(t, ctx, pool, startInput.CommandID, 1)
			assertM24NoSessionIssuance(t, ctx, pool)
		})
	}
}

type m24ActivationAuthorization struct {
	legacy               *m24Authorization
	denyApprover         bool
	deniedUseSubject     authorization.SubjectID
	startChecks          int
	approverChecks       int
	useSubjects          []authorization.SubjectID
	beforeTargetUseAllow func(context.Context) error
}

func (p *m24ActivationAuthorization) Decide(ctx context.Context, caller authorization.DecisionContext) (authorization.Decision, error) {
	r := caller.Request
	denied := authorization.Decision{Outcome: authorization.Deny, Revision: p.legacy.revision}
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	if r.Action == approveAction {
		p.approverChecks++
		if p.denyApprover {
			return denied, nil
		}
	}
	if r.Action == "identity.impersonation.start" {
		if recovering, _ := r.Resource.Attributes["identity.command.recovery"].Bool(); recovering {
			return p.legacy.Decide(ctx, caller)
		}
		permissions, ok := r.Attributes[scopeAttribute].StringSet()
		if caller.PolicyRevision == p.legacy.revision && r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == "request-admin" && r.Resource.Type == "identity.user" && r.Resource.ID == "target-user" && ok && slices.Equal(permissions, []string{"address.read", "profile.read"}) {
			p.startChecks++
			return authorization.Decision{Outcome: authorization.Allow, Revision: p.legacy.revision}, nil
		}
		return denied, nil
	}
	if r.Action == "profile.read" || r.Action == "address.read" || r.Action == "profile.delete" {
		isUse, typed := r.Attributes["impersonation.use"].Bool()
		allowedSubject := r.Subject.ID == "request-admin" || r.Subject.ID == "target-user"
		if caller.PolicyRevision == p.legacy.revision && r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && allowedSubject && r.Resource.Type == "identity.user" && r.Resource.ID == "target-user" && typed && isUse && r.Subject.ID != p.deniedUseSubject {
			p.useSubjects = append(p.useSubjects, r.Subject.ID)
			if r.Subject.ID == "target-user" && p.beforeTargetUseAllow != nil {
				callback := p.beforeTargetUseAllow
				p.beforeTargetUseAllow = nil
				if err := callback(ctx); err != nil {
					return denied, err
				}
			}
			return authorization.Decision{Outcome: authorization.Allow, Revision: p.legacy.revision}, nil
		}
		return denied, nil
	}
	return p.legacy.Decide(ctx, caller)
}
