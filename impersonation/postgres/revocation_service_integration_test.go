//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestImpersonationRevocationServiceDirectConsumerPostgres(t *testing.T) {
	for _, state := range []string{"pending", "approved", "active"} {
		t.Run(state, func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			_, cfg, requester, administrator := newM24ServiceFixture(t, ctx, pool)
			history := m24Must((RevocationMigrationSource{}).Load(ctx))
			if len(history) < 3 || history[0].Version() != 1 || history[1].Version() != 2 {
				t.Fatal("revocation did not extend the installed request and activation history")
			}
			for _, migration := range history[1:] {
				m24Exec(t, ctx, pool, migration.UpSQL())
			}
			for _, action := range []risk.Action{"identity.impersonation.start", "identity.impersonation.revoke"} {
				if err := cfg.Risk.ValidateCounterOnlyOperation(action); err != nil {
					t.Fatal("fixture did not configure the selected privileged counter-only operation", action, err)
				}
			}
			policy := &m24RevocationAuthorization{activation: &m24ActivationAuthorization{legacy: cfg.Authorization.(*m24Authorization)}}
			cfg.Authorization = policy
			lookupKey := m24Must(session.NewDigestKey(7, bytes.Repeat([]byte{71}, 32)))
			service := m24Must(NewServiceWithRevocation(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
			legacy := m24Must(NewServiceWithActivation(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
			requestID := m24Must(identity.NewCommandID())
			request := m24Must(service.PrepareRequest(ctx, RequestInput{
				Authentication: requester, CommandID: requestID, Target: "target-user",
				Scope:    m24Must(impersonation.NewScope([]string{"profile.read", "address.read"})),
				Reason:   m24Must(impersonation.NewReason("private support case request")),
				Duration: 10 * time.Minute, Network: "192.0.2.11",
			}))
			policy.grantID = string(requestID)
			if result := m24Must(service.Execute(ctx, request)); result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("request did not commit", result.Outcome)
			}
			approvalInput := ApproveInput{
				Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
				GrantID: impersonation.GrantID(requestID), ExpectedVersion: 1,
				Reason: m24Must(impersonation.NewReason("private distinct administrator approval")), Network: "192.0.2.12",
			}
			approval := m24Must(legacy.PrepareApproval(ctx, approvalInput))
			version := uint64(1)
			var preparedStart PreparedActivation
			var useInput UseInput
			startInput := StartInput{Authentication: requester, CommandID: m24Must(identity.NewCommandID()), GrantID: impersonation.GrantID(requestID), ExpectedVersion: 2, Network: "192.0.2.11"}
			if state != "pending" {
				if result := m24Must(legacy.Execute(ctx, approval)); result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("approval did not commit", result.Outcome)
				}
				version = 2
				preparedStart = m24Must(legacy.PrepareStart(ctx, startInput))
			}
			if state == "active" {
				active := m24Must(legacy.ExecuteStart(ctx, preparedStart))
				if active.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("activation did not commit", active.Receipt.Outcome)
				}
				version = 3
				useInput = UseInput{Tenant: requester.Tenant, Bearer: m24Must(active.Credential.Reveal()), Permission: "profile.read"}
				if _, err := service.ValidateUse(ctx, useInput); err != nil {
					t.Fatal("active credential did not authorize before revocation", err)
				}
			}

			revokeInput := RevokeInput{
				Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
				GrantID: impersonation.GrantID(requestID), ExpectedVersion: version,
				Reason: m24Must(impersonation.NewReason("private separate administrator revocation")), Network: "192.0.2.12",
			}
			assertM24RevokeRejectedInputs(t, ctx, pool, service, policy, revokeInput, requester)
			if _, err := legacy.PrepareRevoke(ctx, revokeInput); err == nil {
				t.Fatal("activation-only profile admitted administrator revocation")
			}
			competing := revokeInput
			competing.CommandID = m24Must(identity.NewCommandID())
			loser := m24Must(service.PrepareRevoke(ctx, competing))
			revoke := m24Must(service.PrepareRevoke(ctx, revokeInput))
			binding := m24Must(revoke.Binding())
			if binding.ActorID != "approve-admin" || binding.UserID != "target-user" || binding.RecordID != string(requestID) || binding.OperationID != "identity.impersonation.revoke" || binding.TenantID != administrator.Tenant {
				t.Fatal("revocation binding lost the separate authenticated administrator or original grant")
			}
			policy.activation.legacy.recovery[string(revokeInput.CommandID)] = binding
			assertM24CommandEffects(t, ctx, pool, revokeInput.CommandID, 0)
			policy.revokeChecks = 0
			var revoked identity.CommandResult
			if state == "active" {
				var revokeError error
				policy.activation.beforeTargetUseAllow = func(decisionContext context.Context) error {
					revoked, revokeError = service.Execute(decisionContext, revoke)
					return revokeError
				}
				if _, err := service.ValidateUse(ctx, useInput); !errors.Is(err, identity.ForbiddenError{}) {
					t.Fatal("in-flight use authorized after public revocation committed during its target policy decision", err)
				}
				if revokeError != nil || policy.activation.beforeTargetUseAllow != nil {
					t.Fatal("in-flight target decision did not execute its one-shot public revocation", revokeError)
				}
			} else {
				revoked = m24Must(service.Execute(ctx, revoke))
			}
			if revoked.Outcome != identity.CommitOutcomeCommitted || revoked.Binding != binding || revoked.Feature == nil || revoked.Feature.BeforeVersion != version || revoked.Feature.AfterVersion != version+1 || policy.revokeChecks == 0 {
				t.Fatal("revocation did not commit the exact expected version under current named policy", revoked.Outcome)
			}
			if replay := m24Must(service.Execute(ctx, revoke)); !reflect.DeepEqual(replay, revoked) {
				t.Fatal("revocation replay changed the exact original metadata")
			}
			restarted := m24Must(NewServiceWithRevocation(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
			if recovered := m24Must(restarted.Recover(ctx, administrator, binding)); !reflect.DeepEqual(recovered, revoked) {
				t.Fatal("restart recovery did not return exact revocation metadata")
			}
			if _, err := restarted.Recover(ctx, requester, binding); err == nil {
				t.Fatal("another administrator recovered the revoker's command")
			}
			altered := binding
			altered.RecordID = string(m24Must(identity.NewCommandID()))
			if _, err := restarted.Recover(ctx, administrator, altered); err == nil {
				t.Fatal("recovery accepted a different original grant")
			}
			result, err := service.Execute(ctx, loser)
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) || conflict.CommandID != competing.CommandID || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("competing prepared revocation did not settle without a second effect", result.Outcome, err)
			}
			assertM24DeniedEffects(t, ctx, pool, competing.CommandID)
			fresh := revokeInput
			fresh.CommandID = m24Must(identity.NewCommandID())
			if _, err := restarted.PrepareRevoke(ctx, fresh); err == nil {
				t.Fatal("a fresh command revoked the already-terminal grant again")
			}
			assertM24CommandEffects(t, ctx, pool, fresh.CommandID, 0)

			if state == "pending" {
				if result, err := legacy.Execute(ctx, approval); err == nil && result.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("legacy prepared approval restored a revoked pending grant")
				}
				approvalInput.CommandID = m24Must(identity.NewCommandID())
				if prepared, err := legacy.PrepareApproval(ctx, approvalInput); err == nil {
					if result, err := legacy.Execute(ctx, prepared); err == nil && result.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("legacy fresh approval restored a revoked pending grant")
					}
				}
			} else {
				if state == "approved" {
					if result, err := legacy.ExecuteStart(ctx, preparedStart); err == nil && result.Receipt.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("legacy prepared activation restored a revoked approved grant")
					}
				}
				startInput.CommandID = m24Must(identity.NewCommandID())
				if prepared, err := legacy.PrepareStart(ctx, startInput); err == nil {
					if result, err := legacy.ExecuteStart(ctx, prepared); err == nil && result.Receipt.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("legacy fresh activation restored a revoked grant")
					}
				}
			}
			if state == "active" {
				for _, validator := range []*Service{service, legacy, restarted} {
					if _, err := validator.ValidateUse(ctx, useInput); !errors.Is(err, identity.ForbiddenError{}) {
						t.Fatal("warm, legacy or restarted validation authorized after committed revocation", err)
					}
				}
			}
			assertM24CommandEffects(t, ctx, pool, revokeInput.CommandID, 1)
			assertM24NoSessionIssuance(t, ctx, pool)
			var leakedReason int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND position(convert_to('private separate administrator revocation','UTF8') in canonical_record)>0`, string(revokeInput.CommandID)).Scan(&leakedReason); err != nil || leakedReason != 0 {
				t.Fatal("private revocation reason entered audit metadata", err)
			}
		})
	}
}

func assertM24RevokeRejectedInputs(t *testing.T, ctx context.Context, pool *database.Pool, service *Service, policy *m24RevocationAuthorization, input RevokeInput, requester Authentication) {
	t.Helper()
	for _, variation := range []string{"policy", "actor", "csrf", "tenant", "version", "grant", "reason", "command"} {
		wrong := input
		wrong.CommandID = m24Must(identity.NewCommandID())
		switch variation {
		case "policy":
			policy.denyRevoke = true
		case "actor":
			wrong.Authentication = requester
		case "csrf":
			wrong.Authentication.CSRF = requester.CSRF
		case "tenant":
			wrong.Authentication.Tenant = "foreign-tenant"
		case "version":
			wrong.ExpectedVersion++
		case "grant":
			wrong.GrantID = impersonation.GrantID(m24Must(identity.NewCommandID()))
		case "reason":
			wrong.Reason = impersonation.Reason{}
		case "command":
			wrong.CommandID = identity.CommandID(wrong.GrantID)
		}
		_, err := service.PrepareRevoke(ctx, wrong)
		policy.denyRevoke = false
		if err == nil {
			t.Fatal("revocation accepted invalid or unauthorized input", variation)
		}
		if variation != "command" {
			assertM24CommandEffects(t, ctx, pool, wrong.CommandID, 0)
		}
	}
}

type m24RevocationAuthorization struct {
	activation   *m24ActivationAuthorization
	grantID      string
	denyRevoke   bool
	revokeChecks int
}

func (p *m24RevocationAuthorization) Decide(ctx context.Context, caller authorization.DecisionContext) (authorization.Decision, error) {
	r := caller.Request
	if r.Action != "identity.impersonation.revoke" {
		return p.activation.Decide(ctx, caller)
	}
	if recovering, _ := r.Resource.Attributes["identity.command.recovery"].Bool(); recovering {
		return p.activation.legacy.Decide(ctx, caller)
	}
	denied := authorization.Decision{Outcome: authorization.Deny, Revision: p.activation.legacy.revision}
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	grantID, exactGrant := r.Attributes["impersonation.grant-id"].String()
	if !p.denyRevoke && caller.PolicyRevision == p.activation.legacy.revision && r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == "approve-admin" && r.Resource.Type == "identity.user" && r.Resource.ID == "target-user" && exactGrant && grantID == p.grantID {
		p.revokeChecks++
		return authorization.Decision{Outcome: authorization.Allow, Revision: p.activation.legacy.revision}, nil
	}
	return denied, nil
}
