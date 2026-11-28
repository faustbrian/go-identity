//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
)

func TestImpersonationSelfStopServiceDirectConsumerPostgres(t *testing.T) {
	for _, parentState := range []string{"original", "different", "revoked", "grant-revoked"} {
		t.Run(parentState, func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			_, cfg, requester, approver := newM24ServiceFixture(t, ctx, pool)
			history := m24Must((SelfStopMigrationSource{}).Load(ctx))
			for _, migration := range history[1:] {
				m24Exec(t, ctx, pool, migration.UpSQL())
			}
			policy := &m24SelfStopAuthorization{activation: &m24ActivationAuthorization{legacy: cfg.Authorization.(*m24Authorization)}}
			cfg.Authorization = policy
			lookupKey := m24Must(session.NewDigestKey(7, bytes.Repeat([]byte{71}, 32)))
			service := m24Must(NewServiceWithSelfStop(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
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
			approval := m24Must(service.PrepareApproval(ctx, ApproveInput{
				Authentication: approver, CommandID: m24Must(identity.NewCommandID()),
				GrantID: impersonation.GrantID(requestID), ExpectedVersion: 1,
				Reason: m24Must(impersonation.NewReason("private distinct administrator approval")), Network: "192.0.2.12",
			}))
			if result := m24Must(service.Execute(ctx, approval)); result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("approval did not commit", result.Outcome)
			}
			start := m24Must(service.PrepareStart(ctx, StartInput{
				Authentication: requester, CommandID: m24Must(identity.NewCommandID()),
				GrantID: impersonation.GrantID(requestID), ExpectedVersion: 2, Network: "192.0.2.11",
			}))
			if _, err := service.ExecuteStart(ctx, start); err == nil {
				t.Fatal("self-stop activation used the result that cannot transfer its synchronizer")
			}
			activated := m24Must(service.ExecuteStoppableStart(ctx, start))
			if activated.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("stoppable activation did not commit", activated.Receipt.Outcome)
			}
			bearer := m24Must(activated.Credential.Reveal())
			csrfWire := m24Must(activated.StopCSRF.Reveal())
			if _, err := activated.StopCSRF.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
				t.Fatal("stoppable activation disclosed its stop synchronizer twice", err)
			}
			replayedStart := m24Must(service.ExecuteStoppableStart(ctx, start))
			if !reflect.DeepEqual(replayedStart.Receipt, activated.Receipt) {
				t.Fatal("stoppable start replay changed the original receipt")
			}
			if _, err := replayedStart.Credential.Reveal(); err == nil {
				t.Fatal("stoppable start replay disclosed another derived bearer")
			}
			if _, err := replayedStart.StopCSRF.Reveal(); err == nil {
				t.Fatal("stoppable start replay disclosed another stop synchronizer")
			}
			use := UseInput{Tenant: requester.Tenant, Bearer: bearer, Permission: "profile.read"}
			if _, err := service.ValidateUse(ctx, use); err != nil {
				t.Fatal("derived credential was not usable before stop", err)
			}
			stopAuthentication := StopAuthentication{Tenant: requester.Tenant, Bearer: bearer, CSRF: m24Must(session.ParseCSRFToken(csrfWire))}
			input := StopInput{Authentication: stopAuthentication, CommandID: m24Must(identity.NewCommandID()), Network: "192.0.2.11"}
			for _, invalid := range []string{"missing-csrf", "wrong-csrf", "original-csrf", "foreign-tenant", "policy"} {
				wrong := input
				wrong.CommandID = m24Must(identity.NewCommandID())
				switch invalid {
				case "missing-csrf":
					wrong.Authentication.CSRF = session.CSRFToken{}
				case "wrong-csrf":
					wrong.Authentication.CSRF = m24Must(session.NewCSRFToken())
				case "original-csrf":
					wrong.Authentication.CSRF = requester.CSRF
				case "foreign-tenant":
					wrong.Authentication.Tenant = "foreign-tenant"
				case "policy":
					policy.denyStop = true
				}
				_, err := service.PrepareStop(ctx, wrong)
				policy.denyStop = false
				if err == nil {
					t.Fatal("stop accepted an invalid synchronizer, tenant or policy", invalid)
				}
				assertM24CommandEffects(t, ctx, pool, wrong.CommandID, 0)
			}
			prepared := m24Must(service.PrepareStop(ctx, input))
			binding := m24Must(prepared.Binding())
			if binding.TenantID != requester.Tenant || binding.ActorID != "request-admin" || binding.UserID != "target-user" || binding.RecordID != string(requestID) || binding.OperationID != "identity.impersonation.stop" {
				t.Fatal("stop binding lost the original actor, target or exact grant")
			}
			policy.activation.legacy.recovery[string(input.CommandID)] = binding
			assertM24CommandEffects(t, ctx, pool, input.CommandID, 0)
			if parentState == "grant-revoked" {
				revokeInput := RevokeInput{Authentication: approver, CommandID: m24Must(identity.NewCommandID()),
					GrantID: impersonation.GrantID(requestID), ExpectedVersion: 3,
					Reason: m24Must(impersonation.NewReason("private separate administrator revocation")), Network: "192.0.2.12"}
				revoke := m24Must(service.PrepareRevoke(ctx, revokeInput))
				if result := m24Must(service.Execute(ctx, revoke)); result.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("competing administrator revocation did not commit")
				}
				stop, err := service.ExecuteStop(ctx, prepared, requester.Bearer)
				var conflict identity.ConflictError
				if !errors.As(err, &conflict) || conflict.CommandID != input.CommandID ||
					stop.Receipt.Outcome != identity.CommitOutcomeNotCommitted || stop.Parent.Authenticated {
					t.Fatal("stop overwrote the winning revocation or restored a parent", stop.Receipt.Outcome, err)
				}
				assertM24DeniedEffects(t, ctx, pool, input.CommandID)
				assertM24CommandEffects(t, ctx, pool, revokeInput.CommandID, 1)
				if _, err := service.ValidateUse(ctx, use); !errors.Is(err, identity.ForbiddenError{}) {
					t.Fatal("competing transition left derived authority usable", err)
				}
				return
			}
			parent := requester.Bearer
			if parentState == "different" {
				parent = approver.Bearer
			} else if parentState == "revoked" {
				m24Exec(t, ctx, pool, `UPDATE authorization_subject_authorities SET version=version+1 WHERE tenant_id='m24-tenant' AND subject_id='request-admin'`)
			}
			policy.stopChecks = 0
			stopped := m24Must(service.ExecuteStop(ctx, prepared, parent))
			if stopped.Receipt.Outcome != identity.CommitOutcomeCommitted || stopped.Receipt.Binding != binding || stopped.Receipt.Feature == nil || stopped.Receipt.Feature.BeforeVersion != 3 || stopped.Receipt.Feature.AfterVersion != 4 || policy.stopChecks == 0 {
				t.Fatal("stop did not commit the exact active version under current actor policy", stopped.Receipt.Outcome)
			}
			if parentState == "original" {
				if err := stopped.Parent.ValidateAt(time.Now()); err != nil {
					t.Fatal("stop did not qualify the exact original parent session", err)
				}
				parentSession := m24Must(stopped.Parent.Session.Bindings())
				if parentSession.TenantID != requester.Tenant || parentSession.UserID != "request-admin" || parentSession.SessionID != "session-request-admin" || parentSession.FamilyID != "family-request-admin" || parentSession.Version != 1 || parentSession.FamilyVersion != 1 {
					t.Fatal("stop returned a target, replacement or different administrator session")
				}
			} else if stopped.Parent.ValidateAt(time.Now()) == nil || stopped.Parent.Authenticated {
				t.Fatal("stop restored a different or withdrawn original session", parentState)
			}
			replayed := m24Must(service.ExecuteStop(ctx, prepared, authentication.BearerCredential{}))
			if !reflect.DeepEqual(replayed.Receipt, stopped.Receipt) || replayed.Parent.ValidateAt(time.Now()) == nil {
				t.Fatal("stop replay changed metadata or restored without original bearer custody")
			}
			restarted := m24Must(NewServiceWithSelfStop(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
			if recovered := m24Must(restarted.RecoverStop(ctx, stopAuthentication, binding)); !reflect.DeepEqual(recovered, stopped.Receipt) {
				t.Fatal("restart recovery did not return only the exact original stop receipt")
			}
			for _, invalid := range []string{"bearer", "csrf", "grant", "command", "actor"} {
				wrongAuthentication, wrongBinding := stopAuthentication, binding
				switch invalid {
				case "bearer":
					wrongAuthentication.Bearer = ""
				case "csrf":
					wrongAuthentication.CSRF = m24Must(session.NewCSRFToken())
				case "grant":
					wrongBinding.RecordID = string(m24Must(identity.NewCommandID()))
				case "command":
					wrongBinding.CommandID = m24Must(identity.NewCommandID())
				case "actor":
					wrongBinding.ActorID = "approve-admin"
				}
				if _, err := restarted.RecoverStop(ctx, wrongAuthentication, wrongBinding); err == nil {
					t.Fatal("stop recovery accepted different custody or metadata", invalid)
				}
			}
			for _, validator := range []*Service{service, restarted} {
				if _, err := validator.ValidateUse(ctx, use); !errors.Is(err, identity.ForbiddenError{}) {
					t.Fatal("derived credential remained usable after committed stop", err)
				}
			}
			fresh := input
			fresh.CommandID = m24Must(identity.NewCommandID())
			if _, err := restarted.PrepareStop(ctx, fresh); err == nil {
				t.Fatal("a fresh stop command admitted an already-stopped grant")
			}
			assertM24CommandEffects(t, ctx, pool, fresh.CommandID, 0)
			assertM24CommandEffects(t, ctx, pool, input.CommandID, 1)
			assertM24NoSessionIssuance(t, ctx, pool)
		})
	}
}

type m24SelfStopAuthorization struct {
	activation *m24ActivationAuthorization
	grantID    string
	denyStop   bool
	stopChecks int
}

func (p *m24SelfStopAuthorization) Decide(ctx context.Context, caller authorization.DecisionContext) (authorization.Decision, error) {
	r := caller.Request
	if r.Action == authorization.Action(revokeAction) {
		return (&m24RevocationAuthorization{activation: p.activation, grantID: p.grantID}).Decide(ctx, caller)
	}
	if r.Action != "identity.impersonation.stop" {
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
	if !p.denyStop && caller.PolicyRevision == p.activation.legacy.revision && r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == "request-admin" && r.Resource.Type == "identity.user" && r.Resource.ID == "target-user" && exactGrant && grantID == p.grantID {
		p.stopChecks++
		return authorization.Decision{Outcome: authorization.Allow, Revision: p.activation.legacy.revision}, nil
	}
	return denied, nil
}
