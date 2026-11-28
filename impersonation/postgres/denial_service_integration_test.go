//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestImpersonationDenialServiceDirectConsumerPostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	service, legacy, cfg, policy, requester, administrator, activation := newM24DenialFixture(t, ctx, pool)
	grantID := requestM24DenialGrant(t, ctx, service, policy, requester)
	approvalInput := ApproveInput{
		Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
		GrantID: grantID, ExpectedVersion: 1,
		Reason: m24Must(impersonation.NewReason("private distinct administrator approval")), Network: "192.0.2.12",
	}
	grandfatheredApproval := m24Must(legacy.PrepareApproval(ctx, approvalInput))
	revokeInput := RevokeInput{
		Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
		GrantID: grantID, ExpectedVersion: 1,
		Reason: m24Must(impersonation.NewReason("private competing administrator revocation")), Network: "192.0.2.12",
	}
	grandfatheredRevoke := m24Must(legacy.PrepareRevoke(ctx, revokeInput))
	input := DenyInput{
		Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
		GrantID: grantID, ExpectedVersion: 1,
		Reason: m24Must(impersonation.NewReason("private distinct administrator denial")), Network: "192.0.2.12",
	}
	for _, variation := range []string{"policy", "requester", "csrf", "tenant", "version-zero", "version-two", "grant", "reason", "command"} {
		wrong := input
		wrong.CommandID = m24Must(identity.NewCommandID())
		switch variation {
		case "policy":
			policy.deny = true
		case "requester":
			wrong.Authentication = requester
			policy.actor = "request-admin"
		case "csrf":
			wrong.Authentication.CSRF = requester.CSRF
		case "tenant":
			wrong.Authentication.Tenant = "foreign-tenant"
		case "version-zero":
			wrong.ExpectedVersion = 0
		case "version-two":
			wrong.ExpectedVersion = 2
		case "grant":
			wrong.GrantID = impersonation.GrantID(m24Must(identity.NewCommandID()))
		case "reason":
			wrong.Reason = impersonation.Reason{}
		case "command":
			wrong.CommandID = identity.CommandID(grantID)
		}
		_, err := service.PrepareDenial(ctx, wrong)
		policy.deny, policy.actor = false, "approve-admin"
		if err == nil {
			t.Fatal("denial accepted invalid or unauthorized input", variation)
		}
		if variation != "command" {
			assertM24CommandEffects(t, ctx, pool, wrong.CommandID, 0)
		}
	}
	competing := input
	competing.CommandID = m24Must(identity.NewCommandID())
	loser := m24Must(service.PrepareDenial(ctx, competing))
	prepared := m24Must(service.PrepareDenial(ctx, input))
	binding := m24Must(prepared.Binding())
	if binding.ActorID != "approve-admin" || binding.ActorKind != authorization.SubjectUser || binding.UserID != "target-user" || binding.RecordID != string(grantID) || binding.OperationID != "identity.impersonation.deny" || binding.TenantID != administrator.Tenant || binding.CommandID != input.CommandID {
		t.Fatal("denial binding lost the distinct authenticated actor or exact grant")
	}
	policy.base.activation.legacy.recovery[string(input.CommandID)] = binding
	assertM24CommandEffects(t, ctx, pool, input.CommandID, 0)
	policy.deny = true
	if result, err := service.Execute(ctx, prepared); !errors.Is(err, identity.ForbiddenError{}) || result.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("prepared denial ignored current action authorization", result.Outcome, err)
	}
	policy.deny = false
	assertM24CommandEffects(t, ctx, pool, input.CommandID, 0)
	policy.checks.Store(0)
	denied := m24Must(service.Execute(ctx, prepared))
	if denied.Outcome != identity.CommitOutcomeCommitted || denied.Binding != binding || denied.Feature == nil || denied.Feature.Operation.OperationID != "identity.impersonation.deny" || denied.Feature.BeforeVersion != 1 || denied.Feature.AfterVersion != 2 || policy.checks.Load() == 0 {
		t.Fatal("denial did not commit pending version one as terminal version two under exact current policy", denied.Outcome)
	}
	assertM24DenialMarker(t, ctx, pool, binding)
	assertM24CommandEffects(t, ctx, pool, input.CommandID, 1)
	if replay := m24Must(service.Execute(ctx, prepared)); !reflect.DeepEqual(replay, denied) {
		t.Fatal("same-command denial replay changed original metadata")
	}
	restarted := m24Must(NewServiceWithDenial(pool, cfg, activation))
	if recovered := m24Must(restarted.Recover(ctx, administrator, binding)); !reflect.DeepEqual(recovered, denied) {
		t.Fatal("restart recovery changed exact denial metadata")
	}
	for _, variation := range []string{"actor", "csrf", "tenant", "grant", "command", "operation", "policy"} {
		wrongAuth, wrongBinding := administrator, binding
		switch variation {
		case "actor":
			wrongAuth = requester
		case "csrf":
			wrongAuth.CSRF = requester.CSRF
		case "tenant":
			wrongAuth.Tenant = "foreign-tenant"
		case "grant":
			wrongBinding.RecordID = string(m24Must(identity.NewCommandID()))
		case "command":
			wrongBinding.CommandID = m24Must(identity.NewCommandID())
		case "operation":
			wrongBinding.OperationID = "identity.impersonation.revoke"
		case "policy":
			wrongBinding.PolicyVersion++
		}
		if _, err := restarted.Recover(ctx, wrongAuth, wrongBinding); err == nil {
			t.Fatal("denial recovery accepted different credentials or command metadata", variation)
		}
	}
	result, err := service.Execute(ctx, loser)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) || conflict.CommandID != competing.CommandID || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("competing denial did not retain a typed noncommitted conflict", result.Outcome, err)
	}
	assertM24DeniedEffects(t, ctx, pool, competing.CommandID)
	for _, oldCommand := range []PreparedCommand{grandfatheredApproval, grandfatheredRevoke} {
		if result, err := legacy.Execute(ctx, oldCommand); err == nil && result.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("legacy prepared approval or revoke overwrote terminal denial")
		}
	}
	for _, current := range []*Service{service, legacy, restarted} {
		fresh := input
		fresh.CommandID = m24Must(identity.NewCommandID())
		if _, err := current.PrepareDenial(ctx, fresh); err == nil {
			t.Fatal("fresh denial admitted an already terminal grant")
		}
		assertM24CommandEffects(t, ctx, pool, fresh.CommandID, 0)
		approvalInput.CommandID = m24Must(identity.NewCommandID())
		if approval, err := current.PrepareApproval(ctx, approvalInput); err == nil {
			if result, err := current.Execute(ctx, approval); err == nil && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("fresh approval restored a denied grant")
			}
		}
		startInput := StartInput{Authentication: requester, CommandID: m24Must(identity.NewCommandID()), GrantID: grantID, ExpectedVersion: 2, Network: "192.0.2.11"}
		if start, err := current.PrepareStart(ctx, startInput); err == nil {
			if result, err := current.ExecuteStoppableStart(ctx, start); err == nil && result.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("start minted a credential from a denied grant")
			}
		}
		revokeInput.CommandID = m24Must(identity.NewCommandID())
		if revoke, err := current.PrepareRevoke(ctx, revokeInput); err == nil {
			if result, err := current.Execute(ctx, revoke); err == nil && result.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("legacy revoke created another terminal effect after denial")
			}
		}
	}
	assertM24DenialMarker(t, ctx, pool, binding)
	assertM24CommandEffects(t, ctx, pool, input.CommandID, 1)
	assertM24NoSessionIssuance(t, ctx, pool)
}

func TestImpersonationDenialConcurrentOncePostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	s, _, _, policy, requester, administrator, _ := newM24DenialFixture(t, ctx, pool)
	grant := requestM24DenialGrant(t, ctx, s, policy, requester)
	prepared := make([]PreparedCommand, 2)
	for i := range prepared {
		prepared[i] = m24Must(s.PrepareDenial(ctx, DenyInput{
			Authentication: administrator, CommandID: m24Must(identity.NewCommandID()),
			GrantID: grant, ExpectedVersion: 1, Network: "192.0.2.12",
			Reason: m24Must(impersonation.NewReason("private distinct administrator denial")),
		}))
	}
	type completion struct {
		result  identity.CommandResult
		err     error
		binding identity.CommandBinding
	}
	start := make(chan struct{})
	done := make(chan completion, len(prepared))
	for _, command := range prepared {
		binding := m24Must(command.Binding())
		go func() {
			<-start
			out, err := s.Execute(ctx, command)
			done <- completion{out, err, binding}
		}()
	}
	close(start)
	winners := 0
	for range prepared {
		c := <-done
		switch c.result.Outcome {
		case identity.CommitOutcomeCommitted:
			if c.err != nil || c.result.Binding != c.binding {
				t.Fatal("winner lost exact committed command binding", c.err)
			}
			winners++
			assertM24DenialMarker(t, ctx, pool, c.binding)
			assertM24CommandEffects(t, ctx, pool, c.binding.CommandID, 1)
		case identity.CommitOutcomeNotCommitted:
			var conflict identity.ConflictError
			if !errors.As(c.err, &conflict) || conflict.CommandID != c.binding.CommandID {
				t.Fatal("loser lost exact noncommitted conflict", c.err)
			}
			assertM24DeniedEffects(t, ctx, pool, c.binding.CommandID)
		default:
			t.Fatal("unexpected competing denial outcome", c.result.Outcome, c.err)
		}
	}
	if winners != 1 {
		t.Fatal("exactly one denial must commit", winners)
	}
}

func TestImpersonationDenialCannotReplaceApprovalPostgres(t *testing.T) {
	for _, state := range []string{"approved", "active"} {
		t.Run(state, func(t *testing.T) {
			ctx, pool := newImpersonationStorageDatabase(t)
			service, _, _, policy, requester, administrator, _ := newM24DenialFixture(t, ctx, pool)
			grantID := requestM24DenialGrant(t, ctx, service, policy, requester)
			input := DenyInput{Authentication: administrator, CommandID: m24Must(identity.NewCommandID()), GrantID: grantID, ExpectedVersion: 1,
				Reason: m24Must(impersonation.NewReason("private distinct administrator denial")), Network: "192.0.2.12"}
			prepared := m24Must(service.PrepareDenial(ctx, input))
			approvalInput := ApproveInput{Authentication: administrator, CommandID: m24Must(identity.NewCommandID()), GrantID: grantID, ExpectedVersion: 1,
				Reason: m24Must(impersonation.NewReason("private distinct administrator approval")), Network: "192.0.2.12"}
			approval := m24Must(service.PrepareApproval(ctx, approvalInput))
			if result := m24Must(service.Execute(ctx, approval)); result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("competing approval did not commit", result.Outcome)
			}
			var activeUse UseInput
			if state == "active" {
				start := m24Must(service.PrepareStart(ctx, StartInput{Authentication: requester, CommandID: m24Must(identity.NewCommandID()), GrantID: grantID, ExpectedVersion: 2, Network: "192.0.2.11"}))
				activated := m24Must(service.ExecuteStoppableStart(ctx, start))
				if activated.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("approved grant did not activate", activated.Receipt.Outcome)
				}
				activeUse = UseInput{Tenant: requester.Tenant, Bearer: m24Must(activated.Credential.Reveal()), Permission: "profile.read"}
				if _, err := service.ValidateUse(ctx, activeUse); err != nil {
					t.Fatal("winning approval did not preserve usable activation", err)
				}
			}
			result, err := service.Execute(ctx, prepared)
			var conflict identity.ConflictError
			if !errors.As(err, &conflict) || conflict.CommandID != input.CommandID || result.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("prepared denial overwrote a winning approval", result.Outcome, err)
			}
			assertM24DeniedEffects(t, ctx, pool, input.CommandID)
			if state == "active" {
				if _, err := service.ValidateUse(ctx, activeUse); err != nil {
					t.Fatal("losing denial withdrew the winning active authority", err)
				}
			}
			for _, version := range []uint64{1, 2, 3} {
				fresh := input
				fresh.CommandID, fresh.ExpectedVersion = m24Must(identity.NewCommandID()), version
				if _, err := service.PrepareDenial(ctx, fresh); err == nil {
					t.Fatal("denial admitted a nonpending grant", state, version)
				}
				assertM24CommandEffects(t, ctx, pool, fresh.CommandID, 0)
			}
			var denials int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_impersonation.denials WHERE tenant_id=$1 AND grant_id=$2`, string(requester.Tenant), string(grantID)).Scan(&denials); err != nil || denials != 0 {
				t.Fatal("losing denial retained a terminal marker", denials, err)
			}
			assertM24CommandEffects(t, ctx, pool, approvalInput.CommandID, 1)
			assertM24NoSessionIssuance(t, ctx, pool)
		})
	}
}

func TestImpersonationDenialRejectsAuthenticatedTargetPostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	service, _, cfg, policy, requester, _, _ := newM24DenialFixture(t, ctx, pool)
	grantID := requestM24DenialGrant(t, ctx, service, policy, requester)
	target := seedM24PasswordTOTPSession(t, ctx, pool, "target-user", cfg.Session.Validation.LookupKeys[0], cfg.CSRFKey)
	policy.actor = "target-user"
	input := DenyInput{Authentication: target, CommandID: m24Must(identity.NewCommandID()), GrantID: grantID, ExpectedVersion: 1,
		Reason: m24Must(impersonation.NewReason("private target denial attempt")), Network: "192.0.2.13"}
	if _, err := service.PrepareDenial(ctx, input); !errors.Is(err, identity.ForbiddenError{}) {
		t.Fatal("authenticated target denied its own impersonation request", err)
	}
	assertM24CommandEffects(t, ctx, pool, input.CommandID, 0)
}

func newM24DenialFixture(t *testing.T, ctx context.Context, pool *database.Pool) (*Service, *Service, Config, *m24DenialAuthorization, Authentication, Authentication, ActivationConfig) {
	t.Helper()
	_, cfg, requester, administrator := newM24ServiceFixture(t, ctx, pool)
	for _, migration := range m24Must((DenialMigrationSource{}).Load(ctx))[1:] {
		m24Exec(t, ctx, pool, migration.UpSQL())
	}
	policy := &m24DenialAuthorization{
		base:  &m24SelfStopAuthorization{activation: &m24ActivationAuthorization{legacy: cfg.Authorization.(*m24Authorization)}},
		actor: "approve-admin",
	}
	cfg.Authorization = policy
	activation := ActivationConfig{LookupKey: m24Must(session.NewDigestKey(7, bytes.Repeat([]byte{71}, 32)))}
	return m24Must(NewServiceWithDenial(pool, cfg, activation)), m24Must(NewServiceWithSelfStop(pool, cfg, activation)), cfg, policy, requester, administrator, activation
}

func requestM24DenialGrant(t *testing.T, ctx context.Context, service *Service, policy *m24DenialAuthorization, requester Authentication) impersonation.GrantID {
	t.Helper()
	id := m24Must(identity.NewCommandID())
	prepared := m24Must(service.PrepareRequest(ctx, RequestInput{
		Authentication: requester, CommandID: id, Target: "target-user",
		Scope:  m24Must(impersonation.NewScope([]string{"profile.read", "address.read"})),
		Reason: m24Must(impersonation.NewReason("private support case request")), Duration: 10 * time.Minute, Network: "192.0.2.11",
	}))
	policy.grantID, policy.base.grantID = string(id), string(id)
	if result := m24Must(service.Execute(ctx, prepared)); result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("request did not commit", result.Outcome)
	}
	return impersonation.GrantID(id)
}

func assertM24DenialMarker(t *testing.T, ctx context.Context, pool *database.Pool, binding identity.CommandBinding) {
	t.Helper()
	var command, denier, requester, target string
	var before, after, denials, approvals, activations, revocations int
	var ciphertext []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT d.command_id,d.denier_id,d.requester_id,d.target_id,d.before_version,d.after_version,d.encrypted_payload,
		(SELECT count(*) FROM identity_impersonation.denials WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id),
		(SELECT count(*) FROM identity_impersonation.approvals WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id),
		(SELECT count(*) FROM identity_impersonation.active_grants WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id),
		(SELECT count(*) FROM identity_impersonation.revocations WHERE tenant_id=d.tenant_id AND grant_id=d.grant_id)
		FROM identity_impersonation.denials d WHERE d.tenant_id=$1 AND d.grant_id=$2`, string(binding.TenantID), binding.RecordID).
		Scan(&command, &denier, &requester, &target, &before, &after, &ciphertext, &denials, &approvals, &activations, &revocations); err != nil {
		t.Fatal("read durable denial evidence", err)
	}
	if command != string(binding.CommandID) || denier != string(binding.ActorID) || requester != "request-admin" || target != string(binding.UserID) || before != 1 || after != 2 || denials != 1 || approvals != 0 || activations != 0 || revocations != 0 || len(ciphertext) == 0 || bytes.Contains(ciphertext, []byte("private distinct administrator denial")) {
		t.Fatal("denial lost its distinct actor, terminal version or single protected effect")
	}
	var leakedReason int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.records WHERE correlation_id=$1 AND position(convert_to('private distinct administrator denial','UTF8') in canonical_record)>0`, string(binding.CommandID)).Scan(&leakedReason); err != nil || leakedReason != 0 {
		t.Fatal("private denial reason entered audit metadata", err)
	}
}

type m24DenialAuthorization struct {
	base    *m24SelfStopAuthorization
	grantID string
	actor   authorization.SubjectID
	deny    bool
	checks  atomic.Int32
}

func (p *m24DenialAuthorization) Decide(ctx context.Context, caller authorization.DecisionContext) (authorization.Decision, error) {
	r := caller.Request
	if r.Action != "identity.impersonation.deny" {
		return p.base.Decide(ctx, caller)
	}
	if recovering, _ := r.Resource.Attributes["identity.command.recovery"].Bool(); recovering {
		return p.base.activation.legacy.Decide(ctx, caller)
	}
	denied := authorization.Decision{Outcome: authorization.Deny, Revision: p.base.activation.legacy.revision}
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	grantID, exactGrant := r.Attributes["impersonation.grant-id"].String()
	permissions, exactScope := r.Attributes[scopeAttribute].StringSet()
	if !p.deny && caller.PolicyRevision == p.base.activation.legacy.revision && r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == p.actor && r.Resource.Type == "identity.user" && r.Resource.ID == "target-user" && exactGrant && grantID == p.grantID && exactScope && slices.Equal(permissions, []string{"address.read", "profile.read"}) {
		p.checks.Add(1)
		return authorization.Decision{Outcome: authorization.Allow, Revision: p.base.activation.legacy.revision}, nil
	}
	return denied, nil
}
