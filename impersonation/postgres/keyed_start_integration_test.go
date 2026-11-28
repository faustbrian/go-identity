//go:build integration

package impersonationpostgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

func TestImpersonationKeyedStartOneTimeIssuanceAndRestartPostgres(t *testing.T) {
	ctx, pool := newImpersonationStorageDatabase(t)
	_, cfg, requester, approver := newM24ServiceFixture(t, ctx, pool)
	for _, migration := range m24Must((SelfStopMigrationSource{}).Load(ctx))[1:] {
		m24Exec(t, ctx, pool, migration.UpSQL())
	}
	keyHistory := m24Must((kernel.RequestKeyPreparationMigrationSource{
		Base: kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 40}, Version: 41,
	}).Load(ctx))
	for _, migration := range keyHistory {
		if migration.Version() >= 40 {
			m24Exec(t, ctx, pool, migration.UpSQL())
		}
	}
	policy := &m24KeyedStartAuthorization{activation: &m24ActivationAuthorization{legacy: cfg.Authorization.(*m24Authorization)}}
	cfg.Authorization = policy
	lookupKey := m24Must(session.NewDigestKey(7, bytes.Repeat([]byte{71}, 32)))
	native := m24Must(NewServiceWithSelfStop(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
	keys := m24Must(kernel.NewRequestKeyConfig("m24-keyed-start", [32]byte{91}, kernel.CommandQueryPolicy{
		Authorization: policy, Clock: cfg.Session.Validation.Clock, PolicyVersion: cfg.Policy.Version(),
	}))
	custody := KeyedStartCustody{ConfigurationID: "m24-stoppable-start-v1", ActiveKey: "m24-start-v1", Keys: map[string][]byte{"m24-start-v1": bytes.Repeat([]byte{92}, 32)}}
	service := m24Must(NewKeyedStartService(native, keys, custody))
	approveGrant := func() impersonation.GrantID {
		t.Helper()
		id := m24Must(identity.NewCommandID())
		request := m24Must(native.PrepareRequest(ctx, RequestInput{
			Authentication: requester, CommandID: id, Target: "target-user",
			Scope:    m24Must(impersonation.NewScope([]string{"profile.read", "address.read"})),
			Reason:   m24Must(impersonation.NewReason("private support case request")),
			Duration: 10 * time.Minute, Network: "192.0.2.11",
		}))
		if result := m24Must(native.Execute(ctx, request)); result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("grant request did not commit")
		}
		approval := m24Must(native.PrepareApproval(ctx, ApproveInput{
			Authentication: approver, CommandID: m24Must(identity.NewCommandID()),
			GrantID: impersonation.GrantID(id), ExpectedVersion: 1,
			Reason: m24Must(impersonation.NewReason("private distinct administrator approval")), Network: "192.0.2.12",
		}))
		if result := m24Must(native.Execute(ctx, approval)); result.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("distinct grant approval did not commit")
		}
		return impersonation.GrantID(id)
	}
	grant, otherGrant := approveGrant(), approveGrant()
	policy.stopGrant = string(grant)
	const rawKey = "m24-keyed-start-original-request"
	input := KeyedStartInput{
		Authentication: requester, GrantID: grant, ExpectedVersion: 2,
		Network: "192.0.2.11", Key: m24Must(identity.NewIdempotencyKey([]byte(rawKey))),
	}
	before := m24KeyedStartEffects(t, ctx, pool)
	for _, invalid := range []string{"actor", "csrf", "tenant", "start-policy", "admission-policy"} {
		wrong := input
		switch invalid {
		case "actor":
			wrong.Authentication = approver
		case "csrf":
			wrong.Authentication.CSRF = approver.CSRF
		case "tenant":
			wrong.Authentication.Tenant = "foreign-tenant"
		case "start-policy":
			policy.denyStart = true
		case "admission-policy":
			policy.denyAdmission = true
		}
		denied, err := service.Start(ctx, wrong)
		policy.denyStart, policy.denyAdmission = false, false
		if !errors.Is(err, identity.ForbiddenError{}) || denied.Receipt.Outcome == identity.CommitOutcomeCommitted || denied.Receipt.Binding.CommandID != "" {
			t.Fatal("keyed Start accepted invalid current authority or disclosed original metadata", invalid)
		}
		assertM24KeyedStartNoSecrets(t, denied)
		if effects := m24KeyedStartEffects(t, ctx, pool); effects != before {
			t.Fatal("denied keyed Start changed native effects", invalid, effects, before)
		}
	}
	policy.admissionChecks, policy.activation.startChecks = 0, 0
	issued := m24Must(service.Start(ctx, input))
	receipt := issued.Receipt
	if receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Binding.TenantID != requester.Tenant || receipt.Binding.ActorID != "request-admin" || receipt.Binding.UserID != "target-user" || receipt.Binding.RecordID != string(grant) || receipt.Binding.OperationID != startAction || receipt.Binding.PolicyVersion != cfg.Policy.Version() || receipt.Feature == nil || receipt.Feature.BeforeVersion != 2 || receipt.Feature.AfterVersion != 3 {
		t.Fatal("keyed Start did not commit the exact approved grant under its named policy")
	}
	if policy.admissionChecks == 0 || policy.activation.startChecks == 0 {
		t.Fatal("keyed Start omitted request admission or the native Start policy")
	}
	bearer := m24Must(issued.Credential.Reveal())
	stopCSRF := m24Must(issued.StopCSRF.Reveal())
	if _, err := issued.Credential.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
		t.Fatal("keyed Start disclosed its derived bearer twice")
	}
	if _, err := issued.StopCSRF.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
		t.Fatal("keyed Start disclosed its stop synchronizer twice")
	}
	if _, err := native.ValidateUse(ctx, UseInput{Tenant: requester.Tenant, Bearer: bearer, Permission: "profile.read"}); err != nil {
		t.Fatal("acknowledged keyed Start did not issue usable native child authority", err)
	}
	if _, err := native.PrepareStop(ctx, StopInput{
		Authentication: StopAuthentication{Tenant: requester.Tenant, Bearer: bearer, CSRF: m24Must(session.ParseCSRFToken(stopCSRF))},
		CommandID:      m24Must(identity.NewCommandID()), Network: input.Network,
	}); err != nil {
		t.Fatal("keyed Start did not issue a synchronizer bound to the actual child", err)
	}
	policy.activation.legacy.recovery[string(receipt.Binding.CommandID)] = receipt.Binding
	committed := m24KeyedStartEffects(t, ctx, pool)
	if committed != [6]int{1, 1, before[2] + 1, before[3] + 1, before[4] + 1, before[5] + 4} {
		t.Fatal("keyed Start split or duplicated native activation, proof, audit, lifecycle or risk effects", committed)
	}
	assertM24CommandEffects(t, ctx, pool, receipt.Binding.CommandID, 1)
	restartedNative := m24Must(NewServiceWithSelfStop(pool, cfg, ActivationConfig{LookupKey: lookupKey}))
	restarted := m24Must(NewKeyedStartService(restartedNative, keys, custody))
	for _, wrapper := range []*KeyedStartService{service, restarted} {
		replayed := m24Must(wrapper.Start(ctx, input))
		if !reflect.DeepEqual(replayed.Receipt, receipt) {
			t.Fatal("same-key replay or reconstructed wrapper changed its exact committed receipt")
		}
		assertM24KeyedStartNoSecrets(t, replayed)
	}
	changed := input
	changed.GrantID = otherGrant
	conflicted, err := restarted.Start(ctx, changed)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) || conflicted.Receipt.Binding.CommandID != "" || conflicted.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("same key with another approved grant did not conflict without disclosing the original receipt")
	}
	assertM24KeyedStartNoSecrets(t, conflicted)
	for _, invalid := range []string{"csrf", "admission-policy", "recovery-policy"} {
		wrong := input
		switch invalid {
		case "csrf":
			wrong.Authentication.CSRF = approver.CSRF
		case "admission-policy":
			policy.denyAdmission = true
		case "recovery-policy":
			policy.denyRecovery = true
		}
		denied, err := restarted.Start(ctx, wrong)
		policy.denyAdmission, policy.denyRecovery = false, false
		if !errors.Is(err, identity.ForbiddenError{}) || denied.Receipt.Binding.CommandID != "" {
			t.Fatal("retained key bypassed exact current authentication or policy", invalid)
		}
		assertM24KeyedStartNoSecrets(t, denied)
	}
	if effects := m24KeyedStartEffects(t, ctx, pool); effects != committed {
		t.Fatal("replay, changed intent or denied recovery created extra native effects", effects, committed)
	}
	var mappings, leaks int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.request_key_mappings),
		(SELECT count(*) FROM audit.records WHERE position(convert_to($1,'UTF8') in canonical_record)>0)`, rawKey).Scan(&mappings, &leaks); err != nil || mappings != 1 || leaks != 0 {
		t.Fatal("keyed Start duplicated request correlation or disclosed the raw request key in audit", mappings, leaks, err)
	}
	metadata := m24Must(json.Marshal(receipt))
	if bytes.Contains(metadata, []byte(rawKey)) || strings.Contains(fmt.Sprintf("%+v", issued), rawKey) || strings.Contains(fmt.Sprint(err), rawKey) {
		t.Fatal("raw request key entered returned metadata, diagnostics or errors")
	}
	assertM24CommandEffects(t, ctx, pool, receipt.Binding.CommandID, 1)
	assertM24NoSessionIssuance(t, ctx, pool)

	// Model loss between the acknowledged request mapping and the original
	// invocation's execution claim. A restarted process must not take it over.
	lost := changed
	lost.Key = m24Must(identity.NewIdempotencyKey([]byte("m24-lost-start-invocation")))
	scope := kernel.RequestKeyScope{TenantID: requester.Tenant, ActorID: receipt.Binding.ActorID, ActorKind: authorization.SubjectUser, Method: "POST", RouteID: startAction}
	phase := m24Must(service.startInvocation(scope, lost))
	coordinator := m24Must(service.coordinator(phase))
	caller := native.startCaller(scope, "identity.request-admission", startAction, string(lost.GrantID))
	admitted, wire, err := coordinator.ResolvePreparedRequestKey(ctx, scope, lost.Key, phase.keyed.intent, caller, keyedStartRegistration(), phase)
	if err != nil {
		t.Fatal("could not retain the original preparation", err)
	}
	original := m24Must(phase.RestoreRequestKey(ctx, admitted, wire))
	clear(wire)
	policy.activation.legacy.recovery[string(original.CommandID)] = original
	unknown, err := restarted.Start(ctx, lost)
	var ambiguous identity.UnknownCommitError
	if !errors.As(err, &ambiguous) || ambiguous.CommandID != original.CommandID ||
		unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding != original {
		t.Fatal("preparation without execution became a fresh issuance or a fabricated rollback", unknown.Receipt.Outcome, err)
	}
	assertM24KeyedStartNoSecrets(t, unknown)
	assertM24CommandEffects(t, ctx, pool, original.CommandID, 0)
	if effects := m24KeyedStartEffects(t, ctx, pool); effects != committed {
		t.Fatal("status-only recovery created native effects", effects, committed)
	}
}

func assertM24KeyedStartNoSecrets(t *testing.T, result StoppableActivationResult) {
	t.Helper()
	if _, err := result.Credential.Reveal(); err == nil {
		t.Fatal("unacknowledged or replayed keyed Start disclosed a derived bearer")
	}
	if _, err := result.StopCSRF.Reveal(); err == nil {
		t.Fatal("unacknowledged or replayed keyed Start disclosed a stop synchronizer")
	}
}

func m24KeyedStartEffects(t *testing.T, ctx context.Context, pool *database.Pool) [6]int {
	t.Helper()
	var effects [6]int
	if err := pool.Raw().QueryRow(ctx, `SELECT
		(SELECT count(*) FROM identity_impersonation.active_grants),
		(SELECT count(*) FROM identity_impersonation.stop_proofs),
		(SELECT count(*) FROM audit.records),
		(SELECT count(*) FROM public.outbox_messages),
		(SELECT count(*) FROM m24_risk.counter_charges),
		(SELECT count(*) FROM m24_risk.counter_snapshots)`).Scan(&effects[0], &effects[1], &effects[2], &effects[3], &effects[4], &effects[5]); err != nil {
		t.Fatal("cannot observe native keyed Start effects", err)
	}
	return effects
}

type m24KeyedStartAuthorization struct {
	activation      *m24ActivationAuthorization
	stopGrant       string
	denyAdmission   bool
	denyStart       bool
	denyRecovery    bool
	admissionChecks int
}

func (p *m24KeyedStartAuthorization) Decide(ctx context.Context, caller authorization.DecisionContext) (authorization.Decision, error) {
	denied := authorization.Decision{Outcome: authorization.Deny, Revision: p.activation.legacy.revision}
	if err := ctx.Err(); err != nil {
		return denied, err
	}
	r := caller.Request
	if r.Action == stopAction {
		return (&m24SelfStopAuthorization{activation: p.activation, grantID: p.stopGrant}).Decide(ctx, caller)
	}
	if r.Resource.Type == "identity.request-admission" {
		admission, _ := r.Resource.Attributes["identity.request.admission"].Bool()
		method, _ := r.Resource.Attributes["identity.request.method"].String()
		namespace, _ := r.Resource.Attributes["identity.request.namespace"].String()
		if !p.denyAdmission && caller.PolicyRevision == p.activation.legacy.revision && r.Tenant == "m24-tenant" && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID == "request-admin" && r.Action == startAction && r.Resource.ID == startAction && admission && method == "POST" && namespace == "m24-keyed-start" {
			p.admissionChecks++
			return authorization.Decision{Outcome: authorization.Allow, Revision: p.activation.legacy.revision}, nil
		}
		return denied, nil
	}
	if r.Action == startAction {
		recovering, _ := r.Resource.Attributes["identity.command.recovery"].Bool()
		if p.denyStart || recovering && p.denyRecovery {
			return denied, nil
		}
	}
	return p.activation.Decide(ctx, caller)
}
