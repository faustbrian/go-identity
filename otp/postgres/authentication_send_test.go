package postgres

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
)

type authenticationCounterStore func(context.Context, risk.CounterCommand) (risk.CounterResult, error)

func (s authenticationCounterStore) Mutate(ctx context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	return s(ctx, c)
}

type authenticationAuditSink func(context.Context, audit.Record) (audit.AppendResult, error)

func (s authenticationAuditSink) Append(ctx context.Context, r audit.Record) (audit.AppendResult, error) {
	return s(ctx, r)
}
func (s authenticationAuditSink) AppendBatch(context.Context, []audit.Record) (audit.BatchResult, error) {
	return audit.BatchResult{}, errors.New("unexpected batch")
}

// These native tests use genuine evaluator provenance with explicit external
// boundary doubles. They do not certify durable counter/provider composition.
func canonicalAuthenticationSendFixture(t *testing.T, contributors ...kernel.ContributorDescriptor) (*Contributor, identity.Command, kernel.RequestKeyPreparationBinding) {
	t.Helper()
	p, original, binding := initiationFixture(t)
	r, _, err := p.originalPreparedSend(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := original.Feature()
	cb, _ := r.continuation.Bindings()
	old, _ := cb.Authorization.AuthenticatedSession()
	s, _ := old.Bindings()
	s.TenantID, s.UserID = "AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg"
	s.Authentication.Proof.Tenant, s.Authentication.Proof.Subject = string(s.TenantID), string(s.UserID)
	r.authority.Directory.Query.TenantID = s.TenantID
	r.authority.Credential.TenantID, r.authority.Credential.UserID = s.TenantID, s.UserID
	r.authority.UserAuthorization.Scope = authoritypg.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), SubjectID: authorization.SubjectID(s.UserID), PolicyNamespace: "users"}
	vector, _ := s.Authority.Bindings()
	keys, err := kernel.KernelAuthorityKeys(r.authority.Directory.Query, s.UserID)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := sessionpg.SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := r.authority.UserAuthorization.Scope.Key()
	if err != nil {
		t.Fatal(err)
	}
	vector.Global.ScopeKey, vector.Tenant.ScopeKey, vector.User.ScopeKey = keys.Global, keys.Tenant, keys.User
	vector.Identifier.ScopeKey, vector.Credential.ScopeKey = keys.Identifier, keys.Credential
	vector.Session.ScopeKey, vector.SessionFamily.ScopeKey, vector.Authorization.ScopeKey = sk.Session, sk.Family, pk
	s.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := original.SessionToken()
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(3, bytes.Repeat([]byte{0x56}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.Lookup, err = token.Digest(key, string(s.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(s)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := otp.NewBoundSessionAuthorization(record)
	if err != nil {
		t.Fatal(err)
	}
	cb.Scope.TenantID, cb.Scope.SubjectID = string(s.TenantID), string(s.UserID)
	cb.Scope.AuthorizationBinding = [32]byte{}
	r.continuation, err = otp.NewContinuation(cb.Scope, flow, session.RememberPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.TenantID, spec.Binding.UserID, spec.Binding.ActorID = s.TenantID, s.UserID, identity.ActorID(s.UserID)
	spec.Binding.CorrelationID = string(spec.Binding.CommandID)
	r.recipient.Query.TenantID, r.recipient.Query.UserID = s.TenantID, s.UserID
	r.recipient.User.TenantID, r.recipient.User.ID = s.TenantID, s.UserID
	r.recipient.Identifier.UserID = s.UserID
	r.recipient.UserAuthorityVersion, r.recipient.IdentifierAuthorityVersion, r.recipient.CredentialAuthorityVersion = r.authority.UserAuthorityVersion, r.authority.IdentifierAuthorityVersion, r.authority.CredentialAuthorityVersion
	if len(contributors) != 0 {
		p, err = newPreparedSendContributor(p, p.send.delivery, preparedSendConfig{preparation: otp.SendPreparationConfig{Policy: p.send.policy, TemplateID: p.send.template, TemplateVersion: p.send.templateVersion, LocaleChain: p.send.locales}, provider: p.send.provider, contributors: append(contributors, p.Descriptor(), p.send.delivery.Descriptor()), templates: preparedSendTemplates("{{.code}}")})
		if err != nil {
			t.Fatal(err)
		}
	}
	original, err = p.mapPreparedSendRequest(context.Background(), r, spec.Binding, bearer)
	if err != nil {
		t.Fatal(err)
	}
	binding.Scope.TenantID, binding.Scope.ActorID = s.TenantID, identity.ActorID(s.UserID)
	return p, original, binding
}

type authenticationSendClock struct {
	mu      sync.Mutex
	instant time.Time
}

func (c *authenticationSendClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.instant }
func (c *authenticationSendClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.instant = c.instant.Add(d)
}

func authenticationSendFixture(t *testing.T, contributors ...kernel.ContributorDescriptor) (*authenticationSendContributor, identity.Command, risk.AuthenticationAdmissionCustodyConfig, *authenticationSendClock, *risk.SignalState, *int) {
	t.Helper()
	p, original, binding := canonicalAuthenticationSendFixture(t, contributors...)
	request, _, err := p.originalPreparedSend(context.Background(), original)
	if err != nil {
		t.Fatal(err)
	}
	now, state, calls := authenticationSendClock{instant: request.issuedAt}, risk.SignalClean, 0
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2},
	}
	for i := range profiles {
		profiles[i].RequiredSignals = []string{"status", "velocity"}
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal("policy fixture", err)
	}
	key, err := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal("counter key fixture", err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}, Clock: now.Now, Timeout: time.Second,
		Store: authenticationCounterStore(func(_ context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
			calls++
			b := command.Bindings()
			if b.Tenant != string(binding.Scope.TenantID) || b.Operation != "identity.otp.send" || b.Attempt != string(binding.Admission.CommandID) {
				t.Fatal("foreign risk command")
			}
			var snapshot []risk.Counter
			for _, target := range b.Targets {
				snapshot = append(snapshot, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt.Add(-time.Second), WindowExpiresAt: b.PreparedAt.Add(b.Window - time.Second)})
			}
			return risk.NewCounterResult(command, risk.CounterCommitted, snapshot)
		})})
	if err != nil {
		t.Fatal("counter coordinator fixture", err)
	}
	e, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counters, Clock: now.Now, Timeout: 5 * time.Second,
		Sources: []risk.Source{{Name: "status", Version: "status-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			calls++
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", Trust: risk.ServerVerified, State: state, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
		}}},
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: "AAAAAAAAAAAAAAAAAAAAAQ", Timeout: time.Second, OnLoss: func(context.Context, risk.DecisionDelivery) error { return nil }, Delivery: audit.RecorderConfig{Mode: audit.DeliveryFailClosed, Sink: authenticationAuditSink(func(_ context.Context, r audit.Record) (audit.AppendResult, error) {
			calls++
			return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
		})}},
	})
	if err != nil {
		t.Fatal("evaluator fixture", err)
	}
	integrity, err := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x51}, 32), bytes.Repeat([]byte{0x61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	config := risk.AuthenticationAdmissionCustodyConfig{Evaluation: e, ConfigurationID: "otp-auth-v1", Keys: []risk.EvidenceKey{integrity}}
	owner, err := newAuthenticationSendContributor(p, config)
	if err != nil {
		t.Fatal(err)
	}
	dimensions := sendInitiationRisk{network: "192.0.2.8", device: "original-device", identifierDigest: strings.Repeat("a", 64)}
	wire, err := p.sealSendInitiation(context.Background(), binding, original, dimensions, false)
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := original.SessionToken()
	input, err := p.restoreSendInitiation(context.Background(), binding, wire, bearer)
	if err != nil {
		t.Fatal(err)
	}
	command, err := owner.mapInitiatedSend(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return owner, command, config, &now, &state, &calls
}

func TestAuthenticationSendRequiresRiskBeforeGeneration(t *testing.T) {
	p, command, _, _, state, calls := authenticationSendFixture(t)
	*state = risk.SignalDeny
	admission, err := p.PrepareFeatureAdmission(context.Background(), command)
	if !errors.Is(err, risk.ErrInvalidAuthenticationAdmission) || admission != nil {
		t.Fatal("restrictive risk admitted generation", err)
	}
	if *calls != 3 {
		t.Fatal("missing counted/audited evaluation", *calls)
	}
	*state = risk.SignalClean
	admission, err = p.PrepareFeatureAdmission(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := admission.Generate(context.Background(), 1)
	if err != nil || len(wire) == 0 {
		t.Fatal("genuine admission could not generate", err)
	}
}

func TestAuthenticationSendRemappingRetainsOriginalCommand(t *testing.T) {
	owner, command, config, _, _, calls := authenticationSendFixture(t)
	base, dims, err := owner.original(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	_, _, binding := canonicalAuthenticationSendFixture(t)
	wire, err := owner.store.sealSendInitiation(context.Background(), binding, base, dims, false)
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := base.SessionToken()
	var first identity.Command
	for i := 0; i < 2; i++ {
		freshStore := *owner.store
		freshStore.codec, err = NewAttemptCodec(codecConfig())
		if err != nil {
			t.Fatal(err)
		}
		fresh, err := newAuthenticationSendContributor(&freshStore, config)
		if err != nil {
			t.Fatal(err)
		}
		input, err := freshStore.restoreSendInitiation(context.Background(), binding, wire, bearer)
		if err != nil {
			t.Fatal(err)
		}
		mapped, err := fresh.mapInitiatedSend(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = mapped
		} else {
			a, _ := first.Feature()
			b, _ := mapped.Feature()
			if !reflect.DeepEqual(a, b) {
				t.Fatal("identical retained initiation changed command identity")
			}
		}
	}
	if *calls != 0 {
		t.Fatal("remapping performed risk work")
	}
}

func TestAuthenticationSendOriginalAdmissionAcrossOwnerRestart(t *testing.T) {
	p, command, config, now, _, calls := authenticationSendFixture(t)
	a, err := p.PrepareFeatureAdmission(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Generate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	base, dims, err := p.original(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{dims.network, dims.device, dims.identifierDigest} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("plaintext risk dimensions retained")
		}
	}
	generated, plan, err := p.RestoreFeaturePreparation(context.Background(), command, 1, wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateFeatureCommand(generated, plan); err != nil {
		t.Fatal(err)
	}
	declaration, err := p.store.preparedSendPlan(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ValidateFeaturePreparation(command, declaration); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GenerateFeaturePreparation(context.Background(), command, 1); err == nil {
		t.Fatal("ungated generation")
	}
	if _, ok := any(p.store).(kernel.FeatureAdmissionPreparationContributor); ok {
		t.Fatal("legacy owner silently changed")
	}
	before := *calls
	fresh, err := newAuthenticationSendContributor(p.store, config)
	if err != nil {
		t.Fatal(err)
	}
	now.Advance(29 * time.Second)
	retained, err := fresh.RestoreFeatureAdmission(context.Background(), command, 1, wire)
	if err != nil || retained.Check(context.Background()) != nil {
		t.Fatal("original valid admission lost", err)
	}
	if _, err := retained.Generate(context.Background(), 2); err == nil {
		t.Fatal("restored admission regenerated")
	}
	restored, restoredPlan, err := fresh.RestoreFeaturePreparation(context.Background(), command, 1, wire)
	want, _ := generated.Feature()
	got, _ := restored.Feature()
	if err != nil || !reflect.DeepEqual(want, got) || !reflect.DeepEqual(plan, restoredPlan) {
		t.Fatal("original generated command changed", err)
	}
	if *calls != before {
		t.Fatal("restart repeated external admission")
	}
	now.Advance(time.Second)
	if err := retained.Check(context.Background()); !errors.Is(err, risk.ErrInvalidAuthenticationAdmission) {
		t.Fatal("exact original expiry admitted", err)
	}
	if _, err := fresh.RestoreFeatureAdmission(context.Background(), command, 1, wire); !errors.Is(err, risk.ErrInvalidAuthenticationAdmission) {
		t.Fatal("restart renewed freshness", err)
	}
	if *calls != before {
		t.Fatal("expiry repeated external admission")
	}
}

func TestAuthenticationSendRejectsChangedCustodyAndCancellation(t *testing.T) {
	p, command, config, _, _, calls := authenticationSendFixture(t)
	a, err := p.PrepareFeatureAdmission(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := a.Generate(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	before := *calls
	changed := bytes.Clone(wire)
	changed[len(changed)-1] ^= 1
	for _, test := range []struct {
		generation uint64
		wire       []byte
	}{{0, wire}, {2, wire}, {1, changed}, {1, nil}} {
		if _, err := p.RestoreFeatureAdmission(context.Background(), command, test.generation, test.wire); err == nil {
			t.Fatal("foreign output admitted")
		}
	}
	config.ConfigurationID = "otp-auth-v2"
	fresh, err := newAuthenticationSendContributor(p.store, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.RestoreFeatureAdmission(context.Background(), command, 1, wire); err == nil {
		t.Fatal("changed native configuration admitted old output")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.PrepareFeatureAdmission(cancelled, command); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := p.RestoreFeatureAdmission(cancelled, command, 1, wire); !errors.Is(err, context.Canceled) {
		t.Fatal("restoration cancellation lost", err)
	}
	if *calls != before {
		t.Fatal("invalid replay repeated external work")
	}
	if _, err := p.mapInitiatedSend(context.Background(), sendInitiationCustody{suppressed: true}); err == nil {
		t.Fatal("suppression gained generation authority")
	}
}

func TestAuthenticationSendRejectsCodeBearingVariantsBeforeRisk(t *testing.T) {
	p, command, _, _, _, calls := authenticationSendFixture(t)
	spec, _ := command.Feature()
	bearer, _ := command.SessionToken()
	code, err := auth.NewOneTimeCode("123456")
	if err != nil {
		t.Fatal(err)
	}
	for _, makeCommand := range []func(identity.FeatureCommandSpec, auth.OneTimeCode, auth.BearerCredential) (identity.Command, error){identity.NewFeatureOneTimeCodeSessionCommand, identity.NewFeatureOneTimeCodePreAuthCommand} {
		mixed, err := makeCommand(spec, code, bearer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sendCommandWithFields(mixed, spec.Fields); !errors.Is(err, ErrInvalidCommand) {
			t.Fatal("unsupported code-bearing variant erased", err)
		}
		if admission, err := p.PrepareFeatureAdmission(context.Background(), mixed); !errors.Is(err, ErrInvalidCommand) || admission != nil {
			t.Fatal("unsupported code-bearing variant reached admission", err)
		}
		if *calls != 0 {
			t.Fatal("unsupported variant reached risk evaluation")
		}
	}
}

func TestAuthenticationSendRejectsChangedInitiationReference(t *testing.T) {
	p, command, _, _, _, calls := authenticationSendFixture(t)
	spec, _ := command.Feature()
	binding, sealed, err := decodeInitiationReference(spec.Fields[2].Value.Bytes, p.configuration)
	if err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*kernel.RequestKeyPreparationBinding, []byte){
		func(b *kernel.RequestKeyPreparationBinding, _ []byte) { b.Namespace = "foreign" },
		func(b *kernel.RequestKeyPreparationBinding, _ []byte) { b.IntentDigest[0] ^= 1 },
		func(_ *kernel.RequestKeyPreparationBinding, wire []byte) { wire[len(wire)-1] ^= 1 },
	} {
		b, wire := binding, bytes.Clone(sealed)
		alter(&b, wire)
		changed, err := p.initiationReference(sendInitiationCustody{retainedBinding: b, retainedWire: wire})
		if err != nil {
			t.Fatal(err)
		}
		fields := append([]identity.FeatureField(nil), spec.Fields...)
		fields[2].Value.Bytes = changed
		mixed, err := sendCommandWithFields(command, fields)
		if err != nil {
			t.Fatal(err)
		}
		if admission, err := p.PrepareFeatureAdmission(context.Background(), mixed); err == nil || admission != nil {
			t.Fatal("changed initiating provenance admitted")
		}
		if *calls != 0 {
			t.Fatal("changed provenance reached external risk work")
		}
	}
}

func FuzzAuthenticationSendRetainedProjection(f *testing.F) {
	f.Add([]byte("IOAO1"))
	f.Add([]byte("IOAO1\x00\x00\xff\xff"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > maximumSendOutput+1 {
			return
		}
		d, p, inner, err := decodeAuthenticationSend(wire)
		defer clear(inner)
		if err == nil {
			rebuilt, err := encodeAuthenticationSend(d, p, inner)
			defer clear(rebuilt)
			if err != nil || !bytes.Equal(rebuilt, wire) {
				t.Fatal("noncanonical retained projection accepted")
			}
		}
	})
}

func FuzzAuthenticationSendInitiationReference(f *testing.F) {
	owner := &authenticationSendContributor{configuration: "otp-auth-v1"}
	seed, err := owner.initiationReference(sendInitiationCustody{retainedWire: []byte("ciphertext")})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("IOAI2\x00\x00\xff\xff"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 8193 {
			return
		}
		binding, sealed, err := decodeInitiationReference(wire, owner.configuration)
		if err == nil {
			rebuilt, err := owner.initiationReference(sendInitiationCustody{retainedBinding: binding, retainedWire: sealed})
			if err != nil || !bytes.Equal(rebuilt, wire) {
				t.Fatal("noncanonical initiation reference accepted")
			}
		}
	})
}
