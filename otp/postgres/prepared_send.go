package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
)

// Private composition until recipient resolution and authentication risk are
// owned by the public Send service. No caller-selected clearance is accepted.
type preparedSendConfig struct {
	preparation  otp.SendPreparationConfig
	provider     uint64
	contributors []kernel.ContributorDescriptor
	templates    []delivery.Template
	publicAudit  bool
}

type preparedSendProfile struct {
	preparer        *otp.SendPreparer
	delivery        *deliverypg.Contributor
	policy          otp.AttemptPolicy
	template        string
	templateVersion uint32
	provider        uint64
	contributors    []kernel.ContributorDescriptor
	configuration   [32]byte
	renderer        *delivery.TemplateRenderer
	locales         []string
	publicAudit     bool
}

// A new immutable contributor preserves the existing check/consume owner. It
// never holds request state; restart composition derives the same configuration.
func newPreparedSendContributor(store *Contributor, d *deliverypg.Contributor, c preparedSendConfig) (*Contributor, error) {
	if store == nil || store.codec == nil || d == nil || c.provider == 0 || len(c.contributors) < 2 || len(c.contributors) > 16 {
		return nil, ErrInvalidConfiguration
	}
	// Own validated source and compilation together; an opaque renderer/probe
	// cannot attest template identity. Bound the aggregate before copying/hash.
	if len(c.templates) < 1 || len(c.templates) > 16 {
		return nil, ErrInvalidConfiguration
	}
	size := 0
	for _, t := range c.templates {
		if len(t.Subject) > 998 || len(t.Body) > 262144 || len(t.AllowedOrigins) > 32 || len(t.VariableSchema) > 64 || len(t.RequiredVariables) > 64 {
			return nil, ErrInvalidConfiguration
		}
		size += len(t.Subject) + len(t.Body)
		if size > 1<<20 {
			return nil, ErrInvalidConfiguration
		}
	}
	renderer, err := delivery.NewTemplateRenderer(c.templates)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	c.preparation.Renderer = renderer
	// Generation and persistence must use the same owned digest-key selection.
	c.preparation.Verifier = store.codec.verifier
	preparer, err := otp.NewSendPreparer(c.preparation)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	frame := appendAuthorityText([]byte("identity-otp-send-configuration-v1\x00"), c.preparation.TemplateID)
	// This explicit invocation-memory DTO hashes configuration, never exports
	// templates. Do not invoke Template's forbidden diagnostic serialization.
	type templateSource delivery.Template
	sources := make([]templateSource, len(c.templates))
	for i, t := range c.templates {
		sources[i] = templateSource(t)
	}
	source, err := json.Marshal(sources)
	if err != nil {
		return nil, ErrInvalidConfiguration
	}
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(source)))
	frame = append(frame, source...)
	clear(source)
	frame = binary.BigEndian.AppendUint32(frame, c.preparation.TemplateVersion)
	frame = binary.BigEndian.AppendUint64(frame, c.provider)
	frame = append(frame, byte(len(c.preparation.LocaleChain)))
	for _, locale := range c.preparation.LocaleChain {
		frame = appendAuthorityText(frame, locale)
	}
	for i, descriptor := range c.contributors {
		if !sendConfigurationText(descriptor.Owner) || !sendConfigurationText(descriptor.ContractID) || descriptor.Version == 0 {
			return nil, ErrInvalidConfiguration
		}
		for _, previous := range c.contributors[:i] {
			if previous.Owner == descriptor.Owner {
				return nil, ErrInvalidConfiguration
			}
		}
		frame = appendAuthorityText(frame, descriptor.Owner)
		frame = appendAuthorityText(frame, descriptor.ContractID)
		frame = binary.BigEndian.AppendUint32(frame, descriptor.Version)
	}
	// This opt-in profile cannot be confused with retained private/legacy
	// configuration whose security event action and retention remain unchanged.
	if c.publicAudit {
		frame = append(frame, []byte("public-send-audit-v1\x00")...)
	}
	copyOfStore := *store
	copyOfStore.send = &preparedSendProfile{preparer: preparer, delivery: d, policy: c.preparation.Policy, template: c.preparation.TemplateID, templateVersion: c.preparation.TemplateVersion, provider: c.provider, contributors: append([]kernel.ContributorDescriptor(nil), c.contributors...), configuration: sha256.Sum256(frame), renderer: renderer, locales: append([]string(nil), c.preparation.LocaleChain...), publicAudit: c.publicAudit}
	return &copyOfStore, nil
}

func sendConfigurationText(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func (p *Contributor) mapPreparedSendRequest(ctx context.Context, r sendRequestRecord, b identity.CommandBinding, bearer auth.BearerCredential) (identity.Command, error) {
	if p == nil || p.send == nil || !sameSendPolicy(r.policy, p.send.policy) {
		return identity.Command{}, ErrInvalidCommand
	}
	command, err := p.mapSendRequest(ctx, r, b, bearer)
	if err != nil {
		return identity.Command{}, err
	}
	spec, _ := command.Feature()
	configuration, err := p.sendConfiguration(ctx, r)
	if err != nil {
		return identity.Command{}, err
	}
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "otp.send-configuration", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: configuration[:]}})
	return sendCommandWithBearer(spec, command)
}

func sendCommandWithBearer(spec identity.FeatureCommandSpec, original identity.Command) (identity.Command, error) {
	// Send intent must remain code-free; reconstruction must not erase an
	// unsupported credential variant before authenticating the request.
	if _, ok := original.OneTimeCode(); ok {
		return identity.Command{}, ErrInvalidCommand
	}
	if bearer, ok := original.SessionToken(); ok {
		return identity.NewFeatureSessionCommand(spec, bearer)
	}
	if bearer, ok := original.PreAuthCookie(); ok {
		return identity.NewFeaturePreAuthCommand(spec, bearer)
	}
	return identity.Command{}, ErrInvalidCommand
}

func sameSendPolicy(a, b otp.AttemptPolicy) bool {
	x, c, err := a.Bindings()
	y, d, other := b.Bindings()
	return err == nil && other == nil && x == y && c == d
}

func (p *Contributor) originalPreparedSend(ctx context.Context, command identity.Command) (sendRequestRecord, nativeFlow, error) {
	bad := func(err error) (sendRequestRecord, nativeFlow, error) { return sendRequestRecord{}, nativeFlow{}, err }
	if p == nil || p.send == nil {
		return bad(ErrInvalidCommand)
	}
	spec, ok := command.Feature()
	if !ok || len(spec.Fields) != 2 || spec.Fields[0].Name != "otp.send-configuration" || spec.Fields[0].Value.Kind != identity.FeatureBytes || len(spec.Fields[0].Value.Bytes) != 32 {
		return bad(ErrInvalidCommand)
	}
	configuration := spec.Fields[0].Value.Bytes
	spec.Fields = spec.Fields[1:]
	input, err := sendCommandWithBearer(spec, command)
	if err != nil {
		return bad(ErrInvalidCommand)
	}
	r, flow, err := p.authenticateSendRequest(ctx, input)
	if err != nil {
		return bad(err)
	}
	if !sameSendPolicy(r.policy, p.send.policy) {
		return bad(ErrInvalidCommand)
	}
	expected, err := p.sendConfiguration(ctx, r)
	if err != nil {
		return bad(err)
	}
	if !bytes.Equal(configuration, expected[:]) {
		return bad(ErrInvalidCommand)
	}
	return r, flow, nil
}

// Two distinct non-secret probes establish actual code substitution under the
// fixed renderer's literal/substitution-only grammar. They do not fingerprint
// templates: the configuration already binds complete validated source.
func (p *Contributor) sendConfiguration(ctx context.Context, r sendRequestRecord) ([32]byte, error) {
	profile, _, err := r.policy.Bindings()
	b, other := r.continuation.Bindings()
	if err != nil || other != nil || ctx == nil {
		return [32]byte{}, ErrInvalidCommand
	}
	channel := delivery.ChannelEmail
	if b.Scope.Channel == otp.ChannelSMS {
		channel = delivery.ChannelSMS
	}
	message, err := p.send.renderer.Render(ctx, delivery.Message{Purpose: "otp-" + string(profile.Purpose), Channel: channel, Recipient: delivery.Recipient{Channel: channel, Address: b.Scope.Destination.Value(), ScopeDigest: strings.Repeat("1", 64)}, TemplateID: p.send.template, TemplateVersion: uint64(p.send.templateVersion), LocaleChain: p.send.locales, Variables: []delivery.TemplateVariable{{Name: "code", Kind: "code", Sensitive: true, CodeValue: strings.Repeat(profile.Alphabet[:1], profile.Length)}}})
	if err != nil {
		if ctx.Err() != nil {
			return [32]byte{}, ctx.Err()
		}
		return [32]byte{}, ErrInvalidCommand
	}
	alternate, err := p.send.renderer.Render(ctx, delivery.Message{Purpose: "otp-" + string(profile.Purpose), Channel: channel, Recipient: delivery.Recipient{Channel: channel, Address: b.Scope.Destination.Value(), ScopeDigest: strings.Repeat("1", 64)}, TemplateID: p.send.template, TemplateVersion: uint64(p.send.templateVersion), LocaleChain: p.send.locales, Variables: []delivery.TemplateVariable{{Name: "code", Kind: "code", Sensitive: true, CodeValue: strings.Repeat(profile.Alphabet[1:2], profile.Length)}}})
	if err != nil {
		if ctx.Err() != nil {
			return [32]byte{}, ctx.Err()
		}
		return [32]byte{}, ErrInvalidCommand
	}
	if message.Body == alternate.Body && message.Subject == alternate.Subject {
		return [32]byte{}, ErrInvalidCommand
	}
	return p.send.configuration, nil
}

// The probe exists only to derive the existing safe audit scope digest. It is
// never persisted and uses no entropy/clock callback from application code.
func (p *Contributor) preparedSendPlan(command identity.Command, effect *kernel.DeliveryPlan) (kernel.CommandPlan, error) {
	return p.sendPlan(command, effect, false)
}

func (p *Contributor) sendPlan(command identity.Command, effect *kernel.DeliveryPlan, suppressed bool) (kernel.CommandPlan, error) {
	if p == nil || p.send == nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	spec, ok := command.Feature()
	expectedOperation := issuanceOperation(spec.Operation.SubjectRequirement)
	subjectType, eventType, target, afterVersion := "otp_challenge", "otp.sent.v1", spec.Binding.RecordID, uint64(1)
	if suppressed {
		expectedOperation = suppressedSendOperation(spec.Operation.SubjectRequirement)
		subjectType, eventType, afterVersion = "otp_request", "otp.send.accepted.v1", 0
		target = string(spec.Binding.UserID)
		if target == "" {
			target = spec.Binding.AnonymousFlowID
		}
	}
	if !ok || spec.Operation != expectedOperation || suppressed && effect != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	b := spec.Binding
	action, retention := "otp.send", "protected"
	if p.send.publicAudit {
		action, retention = "identity.otp.request", "standard"
		subjectType = "authentication_attempt"
		if suppressed && b.UserID != "" {
			subjectType = "user"
		}
	}
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	builder, err := audit.NewBuilder(audit.BuilderConfig{Clock: func() time.Time { return when }, IDGenerator: func() (string, error) { return "otp-binding-probe", nil }})
	if err != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	kind := audit.ActorService
	if b.ActorKind == authorization.SubjectUser {
		kind = audit.ActorHuman
	}
	record, err := builder.Build(audit.RecordInput{OccurredAt: when, Action: action, Outcome: audit.OutcomeSucceeded, ReasonCode: "completed", Actor: audit.ActorInput{Kind: kind, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: subjectType, ID: target}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{NoChange: true}, Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "aggregate.type": subjectType, "aggregate.id": target, "aggregate.before_version": "0", "aggregate.after_version": strconv.FormatUint(afterVersion, 10), "retention.class": retention}})
	if err != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, subjectType, record)
	if err != nil {
		return kernel.CommandPlan{}, ErrInvalidCommand
	}
	contributors := make([]kernel.ContributorDescriptor, 0, len(p.send.contributors))
	for _, d := range p.send.contributors {
		if effect != nil || d != p.send.delivery.Descriptor() {
			contributors = append(contributors, d)
		}
	}
	return kernel.CommandPlan{Contributors: contributors, SubjectType: subjectType, Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: spec.Operation}, Lifecycle: &kernel.LifecyclePlan{EventType: eventType, AfterVersion: afterVersion}, Audits: []kernel.AuditPlan{{EventType: action, SchemaVersion: 1, BindingDigest: digest, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: retention}}, Delivery: effect}, nil
}

// ValidateFeaturePreparation performs bounded original-input and exact plan
// validation only. No current authority, entropy, network or SQL is implied.
func (p *Contributor) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if _, _, err := p.originalPreparedSend(ctx, command); err != nil {
		return err
	}
	expected, err := p.preparedSendPlan(command, nil)
	plan.Digest = [32]byte{}
	if err != nil || !reflect.DeepEqual(plan, expected) {
		return ErrInvalidCommand
	}
	return nil
}

// AdmitFeaturePreparation borrows only the registered owner's read-only phase.
// Rechecks original primary authority/flow and DB expiry after lock waits;
// generation and all domain effects remain outside this admission transaction.
func (p *Contributor) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	return p.admitFeaturePreparation(ctx, w, command, p)
}

// The opt-in authentication owner remains the exact registered participant;
// descriptor equality must never substitute for invocation ownership.
func (p *Contributor) admitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command, owner kernel.FeatureExecutionContributor) error {
	r, flow, err := p.originalPreparedSend(ctx, command)
	if err != nil {
		return err
	}
	b, registration, _, err := w.FeatureScope(owner)
	spec, _ := command.Feature()
	if err != nil || b != spec.Binding || registration.Operation != spec.Operation {
		return ErrInvalidCommand
	}
	return p.admitSendPrimary(ctx, w, r, flow, b, owner)
}

func (p *Contributor) admitSendPrimary(ctx context.Context, w kernel.Work, r sendRequestRecord, flow nativeFlow, b identity.CommandBinding, owner kernel.FeatureExecutionContributor) error {
	a := r.authority
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, a.Directory); err != nil {
		return err
	}
	if b.UserID != "" {
		expected := kernel.UserAuthorityAdmission{UserAuthorityVersion: a.UserAuthorityVersion, IdentifierAuthorityVersion: a.IdentifierAuthorityVersion, CredentialAuthorityVersion: a.CredentialAuthorityVersion}
		if err := w.RequireActiveUserAuthority(ctx, owner, expected); err != nil {
			return err
		}
		if a.Credential != (identity.CredentialRef{}) {
			if _, err := w.RequireActiveCredential(ctx, owner, issuanceCredential(a)); err != nil {
				return err
			}
		}
		if err := w.RequireActiveUserAuthorization(ctx, owner, a.UserAuthorization); err != nil {
			return err
		}
	}
	if err := requireNativeFlow(ctx, w, p, flow, nil); err != nil {
		return err
	}
	if r.recipient != nil {
		if err := w.RequireRecipient(ctx, owner, *r.recipient); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if a.Credential != (identity.CredentialRef{}) {
		now, err = w.RequireActiveCredential(ctx, owner, issuanceCredential(a))
		if err != nil {
			return err
		}
	}
	if now.Before(r.issuedAt) || !now.Before(r.expiresAt) || p.flowTime(flow, now) != nil {
		return ErrInvalidCommand
	}
	return nil
}

func preparedSendAAD(command identity.Command, generation uint64) (envelope.Context, error) {
	spec, ok := command.Feature()
	if !ok || generation == 0 || len(spec.Fields) != 2 || spec.Fields[0].Name != "otp.send-configuration" || spec.Fields[0].Value.Kind != identity.FeatureBytes || len(spec.Fields[0].Value.Bytes) != 32 || spec.Fields[1].Name != "otp.send-request" || spec.Fields[1].Value.Kind != identity.FeatureBytes || len(spec.Fields[1].Value.Bytes) < 1 || len(spec.Fields[1].Value.Bytes) > 8192 {
		return envelope.Context{}, ErrInvalidCommand
	}
	base, err := sendOutputAAD(spec, generation)
	if err != nil {
		return envelope.Context{}, err
	}
	frame := appendAuthorityText([]byte("identity-otp-prepared-send-output-v1\x00"), string(base.AdditionalData()))
	for _, field := range spec.Fields {
		frame = binary.BigEndian.AppendUint32(frame, uint32(len(field.Value.Bytes)))
		frame = append(frame, field.Value.Bytes...)
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	return envelope.NewContext(map[string]string{"profile": "identity-otp-prepared-send-output-v1", "request": base64.RawURLEncoding.EncodeToString(digest[:]), "generation": strconv.FormatUint(generation, 10)})
}

// GenerateFeaturePreparation produces one code through the existing owned core
// preparer and seals the same-code digest/delivery. The coordinator alone calls
// this after durable generation-start acknowledgement; never use it on retry.
func (p *Contributor) GenerateFeaturePreparation(ctx context.Context, original identity.Command, generation uint64) ([]byte, error) {
	r, _, err := p.originalPreparedSend(ctx, original)
	if err != nil {
		return nil, err
	}
	aad, err := preparedSendAAD(original, generation)
	if err != nil {
		return nil, err
	}
	return p.generatePreparedSend(ctx, original, r, generation, aad)
}

// Both native callers use the same generator and output checkpoint. Their
// own admission and original AAD remain separate; no clearance is accepted.
func (p *Contributor) generatePreparedSend(ctx context.Context, original identity.Command, r sendRequestRecord, generation uint64, aad envelope.Context) ([]byte, error) {
	spec, _ := original.Feature()
	spec.Fields = nil
	bearer, _ := original.SessionToken()
	_, sessionBound := original.SessionToken()
	if !sessionBound {
		bearer, _ = original.PreAuthCookie()
	}
	var output []byte
	_, err := p.send.preparer.Prepare(ctx, r.continuation, r.issuedAt, r.expiresAt, func(ctx context.Context, challenge otp.Challenge, recipient delivery.Recipient, message delivery.RenderedMessage) error {
		var generated identity.Command
		var err error
		var selected []kernel.RecipientRecord
		if r.recipient != nil {
			selected = []kernel.RecipientRecord{*r.recipient}
		}
		generated, err = p.codec.mapIssuance(ctx, challenge, spec, bearer, r.authority, sessionBound, selected...)
		if err != nil {
			return err
		}
		b, _ := r.continuation.Bindings()
		target := string(spec.Binding.UserID)
		if target == "" {
			target = spec.Binding.AnonymousFlowID
		}
		prepared, err := p.send.delivery.Prepare(ctx, spec.Binding, []deliverypg.IntentInput{{Purpose: "otp-" + string(b.Scope.Purpose), SubjectID: target, TemplateID: p.send.template, TemplateVersion: p.send.templateVersion, ProviderConfigVersion: p.send.provider, ExpiresAt: r.expiresAt, Recipient: recipient, Rendered: message}})
		if err != nil {
			return err
		}
		phase, err := newIssuanceContributor(p, p.send.delivery, prepared)
		if err != nil {
			return err
		}
		output, err = phase.sealSendOutputContext(ctx, generated, generation, aad)
		return err
	})
	if err != nil {
		clear(output)
		return nil, err
	}
	return output, nil
}

func (p *Contributor) restorePreparedSend(ctx context.Context, original identity.Command, generation uint64, wire []byte) (*issuanceContributor, identity.Command, error) {
	r, _, err := p.originalPreparedSend(ctx, original)
	if err != nil {
		return nil, identity.Command{}, err
	}
	aad, err := preparedSendAAD(original, generation)
	if err != nil {
		return nil, identity.Command{}, err
	}
	spec, _ := original.Feature()
	bearer, _ := original.SessionToken()
	if _, ok := original.SessionToken(); !ok {
		bearer, _ = original.PreAuthCookie()
	}
	phase, generated, err := restoreSendOutputContext(ctx, p, p.send.delivery, spec.Binding, generation, bearer, wire, aad)
	if err != nil {
		return nil, identity.Command{}, err
	}
	custody, _, err := p.authenticateIssuance(ctx, generated)
	if err != nil {
		return nil, identity.Command{}, err
	}
	s, _ := custody.challenge.Bindings()
	restored := sendRequestRecord{continuation: s.Continuation, policy: s.Policy, authority: custody.authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt, recipient: custody.recipient}
	expected, e := encodeSendRequestRecord(r, spec.Binding)
	actual, a := encodeSendRequestRecord(restored, spec.Binding)
	defer clear(expected)
	defer clear(actual)
	if e != nil || a != nil || !bytes.Equal(expected, actual) {
		return nil, identity.Command{}, ErrInvalidCommand
	}
	return phase, generated, nil
}

// RestoreFeaturePreparation conserves authenticated original bytes and expiry;
// it separately checks bearer possession and does not generate or encrypt.
func (p *Contributor) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	phase, generated, err := p.restorePreparedSend(ctx, original, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	dp, err := phase.prepared.Plan()
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.preparedSendPlan(generated, &dp)
	return generated, plan, err
}

func (p *Contributor) originalFromGenerated(ctx context.Context, command identity.Command) (identity.Command, error) {
	custody, _, err := p.authenticateIssuance(ctx, command)
	if err != nil {
		return identity.Command{}, err
	}
	s, _ := custody.challenge.Bindings()
	spec, _ := command.Feature()
	bearer, _ := command.SessionToken()
	if _, ok := command.SessionToken(); !ok {
		bearer, _ = command.PreAuthCookie()
	}
	return p.mapPreparedSendRequest(ctx, sendRequestRecord{continuation: s.Continuation, policy: s.Policy, authority: custody.authority, issuedAt: s.IssuedAt, expiresAt: s.ExpiresAt, recipient: custody.recipient}, spec.Binding, bearer)
}

func (p *Contributor) validatePreparedSendExecution(command identity.Command, plan kernel.CommandPlan) error {
	ctx, stop := context.WithTimeout(context.Background(), p.codec.maximumDuration)
	defer stop()
	if _, err := p.originalFromGenerated(ctx, command); err != nil {
		return err
	}
	expected, err := p.preparedSendPlan(command, plan.Delivery)
	plan.Digest = [32]byte{}
	if err != nil || plan.Delivery == nil || !reflect.DeepEqual(plan, expected) || len(plan.Delivery.Intents) != 1 || plan.Delivery.Contributor != p.send.delivery.Descriptor() {
		return ErrInvalidCommand
	}
	spec, _ := command.Feature()
	custody, _, err := p.authenticateIssuance(ctx, command)
	if err != nil {
		return err
	}
	s, _ := custody.challenge.Bindings()
	b, _ := s.Continuation.Bindings()
	target := string(spec.Binding.UserID)
	if target == "" {
		target = spec.Binding.AnonymousFlowID
	}
	effect := plan.Delivery.Intents[0]
	if effect.Purpose != "otp-"+string(b.Scope.Purpose) || effect.SubjectID != target || effect.TemplateID != p.send.template || effect.TemplateVersion != p.send.templateVersion || effect.ProviderConfigVersion != p.send.provider || !effect.ExpiresAt.Equal(s.ExpiresAt) {
		return ErrInvalidCommand
	}
	return p.send.delivery.ValidateDeliveryPlan(spec.Binding, *plan.Delivery)
}

func (p *Contributor) applyPreparedSend(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	original, err := p.originalFromGenerated(ctx, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	defer clear(wire)
	phase, restored, err := p.restorePreparedSend(ctx, original, generation, wire)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	x, _ := command.Feature()
	y, _ := restored.Feature()
	if !reflect.DeepEqual(x, y) {
		return identity.FeatureReceipt{}, ErrInvalidCommand
	}
	return phase.applyIssuance(ctx, w, restored, p)
}

var _ kernel.FeaturePreparationContributor = (*Contributor)(nil)
