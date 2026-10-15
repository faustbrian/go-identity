package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password/v2"
	envelope "github.com/faustbrian/go-secret-envelope"
)

type totpURIPhase struct {
	otpConfirmation    *otpEnrollmentConfirmationState
	otpConfirmRequest  mfa.OtpVerifyRequest
	nativeConfirmation OTPEnrollmentConfirmation
	generatedOTP       identity.Command
	otpPlan            *kernel.OTPAttemptPlan
	send               *otpEnrollmentSendState
	sendRequest        mfa.OtpSendRequest
	sendInput          *otpEnrollmentSendInput
	preparedSend       OTPEnrollmentPreparedSend
	confirmation       *totpConfirmationState
	confirmRequest     mfa.TotpVerifyRequest
	secret             primitive.Secret
	state              *totpURIState
	request            mfa.TotpUriRequest
	pending            *totpURIPending
	primary            TOTPURIPrimary
	coordinator        *kernel.Coordinator
	registry           *kernel.ContributorRegistry
	command            identity.Command
	plan               kernel.CommandPlan
	counters           kernel.CommandCounterPlan
	output             *totpURIOutput
	risk               risk.ProtectedProviderAdmission
	applied            bool
	activated          bool
	// Invocation-local CAS observed under the predecessor lock. Ordinary TOTP
	// replay advancement must not rewrite the immutable initiation receipt.
	predecessorRowVersion uint64
}
type totpURIOutput struct {
	Schema     uint32
	Generation uint64
	URI        string
	Risk       enrollmentStoredRisk
	OTP        []byte `json:",omitempty"`
}

func (*totpURIPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *totpURIPhase) operation() identity.FeatureOperation {
	if p.otpConfirmation != nil {
		return otpConfirmationOperation()
	}
	if p.send != nil {
		return otpSendOperation()
	}
	if p.confirmation != nil {
		return confirmationOperation()
	}
	return uriOperation()
}
func (p *totpURIPhase) lifecycle() kernel.LifecyclePlan {
	event := "factor.uri-revealed.v1"
	if p.send != nil {
		event = "otp.sent.v1"
	}
	if p.confirmation != nil || p.otpConfirmation != nil {
		event = "factor.enrolled.v1"
	}
	return kernel.LifecyclePlan{EventType: event, BeforeVersion: p.pending.RowVersion, AfterVersion: p.pending.RowVersion + 1}
}
func (p *totpURIPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{p.operation()}
}

func (p *totpURIPhase) buildCommand() error {
	if p.pending == nil || p.primary == nil {
		return invalidEnrollment()
	}
	r := p.request
	m := p.pending.metadata()
	b := p.pending.binding()
	b.CommandID = r.CommandID
	b.OperationID = p.operation().OperationID
	b.SchemaID = p.operation().SchemaID
	b.SchemaVersion = 1
	b.RecordID = m.FactorID
	b.CorrelationID = string(r.CommandID)
	field := func(name string, v identity.FeatureValue) identity.FeatureField {
		return identity.FeatureField{Name: name, Value: v}
	}
	digest := sha256.Sum256(p.pending.Wire)
	label := sha256.Sum256([]byte(p.pending.Label))
	fields := []identity.FeatureField{
		field("factor.parent", identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.pending.binding().CommandID)}),
		field("factor.before", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.pending.RowVersion}),
		field("factor.envelope", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}),
		field("factor.uri.configuration", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.state.identity[:]}),
		field("factor.uri.origin", identity.FeatureValue{Kind: identity.FeatureText, Text: r.Origin}),
		field("factor.uri.network", identity.FeatureValue{Kind: identity.FeatureText, Text: r.Network}),
		field("factor.uri.identifier", identity.FeatureValue{Kind: identity.FeatureText, Text: p.pending.LabelID}),
		field("factor.uri.identifier-version", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.pending.LabelVersion}),
		field("factor.uri.identifier-primary", identity.FeatureValue{Kind: identity.FeatureBool, Bool: p.pending.LabelPrimary}),
		field("factor.uri.label", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: label[:]}),
	}
	if p.send != nil || p.otpConfirmation != nil {
		if p.sendInput == nil || p.pending.Input.OTP == nil {
			return invalidEnrollment()
		}
		// Audit/counter time belongs to this original send, not its older parent.
		m.CreatedAt = p.sendInput.IssuedAt
		om := p.pending.Input.OTP
		fields = []identity.FeatureField{
			field("factor.parent-command", identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.pending.binding().CommandID)}),
			field("factor.before", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.pending.RowVersion}),
			field("factor.authority", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.pending.AuthorityVersion}),
			field("factor.otp.input", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}),
			field("factor.otp.configuration", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.state.identity[:]}),
			field("factor.otp.origin", identity.FeatureValue{Kind: identity.FeatureText, Text: r.Origin}),
			field("factor.otp.network", identity.FeatureValue{Kind: identity.FeatureText, Text: r.Network}),
			field("factor.otp.channel", identity.FeatureValue{Kind: identity.FeatureText, Text: otpChannelText(om.Channel)}),
			field("factor.otp.identifier", identity.FeatureValue{Kind: identity.FeatureText, Text: string(om.IdentifierID)}),
			field("factor.otp.identifier-version", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: om.IdentifierVersion}),
			field("factor.otp.verification-version", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: om.VerificationVersion}),
			field("factor.otp.issued-at", identity.FeatureValue{Kind: identity.FeatureText, Text: m.CreatedAt.Format(time.RFC3339Nano)}),
		}
		if p.otpConfirmation != nil {
			key := p.state.enrollment.config.intentKey()
			digest, err := p.otpConfirmRequest.Code.CommandDigest(key, "mfa-otp-enrollment-confirm-v1\x00"+string(r.CommandID))
			clear(key[:])
			if err != nil {
				return err
			}
			fields = append(fields, field("factor.confirm.code", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}), field("factor.confirm.send", identity.FeatureValue{Kind: identity.FeatureText, Text: string(p.sendInput.Binding.CommandID)}))
		}
	}
	if p.confirmation != nil {
		scope, err := enrollmentConfirmationScope(m, r.CommandID, p.confirmation.keyVersion)
		if err != nil {
			return err
		}
		key := p.confirmation.key()
		defer clear(key[:])
		codeDigest, err := p.confirmRequest.Code.CommandDigest(key, string(scope))
		if err != nil {
			return err
		}
		fields = append(fields, field("factor.confirm.code", identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: codeDigest[:]}), field("factor.confirm.authority", identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.pending.AuthorityVersion}))
	}
	c, err := p.primary.Command(b, fields)
	if err != nil {
		return err
	}
	original, err := p.primary.Original()
	if err != nil {
		return err
	}
	session, err := original.Bindings()
	if err != nil {
		return err
	}
	c, counters, err := p.state.enrollment.counters.PrepareCommandCounters(c, risk.Subject{User: string(b.UserID), Session: session.SessionID, Network: r.Network}, m.CreatedAt)
	if err != nil {
		return err
	}
	p.command, p.counters = c, counters
	if p.send != nil && p.sendInput.Root != nil {
		root, ok := c.Feature()
		if !ok || !reflect.DeepEqual(root, *p.sendInput.Root) {
			return invalidEnrollment()
		}
	}
	builder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	before := strconv.FormatUint(p.pending.RowVersion, 10)
	after := strconv.FormatUint(p.pending.RowVersion+1, 10)
	seed, err := builder.Build(audit.RecordInput{OccurredAt: m.CreatedAt, Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "factor", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "factor", "aggregate.id": b.RecordID, "aggregate.before_version": before, "aggregate.after_version": after, "retention.class": "protected"}})
	if err != nil {
		return err
	}
	auditDigest, err := kernel.FeatureAuditBindingDigest(b, p.operation(), "factor", seed)
	if err != nil {
		return err
	}
	life := p.lifecycle()
	declaration := kernel.CommandPlan{Contributors: p.registry.Descriptors(), SubjectType: "factor", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: p.operation()}, CommandCounters: &counters, Lifecycle: &life, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: auditDigest}}}
	if p.send != nil {
		deliveryOwner := p.send.issuance.DeliveryContributor().Descriptor()
		declaration.Contributors = slices.DeleteFunc(declaration.Contributors, func(d kernel.ContributorDescriptor) bool { return d == deliveryOwner })
	}
	if p.otpConfirmation != nil {
		owner := p.otpConfirmation.owner.ConfirmationContributor().Descriptor()
		declaration.Contributors = slices.DeleteFunc(declaration.Contributors, func(d kernel.ContributorDescriptor) bool { return d == owner })
	}
	p.plan, err = p.coordinator.PrepareFeaturePreparationPlan(c, declaration)
	return err
}

func (p *totpURIPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.pending == nil || c != p.command && c != p.generatedOTP || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Feature.Operation != p.operation() || plan.SubjectType != "factor" || plan.Lifecycle == nil || *plan.Lifecycle != p.lifecycle() || plan.CommandCounters == nil || *plan.CommandCounters != p.counters || plan.Capability != nil || plan.RiskEvidence != nil || plan.MFACompletion != nil || plan.MFAContinuation != nil || plan.CapabilityIssuance != nil || len(plan.Audits) != 1 {
		return invalidEnrollment()
	}
	if plan.OTP != nil && (p.otpConfirmation == nil || p.otpPlan == nil || *plan.OTP != *p.otpPlan || c != p.generatedOTP) || plan.OTP == nil && c != p.command {
		return invalidEnrollment()
	}
	if plan.Delivery != nil {
		if p.send == nil || p.preparedSend == nil {
			return invalidEnrollment()
		}
		expected, err := p.preparedSend.Plan()
		if err != nil || !reflect.DeepEqual(*plan.Delivery, expected) {
			return invalidEnrollment()
		}
	}
	a := plan.Audits[0]
	if !a.Required || a.EventType != p.operation().OperationID || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" {
		return invalidEnrollment()
	}
	return nil
}
func (p *totpURIPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if plan.Delivery != nil || plan.OTP != nil || c != p.command {
		return invalidEnrollment()
	}
	return p.ValidateFeatureCommand(c, plan)
}

func (p *totpURIPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.pending == nil || c != p.command && c != p.generatedOTP {
		return invalidEnrollment()
	}
	if err := p.primary.Admit(ctx, w, p, c); err != nil {
		return err
	}
	if p.send != nil {
		return p.admitOTPSend(ctx, w)
	}
	if p.otpConfirmation != nil {
		return p.admitOTPConfirmation(ctx, w, c)
	}
	if p.confirmation != nil {
		return p.admitConfirmation(ctx, w)
	}
	b := p.pending.binding()
	m := p.pending.metadata()
	rows, err := w.Query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, string(b.TenantID), string(b.UserID))
	if err != nil {
		return err
	}
	var version string
	var count int32
	if !rows.Next() || rows.Scan(&version, &count) != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	extra := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	got, err := strconv.ParseUint(version, 10, 64)
	expectedCount, expectedVersion := int32(0), m.AuthorityVersion+1
	if p.pending.Replacement != nil {
		expectedCount, expectedVersion = 1, m.AuthorityVersion
	}
	if err != nil || extra || rowErr != nil || count != expectedCount || got != expectedVersion {
		return identity.ForbiddenError{}
	}
	if err := p.checkReplacementPredecessor(ctx, w); err != nil {
		return err
	}
	rows, err = w.Query(ctx, `SELECT row_version::text,encrypted_secret,created_command_id,enrollment_expires_at FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND NOT reveal_consumed FOR UPDATE`, string(b.TenantID), string(b.UserID), m.FactorID)
	if err != nil {
		return err
	}
	var wire, parent []byte
	var expires time.Time
	if !rows.Next() || rows.Scan(&version, &wire, &parent, &expires) != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	extra = rows.Next()
	rowErr = rows.Err()
	rows.Close()
	defer clear(wire)
	got, err = strconv.ParseUint(version, 10, 64)
	if err != nil || extra || rowErr != nil || got != p.pending.RowVersion || sha256.Sum256(wire) != sha256.Sum256(p.pending.Wire) || base64.RawURLEncoding.EncodeToString(parent) != string(b.CommandID) || !expires.Equal(m.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, `SELECT canonical_value,version::text FROM identity.identifiers i WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND verified AND verification_state=2 AND is_primary=$4 AND kind='email' AND (is_primary OR NOT EXISTS(SELECT 1 FROM identity.identifiers p WHERE p.tenant_id=i.tenant_id AND p.user_id=i.user_id AND p.verified AND p.verification_state=2 AND p.is_primary AND p.kind='email')) FOR SHARE`, string(b.TenantID), string(b.UserID), p.pending.LabelID, p.pending.LabelPrimary)
	if err != nil {
		return err
	}
	var label string
	if !rows.Next() || rows.Scan(&label, &version) != nil {
		rows.Close()
		return identity.ForbiddenError{}
	}
	extra = rows.Next()
	rowErr = rows.Err()
	rows.Close()
	if extra || rowErr != nil || version != strconv.FormatUint(p.pending.LabelVersion, 10) || label != p.pending.Label {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(m.CreatedAt) || !now.Before(expires) {
		return identity.ForbiddenError{}
	}
	return p.primary.Check(ctx, w, p, c)
}

type totpURIAdmission struct {
	phase *totpURIPhase
	risk  risk.ProtectedProviderAdmission
}

func (a *totpURIAdmission) Check(ctx context.Context) error {
	if ctx == nil || a == nil || a.phase == nil || a.phase.pending == nil {
		return invalidEnrollment()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	until, err := a.phase.deadline()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if !now.Before(until) || !now.Before(a.phase.pending.metadata().ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return a.risk.CheckAt(ctx, now)
}
func (p *totpURIPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if p == nil || p.pending == nil || c != p.command {
		return nil, invalidEnrollment()
	}
	if err := p.refreshPrimary(ctx); err != nil {
		return nil, err
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(p.operation().OperationID), Attempt: string(p.request.CommandID)}
	assessment, err := p.state.enrollment.config.Risk.Evaluation.EvaluateProtectedProviders(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing})
	if err != nil {
		return nil, enrollmentReadError(ctx)
	}
	admission, err := p.state.enrollment.custody.Prepare(ctx, assessment, scope)
	if err != nil {
		return nil, err
	}
	a := &totpURIAdmission{phase: p, risk: admission}
	return a, a.Check(ctx)
}
func (*totpURIPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidEnrollment()
}

func (p *totpURIPhase) outputAAD(generation uint64) (envelope.Context, error) {
	if p == nil || p.pending == nil || generation == 0 {
		return envelope.Context{}, invalidEnrollment()
	}
	b, _ := p.command.Feature()
	wire, err := json.Marshal(struct {
		Input         totpEnrollmentInput
		Command       identity.CommandBinding
		Fields        []identity.FeatureField
		Row           uint64
		Label         string
		LabelVersion  uint64
		Configuration [32]byte
		Generation    uint64
	}{p.pending.Input, b.Binding, b.Fields, p.pending.RowVersion, p.pending.Label, p.pending.LabelVersion, p.state.identity, generation})
	if err != nil {
		return envelope.Context{}, invalidEnrollment()
	}
	if p.pending.Replacement != nil {
		clear(wire)
		wire, err = json.Marshal(struct {
			Replacement   factorUpdateInput
			Command       identity.CommandBinding
			Fields        []identity.FeatureField
			Row           uint64
			Label         string
			LabelVersion  uint64
			Configuration [32]byte
			Generation    uint64
		}{*p.pending.Replacement, b.Binding, b.Fields, p.pending.RowVersion, p.pending.Label, p.pending.LabelVersion, p.state.identity, generation})
		if err != nil {
			return envelope.Context{}, invalidEnrollment()
		}
	}
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "mfa-uri-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (a *totpURIAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	p := a.phase
	if p.otpConfirmation != nil {
		generated, _, err := p.nativeConfirmation.Prepare(ctx, p.state.enrollment.pool, p.command, p.otpConfirmRequest.Code, p.otpConfirmation.key)
		if err != nil {
			return nil, err
		}
		metadata, ok := generated.Feature()
		if !ok {
			return nil, invalidEnrollment()
		}
		wire, err := json.Marshal(metadata)
		if err != nil {
			return nil, invalidEnrollment()
		}
		defer clear(wire)
		return p.sealURIOutput(ctx, generation, totpURIOutput{Schema: 3, Generation: generation, Risk: enrollmentStoredRisk(a.risk.Prepared()), OTP: wire})
	}
	if p.send != nil {
		if p.sendInput == nil {
			return nil, invalidEnrollment()
		}
		output, err := p.send.issuance.GenerateEnrollmentSend(ctx, p.command, p.sendInput.NativeInput, generation)
		if err != nil {
			return nil, err
		}
		defer clear(output)
		return p.sealURIOutput(ctx, generation, totpURIOutput{Schema: 2, Generation: generation, Risk: enrollmentStoredRisk(a.risk.Prepared()), OTP: output})
	}
	m := p.pending.metadata()
	binding, err := totpEncryptionContext(m.TenantID, m.UserID, m.FactorID, 1, m.Profile)
	if err != nil {
		return nil, err
	}
	sealed, err := envelope.ParseEnvelope(p.pending.Wire)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	raw, err := p.state.enrollment.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: binding})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer clear(raw)
	if len(raw) != 32 {
		return nil, identity.UnavailableError{}
	}
	secret, err := primitive.NewSecret(raw)
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	defer secret.Destroy()
	var uri mfa.RevealOnceURI
	if p.confirmation == nil {
		uri, err = mfa.NewTOTPProvisioningURI(ctx, secret, m.Profile, p.pending.Label, p.request.EnrollmentID)
		if err != nil {
			return nil, err
		}
	}
	output := totpURIOutput{Schema: 1, Generation: generation, URI: uri.URI, Risk: enrollmentStoredRisk(a.risk.Prepared())}
	return p.sealURIOutput(ctx, generation, output)
}

func (p *totpURIPhase) sealURIOutput(ctx context.Context, generation uint64, output totpURIOutput) ([]byte, error) {
	plain, err := json.Marshal(output)
	if err != nil {
		return nil, invalidEnrollment()
	}
	defer clear(plain)
	aad, err := p.outputAAD(generation)
	if err != nil {
		return nil, err
	}
	codec := &totpEnrollmentPhase{state: p.state.enrollment}
	return codec.seal(ctx, aad, plain)
}
func (p *totpURIPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	bad := func(err error) (identity.Command, kernel.CommandPlan, error) {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if p == nil || c != p.command {
		return bad(invalidEnrollment())
	}
	aad, err := p.outputAAD(generation)
	if err != nil {
		return bad(err)
	}
	codec := &totpEnrollmentPhase{state: p.state.enrollment}
	plain, err := codec.open(ctx, aad, wire)
	if err != nil {
		return bad(err)
	}
	defer clear(plain)
	var output totpURIOutput
	if decodeEnrollmentJSON(plain, &output) != nil || output.Generation != generation {
		return bad(invalidEnrollment())
	}
	if p.send != nil || p.otpConfirmation != nil {
		schema := uint32(2)
		if p.otpConfirmation != nil {
			schema = 3
		}
		if output.Schema != schema || output.URI != "" || len(output.OTP) == 0 || p.sendInput == nil {
			return bad(invalidEnrollment())
		}
	} else if output.Schema != 1 || len(output.OTP) != 0 || p.confirmation == nil && (len(output.URI) == 0 || len(output.URI) > 4096) || p.confirmation != nil && output.URI != "" {
		return bad(invalidEnrollment())
	}
	scope := risk.Context{Tenant: string(p.request.TenantID), Operation: risk.Action(p.operation().OperationID), Attempt: string(p.request.CommandID)}
	admission, err := p.state.enrollment.custody.Restore(ctx, risk.PreparedProtectedProviderAdmission(output.Risk), scope)
	if err != nil {
		return bad(err)
	}
	p.output, p.risk = &output, admission
	if p.otpConfirmation != nil {
		var metadata identity.FeatureCommandSpec
		if decodeEnrollmentJSON(output.OTP, &metadata) != nil {
			return bad(invalidEnrollment())
		}
		generated, attempt, err := p.nativeConfirmation.RestorePrepared(ctx, c, p.otpConfirmRequest.Code, metadata)
		if err != nil {
			return bad(err)
		}
		p.generatedOTP, p.otpPlan = generated, &attempt
		plan := p.plan
		plan.Digest = [32]byte{}
		plan.Contributors = append(slices.Clone(plan.Contributors), p.nativeConfirmation.Contributor().Descriptor())
		plan.OTP = &attempt
		return generated, plan, nil
	}
	if p.send != nil {
		p.preparedSend, err = p.send.issuance.RestoreEnrollmentSend(ctx, c, p.sendInput.NativeInput, generation, output.OTP)
		if err != nil {
			return bad(err)
		}
		delivery, err := p.preparedSend.Plan()
		if err != nil {
			return bad(err)
		}
		plan := p.plan
		plan.Digest = [32]byte{}
		plan.Contributors = append(slices.Clone(plan.Contributors), delivery.Contributor)
		plan.Delivery = &delivery
		return p.command, plan, nil
	}
	if p.confirmation != nil {
		if err := p.restoreConfirmationSecret(ctx); err != nil {
			return bad(err)
		}
	}
	return p.command, p.plan, nil
}
func (p *totpURIPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if err := p.refreshPrimary(ctx); err != nil {
		return nil, err
	}
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &totpURIAdmission{phase: p, risk: p.risk}
	return a, a.Check(ctx)
}

func (p *totpURIPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if p == nil || p.output == nil || c != p.command && c != p.generatedOTP {
		return identity.FeatureReceipt{}, invalidEnrollment()
	}
	if p.otpConfirmation != nil {
		return p.applyOTPConfirmation(ctx, w, c)
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.AdmitFeaturePreparation(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.send != nil {
		return p.applyOTPSend(ctx, w, c)
	}
	if p.confirmation != nil {
		return p.applyConfirmation(ctx, w, c)
	}
	command, _ := base64.RawURLEncoding.Strict().DecodeString(string(p.request.CommandID))
	n, err := w.Exec(ctx, `UPDATE identity_mfa.totp_factors SET reveal_consumed=true,reveal_command_id=$4,reveal_before_version=row_version,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND NOT reveal_consumed AND row_version=$5::numeric`, string(p.request.TenantID), string(p.pending.binding().UserID), string(p.request.EnrollmentID), command, strconv.FormatUint(p.pending.RowVersion, 10))
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if n != 1 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := p.CheckFeatureCommit(ctx, w, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: uriOperation(), BeforeVersion: p.pending.RowVersion, AfterVersion: p.pending.RowVersion + 1}, nil
}
func (p *totpURIPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if p == nil || p.output == nil || c != p.command && c != p.generatedOTP {
		return invalidEnrollment()
	}
	if p.activated && p.pending.Replacement != nil {
		if err := p.state.config.Replacement.Sessions.Check(ctx, w, p, c); err != nil {
			return err
		}
		if err := p.checkActivatedReplacement(ctx, w); err != nil {
			return err
		}
	} else {
		if err := p.primary.Check(ctx, w, p, c); err != nil {
			return err
		}
		if err := p.checkReplacementPredecessor(ctx, w); err != nil {
			return err
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	until, err := p.deadline()
	if err != nil {
		return err
	}
	if !now.Before(until) || !now.Before(p.pending.metadata().ExpiresAt) {
		return identity.ForbiddenError{}
	}
	if p.send != nil {
		if err := p.checkOTPSendState(ctx, w, p.applied); err != nil {
			return err
		}
	}
	if p.otpConfirmation != nil {
		if err := p.checkOTPConfirmationState(ctx, w, p.applied); err != nil {
			return err
		}
	}
	return p.risk.CheckAt(ctx, now)
}
func (p *totpURIPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	if p.otpConfirmation != nil {
		return p.recoverOTPConfirmation(ctx, w)
	}
	if p.send != nil {
		return p.send.issuance.RecoverEnrollmentSend(ctx, w, p)
	}
	if p.confirmation != nil {
		return p.recoverConfirmation(ctx, w)
	}
	b, f, life, err := w.FeatureScope(p)
	if err != nil || f.Contributor != p.Descriptor() || f.Operation != uriOperation() || life.EventType != "factor.uri-revealed.v1" || life.BeforeVersion == 0 || life.AfterVersion != life.BeforeVersion+1 {
		return kernel.RecoveryUnknown, invalidEnrollment()
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	rows, err := w.Query(ctx, `SELECT user_id,factor_id,reveal_before_version::text FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND reveal_command_id=$2 AND reveal_consumed`, string(b.TenantID), id)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return kernel.RecoveryUnknown, rows.Err()
		}
		return kernel.RecoveryNotCommitted, nil
	}
	var user, factor, before string
	if rows.Scan(&user, &factor, &before) != nil || rows.Next() || rows.Err() != nil || user != string(b.UserID) || factor != b.RecordID || before != strconv.FormatUint(life.BeforeVersion, 10) {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	return kernel.RecoveryCommitted, nil
}
func (p *totpURIPhase) destroy() {
	p.secret.Destroy()
	if p.pending != nil {
		clear(p.pending.Input.Primary)
		if p.pending.Replacement != nil {
			clear(p.pending.Replacement.Primary)
			clear(p.pending.Replacement.Record.Original.Signature)
		}
		clear(p.pending.Wire)
		p.pending = nil
	}
	if p.output != nil {
		clear(p.output.OTP)
		p.output.URI = ""
		p.output = nil
	}
	if p.sendInput != nil {
		clear(p.sendInput.NativeInput)
		p.sendInput = nil
	}
	p.preparedSend = nil
}
