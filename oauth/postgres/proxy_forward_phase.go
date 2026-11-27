package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	kernel "github.com/faustbrian/go-identity/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

const proxyAuditEvent = "identity.oauth.use_proxy"
const proxySubjectType = "oauth_proxy_transaction"

func lockProxyForwardSQL(schema string) string {
	return `SELECT version::text FROM ` + rpQuotedSchema(schema) + `.proxy_transactions
WHERE tenant_id=$1 AND transaction_id=$2 AND callback_command_id=$3 AND version=$4::numeric AND binding_ciphertext=$5 FOR UPDATE`
}

func settleProxyForwardSQL(schema string) string {
	return `UPDATE ` + rpQuotedSchema(schema) + `.proxy_transactions
SET version=2,outcome=$4,handoff_ciphertext=$5,settled_at=$6,state_proof_ciphertext=NULL,pkce_ciphertext=NULL
WHERE tenant_id=$1 AND transaction_id=$2 AND callback_command_id=$3 AND version=1`
}

// One phase exists per native invocation. Original browser custody stays in
// its own row; no method uses the production user/account/session repositories.
type proxyForwardPhase struct {
	schema, authority, envelopeKey string
	envelopes                      *secretenvelope.Service
	directory                      *kernel.Repository
	providerAuthority              *ProviderAuthority
	locator                        proxyBindingLocator
	original                       proxyOriginalBinding
	row                            proxyLookupRow
	command                        identity.Command
	proof                          kernel.CapabilityPlan
	plan                           kernel.CommandPlan
	generate                       oauthproxy.CallbackGeneration
	providerDenied                 bool
	generatedHere                  bool
	startedAt                      time.Time
	output                         proxyForwardOutput
	outputDigest                   [32]byte
	outputGeneration               uint64
}

var _ kernel.OAuthProxyForwardContributor = (*proxyForwardPhase)(nil)

func makeProxyForwardCommand(l proxyBindingLocator, actor identity.ActorID, policy string, version uint64, encryptedBinding []byte, denied bool) (identity.Command, error) {
	op := kernel.OAuthProxyForwardOperation()
	disposition := "code"
	if denied {
		disposition = "provider-denied"
	}
	digest := sha256.Sum256(encryptedBinding)
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{
		Operation: op,
		Binding: identity.CommandBinding{
			CommandID: l.CallbackCommand, TenantID: l.Tenant, ActorID: actor, ActorKind: authorization.SubjectServiceAccount,
			AnonymousFlowID: string(l.Transaction), RecordID: string(l.Transaction), CorrelationID: string(l.OriginCommand),
			OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: policy, PolicyVersion: version,
		},
		Fields: []identity.FeatureField{
			{Name: "oauth.proxy.original", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}},
			{Name: "oauth.proxy.callback-mode", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: disposition}},
		},
	})
}

func (p *proxyForwardPhase) declare(registry *kernel.ContributorRegistry, retention uint64) error {
	spec, ok := p.command.Feature()
	if !ok || registry == nil || retention == 0 {
		return identity.InvalidInputError{Field: "oauth_proxy_forward_plan"}
	}
	b := spec.Binding
	auditBuilder, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return err
	}
	seed, err := auditBuilder.Build(audit.RecordInput{
		OccurredAt: p.row.observed, Action: proxyAuditEvent, Outcome: audit.OutcomeSucceeded,
		Actor:   audit.ActorInput{Kind: audit.ActorService, ID: string(b.ActorID)},
		Subject: audit.SubjectInput{Type: proxySubjectType, ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": proxySubjectType,
			"aggregate.id": b.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"},
	})
	if err != nil {
		return err
	}
	bound, err := kernel.FeatureAuditBindingDigest(b, spec.Operation, proxySubjectType, seed)
	if err != nil {
		return err
	}
	feature := kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: spec.Operation}
	lifecycle := kernel.OAuthProxyForwardLifecycle()
	proof := p.proof
	p.plan = kernel.CommandPlan{Contributors: registry.Descriptors(), Feature: &feature, Capability: &proof, SubjectType: proxySubjectType,
		Lifecycle: &lifecycle, Audits: []kernel.AuditPlan{{EventType: proxyAuditEvent, SchemaVersion: 1, RequiredRecordCount: 1,
			Required: true, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: retention, RetentionClass: "protected", BindingDigest: bound}}}
	return nil
}

func (*proxyForwardPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.OAuthProxyForwardDescriptor()
}
func (*proxyForwardPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.OAuthProxyForwardOperation()}
}

func (p *proxyForwardPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.plan.Feature == nil || plan.Feature == nil || *plan.Feature != *p.plan.Feature || plan.Capability == nil || plan.SubjectType != proxySubjectType {
		return identity.ForbiddenError{}
	}
	return p.ValidateOAuthProxyForward(c, *plan.Capability)
}

func (p *proxyForwardPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(c, plan)
}

func (p *proxyForwardPhase) ValidateOAuthProxyForward(c identity.Command, proof kernel.CapabilityPlan) error {
	if p == nil || p.command == (identity.Command{}) || c != p.command || p.proof != proof {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *proxyForwardPhase) Check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || p == nil || p.startedAt.IsZero() || time.Since(p.startedAt) >= proxyAuthorityLifetime ||
		p.row.observed.Before(p.locator.IssuedAt) || !p.row.observed.Before(p.locator.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *proxyForwardPhase) directoryAdmission() kernel.DirectoryAuthorityAdmission {
	return kernel.DirectoryAuthorityAdmission{
		Query:         kernel.DirectoryAuthorityQuery{TenantID: p.locator.Tenant, GlobalAuthorityID: p.authority},
		GlobalVersion: p.original.GlobalVersion, TenantVersion: p.original.TenantVersion,
	}
}

func (p *proxyForwardPhase) requireCurrent(ctx context.Context, w kernel.Work, version uint64) (time.Time, error) {
	if err := p.Check(ctx); err != nil {
		return time.Time{}, err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, p.directoryAdmission()); err != nil {
		return time.Time{}, err
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(p.locator.CallbackCommand))
	rows, err := w.Query(ctx, lockProxyForwardSQL(p.schema),
		string(p.locator.Tenant), string(p.locator.Transaction), command, version, p.row.binding)
	if err != nil {
		return time.Time{}, err
	}
	if !rows.Next() {
		rows.Close()
		return time.Time{}, identity.ForbiddenError{}
	}
	var found string
	if rows.Scan(&found) != nil || found != strconv.FormatUint(version, 10) || rows.Next() || rows.Err() != nil {
		rows.Close()
		return time.Time{}, identity.ForbiddenError{}
	}
	rows.Close()
	if err := requireProxyProviderAuthority(ctx, p.providerAuthority, p.original.Evidence); err != nil {
		return time.Time{}, err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if now.Before(p.row.observed) || now.Sub(p.row.observed) >= proxyAuthorityLifetime || now.Before(p.locator.IssuedAt) || !now.Before(p.locator.ExpiresAt) {
		return time.Time{}, identity.ForbiddenError{}
	}
	return now, nil
}

func (p *proxyForwardPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	_, err := p.requireCurrent(ctx, w, 1)
	return err
}

func (p *proxyForwardPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command || p.generate == nil || p.Check(ctx) != nil {
		return nil, identity.ForbiddenError{}
	}
	return p, nil
}

func (p *proxyForwardPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command || p.Check(ctx) != nil {
		return nil, identity.ForbiddenError{}
	}
	value, err := openProxyForwardOutput(ctx, p.envelopes, p.locator, generation, wire)
	clear(value.Artifact)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (*proxyForwardPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{} // The admission-gated generation is required.
}

func (p *proxyForwardPhase) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if generation == 0 || p.generatedHere || p.Check(ctx) != nil {
		return nil, identity.ForbiddenError{}
	}
	p.generatedHere = true
	original := oauthproxy.OriginalCallback{
		ID: sha256.Sum256([]byte(p.locator.CallbackCommand)), Binding: p.original.Evidence, Nonce: p.original.CallbackNonce,
	}
	if !p.providerDenied {
		// The generation marker has committed and released its directory locks.
		// Recheck the same original epochs on the primary before revealing PKCE;
		// this observation does not extend the original callback lifetime.
		expected := p.directoryAdmission()
		current, err := p.directory.GetDirectoryAuthority(ctx, expected.Query)
		if err != nil || !current.Enabled || current.GlobalVersion != expected.GlobalVersion || current.TenantVersion != expected.TenantVersion || p.Check(ctx) != nil {
			return nil, identity.ForbiddenError{}
		}
	}
	// A provider change can commit after the generation reservation. Do not
	// release the original verifier based on the earlier admission read.
	if err := requireProxyProviderAuthority(ctx, p.providerAuthority, original.Binding); err != nil {
		return nil, err
	}
	if !p.providerDenied {
		plain, err := openProxyPart(ctx, p.envelopes, p.locator, proxyVerifier, 0, p.row.verifier, 4096)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		original.Verifier, err = oauth.NewPKCEVerifier(plain)
		if err != nil {
			return nil, err
		}
		defer original.Verifier.Destroy()
	}
	prepared, err := p.generate(ctx, original)
	if err != nil {
		return nil, err
	}
	value := proxyForwardOutput{Disposition: prepared.Disposition(), Until: prepared.ExpiresAt(), Artifact: prepared.Envelope()}
	defer clear(value.Artifact)
	return sealProxyForwardOutput(ctx, p.envelopes, p.envelopeKey, p.locator, generation, value)
}

func (p *proxyForwardPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command || p.Check(ctx) != nil {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	value, err := openProxyForwardOutput(ctx, p.envelopes, p.locator, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	clear(p.output.Artifact)
	p.output, p.outputGeneration, p.outputDigest = value, generation, sha256.Sum256(wire)
	return c, p.plan, nil
}

func (p *proxyForwardPhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	if c != p.command || !p.output.valid(p.locator) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	claimed, err := w.OAuthProxyForwardConsumption(p)
	if err != nil || claimed.Plan != p.proof || claimed.Command.CommandID != p.locator.CallbackCommand {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || generation != p.outputGeneration || sha256.Sum256(wire) != p.outputDigest {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	now, err := p.requireCurrent(ctx, w, 1)
	if err != nil || p.output.Disposition == oauthproxy.CallbackForwarded && !now.Before(p.output.Until) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	command, _ := base64.RawURLEncoding.DecodeString(string(p.locator.CallbackCommand))
	var artifact []byte
	if p.output.Disposition == oauthproxy.CallbackForwarded {
		artifact = bytes.Clone(p.output.Artifact)
	}
	defer clear(artifact)
	n, err := w.Exec(ctx, settleProxyForwardSQL(p.schema),
		string(p.locator.Tenant), string(p.locator.Transaction), command, int16(p.output.Disposition), artifact, now)
	if err != nil || n != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	return identity.FeatureReceipt{Operation: kernel.OAuthProxyForwardOperation(), BeforeVersion: 1, AfterVersion: 2}, nil
}

func (p *proxyForwardPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	now, err := p.requireCurrent(ctx, w, 2)
	if err != nil || p.output.Disposition == oauthproxy.CallbackForwarded && !now.Before(p.output.Until) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (*proxyForwardPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil // Only the coordinator settles an ambiguous command.
}
