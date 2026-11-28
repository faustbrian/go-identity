package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"reflect"
	"slices"
	"strconv"
	"time"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
)

type proxyStartPhase struct {
	forward               *ProxyForwardService
	checkpoint            *capabilitypg.IssuancePreparationCodec
	command               identity.Command
	binding               identity.CommandBinding
	request               [32]byte
	locator               proxyBindingLocator
	original              proxyOriginalBinding
	profile               *oauth.OIDCProvider
	basePlan              kernel.CommandPlan
	admittedAt, startedAt time.Time
	lifetime              time.Duration
	issuer, audience      string
	generated             bool
	response              oauth.AuthorizationRequest
	evidence              oauth.ProxyOIDCEvidenceBinding
	prepared              proxyStartOutput
	preparedGeneration    uint64
	preparedDigest        [32]byte
	issued                capabilitypg.PreparedIssuance
	custodyFence          bool
}

var _ kernel.FeatureAdmissionPreparationContributor = (*proxyStartPhase)(nil)
var _ kernel.FeatureCommitContributor = (*proxyStartPhase)(nil)

func (*proxyStartPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.OAuthProxyStartDescriptor()
}

func (*proxyStartPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{kernel.OAuthProxyStartOperation()}
}

func (p *proxyStartPhase) executionCommand(sealed [32]byte) (identity.Command, error) {
	fields := []identity.FeatureField{{Name: "oauth.proxy.request", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: p.request[:]}}}
	if sealed != ([32]byte{}) {
		fields = append(fields, identity.FeatureField{Name: "identity.oauth.proxy.binding", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: sealed[:]}})
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.binding, Operation: kernel.OAuthProxyStartOperation(), Fields: fields})
}

func (p *proxyStartPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.CapabilityIssuance != nil || p.basePlan.Feature == nil || plan.Feature == nil || *plan.Feature != *p.basePlan.Feature {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *proxyStartPhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	f, ok := c.Feature()
	if !ok || f.Binding != p.binding || f.Operation != kernel.OAuthProxyStartOperation() || len(f.Fields) != 2 ||
		plan.CapabilityIssuance == nil || len(plan.CapabilityIssuance.Grants) != 1 || p.preparedGeneration == 0 {
		return identity.ForbiddenError{}
	}
	return nil // Kernel already checks the exact transformation and grant intent.
}

func (p *proxyStartPhase) Check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || p.startedAt.IsZero() || time.Since(p.startedAt) >= proxyAuthorityLifetime {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *proxyStartPhase) requireAuthority(ctx context.Context, work kernel.Work) (time.Time, error) {
	if err := p.Check(ctx); err != nil {
		return time.Time{}, err
	}
	if err := work.RequireActiveDirectoryAuthority(ctx, p, kernel.DirectoryAuthorityAdmission{
		Query:         kernel.DirectoryAuthorityQuery{TenantID: p.binding.TenantID, GlobalAuthorityID: p.forward.config.GlobalAuthorityID},
		GlobalVersion: p.original.GlobalVersion, TenantVersion: p.original.TenantVersion,
	}); err != nil {
		return time.Time{}, err
	}
	if err := requireProxyProviderAuthority(ctx, p.forward.providerAuthority, p.original.Evidence); err != nil {
		return time.Time{}, err
	}
	return work.DatabaseTime(ctx)
}

func (p *proxyStartPhase) AdmitFeaturePreparation(ctx context.Context, work kernel.Work, c identity.Command) error {
	if c != p.command {
		return identity.ForbiddenError{}
	}
	now, err := p.requireAuthority(ctx, work)
	if err != nil {
		return err
	}
	if p.admittedAt.IsZero() {
		p.admittedAt = now
	}
	return nil
}

func (p *proxyStartPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command || p.admittedAt.IsZero() || p.Check(ctx) != nil {
		return nil, identity.ForbiddenError{}
	}
	return p, nil
}

func (p *proxyStartPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, _ uint64, _ []byte) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command || p.Check(ctx) != nil {
		return nil, identity.ForbiddenError{}
	}
	return p, nil // RestoreFeaturePreparation authenticates the retained output before Apply.
}

func (*proxyStartPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.ForbiddenError{} // Only the acknowledged gated owner can generate.
}

func (p *proxyStartPhase) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if generation == 0 || p.admittedAt.IsZero() || p.generated || p.Check(ctx) != nil {
		return nil, identity.ForbiddenError{}
	}
	p.generated = true
	var random [96]byte
	defer clear(random[:])
	for i := 0; i < len(random); i += 32 {
		part := random[i : i+32]
		if _, err := rand.Read(part); err != nil || [32]byte(part) == ([32]byte{}) {
			return nil, identity.UnavailableError{}
		}
	}
	var verifier [43]byte
	base64.RawURLEncoding.Encode(verifier[:], random[64:])
	defer clear(verifier[:])
	pkce, err := oauth.NewPKCEVerifier(verifier[:])
	if err != nil {
		return nil, err
	}
	defer pkce.Destroy()
	state := base64.RawURLEncoding.EncodeToString(random[:32])
	l := p.locator
	l.CallbackCommand, err = identity.NewCommandID()
	if err != nil || l.CallbackCommand == l.OriginCommand {
		return nil, identity.UnavailableError{}
	}
	l.IssuedAt = p.admittedAt.UTC().Truncate(time.Second)
	l.ExpiresAt = l.IssuedAt.Add(p.lifetime)
	original := p.original
	original.CallbackNonce = base64.RawURLEncoding.EncodeToString(random[32:64])
	original.Evidence.StateDigest = sha256.Sum256([]byte(state))
	original.Evidence.PKCEChallengeDigest = sha256.Sum256([]byte(pkce.Challenge()))
	original.Evidence.IssuedAt, original.Evidence.ExpiresAt = l.IssuedAt, l.ExpiresAt
	l.LookupDigest = proxyLookupDigest(p.forward.config.StateKeys[l.StateKeyVersion], l.StateKeyVersion, l.Production, l.Provider, l.ProviderVersion, original.Evidence.StateDigest)
	return p.sealGenerated(ctx, generation, l, original, state, pkce.Challenge(), verifier[:])
}

func (p *proxyStartPhase) sealGenerated(ctx context.Context, generation uint64, l proxyBindingLocator, original proxyOriginalBinding, state, challenge string, verifier []byte) ([]byte, error) {
	forward := p.forward
	output := proxyStartOutput{Version: 1, Locator: l, State: state, Challenge: challenge}
	defer output.clear()
	key := forward.config.CurrentEnvelopeKey
	var err error
	output.BindingCiphertext, err = sealProxyOriginalBinding(ctx, forward.envelopes, key, l, original)
	if err != nil {
		return nil, err
	}
	output.PKCECiphertext, err = sealProxyPart(ctx, forward.envelopes, key, l, proxyVerifier, 0, verifier, 4096)
	if err != nil {
		return nil, err
	}
	commitment := sha256.Sum256(output.BindingCiphertext)
	proof, err := forward.issuer.Prepare(ctx, p.binding, []capability.Payload{{
		Version: 1, Issuer: p.issuer, Audiences: []string{p.audience}, Operation: "identity.oauth.proxy-forward",
		Tenant: string(l.Tenant), Subject: p.binding.AnonymousFlowID, Resource: p.binding.RecordID, CorrelationID: p.binding.CorrelationID,
		IssuedAt: l.IssuedAt, NotBefore: l.IssuedAt, ExpiresAt: l.ExpiresAt, MaxUses: 1,
		Caveats: map[string]string{"identity.oauth.proxy.binding": base64.RawURLEncoding.EncodeToString(commitment[:])},
	}})
	if err != nil {
		return nil, err
	}
	plan, err := proof.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, identity.UnavailableError{}
	}
	output.Grant = rpStoredGrant(plan.Grants[0])
	output.Checkpoint, err = p.checkpoint.CheckpointPreparation(ctx, proof, generation, func(ctx context.Context, i uint16, wire []byte) error {
		if i != 0 || len(output.StateProofCiphertext) != 0 || len(wire) >= proxyStateProofLimit-5 {
			return identity.ForbiddenError{}
		}
		framed := binary.BigEndian.AppendUint32([]byte{1}, output.Grant.ReplayKeyVersion)
		framed = append(framed, wire...)
		defer clear(framed)
		var err error
		output.StateProofCiphertext, err = sealProxyPart(ctx, forward.envelopes, key, l, proxyStateProof, 0, framed, proxyStateProofLimit)
		return err
	})
	if err != nil {
		return nil, err
	}
	return sealProxyStartOutput(ctx, forward.envelopes, key, p.binding, p.request, generation, output)
}

func (p *proxyStartPhase) restoreOriginal(ctx context.Context, o proxyStartOutput) (proxyOriginalBinding, error) {
	l := o.Locator
	expected := p.locator
	expected.CallbackCommand, expected.IssuedAt, expected.ExpiresAt = l.CallbackCommand, l.IssuedAt, l.ExpiresAt
	// Restore uses the original retained lookup key; rotation does not renew
	// or reinterpret a started proxy transaction.
	expected.StateKeyVersion = l.StateKeyVersion
	key := p.forward.config.StateKeys[l.StateKeyVersion]
	state := sha256.Sum256([]byte(o.State))
	expected.LookupDigest = proxyLookupDigest(key, l.StateKeyVersion, l.Production, l.Provider, l.ProviderVersion, state)
	if key == ([32]byte{}) || l != expected || l.ExpiresAt.Sub(l.IssuedAt) != p.lifetime {
		return proxyOriginalBinding{}, identity.ForbiddenError{}
	}
	original, err := openProxyOriginalBinding(ctx, p.forward.envelopes, l, o.BindingCiphertext)
	if err != nil {
		return proxyOriginalBinding{}, err
	}
	profile := p.original
	profile.CallbackNonce = original.CallbackNonce
	profile.Evidence.StateDigest = state
	profile.Evidence.PKCEChallengeDigest = sha256.Sum256([]byte(o.Challenge))
	profile.Evidence.IssuedAt, profile.Evidence.ExpiresAt = l.IssuedAt, l.ExpiresAt
	if !reflect.DeepEqual(original, profile) {
		return proxyOriginalBinding{}, identity.ForbiddenError{}
	}
	return original, nil
}

func (p *proxyStartPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command || p.Check(ctx) != nil {
		return identity.Command{}, kernel.CommandPlan{}, identity.ForbiddenError{}
	}
	out, err := openProxyStartOutput(ctx, p.forward.envelopes, p.binding, p.request, generation, wire)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	defer func() { out.clear() }()
	original, err := p.restoreOriginal(ctx, out)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	issuer := p.forward.issuer.Descriptor()
	issuance := kernel.CapabilityIssuancePlan{Contributor: issuer, Grants: []kernel.CapabilityPlan{kernel.CapabilityPlan(out.Grant)}}
	issued, err := p.checkpoint.RestorePreparation(ctx, p.binding, generation, issuance, out.Checkpoint)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	command, err := p.executionCommand(sha256.Sum256(out.BindingCiphertext))
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	if p.generated {
		p.response, err = p.profile.Authorization(ctx, oauth.AuthorizationParameters{State: out.State, Nonce: original.CallbackNonce, PKCEChallenge: out.Challenge})
		if err != nil {
			return identity.Command{}, kernel.CommandPlan{}, err
		}
		p.evidence = original.Evidence
	}
	plan := p.basePlan
	plan.Contributors = append(slices.Clone(p.basePlan.Contributors), issuer)
	plan.CapabilityIssuance = &issuance
	p.prepared.clear()
	p.prepared, p.preparedGeneration, p.preparedDigest, p.issued = out, generation, sha256.Sum256(wire), issued
	out = proxyStartOutput{} // Ownership moved to this invocation.
	return command, plan, nil
}

func insertProxyStartSQL(schema string) string {
	return proxyStartInsertSQL(schema, false)
}

func proxyStartInsertSQL(schema string, fenced bool) string {
	var columns, values string
	if fenced {
		columns, values = ",fence_provider_id,fence_provider_epoch", ",$16,$17::numeric"
	}
	return `INSERT INTO ` + rpQuotedSchema(schema) + `.proxy_transactions(tenant_id,transaction_id,origin_command_id,callback_command_id,
production_deployment,provider_id,configuration_version,production_callback_uri,state_key_version,state_lookup_digest,
binding_ciphertext,state_proof_ciphertext,pkce_ciphertext,issued_at,expires_at,version` + columns + `)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1` + values + `)`
}

func (p *proxyStartPhase) ApplyFeature(ctx context.Context, work kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if err := work.RequireFeatureCommand(ctx, p, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	wire, generation, err := work.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || generation != p.preparedGeneration || sha256.Sum256(wire) != p.preparedDigest {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	now, err := p.requireAuthority(ctx, work)
	l, o := p.prepared.Locator, p.prepared
	if err != nil || now.Before(l.IssuedAt) || !now.Before(l.ExpiresAt) {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	origin, _ := base64.RawURLEncoding.DecodeString(string(l.OriginCommand))
	callback, _ := base64.RawURLEncoding.DecodeString(string(l.CallbackCommand))
	args := []any{string(l.Tenant), string(l.Transaction), origin, callback,
		l.Production, l.Provider, l.ProviderVersion, l.CallbackURI, l.StateKeyVersion, l.LookupDigest[:], o.BindingCiphertext,
		o.StateProofCiphertext, o.PKCECiphertext, l.IssuedAt, l.ExpiresAt}
	statement := insertProxyStartSQL(p.forward.config.Schema)
	if p.custodyFence {
		epoch := p.original.Evidence.ProviderAuthorityEpoch
		if epoch == 0 {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
		args = append(args, l.Provider, strconv.FormatUint(epoch, 10))
		statement = proxyStartInsertSQL(p.forward.config.Schema, true)
	}
	count, err := work.Exec(ctx, statement, args...)
	if err != nil || count != 1 {
		return identity.FeatureReceipt{}, identity.UnavailableError{}
	}
	if err := p.forward.issuer.Stage(ctx, work, p.issued); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: kernel.OAuthProxyStartOperation(), AfterVersion: 1}, nil
}

func (p *proxyStartPhase) CheckFeatureCommit(ctx context.Context, work kernel.Work, _ identity.Command) error {
	now, err := p.requireAuthority(ctx, work)
	if err != nil || now.Before(p.prepared.Locator.IssuedAt) || !now.Before(p.prepared.Locator.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

func (*proxyStartPhase) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	// Recovery of retained preparation uses the original coordinator. This
	// participant must not infer no commit from missing request-local material.
	return kernel.RecoveryUnknown, nil
}
