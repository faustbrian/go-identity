package postgres

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
)

// EnqueueOperation declares the closed native enqueue command. Its primary
// record is the first deterministic effect ID; the command freezes all 1..16
// effects, not only that primary. Declaration conveys no recipient authority.
func EnqueueOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/delivery", OperationID: "identity.delivery.enqueue", SchemaID: "identity-delivery-enqueue-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// PrepareEnqueue prepares an owned standalone enqueue command's custody before
// opening Work. Binding must select EnqueueOperation, with RecordID empty; the
// primary effect ID is derived here, never caller-selected. Other binding fields
// must come from the authenticated owning workflow. Bounds/encryption/expiry
// are Prepare's unchanged contract. Neither preparation nor command mapping
// supplies authorization, idempotency admission, a transaction or queue success.
func (c *Contributor) PrepareEnqueue(ctx context.Context, b identity.CommandBinding, inputs []IntentInput) (PreparedDelivery, error) {
	if c == nil {
		return PreparedDelivery{}, delivery.ErrInvalidInput
	}
	return c.prepareEnqueueVersion(ctx, b, inputs, c.current)
}

func (c *Contributor) prepareEnqueueVersion(ctx context.Context, b identity.CommandBinding, inputs []IntentInput, version uint32) (PreparedDelivery, error) {
	if c == nil || c.store == nil || ctx == nil {
		return PreparedDelivery{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return PreparedDelivery{}, err
	}
	if b.RecordID != "" || len(inputs) < 1 || len(inputs) > 16 {
		return PreparedDelivery{}, delivery.ErrInvalidInput
	}
	// Validate every caller field before proportional hashing. The required
	// record is adapter-derived; this bounded placeholder grants no identity.
	checked := b
	checked.RecordID = "enqueue-validation"
	if checked.ValidateFor(EnqueueOperation()) != nil {
		return PreparedDelivery{}, delivery.ErrInvalidInput
	}
	b.RecordID = deliveryEffectID(c.store.deployment, b, inputs[0].EffectIndex)
	if b.ValidateFor(EnqueueOperation()) != nil {
		return PreparedDelivery{}, delivery.ErrInvalidInput
	}
	return c.prepareVersion(ctx, b, inputs, version)
}

// EnqueueCommand returns an immutable core command containing confidential
// logical digests and every frozen safe effect field, never ciphertext, recipient
// or rendered content. Only a valid PrepareEnqueue result is accepted. Its
// caller must stage this same preparation under the original coordinator Work;
// the native participant and encrypted-effect participant are distinct phases.
// This mapping grants no authentication, policy, execution or commit authority.
func (p PreparedDelivery) EnqueueCommand() (identity.Command, error) {
	if p.state == nil || p.state.owner == nil || p.state.owner.store == nil || p.state.binding.ValidateFor(EnqueueOperation()) != nil || p.state.owner.store.ValidateDeliveryPlan(p.state.binding, p.state.plan) != nil || p.state.binding.RecordID != p.state.plan.Intents[0].EffectID {
		return identity.Command{}, delivery.ErrInvalidInput
	}
	fields := make([]identity.FeatureField, 0, len(p.state.plan.Intents)*8)
	for _, v := range p.state.plan.Intents {
		prefix := enqueuePrefix(v.EffectIndex)
		fields = append(fields,
			identity.FeatureField{Name: prefix + ".digest", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: v.IntentDigest[:]}},
			identity.FeatureField{Name: prefix + ".effect", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v.EffectID}},
			identity.FeatureField{Name: prefix + ".expires", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: v.ExpiresAt}},
			identity.FeatureField{Name: prefix + ".provider", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: v.ProviderConfigVersion}},
			identity.FeatureField{Name: prefix + ".purpose", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v.Purpose}},
			identity.FeatureField{Name: prefix + ".subject", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v.SubjectID}},
			identity.FeatureField{Name: prefix + ".template", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: v.TemplateID}},
			identity.FeatureField{Name: prefix + ".version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: uint64(v.TemplateVersion)}},
		)
		if len(p.state.recipients) > 0 {
			if len(p.state.recipients) != len(p.state.plan.Intents) {
				return identity.Command{}, delivery.ErrInvalidInput
			}
			r := p.state.recipients[len(fields)/11]
			fields = append(fields, identity.FeatureField{Name: prefix + ".x-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(r.id)}}, identity.FeatureField{Name: prefix + ".x-id-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.version}}, identity.FeatureField{Name: prefix + ".x-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: r.authority}})
		}
	}
	return identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: p.state.binding, Operation: EnqueueOperation(), Fields: fields})
}

func enqueuePrefix(index uint16) string { return fmt.Sprintf("delivery.intent-%05d", index) }

// EnqueueContributor supplies only the native enqueue phase of the sole kernel
// coordinator. Enlist its borrowed ciphertext Contributor separately and last,
// using the same exact instance. This phase owns no pool, transaction, provider,
// generic workflow or separate ledger. Zero is invalid; independent Work calls
// are safe concurrently. It is not a Queue or authenticated application endpoint.
type EnqueueContributor struct{ custody *Contributor }

var _ identitypostgres.FeatureExecutionContributor = (*EnqueueContributor)(nil)

// NewEnqueueContributor borrows ciphertext configuration without IO or resource
// ownership transfer. Trusted composition must enlist kernel, this native phase,
// protected audit, lifecycle and the supplied custody contributor. The kernel
// enforces the exact registered custody instance during staging/persistence,
// but this native phase validates its descriptor/profile, not pointer identity:
// a distinct configuration-compatible custody instance can be enlisted instead.
// The owned Queue must use the same instance for both phases; applications must
// not implement that unfinished Queue orchestration themselves.
func NewEnqueueContributor(c *Contributor) (*EnqueueContributor, error) {
	if c == nil || c.store == nil {
		return nil, delivery.ErrInvalidInput
	}
	return &EnqueueContributor{custody: c}, nil
}

// Descriptor is the distinct immutable native phase identity, not authority.
func (*EnqueueContributor) Descriptor() identitypostgres.ContributorDescriptor {
	return identitypostgres.ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.enqueue", Version: 1}
}

// FeatureOperations declares native enqueue only, not unfinished Queue methods.
func (*EnqueueContributor) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{EnqueueOperation()}
}

// ValidateFeatureCommand freezes the exact complete delivery declaration and
// protected effect plan before reservation. It performs no IO, authorization,
// encryption or callback. Ciphertext attestation remains the existing custody
// phase's responsibility, under the same Work before commit.
func (c *EnqueueContributor) ValidateFeatureCommand(command identity.Command, p identitypostgres.CommandPlan) error {
	s, intents, err := c.decode(command)
	if err != nil || p.Feature == nil || p.Feature.Contributor != c.Descriptor() || p.Feature.Operation != EnqueueOperation() || p.SubjectType != "delivery_intent" || !enqueueTransition(p.Lifecycle) || p.Delivery == nil || p.Delivery.Contributor != c.custody.Descriptor() || len(p.Delivery.Intents) != len(intents) || len(p.Audits) != 1 {
		return delivery.ErrInvalidInput
	}
	if c.custody.ValidateDeliveryPlan(s.Binding, *p.Delivery) != nil {
		return delivery.ErrInvalidInput
	}
	for n, want := range intents {
		got := p.Delivery.Intents[n]
		got.ExpiresAt, want.ExpiresAt = got.ExpiresAt.UTC(), want.ExpiresAt.UTC()
		if got != want {
			return delivery.ErrConflict
		}
	}
	a := p.Audits[0]
	if a.EventType != "identity.delivery.enqueue" || a.SchemaVersion != 1 || !a.Required || a.RequiredRecordCount != 1 || a.RetentionClass != "protected" || a.RetentionPolicyVersion == 0 || p.Capability != nil {
		return delivery.ErrInvalidInput
	}
	return nil
}

func enqueueTransition(p *identitypostgres.LifecyclePlan) bool {
	return p != nil && p.EventType == "delivery.enqueued.v1" && p.BeforeVersion == 0 && p.AfterVersion == 1
}

// ApplyFeature runs only in this exact participant's native invocation. The
// returned primary-record receipt is provisional: all staged ciphertext is
// authenticated/persisted by the separate exact custody phase during Commit,
// atomically with this command, protected audit and lifecycle/outbox. Missing
// custody causes rollback, not an empty successful enqueue. No transaction,
// provider work, recipient discovery, secret creation or retry occurs here.
func (c *EnqueueContributor) ApplyFeature(ctx context.Context, w identitypostgres.Work, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || c == nil || c.custody == nil {
		return identity.FeatureReceipt{}, delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, feature, transition, err := w.FeatureScope(c)
	s, intents, decoded := c.decode(command)
	if err != nil || decoded != nil || b != s.Binding || feature.Contributor != c.Descriptor() || feature.Operation != EnqueueOperation() || !enqueueTransition(&transition) {
		return identity.FeatureReceipt{}, delivery.ErrForbidden
	}
	if err := checkRecipients(ctx, w, s, intents); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: EnqueueOperation(), AfterVersion: 1}, nil
}

// RecoverParticipant supplies retained native effect evidence only inside its
// exact recovery invocation. No row can be created without the same atomic Work;
// original bindings are not pruned. Positive evidence is not a reconstructed
// successful receipt; the separately enlisted custody phase checks every effect.
// Expired or erased payloads never imply rollback or permission to reissue.
func (c *EnqueueContributor) RecoverParticipant(ctx context.Context, w identitypostgres.RecoveryWork) (identitypostgres.RecoveryStatus, error) {
	if ctx == nil || c == nil || c.custody == nil || c.custody.store == nil {
		return identitypostgres.RecoveryUnknown, delivery.ErrInvalidInput
	}
	b, feature, transition, err := w.FeatureScope(c)
	if err != nil || feature.Contributor != c.Descriptor() || feature.Operation != EnqueueOperation() || !enqueueTransition(&transition) {
		return identitypostgres.RecoveryUnknown, delivery.ErrForbidden
	}
	rows, err := w.Query(ctx, `SELECT binding_aad FROM identity.delivery_intents WHERE deployment=$1 AND tenant_id=$2 AND effect_id=$3`, c.custody.store.deployment, string(b.TenantID), b.RecordID)
	if err != nil {
		return identitypostgres.RecoveryUnknown, err
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return identitypostgres.RecoveryUnknown, delivery.ErrUnavailable
		}
		return identitypostgres.RecoveryNotCommitted, nil
	}
	var aad []byte
	if rows.Scan(&aad) != nil || rows.Next() || rows.Err() != nil {
		return identitypostgres.RecoveryUnknown, delivery.ErrUnavailable
	}
	bound, err := decodeBinding(aad)
	if err != nil || bound.Command != b || bound.Deployment != c.custody.store.deployment || bound.Intent.EffectID != b.RecordID {
		return identitypostgres.RecoveryUnknown, delivery.ErrConflict
	}
	return identitypostgres.RecoveryCommitted, nil
}

func (c *EnqueueContributor) decode(command identity.Command) (identity.FeatureCommandSpec, []identitypostgres.DeliveryIntentPlan, error) {
	fail := func() (identity.FeatureCommandSpec, []identitypostgres.DeliveryIntentPlan, error) {
		return identity.FeatureCommandSpec{}, nil, delivery.ErrInvalidInput
	}
	if c == nil || c.custody == nil || c.custody.store == nil {
		return fail()
	}
	s, ok := command.Feature()
	if !ok || s.Operation != EnqueueOperation() || s.Binding.ValidateFor(EnqueueOperation()) != nil || len(s.Fields) < 8 || len(s.Fields) > 128 {
		return fail()
	}
	stride := 8
	fences, err := recipientFields(s)
	if err != nil {
		return fail()
	}
	if len(fences) > 0 {
		stride = 11
	}
	if len(s.Fields)%stride != 0 {
		return fail()
	}
	intents := make([]identitypostgres.DeliveryIntentPlan, len(s.Fields)/stride)
	for n := range intents {
		v := &intents[n]
		name := s.Fields[n*stride].Name
		if !strings.HasPrefix(name, "delivery.intent-") || len(name) != len("delivery.intent-00000.digest") {
			return fail()
		}
		index, err := strconv.ParseUint(name[16:21], 10, 16)
		if err != nil {
			return fail()
		}
		v.EffectIndex = uint16(index)
		prefix := enqueuePrefix(v.EffectIndex)
		for j, suffix := range []string{"digest", "effect", "expires", "provider", "purpose", "subject", "template", "version"} {
			f := s.Fields[n*stride+j]
			if f.Name != prefix+"."+suffix {
				return fail()
			}
			switch j {
			case 0:
				if f.Value.Kind != identity.FeatureBytes || len(f.Value.Bytes) != 32 {
					return fail()
				}
				copy(v.IntentDigest[:], f.Value.Bytes)
			case 2:
				if f.Value.Kind != identity.FeatureTime {
					return fail()
				}
				v.ExpiresAt = f.Value.Time.UTC()
			case 3, 7:
				if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 || j == 7 && f.Value.Uint64 > 4294967295 {
					return fail()
				}
				if j == 3 {
					v.ProviderConfigVersion = f.Value.Uint64
				} else {
					v.TemplateVersion = uint32(f.Value.Uint64)
				}
			default:
				if f.Value.Kind != identity.FeatureText {
					return fail()
				}
				switch j {
				case 1:
					v.EffectID = f.Value.Text
				case 4:
					v.Purpose = f.Value.Text
				case 5:
					v.SubjectID = f.Value.Text
				case 6:
					v.TemplateID = f.Value.Text
				}
			}
		}
	}
	if s.Binding.RecordID != intents[0].EffectID || c.custody.ValidateDeliveryPlan(s.Binding, identitypostgres.DeliveryPlan{Contributor: c.custody.Descriptor(), Intents: intents}) != nil {
		return fail()
	}
	return s, intents, nil
}
