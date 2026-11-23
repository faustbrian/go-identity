//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

const sealedIDPConfirmationFixture = "synthetic-sealed-idp-confirmation-output"

type idpConfirmationRestoreProbe struct {
	samlIDPConfirmationParticipant
	restored identity.Command
	plan     CommandPlan
	applies  int
}

// The fixture accepts any structurally valid pair so the test proves the
// coordinator's own guard rather than a native participant's comparison.
func (p *idpConfirmationRestoreProbe) ValidateSSOSAMLIDPConfirmationConsumption(c identity.Command, proof CapabilityPlan) error {
	_, _, ok := c.SAMLIDPConfirmationCustody()
	if !ok || proof != p.proof {
		return invalidPlan()
	}
	return nil
}

func (*idpConfirmationRestoreProbe) PrepareFeatureAdmission(ctx context.Context, _ identity.Command) (FeaturePreparationAdmission, error) {
	return idpConfirmationRestoreAdmission{}, ctx.Err()
}

type idpConfirmationRestoreAdmission struct{}

func (idpConfirmationRestoreAdmission) Check(ctx context.Context) error { return ctx.Err() }
func (idpConfirmationRestoreAdmission) Generate(ctx context.Context, _ uint64) ([]byte, error) {
	return []byte(sealedIDPConfirmationFixture), ctx.Err()
}

func (p *idpConfirmationRestoreProbe) RestoreFeaturePreparation(ctx context.Context, _ identity.Command, generation uint64, sealed []byte) (identity.Command, CommandPlan, error) {
	if generation != 1 || string(sealed) != sealedIDPConfirmationFixture {
		return identity.Command{}, CommandPlan{}, invalidPreparation()
	}
	return p.restored, p.plan, ctx.Err()
}

func (p *idpConfirmationRestoreProbe) ApplyFeature(_ context.Context, w Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.applies++
	spec, ok := c.SAMLIDPConfirmationFeature()
	proof, err := w.SSOSAMLIDPConfirmationConsumption(p)
	if !ok || err != nil || proof.Command != spec.Binding || proof.Plan != p.proof {
		return identity.FeatureReceipt{}, invalidWork()
	}
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 1, AfterVersion: 2}, nil
}

func (*idpConfirmationRestoreProbe) CheckFeatureCommit(ctx context.Context, _ Work, _ identity.Command) error {
	return ctx.Err()
}

func TestSSOSAMLIDPConfirmationRejectsSubstitutedRestoredPairBeforeApply(t *testing.T) {
	for _, change := range []string{"none", "browser", "form"} {
		t.Run(change, func(t *testing.T) {
			ctx, pool, repository := newAccountAuthorityStore(t)
			for _, schema := range []string{preparationSchemaSQL, admissionPreparationSchemaSQL, counterPreparationSchemaSQL, ssoSAMLIDPConfirmationPreparationErasureSQL, `CREATE TABLE public.signin_preparation_state(command_id text PRIMARY KEY,fingerprint bytea NOT NULL,generation numeric NOT NULL,state text NOT NULL);
CREATE TABLE public.identity_test_audits(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE);
CREATE TABLE public.identity_test_lifecycle(event_id text PRIMARY KEY,command_id text NOT NULL UNIQUE)`} {
				if _, err := pool.Raw().Exec(ctx, schema); err != nil {
					t.Fatal("install confirmation fixture", err)
				}
			}
			binding, plan := samlIDPConfirmationPlanFixture(t)
			original := samlIDPConfirmationCommand(t, binding, plan.Feature.Operation)
			browser, form, _ := original.SAMLIDPConfirmationCustody()
			replacement := authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
			switch change {
			case "browser":
				browser = replacement
			case "form":
				form = replacement
			}
			spec, _ := original.SAMLIDPConfirmationFeature()
			restored, err := identity.NewFeatureSAMLIDPConfirmationCommand(spec, browser, form)
			if err != nil {
				t.Fatal(err)
			}
			plan.Capability.ExpiresAt = time.Now().UTC().Add(4 * time.Minute).Truncate(time.Second)
			plan.Audits[0].BindingDigest = securityAuditScopeDigest(binding, &plan.Feature.Operation, plan.SubjectType, featureAuditTargetID(binding, plan.Feature.Operation), audit.ActorService, "identity-feature-audit-binding-v1")
			phase := &idpConfirmationRestoreProbe{samlIDPConfirmationParticipant: samlIDPConfirmationParticipant{
				outputPreparationParticipant: outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{plan.Feature.Operation}}},
				proof:                        *plan.Capability,
			}, restored: restored}
			owners, err := NewContributorRegistry([]Contributor{repository, &recoveryAuditPhase{}, &recoveryLifecyclePhase{}, phase, &signinPreparationCapability{}})
			if err != nil {
				t.Fatal(err)
			}
			plan.Contributors = owners.Descriptors()
			phase.plan = plan
			c, err := NewCoordinator(pool, owners, CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if err != nil {
				t.Fatal(err)
			}
			out, err := c.ExecutePreparedFeature(ctx, original, plan)
			raw, _ := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
			var state, reserved string
			var ciphertext, final, receipt []byte
			if readErr := pool.Raw().QueryRow(ctx, `SELECT state,preparation_ciphertext,command_plan,result,(SELECT state FROM public.signin_preparation_state WHERE command_id=$2) FROM identity.commands WHERE command_id=$1`, raw, string(binding.CommandID)).Scan(&state, &ciphertext, &final, &receipt, &reserved); readErr != nil {
				t.Fatal("read actual confirmation settlement", readErr)
			}
			if change == "none" {
				if err != nil || out.Outcome != identity.CommitOutcomeCommitted || phase.applies != 1 || state != "committed" || reserved != "finalized" || ciphertext != nil || final == nil || receipt == nil {
					t.Fatal("matching restored pair did not commit exactly once", out.Outcome, err, state, reserved)
				}
			} else if !errors.As(err, new(identity.UnknownCommitError)) || out.Outcome != identity.CommitOutcomeUnknown || phase.applies != 0 || state != "pending" || reserved != "reserved" || string(ciphertext) != sealedIDPConfirmationFixture || final != nil || receipt != nil {
				t.Fatal("substituted input reached Apply or replaced pending custody", out.Outcome, err, state, reserved)
			}
		})
	}
}
