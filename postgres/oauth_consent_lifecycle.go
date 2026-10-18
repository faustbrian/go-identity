package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	identity "github.com/faustbrian/go-identity"
)

// OAuthConsentContributor is the closed native public-password OAuth consent
// owner. Pure validation exhaustively matches original consent ID/version,
// client and current command custody. Apply locks and writes the actual consent
// in the sole Work, recording its successful provisional mutation; final commit
// checks repeat original authority. The declaration is not consent or a grant.
type OAuthConsentContributor interface {
	FeatureCommitContributor
	ValidateOAuthConsent(identity.Command) error
}

// OAuthConsentLifecycleContributor atomically persists the grant's primary
// lifecycle and distinct consent event through the existing outbox. Use
// StagedOAuthConsent for the secondary record; no arbitrary caller payload,
// private transaction, retained Work, network IO or independent journal exists.
type OAuthConsentLifecycleContributor interface {
	LifecycleContributor
	PersistOAuthConsent(context.Context, Work) error
}

// OAuthConsentMutation is the trusted native owner's actual successful SQL
// mutation, still provisional. ID identifies the independent consent, never the
// grant. Creation is0→1; reconfirmation preserves ID and advances its own retained
// positive version. The value alone grants neither authority nor event staging.
type OAuthConsentMutation struct {
	ID                          string
	BeforeVersion, AfterVersion uint64
	Created                     bool
}

func oauthConsentSelected(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation.OperationID == "identity.oauth-server.continue" && p.Lifecycle != nil && (p.Lifecycle.EventType == "grant.authorized.v1" || p.Lifecycle.EventType == "grant.scope_changed.v1")
}

func validOAuthConsentProfile(b identity.CommandBinding, p CommandPlan) bool {
	op := identity.FeatureOperation{Owner: "oauth-server", OperationID: "identity.oauth-server.continue", SchemaID: "identity.oauth-server.continue.public-password-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	return oauthConsentSelected(p) && p.Feature.Operation == op && p.Feature.Contributor == (ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}) && b.ValidateFor(op) == nil && string(b.ActorID) == string(b.UserID) && p.SubjectType == "oauth_grant" && p.Lifecycle.EventIndex == 0 && p.Lifecycle.BeforeVersion > 0 && p.Lifecycle.BeforeVersion < ^uint64(0) && p.Lifecycle.AfterVersion == p.Lifecycle.BeforeVersion+1 && p.CommandCounters != nil && p.Capability == nil && p.CapabilityIssuance == nil && p.OTP == nil && p.Delivery == nil
}

// RecordOAuthConsent retains one mutation only during the exact native owner's
// Apply invocation, matching every frozen consent field in the authenticated
// command. Call only after successful owner SQL; the kernel does not inspect
// foreign tables. Invalid, duplicate, wrong-phase or foreign recording poisons
// otherwise usable Work, so ignoring rejection cannot commit prior effects.
func (w Work) RecordOAuthConsent(owner OAuthConsentContributor, mutation OAuthConsentMutation) error {
	if err := w.usable(); err != nil {
		return err
	}
	fail := func() error { return w.fail(w.state.ctx, invalidWork()) }
	b, _, _, err := w.FeatureCommandIdentity(owner)
	if err != nil || w.state.featureApplyCommand == nil || w.state.oauthConsent != nil {
		return fail()
	}
	p := w.state.execution.reservation.plan.snapshot()
	if !validOAuthConsentProfile(b, p) || mutation.ID == b.RecordID || mutation.BeforeVersion == ^uint64(0) || mutation.AfterVersion != mutation.BeforeVersion+1 || mutation.Created != (mutation.BeforeVersion == 0) {
		return fail()
	}
	if _, err := identity.ParseSubjectID(mutation.ID); err != nil {
		return fail()
	}
	s, ok := w.state.featureApplyCommand.Feature()
	if !ok {
		return fail()
	}
	matched := 0
	for _, f := range s.Fields {
		switch f.Name {
		case "oauth.consent-id":
			if f.Value.Kind != identity.FeatureText || f.Value.Text != mutation.ID {
				return fail()
			}
			matched++
		case "oauth.consent-before-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 != mutation.BeforeVersion {
				return fail()
			}
			matched++
		case "oauth.consent-after-version":
			if f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 != mutation.AfterVersion {
				return fail()
			}
			matched++
		case "oauth.consent-created":
			if f.Value.Kind != identity.FeatureBool || f.Value.Bool != mutation.Created {
				return fail()
			}
			matched++
		}
	}
	if matched != 4 {
		return fail()
	}
	copy := mutation
	w.state.oauthConsent = &copy
	return nil
}

// StagedOAuthConsent returns an owned safe secondary record only after matching
// successful primary audit/lifecycle and actual native consent recording. Fixed
// index1 cannot collide with primary index0. Creation and reconfirmation use the
// independent consent's original version, ID and primary occurrence time; this
// never fabricates grant scope changes or a downstream acknowledgement.
func (w Work) StagedOAuthConsent() (StagedLifecycle, error) {
	if err := w.usable(); err != nil {
		return StagedLifecycle{}, err
	}
	if w.state.execution == nil || w.state.execution.reservation == nil || w.state.oauthConsent == nil || w.state.featureReceipt == nil {
		return StagedLifecycle{}, invalidWork()
	}
	b := w.state.binding
	if !validOAuthConsentProfile(b, w.state.execution.reservation.plan.snapshot()) {
		return StagedLifecycle{}, invalidWork()
	}
	primary, err := w.StagedLifecycle()
	if err != nil || len(primary) != 1 || primary[0].EventIndex != 0 || primary[0].SubjectType != "oauth_grant" || primary[0].SubjectID != b.RecordID {
		return StagedLifecycle{}, invalidLifecycle()
	}
	m := w.state.oauthConsent
	event := "consent.reconfirmed.v1"
	if m.Created {
		event = "consent.created.v1"
	}
	id := sha256.Sum256(cborMap(map[string][]byte{"profile": cborText("identity-effect-id-v1"), "command_id": cborText(string(b.CommandID)), "class": cborText("lifecycle"), "index": cborUint(1)}))
	return StagedLifecycle{ID: hex.EncodeToString(id[:]), CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, OperationID: b.OperationID, EventType: event, EventIndex: 1, SubjectType: "oauth_consent", SubjectID: m.ID, BeforeVersion: m.BeforeVersion, AfterVersion: m.AfterVersion, OccurredAt: primary[0].OccurredAt}, nil
}
