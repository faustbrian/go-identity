package postgres

import (
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func oauthRegistrationPreparationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "oauth-server", OperationID: "identity.oauth-server.dynamic-register", SchemaID: "identity.oauth-server.dynamic-register.native-public-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// This is the existing public-client preparation declaration, not a new grant
// or general-purpose recovery profile. Before final attachment, the coordinator
// cannot invoke client creation or consume the native initial token. Under its
// original claim/journal locks, absent attachment can therefore prove noncommit.
// Provider exchange and other externally effectful preparations do not inherit
// that conclusion. Token validity, current policy and metadata remain native-
// owned; this projection only permits historical observation and recovery.
func validOAuthRegistrationPreparation(b identity.CommandBinding, p CommandPlan) bool {
	op := oauthRegistrationPreparationOperation()
	native := ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}
	if p.Feature == nil || p.Feature.Operation != op || p.Feature.Contributor != native || b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectServiceAccount || b.UserID != "" || b.RecordID != string(b.CommandID) || b.AnonymousFlowID != b.RecordID || p.SubjectType != "oauth_client" {
		return false
	}
	if p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "oauth_client.created.v1", AfterVersion: 1}) || p.CommandCounters == nil || p.CommandCounters.PolicyVersion == 0 || p.CommandCounters.Fingerprint == ([32]byte{}) {
		return false
	}
	if len(p.Audits) != 1 {
		return false
	}
	audit := p.Audits[0]
	if audit.EventType != "identity.oauth_server.create_client" || audit.EventIndex != 0 || audit.SchemaVersion != 1 || !audit.Required || audit.RequiredRecordCount != 1 || audit.RetentionClass != "protected" {
		return false
	}
	if len(p.Contributors) != 5 ||
		p.Contributors[0] != (ContributorDescriptor{Owner: "identity/postgres", ContractID: "identity.domain", Version: 1}) ||
		p.Contributors[1] != (ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}) ||
		p.Contributors[2].Owner != "audit/postgres" ||
		p.Contributors[3] != (ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}) || p.Contributors[4] != native {
		return false
	}
	return !preparationProtected(p) && p.Delivery == nil && p.AccountLinkState == nil &&
		p.APIKeyVerification == nil && p.OrganizationInvitationOrigin == nil &&
		p.MFACompletion == nil && p.MFAContinuation == nil && p.MagicLinkRegistration == nil &&
		p.PasskeyRegistration == nil && !p.SignupAcceptance && !p.MagicLinkRequestAcceptance
}
