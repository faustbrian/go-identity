package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
)

// The reader comes from the designated audit primary, not from the restricted
// callback role or an outbox message. The current connection row cannot prove
// an older disable once a subsequent operator transition has committed.
func readProxyProviderDisable(ctx context.Context, reader *auditpg.Store, actor identity.ActorID, c ProviderAuthorityChange) error {
	denied := identity.ForbiddenError{}
	if ctx == nil || reader == nil || !rpDirectoryID(string(actor)) || !validProviderAuthorityKey(c.Key) ||
		c.Next.Enabled || c.ExpectedVersion == 0 || c.Next.Version <= c.ExpectedVersion || c.Next.ProfileVersion == 0 {
		return denied
	}
	if _, err := identity.ParseCommandID(string(c.CommandID)); err != nil {
		return denied
	}
	tenant, err := audit.Tenant(string(c.Key.TenantID))
	if err != nil {
		return denied
	}
	command, operator := string(c.CommandID), string(actor)
	filters := audit.QueryInput{
		Tenant: tenant, RecordID: providerAuthorityRecordPrefix + command, ActorID: operator,
		SubjectType: "social_connection", SubjectID: c.Key.ProviderID, Action: providerAuthorityDisableAudit,
		CorrelationID: command, Outcome: audit.OutcomeSucceeded, Limit: 1,
	}
	query, err := audit.NewQuery(filters)
	if err != nil {
		return denied
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	page, err := reader.Query(bounded, query)
	if err != nil || bounded.Err() != nil {
		return providerAuthorityFailure(bounded)
	}
	if len(page.Records) != 1 || !page.Next.IsZero() {
		return denied
	}
	record := page.Records[0]
	subject, originalActor, scope := record.Subject(), record.Actor(), record.Context()
	if record.ID() != filters.RecordID || record.Action() != filters.Action || record.Outcome() != filters.Outcome ||
		originalActor.Kind() != audit.ActorService || originalActor.ID() != operator ||
		subject.Type() != filters.SubjectType || subject.ID() != filters.SubjectID || subject.Deleted() ||
		scope.TenantID() != string(c.Key.TenantID) || scope.CorrelationID() != command {
		return denied
	}
	versions := record.Attributes()
	if len(versions) != 3 || versions["connection.previous_version"] != strconv.FormatUint(c.ExpectedVersion, 10) ||
		versions["connection.version"] != strconv.FormatUint(c.Next.Version, 10) ||
		versions["connection.profile_version"] != strconv.FormatUint(c.Next.ProfileVersion, 10) {
		return denied
	}
	return nil
}

// The caller has authenticated both the historical disable and the original
// custody binding. Disable covers still-retained earlier profiles as well as
// the last enabled epoch, never the legacy no-epoch mode or a later re-enable.
func proxyProviderDisableCoversOriginal(disable ProviderAuthorityChange, original oauth.ProxyOIDCEvidenceBinding) bool {
	return original.TenantID == disable.Key.TenantID && original.ProviderID == disable.Key.ProviderID &&
		original.ProviderAuthorityEpoch > 0 && original.ProviderAuthorityEpoch <= disable.ExpectedVersion &&
		original.ProviderVersion > 0 && original.ProviderVersion <= disable.Next.ProfileVersion
}
