package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

const (
	providerDisableCascadeTopic    = "social_provider.disabled.v1"
	providerDisableCascadeManifest = "identity-lifecycle-consumers-v1"
	providerDisableCascadeHold     = "not_applicable"
)

// ProviderDisableConsumer is a required, versioned consumer of this generation.
// Listing a consumer does not assert that its adapter exists or has run.
type ProviderDisableConsumer struct {
	ID              string `json:"id"`
	ContractVersion uint16 `json:"contract_version"`
}

// ProviderDisableAdmission records one committed pending generation. It is
// historical evidence, not current connection authority or a cleanup receipt.
// The caller owns Consumers. Keep these correlation IDs within trusted tooling.
type ProviderDisableAdmission struct {
	CascadeID            identity.CascadeID
	Generation           uint64
	Disable              ProviderAuthorityChange
	EventID              identity.CommandID
	EventTopic           string
	EventVersion         uint16
	ManifestVersion      string
	Consumers            []ProviderDisableConsumer
	Status               identity.RevocationStatus
	AdmittedAt, Deadline time.Time
}

type providerDisableCascadeSelection struct {
	window    time.Duration
	admission ProviderDisableAdmission
}

// ApplyDisableCascade atomically disables the selected connection and admits
// a pending cleanup generation with the existing audit and outbox event.
// Install ProviderDisableCascadeMigrationSource before selecting this method.
// Window defaults to seven days; explicit whole-second windows span one hour
// to thirty days. Retry an uncertain commit with the original command and
// window. Later re-enable does not change that command's retained admission.
// A disable originally committed through Apply cannot acquire admission later.
func (o *ProviderAuthorityOperator) ApplyDisableCascade(ctx context.Context, c ProviderAuthorityChange, window time.Duration) (ProviderDisableAdmission, error) {
	if c.Next.Enabled || c.ExpectedVersion == 0 {
		return ProviderDisableAdmission{}, providerAuthorityInvalid()
	}
	window, err := providerDisableCascadeWindow(window)
	if err != nil {
		return ProviderDisableAdmission{}, err
	}
	selection := providerDisableCascadeSelection{window: window}
	if _, err := o.apply(ctx, c, &selection); err != nil {
		return ProviderDisableAdmission{}, err
	}
	return selection.admission, nil
}

func providerDisableCascadeWindow(window time.Duration) (time.Duration, error) {
	if window == 0 {
		return 7 * 24 * time.Hour, nil
	}
	if window < time.Hour || window > 30*24*time.Hour || window%time.Second != 0 {
		return 0, identity.InvalidInputError{Field: "oauth_provider_disable_cascade_window"}
	}
	return window, nil
}

// This is the frozen social-provider-disable v1 list, not the identifier
// cleanup list. No owner disappears merely because its adapter is absent.
func providerDisableCascadeConsumers() []ProviderDisableConsumer {
	return []ProviderDisableConsumer{
		{"identity/oauth", 1}, {"identity/oauth/onetap", 1}, {"identity/oauth/proxy", 1},
		{"identity", 1}, {"identity/session", 1}, {"identity/session/valkey", 1},
		{"identity/delivery", 1}, {"audit", 1},
	}
}

func providerDisableCascadeReadSQL(table string) string {
	return `SELECT provider_id,actor_id,previous_version::text,disabled_version::text,profile_version::text,
 cascade_id,generation,manifest_version,event_topic,event_version,consumer_contracts,status,legal_hold_state,admitted_at,deadline_at
 FROM ` + table + ` WHERE tenant_id=$1 AND source_command_id=$2`
}

func providerDisableCascadeInsertSQL(table string) string {
	return `INSERT INTO ` + table + `(
 tenant_id,source_command_id,provider_id,actor_id,previous_version,disabled_version,profile_version,cascade_id,
 generation,manifest_version,event_topic,event_version,consumer_contracts,status,legal_hold_state,admitted_at,deadline_at)
 VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7::numeric,$8,1,$9,$10,1,$11::jsonb,1,'not_applicable',$12,$13)`
}

func (o *ProviderAuthorityOperator) readDisableCascade(ctx context.Context, tx pgx.Tx, c ProviderAuthorityChange, window time.Duration) (ProviderDisableAdmission, error) {
	row := tx.QueryRow(ctx, providerDisableCascadeReadSQL(o.authority.cascadeTable), string(c.Key.TenantID), string(c.CommandID))
	admission, err := decodeProviderDisableAdmission(ctx, row, c.Key.TenantID, c.CommandID, o.actor)
	if err != nil || admission.CascadeID == "" {
		return admission, err
	}
	if admission.Disable != c || admission.Deadline.Sub(admission.AdmittedAt) != window {
		return ProviderDisableAdmission{}, identity.ConflictError{}
	}
	return admission, nil
}

func decodeProviderDisableAdmission(ctx context.Context, row pgx.Row, tenant identity.TenantID, command identity.CommandID, operator identity.ActorID) (ProviderDisableAdmission, error) {
	var provider, actor, previous, disabled, profile, rawID, manifest, topic, hold string
	var generation int64
	var version, status int16
	var contracts []byte
	var admitted, deadline time.Time
	err := row.Scan(&provider, &actor, &previous, &disabled, &profile, &rawID, &generation, &manifest, &topic, &version,
		&contracts, &status, &hold, &admitted, &deadline)
	if ctx.Err() != nil {
		return ProviderDisableAdmission{}, ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ProviderDisableAdmission{}, nil
	}
	if err != nil {
		return ProviderDisableAdmission{}, providerAuthorityFailure(ctx)
	}
	if actor != string(operator) {
		return ProviderDisableAdmission{}, identity.ForbiddenError{}
	}
	id, err := identity.ParseCascadeID(rawID)
	prior, pErr := strconv.ParseUint(previous, 10, 64)
	epoch, eErr := strconv.ParseUint(disabled, 10, 64)
	configuration, cErr := strconv.ParseUint(profile, 10, 64)
	_, windowErr := providerDisableCascadeWindow(deadline.Sub(admitted))
	var consumers []ProviderDisableConsumer
	if err != nil || generation != 1 || manifest != providerDisableCascadeManifest || topic != providerDisableCascadeTopic ||
		version != 1 || status != int16(identity.RevocationPending) || hold != providerDisableCascadeHold || admitted.IsZero() ||
		deadline.IsZero() || !deadline.After(admitted) || windowErr != nil || !rpProviderID(provider) ||
		pErr != nil || eErr != nil || cErr != nil || prior == 0 || epoch <= prior || configuration == 0 ||
		json.Unmarshal(contracts, &consumers) != nil || !slices.Equal(consumers, providerDisableCascadeConsumers()) {
		return ProviderDisableAdmission{}, identity.UnavailableError{}
	}
	change := ProviderAuthorityChange{Key: ProviderAuthorityKey{TenantID: tenant, ProviderID: provider}, ExpectedVersion: prior,
		Next: ProviderAuthorityState{Version: epoch, ProfileVersion: configuration}, CommandID: command}
	return ProviderDisableAdmission{CascadeID: id, Generation: 1, Disable: change, EventID: command, EventTopic: topic,
		EventVersion: 1, ManifestVersion: manifest, Consumers: consumers, Status: identity.RevocationPending,
		AdmittedAt: admitted.UTC(), Deadline: deadline.UTC()}, nil
}

func (o *ProviderAuthorityOperator) stageDisableCascade(ctx context.Context, tx pgx.Tx, c ProviderAuthorityChange, accepted time.Time, window time.Duration) (ProviderDisableAdmission, error) {
	id, err := identity.NewCascadeID()
	if err != nil {
		return ProviderDisableAdmission{}, providerAuthorityFailure(ctx)
	}
	consumers := providerDisableCascadeConsumers()
	contracts, err := json.Marshal(consumers)
	if err != nil {
		return ProviderDisableAdmission{}, providerAuthorityFailure(ctx)
	}
	deadline := accepted.Add(window)
	written, err := tx.Exec(ctx, providerDisableCascadeInsertSQL(o.authority.cascadeTable),
		string(c.Key.TenantID), string(c.CommandID), c.Key.ProviderID, string(o.actor),
		providerAuthorityVersion(c.ExpectedVersion), providerAuthorityVersion(c.Next.Version), providerAuthorityVersion(c.Next.ProfileVersion),
		string(id), providerDisableCascadeManifest, providerDisableCascadeTopic, contracts, accepted, deadline)
	if err != nil || written.RowsAffected() != 1 {
		return ProviderDisableAdmission{}, providerAuthorityFailure(ctx)
	}
	return ProviderDisableAdmission{CascadeID: id, Generation: 1, Disable: c, EventID: c.CommandID, EventTopic: providerDisableCascadeTopic,
		EventVersion: 1, ManifestVersion: providerDisableCascadeManifest, Consumers: consumers, Status: identity.RevocationPending,
		AdmittedAt: accepted, Deadline: deadline}, nil
}
