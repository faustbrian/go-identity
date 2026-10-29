package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// This per-invocation owner carries no independent journal, goroutine or shared
// mutable verification state. Native preparation retains only digest-free
// authority custody; the presented secret remains in the caller's invocation.
type verificationPhase struct {
	service             *Service
	request             apikey.AtomicVerificationRequest
	presented           apikey.Digest
	candidate           *apikey.Record
	binding             identity.CommandBinding
	original, generated identity.Command
	coordinator         *kernel.Coordinator
	registry            *kernel.ContributorRegistry
	snapshot            verificationSnapshot
	applied             bool
	changed             bool
	resultRecord        *apikey.Record
}

// Scalar projections avoid accidentally invoking an owner's redacted encoder.
// Authenticated original output, not a reconstructed current read, supplies
// every epoch, permission ceiling and timestamp on resumed preparation.
type verificationSnapshot struct {
	Schema                              uint16
	Generation                          uint64
	Binding                             storedBinding
	Record                              []byte
	GlobalVersion, TenantVersion        uint64
	UserVersion, UserSecurity           uint64
	UserStatus                          identity.Status
	AuthorizationVersion, PolicyVersion uint64
	ConfigurationVersion                uint64
	Permissions                         []string
	Started, Verified, Until            time.Time
	Organization                        *organization.CredentialAuthorityObservation `json:",omitempty"`
}

func (x verificationSnapshot) owner(record apikey.Record) (apikey.Owner, error) {
	o := record.Owner.Spec()
	if o.Kind == apikey.OwnerOrganization {
		if x.Organization == nil || x.Organization.Validate(organization.CredentialAuthorityQuery{TenantID: o.TenantID, OrganizationID: organization.ID(o.OrganizationID)}, x.Verified) != nil || o.Version != x.Organization.CredentialVersion {
			return apikey.Owner{}, apikey.ErrDenied
		}
		o.Version = x.Organization.CredentialVersion
	} else {
		o.Version = x.UserSecurity
	}
	return apikey.NewOwner(o)
}

var _ kernel.APIKeyVerificationContributor = (*verificationPhase)(nil)
var _ kernel.FeaturePreparationContributor = (*verificationPhase)(nil)

func (*verificationPhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/apikey/postgres", ContractID: "identity.apikey", Version: 1}
}
func (*verificationPhase) FeatureOperations() []identity.FeatureOperation {
	return []identity.FeatureOperation{verificationOperation(false), verificationOperation(true), verificationBindingOperation(identity.CommandBinding{ActorKind: authorization.SubjectAPIKey})}
}
func (p *verificationPhase) ValidateFeatureCommand(command identity.Command, plan kernel.CommandPlan) error {
	if p == nil || p.service == nil || plan.APIKeyVerification == nil || command != p.original && command != p.generated {
		return apikey.ErrInvalid
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != p.binding || spec.Operation != verificationBindingOperation(p.binding) {
		return apikey.ErrInvalid
	}
	return nil
}
func (p *verificationPhase) ValidateFeaturePreparation(command identity.Command, plan kernel.CommandPlan) error {
	return p.ValidateFeatureCommand(command, plan)
}
func (p *verificationPhase) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	b, _, _, err := w.FeatureScope(p)
	if err != nil || command != p.original || b != p.binding {
		return apikey.ErrInvalid
	}
	// Current credential and authority comparison happens in protected Apply;
	// preparation only reserves the original native snapshot generation.
	return ctx.Err()
}

func (p *verificationPhase) snapshotContext(generation uint64) (envelope.Context, error) {
	if generation == 0 {
		return envelope.Context{}, apikey.ErrInvalid
	}
	spec, ok := p.original.Feature()
	if !ok || spec.Binding != p.binding {
		return envelope.Context{}, apikey.ErrInvalid
	}
	// Bind original scope/generation/configuration, not today's mutable key
	// version. QueryFeaturePreparation authenticates this owner and scope;
	// ExecutePreparedAPIKeyVerification separately compares the complete
	// incoming secret/permission intent after the original record is restored.
	// Including command fields here would make that original version impossible
	// to restore after an intervening key transition and effect rollback.
	wire, err := json.Marshal(struct {
		Binding       storedBinding
		Generation    uint64
		Configuration apikey.ConfigurationSpec
	}{storedBinding(p.binding), generation, p.service.config().Configuration.Spec()})
	if err != nil {
		return envelope.Context{}, apikey.ErrInvalid
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "api-key-original-verification-v1", "scope": hex.EncodeToString(digest[:])})
}

func (p *verificationPhase) GenerateFeaturePreparation(ctx context.Context, command identity.Command, generation uint64) ([]byte, error) {
	if command != p.original || generation == 0 {
		return nil, apikey.ErrInvalid
	}
	s := p.service
	started, err := s.primaryTime(ctx)
	if err != nil {
		return nil, err
	}
	directory, err := s.directory.GetDirectoryAuthority(ctx, kernel.DirectoryAuthorityQuery{GlobalAuthorityID: s.config().Profile.GlobalAuthorityID, TenantID: p.binding.TenantID})
	if err != nil || !directory.Enabled {
		return nil, apikey.ErrDenied
	}
	config, err := s.configurationAuthority(ctx, p.binding.TenantID)
	if err != nil {
		return nil, err
	}
	x := verificationSnapshot{Schema: 1, Generation: generation, Binding: storedBinding(p.binding), GlobalVersion: directory.GlobalVersion, TenantVersion: directory.TenantVersion, ConfigurationVersion: config.Version, PolicyVersion: s.config().PolicyVersion, Started: started, Permissions: []string{}}
	if p.candidate != nil {
		record, err := s.currentRecord(ctx, p.binding.TenantID, p.candidate.ID)
		if err != nil || !sameRecord(record, *p.candidate, s.config().Configuration) {
			return nil, identity.ConflictError{}
		}
		x.Record, err = encodeRecord(record, s.config().Configuration)
		if err != nil {
			return nil, err
		}
		if record.Owner.Spec().Kind == apikey.OwnerOrganization {
			if s.organization == nil || s.organization.repository == nil {
				return nil, apikey.ErrDenied
			}
			// SI-07: owner-only observation intentionally never selects the
			// creator. Its durable credential epoch is distinct from the
			// aggregate version that fences current organization policy.
			observed, err := s.organization.repository.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{TenantID: p.binding.TenantID, OrganizationID: organization.ID(record.Owner.Spec().OrganizationID)})
			if err != nil || observed.CredentialVersion != record.Owner.Spec().Version {
				return nil, apikey.ErrDenied
			}
			x.Organization = &observed
		} else {
			status, err := s.directory.GetStatus(ctx, identity.UserStatusQuery{TenantID: p.binding.TenantID, UserID: p.binding.UserID})
			if err != nil {
				return nil, err
			}
			x.UserVersion, x.UserSecurity, x.UserStatus = status.User.Version, status.AuthorityVersion, status.User.Status
			store, err := authority.NewAuthorityStore(s.pool.Raw(), s.config().MaximumDuration)
			if err != nil {
				return nil, err
			}
			policy, err := store.Get(ctx, p.authorizationScope())
			if err != nil {
				return nil, identity.UnavailableError{}
			}
			x.AuthorizationVersion = policy.Version
		}
		for _, permission := range record.Grant {
			decision, err := s.config().Authorization.Decide(ctx, p.permissionDecision(record, x, permission))
			if err != nil || decision.Revision != authorization.Revision(x.PolicyVersion) || decision.Outcome != authorization.Allow && decision.Outcome != authorization.Deny || ctx.Err() != nil {
				return nil, identity.UnavailableError{}
			}
			if decision.Outcome == authorization.Allow {
				x.Permissions = append(x.Permissions, permission)
			}
		}
	}
	x.Verified, err = s.primaryTime(ctx)
	if err != nil {
		return nil, err
	}
	// Shared issuer positive authority expires from the original read beginning;
	// the configured uncertainty/race budgets consume, never renew, that bound.
	c := s.config().Configuration.Spec()
	// PostgreSQL authority timestamps are microsecond-exact. Floor a legal
	// fractional budget rather than retain an unrestorable deadline or round
	// it upward and extend the original authority window.
	x.Until = started.Add(20*time.Second - c.ClockUncertainty - c.DecisionRaceBudget).Truncate(time.Microsecond)
	if p.candidate != nil && !p.candidate.ExpiresAt.IsZero() {
		x.Until = minTime(x.Until, p.candidate.ExpiresAt)
	}
	if x.Organization != nil {
		x.Until = minTime(x.Until, x.Organization.ValidUntil).Truncate(time.Microsecond)
	}
	if x.Verified.Before(x.Started) || x.Verified.Sub(x.Started) > c.MaximumRead || !x.Verified.Before(x.Until) {
		return nil, apikey.ErrDenied
	}
	aad, err := p.snapshotContext(generation)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(x)
	defer clear(plain)
	if err != nil || len(plain) > maximumVerificationSnapshotBytes {
		return nil, apikey.ErrInvalid
	}
	return s.seal(ctx, aad, plain)
}

func (p *verificationPhase) restore(ctx context.Context, generation uint64, wire []byte) error {
	aad, err := p.snapshotContext(generation)
	if err != nil {
		return err
	}
	plain, err := p.service.open(ctx, aad, wire, maximumVerificationSnapshotBytes)
	defer clear(plain)
	if err != nil {
		return err
	}
	var x verificationSnapshot
	if decodeCanonical(plain, &x) != nil || x.Schema != 1 || x.Generation != generation || x.Binding != storedBinding(p.binding) || x.GlobalVersion == 0 || x.TenantVersion == 0 || x.ConfigurationVersion == 0 || x.PolicyVersion != p.service.config().PolicyVersion || !exactTime(x.Started) || !exactTime(x.Verified) || !exactTime(x.Until) || x.Verified.Before(x.Started) || x.Verified.Sub(x.Started) > p.service.config().Configuration.Spec().MaximumRead || !x.Until.After(x.Verified) || x.Until.Sub(x.Started) > 20*time.Second {
		return identity.UnavailableError{}
	}
	if p.binding.ActorKind == authorization.SubjectServiceAccount {
		if len(x.Record) != 0 || x.UserVersion != 0 || x.UserSecurity != 0 || x.AuthorizationVersion != 0 || len(x.Permissions) != 0 || x.Organization != nil {
			return identity.UnavailableError{}
		}
	} else {
		record, err := decodeRecord(x.Record, p.service.config().Configuration)
		if err != nil || !verificationOwnerBinding(record, p.binding) {
			return identity.UnavailableError{}
		}
		if record.Owner.Spec().Kind == apikey.OwnerOrganization {
			// The organization read uses its application clock; this snapshot
			// uses PostgreSQL's clock. Exact interval nesting is not meaningful
			// across them. Retain both original deadlines (the earliest wins)
			// and validate the owner's original freshness below, without renewal.
			if x.Organization == nil || x.UserVersion != 0 || x.UserSecurity != 0 || x.UserStatus != "" || x.AuthorizationVersion != 0 || x.Until.After(x.Organization.ValidUntil) {
				return identity.UnavailableError{}
			}
			if _, err := x.owner(record); err != nil {
				return identity.UnavailableError{}
			}
		} else if x.Organization != nil || x.UserVersion == 0 || x.UserSecurity == 0 || x.AuthorizationVersion == 0 {
			return identity.UnavailableError{}
		}
		p.candidate = &record
	}
	p.snapshot = x
	return nil
}

func (p *verificationPhase) permissionDecision(record apikey.Record, x verificationSnapshot, permission string) authorization.DecisionContext {
	s := p.service
	dc := s.decision(p.binding.TenantID, p.binding.UserID, permission, "api-key", s.config().Configuration.Spec().ID, string(p.binding.CommandID))
	if record.Owner.Spec().Kind == apikey.OwnerOrganization && x.Organization != nil {
		dc.Request.Subject = authorization.Subject{Kind: authorization.SubjectAPIKey, ID: authorization.SubjectID(record.ID)}
		dc.Request.Resource = authorization.Resource{Type: "organization-api-key", ID: authorization.ResourceID(record.Owner.Spec().OrganizationID), Attributes: authorization.Attributes{
			"organization.version":                    authorization.StringValue(strconv.FormatUint(x.Organization.Version, 10)),
			"organization.credential-version":         authorization.StringValue(strconv.FormatUint(x.Organization.CredentialVersion, 10)),
			"api-key.configuration-id":                authorization.StringValue(record.ConfigurationID),
			"api-key.configuration-revision":          authorization.StringValue(strconv.FormatUint(record.ConfigurationRevision, 10)),
			"api-key.configuration-authority-version": authorization.StringValue(strconv.FormatUint(x.ConfigurationVersion, 10)),
			"api-key.policy-version":                  authorization.StringValue(strconv.FormatUint(x.PolicyVersion, 10)),
		}}
	}
	return dc
}

func (p *verificationPhase) RestoreFeaturePreparation(ctx context.Context, original identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if original != p.original {
		return identity.Command{}, kernel.CommandPlan{}, apikey.ErrInvalid
	}
	if err := p.restore(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	spec, _ := p.original.Feature()
	digest := sha256.Sum256(wire)
	spec.Fields = append(spec.Fields, identity.FeatureField{Name: "apikey.verify.authority", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}})
	generated, err := identity.NewFeatureCommand(spec)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	p.generated = generated
	plan, err := p.plan()
	return generated, plan, err
}

func (p *verificationPhase) authorizationScope() authority.AuthorityScope {
	return authority.AuthorityScope{TenantID: authorization.TenantID(p.binding.TenantID), PolicyNamespace: p.service.config().Profile.PolicyNamespace, SubjectID: authorization.SubjectID(p.binding.UserID)}
}

func (p *verificationPhase) check(ctx context.Context, w kernel.Work) error {
	x := p.snapshot
	directory := kernel.DirectoryAuthorityAdmission{Query: kernel.DirectoryAuthorityQuery{GlobalAuthorityID: p.service.config().Profile.GlobalAuthorityID, TenantID: p.binding.TenantID}, GlobalVersion: x.GlobalVersion, TenantVersion: x.TenantVersion}
	if err := w.RequireActiveDirectoryAuthority(ctx, p, directory); err != nil {
		return err
	}
	if p.binding.UserID != "" {
		status := identity.UserStatusRecord{User: identity.User{ID: p.binding.UserID, TenantID: p.binding.TenantID, Status: x.UserStatus, Version: x.UserVersion}, AuthorityVersion: x.UserSecurity}
		if err := w.RequireActiveUserStatus(ctx, p, status); err != nil {
			return err
		}
		if err := w.RequireActiveUserAuthorization(ctx, p, kernel.UserAuthorizationAdmission{Scope: p.authorizationScope(), Version: x.AuthorizationVersion}); err != nil {
			return err
		}
	}
	if x.Organization != nil {
		if p.service.organization == nil || p.service.organization.repository == nil {
			return apikey.ErrDenied
		}
		if err := p.service.organization.repository.RequireCredentialAuthority(ctx, w, p, *x.Organization); err != nil {
			return err
		}
	}
	// Same lock order as native key management: directory/user first, then
	// configuration UPDATE, then exact key UPDATE. Never upgrade a SHARE lock.
	rows, err := w.Query(ctx, `SELECT authority_version::text,configuration_digest,enabled FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2 FOR UPDATE`, string(p.binding.TenantID), p.service.config().Configuration.Spec().ID)
	if err != nil {
		return err
	}
	var version string
	var digest []byte
	var enabled bool
	if !rows.Next() || rows.Scan(&version, &digest, &enabled) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.UnavailableError{}
	}
	rows.Close()
	want, _ := configurationDigest(p.service.config().Configuration)
	expected := x.ConfigurationVersion
	if p.applied && p.changed {
		expected++
	}
	if !enabled || version != strconv.FormatUint(expected, 10) || !bytes.Equal(digest, want[:]) {
		return apikey.ErrDenied
	}
	at, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if at.Before(x.Verified) || !at.Before(x.Until) {
		return apikey.ErrDenied
	}
	return nil
}

func (*verificationPhase) ApplyFeature(context.Context, kernel.Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, apikey.ErrInvalid
}

func (p *verificationPhase) ApplyAPIKeyVerification(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, kernel.APIKeyVerificationOutcome, error) {
	zero := func(err error) (identity.FeatureReceipt, kernel.APIKeyVerificationOutcome, error) {
		return identity.FeatureReceipt{}, kernel.APIKeyVerificationOutcome{}, err
	}
	if command != p.generated || w.RequireFeatureCommand(ctx, p, command) != nil {
		return zero(apikey.ErrInvalid)
	}
	wire, generation, err := w.FeaturePreparationOutput(p)
	defer clear(wire)
	if err != nil || p.restore(ctx, generation, wire) != nil {
		return zero(identity.UnavailableError{})
	}
	if err := p.check(ctx, w); err != nil {
		return zero(err)
	}
	outcome := kernel.APIKeyVerificationOutcome{}
	effect := verificationEffect{Schema: 1, Snapshot: p.snapshot, Grant: []string{}}
	if p.candidate != nil {
		record, stored, err := p.lockKey(ctx, w, *p.candidate)
		if err != nil {
			return zero(err)
		}
		// Constant-time comparison includes pepper version and every digest byte.
		presented, err := p.service.presentedDigest(p.request)
		if err != nil {
			return zero(err)
		}
		valid := presented.Equal(stored)
		if valid && record.Status == apikey.KeyActive && (record.ExpiresAt.IsZero() || p.snapshot.Verified.Before(record.ExpiresAt)) {
			owner, err := p.snapshot.owner(record)
			if err != nil {
				return zero(err)
			}
			a := apikey.CurrentAuthority{Owner: owner, OwnerActive: true, TenantActive: true, Permissions: slices.Clone(p.snapshot.Permissions), PolicyVersion: p.snapshot.PolicyVersion, ConfigurationAuthority: apikey.ConfigurationAuthorityBinding{TenantID: p.binding.TenantID, ConfigurationID: record.ConfigurationID, Version: p.snapshot.ConfigurationVersion}, ReadStartedAt: p.snapshot.Started, VerifiedAt: p.snapshot.Verified, ValidUntil: p.snapshot.Until}
			grant, err := (apikey.ScopePolicy{}).EffectiveGrant(record, a, p.service.config().Configuration, p.snapshot.Verified)
			if err != nil {
				return zero(err)
			}
			if !slices.Equal(grant, record.Grant) {
				decision, err := (apikey.ScopePolicy{}).DecidePermissionReduction(p.binding.CommandID, record, a, p.service.config().Configuration, p.snapshot.Verified)
				if err != nil {
					return zero(err)
				}
				record.Owner, record.Grant = owner, slices.Clone(decision.Grant)
				record.Version++
				record.AuthorityVersion++
				record.RootVersion++
				if err := p.persistReduction(ctx, w, record); err != nil {
					return zero(err)
				}
				outcome.PermissionsChanged, p.changed = true, true
			}
			outcome.Authenticated = record.Status == apikey.KeyActive
			for _, required := range p.request.RequiredPermissions {
				outcome.Authenticated = outcome.Authenticated && slices.Contains(grant, required)
			}
			effect.Grant = slices.Clone(grant)
		}
		p.resultRecord = &record
		effect.Record, err = encodeRecord(record, p.service.config().Configuration)
		if err != nil {
			return zero(err)
		}
	}
	effect.Authenticated = outcome.Authenticated
	if outcome.PermissionsChanged {
		effect.Snapshot.ConfigurationVersion++
	}
	if err := p.persistEffect(ctx, w, effect); err != nil {
		return zero(err)
	}
	p.applied = true
	return identity.FeatureReceipt{Operation: verificationBindingOperation(p.binding)}, outcome, nil
}

func (p *verificationPhase) lockKey(ctx context.Context, w kernel.Work, expected apikey.Record) (apikey.Record, apikey.Digest, error) {
	query := `SELECT coalesce(user_id::text,''),pepper_version,lookup_digest,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3 FOR UPDATE`
	args := []any{string(p.binding.TenantID), expected.ConfigurationID, string(expected.ID)}
	if expected.Owner.Spec().Kind == apikey.OwnerOrganization {
		query = `SELECT coalesce(user_id::text,''),pepper_version,lookup_digest,record FROM identity_api_keys.keys WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3 AND organization_id=$4 FOR UPDATE`
		args = append(args, string(expected.Owner.Spec().OrganizationID))
	}
	rows, err := w.Query(ctx, query, args...)
	if err != nil {
		return apikey.Record{}, apikey.Digest{}, err
	}
	defer rows.Close()
	var user string
	var pepper int64
	var digest, wire []byte
	if !rows.Next() || rows.Scan(&user, &pepper, &digest, &wire) != nil || rows.Next() || rows.Err() != nil {
		return apikey.Record{}, apikey.Digest{}, identity.UnavailableError{}
	}
	record, err := decodeRecord(wire, p.service.config().Configuration)
	legacy := p.service.config().Configuration.Spec().Algorithm == apikey.AlgorithmLegacySHA256V1
	validPepper := legacy && pepper == 0 || !legacy && pepper >= 1 && pepper <= 4294967295
	if err != nil || user != string(p.binding.UserID) || !sameRecord(record, expected, p.service.config().Configuration) || !validPepper || len(digest) != 32 {
		return apikey.Record{}, apikey.Digest{}, identity.ConflictError{}
	}
	return record, apikey.Digest{PepperVersion: uint32(pepper), Sum: [32]byte(digest)}, nil
}

func (p *verificationPhase) persistReduction(ctx context.Context, w kernel.Work, record apikey.Record) error {
	wire, err := encodeRecord(record, p.service.config().Configuration)
	if err != nil {
		return err
	}
	n, err := w.Exec(ctx, `UPDATE identity_api_keys.keys SET record=$4 WHERE tenant_id=$1 AND configuration_id=$2 AND key_id=$3`, string(p.binding.TenantID), record.ConfigurationID, string(record.ID), wire)
	if err != nil || n != 1 {
		return identity.ConflictError{}
	}
	n, err = w.Exec(ctx, `UPDATE identity_api_keys.configurations SET authority_version=authority_version+1 WHERE tenant_id=$1 AND configuration_id=$2 AND authority_version=$3::numeric`, string(p.binding.TenantID), record.ConfigurationID, strconv.FormatUint(p.snapshot.ConfigurationVersion, 10))
	if err != nil || n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *verificationPhase) persistEffect(ctx context.Context, w kernel.Work, effect verificationEffect) error {
	b, fp, generation, err := w.FeatureCommandIdentity(p)
	if err != nil || b != p.binding || fp == ([32]byte{}) || generation == 0 {
		return apikey.ErrInvalid
	}
	bound, err := json.Marshal(storedBinding(b))
	if err != nil {
		return err
	}
	wire, err := json.Marshal(effect)
	if err != nil || len(wire) > maximumCommandEffectBytes {
		return apikey.ErrInvalid
	}
	id := string(b.ActorID)
	if b.ActorKind == authorization.SubjectServiceAccount {
		id = string(b.CommandID)
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_api_keys.command_effects(command_id,tenant_id,key_id,binding,fingerprint,generation,record) VALUES($1,$2,$3,$4,$5,$6::numeric,$7)`, string(b.CommandID), string(b.TenantID), id, bound, fp[:], strconv.FormatUint(generation, 10), wire)
	if err != nil || n != 1 {
		return identity.UnavailableError{}
	}
	return nil
}

func (p *verificationPhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if command != p.generated || !p.applied {
		return apikey.ErrInvalid
	}
	if err := p.check(ctx, w); err != nil {
		return err
	}
	if p.resultRecord != nil {
		_, _, err := p.lockKey(ctx, w, *p.resultRecord)
		return err
	}
	return nil
}

func (p *verificationPhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	rows, err := w.Query(ctx, `SELECT EXISTS(SELECT 1 FROM identity_api_keys.command_effects WHERE command_id=$1 AND tenant_id=$2)`, string(b.CommandID), string(b.TenantID))
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	defer rows.Close()
	var exists bool
	if !rows.Next() || rows.Scan(&exists) != nil || rows.Next() || rows.Err() != nil {
		return kernel.RecoveryUnknown, identity.UnavailableError{}
	}
	if exists {
		return kernel.RecoveryCommitted, nil
	}
	return kernel.RecoveryNotCommitted, nil
}
