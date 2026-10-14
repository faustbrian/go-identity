package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"slices"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
)

var _ identitypostgres.CaptchaReplayContributor = (*Repository)(nil)

// ReserveCaptchaReplay claims every retained provider-token alias under one
// original command, in the coordinator's reservation transaction. It
// authenticates exact selected configuration before SQL, reveals no reference
// and runs no provider, clock callback or private transaction. Alias ownership
// survives domain rollback/expiry; a different command always conflicts.
// Errors require coordinator rollback. Handles are serial-use and not retained.
func (r *Repository) ReserveCaptchaReplay(ctx context.Context, w identitypostgres.CaptchaReservationWork) error {
	return r.reserveCaptcha(ctx, w, false)
}

// RebindCaptchaReplay conserves the original winner and all aliases while CAS
// transferring exactly the predecessor generation to the coordinator's new
// owner. It never releases unresolved ownership, replaces signed input, extends
// evidence validity or grants domain/protected-use authority.
func (r *Repository) RebindCaptchaReplay(ctx context.Context, w identitypostgres.CaptchaReservationWork) error {
	return r.reserveCaptcha(ctx, w, true)
}

func (r *Repository) restoreCaptcha(c identity.Command) (risk.CaptchaEvidenceIssue, error) {
	if r == nil || len(r.captcha) == 0 {
		return risk.CaptchaEvidenceIssue{}, risk.ErrInvalidEvidenceExecution
	}
	issue, err := restoreCaptchaCommand(c, r.keys, r.policy)
	if err != nil {
		return risk.CaptchaEvidenceIssue{}, err
	}
	for _, custody := range r.captcha {
		if restored, err := custody.RestoreCaptchaIssue(issue.Prepared()); err == nil {
			return restored, nil
		}
	}
	return risk.CaptchaEvidenceIssue{}, risk.ErrInvalidEvidenceExecution
}

func (r *Repository) reserveCaptcha(ctx context.Context, w identitypostgres.CaptchaReservationWork, rebind bool) error {
	if ctx == nil || r == nil || r.schema == "" {
		return risk.ErrInvalidEvidenceExecution
	}
	owner, err := w.Binding(r)
	if err != nil {
		return err
	}
	issue, err := r.restoreCaptcha(owner.Command)
	if err != nil || owner.Generation == 0 || owner.Fingerprint == ([32]byte{}) || !rebind && owner.PreviousGeneration != 0 || rebind && (owner.PreviousGeneration == 0 || owner.PreviousGeneration == ^uint64(0) || owner.Generation != owner.PreviousGeneration+1) {
		return identity.ConflictError{}
	}
	spec, _ := owner.Command.Feature()
	b, p := spec.Binding, issue.Prepared()
	replay := p.Binding.Replay
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return identity.ConflictError{}
	}
	link := bindingDigest(b)
	var keyCustodies []risk.CaptchaReplayKeyCustody
	for _, custody := range r.captcha {
		if _, err := custody.RestoreCaptchaIssue(p); err == nil {
			keyCustody, err := custody.ReplayKeyCustody()
			if err != nil {
				return err
			}
			keyCustodies = append(keyCustodies, keyCustody)
		}
	}
	if err := r.reserveCaptchaScope(ctx, w, replay, keyCustodies, rebind); err != nil {
		return err
	}
	if !rebind {
		now, err := w.DatabaseTime(ctx)
		if err != nil {
			return err
		}
		if _, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.captcha_replay_winners(tenant_id,command_id,command_purpose,command_fingerprint,generation,binding_digest,intent_digest,configuration_digest,provider,site,api_profile,configuration_version,reserved_at) VALUES($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT DO NOTHING`, string(b.TenantID), id, b.OperationID, owner.Fingerprint[:], strconv.FormatUint(owner.Generation, 10), link[:], p.Binding.IntentDigest[:], p.ConfigurationDigest[:], replay.Provider, replay.Site, replay.APIProfile, replay.ConfigurationVersion, now); err != nil {
			return err
		}
	}
	rows, err := w.Query(ctx, `SELECT command_fingerprint,generation::text,binding_digest,intent_digest,configuration_digest,provider,site,api_profile,configuration_version FROM `+r.schema+`.captcha_replay_winners WHERE tenant_id=$1 AND command_id=$2 FOR UPDATE`, string(b.TenantID), id)
	if err != nil {
		return err
	}
	var fingerprint, binding, intent, configuration []byte
	var generation, provider, site, profile, version string
	matched := rows.Next() && rows.Scan(&fingerprint, &generation, &binding, &intent, &configuration, &provider, &site, &profile, &version) == nil
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	expected := owner.Generation
	if rebind {
		expected = owner.PreviousGeneration
	}
	if !matched || generation != strconv.FormatUint(expected, 10) || !bytes.Equal(fingerprint, owner.Fingerprint[:]) || !bytes.Equal(binding, link[:]) || !bytes.Equal(intent, p.Binding.IntentDigest[:]) || !bytes.Equal(configuration, p.ConfigurationDigest[:]) || provider != replay.Provider || site != replay.Site || profile != replay.APIProfile || version != replay.ConfigurationVersion {
		return identity.ConflictError{}
	}
	// A consistent lexical order includes non-newest retained aliases. Different
	// key order/set overlap cannot deadlock by taking common aliases oppositely.
	aliases := slices.Clone(replay.Keys)
	slices.SortFunc(aliases, func(a, b risk.CaptchaReplayDigest) int {
		return bytes.Compare([]byte(a.Fingerprint), []byte(b.Fingerprint))
	})
	for _, alias := range aliases {
		args := []any{string(b.TenantID), replay.Provider, replay.Site, replay.APIProfile, replay.ConfigurationVersion, alias.Fingerprint, id}
		if !rebind {
			if _, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.captcha_replay_aliases(tenant_id,provider,site,api_profile,configuration_version,fingerprint,command_id) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, args...); err != nil {
				return err
			}
		}
		rows, err := w.Query(ctx, `SELECT command_id FROM `+r.schema+`.captcha_replay_aliases WHERE tenant_id=$1 AND provider=$2 AND site=$3 AND api_profile=$4 AND configuration_version=$5 AND fingerprint=$6 FOR UPDATE`, args[:6]...)
		if err != nil {
			return err
		}
		var winner []byte
		matched := rows.Next() && rows.Scan(&winner) == nil
		if rows.Next() || rows.Err() != nil {
			matched = false
		}
		rows.Close()
		if !matched || !bytes.Equal(winner, id) {
			return identity.ConflictError{}
		}
		versions := append(args[:6:6], int64(alias.Version))
		if !rebind {
			if _, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.captcha_replay_alias_versions VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, versions...); err != nil {
				return err
			}
		} else {
			rows, err := w.Query(ctx, `SELECT key_version FROM `+r.schema+`.captcha_replay_alias_versions WHERE tenant_id=$1 AND provider=$2 AND site=$3 AND api_profile=$4 AND configuration_version=$5 AND fingerprint=$6 AND key_version=$7`, versions...)
			if err != nil {
				return err
			}
			var retained int64
			matched := rows.Next() && rows.Scan(&retained) == nil && retained == int64(alias.Version)
			if rows.Next() || rows.Err() != nil {
				matched = false
			}
			rows.Close()
			if !matched {
				return identity.ConflictError{}
			}
		}
	}
	if rebind {
		count, err := w.Exec(ctx, `UPDATE `+r.schema+`.captcha_replay_winners SET generation=$3::numeric WHERE tenant_id=$1 AND command_id=$2 AND generation=$4::numeric AND command_fingerprint=$5`, string(b.TenantID), id, strconv.FormatUint(owner.Generation, 10), strconv.FormatUint(owner.PreviousGeneration, 10), owner.Fingerprint[:])
		if err != nil {
			return err
		}
		if count != 1 {
			return identity.ConflictError{}
		}
	}
	return nil
}

// Scope ownership is a SQL lock in the existing reservation transaction, not
// another command journal. Serialize before reading key history so two fresh
// disjoint configurations cannot both observe an empty retention set.
func (r *Repository) reserveCaptchaScope(ctx context.Context, w identitypostgres.CaptchaReservationWork, replay risk.CaptchaReplayBinding, candidates []risk.CaptchaReplayKeyCustody, rebind bool) error {
	args := []any{replay.Flow.Tenant, replay.Provider, replay.Site, replay.APIProfile, replay.ConfigurationVersion}
	if !rebind {
		if _, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.captcha_replay_scopes VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, args...); err != nil {
			return err
		}
	}
	rows, err := w.Query(ctx, `SELECT tenant_id FROM `+r.schema+`.captcha_replay_scopes WHERE tenant_id=$1 AND provider=$2 AND site=$3 AND api_profile=$4 AND configuration_version=$5 FOR UPDATE`, args...)
	if err != nil {
		return err
	}
	var tenant string
	matched := rows.Next() && rows.Scan(&tenant) == nil && tenant == replay.Flow.Tenant
	if rows.Next() || rows.Err() != nil {
		matched = false
	}
	rows.Close()
	if !matched {
		return identity.ConflictError{}
	}
	rows, err = w.Query(ctx, `SELECT key_version,commitment FROM `+r.schema+`.captcha_replay_scope_keys WHERE tenant_id=$1 AND provider=$2 AND site=$3 AND api_profile=$4 AND configuration_version=$5 ORDER BY key_version LIMIT 17`, args...)
	if err != nil {
		return err
	}
	var retained []risk.CaptchaReplayKeyIdentity
	for rows.Next() {
		var version int64
		var commitment []byte
		if err := rows.Scan(&version, &commitment); err != nil {
			rows.Close()
			return err
		}
		if len(retained) >= 16 || version <= 0 || version > 4294967295 || len(commitment) != 32 {
			rows.Close()
			return identity.ConflictError{}
		}
		key := risk.CaptchaReplayKeyIdentity{Version: uint32(version)}
		copy(key.Commitment[:], commitment)
		retained = append(retained, key)
		if !rebind {
			found := false
			for _, alias := range replay.Keys {
				if int64(alias.Version) == version {
					found = true
					break
				}
			}
			if !found {
				rows.Close()
				return identity.ConflictError{}
			}
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// One selected, authenticated profile must cover the complete retained
	// history. Never splice keys from incompatible profiles. Historical rebind
	// conserves its original alias subset while a newer retained profile may
	// supply additional versions referenced by other commands in this scope.
	var custody risk.CaptchaReplayKeyCustody
	for _, candidate := range candidates {
		complete := true
		for _, prior := range retained {
			found := false
			for _, key := range candidate.Keys {
				if key == prior {
					found = true
					break
				}
			}
			if !found {
				complete = false
				break
			}
		}
		if complete {
			custody = candidate
			break
		}
	}
	if len(custody.Keys) == 0 {
		return identity.ConflictError{}
	}
	if !rebind {
		for _, alias := range replay.Keys {
			found := false
			for _, key := range custody.Keys {
				if key.Version != alias.Version {
					continue
				}
				found = true
				if _, err := w.Exec(ctx, `INSERT INTO `+r.schema+`.captcha_replay_scope_keys VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, append(args[:5:5], int64(key.Version), key.Commitment[:])...); err != nil {
					return err
				}
				break
			}
			if !found {
				return identity.ConflictError{}
			}
		}
	}
	return nil
}
