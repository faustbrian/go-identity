//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
)

func testCommandClaims(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}, 2: {2}}}
	request := claimRequest{commandID: "AAAAAAAAAAAAAAAAAAAAAQ", tenant: "tenant-a", purpose: "identity.user.create", canonical: []byte{0xa1, 0x61, 'a', 0x01}, safeFields: []byte{0xa0}}
	execute := func(q claimRequest, k claimKeys, persist bool) (claimDisposition, error) {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal("claim transaction unavailable")
		}
		defer tx.Rollback(ctx)
		result, err := lockCommandClaim(ctx, tx, q, k)
		if err != nil {
			return result, err
		}
		if result == claimNew && persist {
			id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
			_, err = tx.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose)
SELECT command_id,tenant_id,purpose FROM identity.identity_command_id_claims WHERE command_id=$1`, id)
			if err != nil {
				t.Fatal("scoped journal fixture failed")
			}
		}
		if tx.Commit(ctx) != nil {
			t.Fatal("claim transaction commit failed")
		}
		return result, nil
	}
	if got, err := execute(request, keys, true); err != nil || got != claimNew {
		t.Fatal("initial claim denied")
	}
	if got, err := execute(request, keys, true); err != nil || got != claimReplay {
		t.Fatal("exact replay failed")
	}
	rotated := keys
	rotated.current = 2
	typed := codecCreation(t, []identity.AttributeUpdate{{Name: "private", Value: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "synthetic"}}}})
	prepared, err := prepareClaim(typed, keys.retained[keys.current])
	if err != nil {
		t.Fatal("typed claim preparation failed")
	}
	if got, err := execute(prepared, keys, true); err != nil || got != claimNew {
		t.Fatal("typed initial admission failed")
	}
	prepared, err = prepareClaim(typed, rotated.retained[rotated.current])
	if err != nil {
		t.Fatal("rotated typed preparation failed")
	}
	if got, err := execute(prepared, rotated, true); err != nil || got != claimReplay {
		t.Fatal("stored-key secret re-encoding failed")
	}
	for _, build := range []func(bool) identity.Command{
		func(changed bool) identity.Command {
			return recordLink(t, identity.AccountLinkImplicit, func(s *identity.AccountLinkCommand) {
				if changed {
					s.Change.ExpectedUserVersion++
				}
			}, nil, "proof-key")
		},
		func(changed bool) identity.Command {
			return recordUnlink(t, func(s *identity.AccountUnlinkCommand) {
				s.Binding.CommandID = "AAAAAAAAAAAAAAAAAAAABg"
				if changed {
					s.RevokeProvider = false
				}
			}, nil)
		},
		func(changed bool) identity.Command {
			return recordIdentifier(t, identity.IdentifierReplace, func(s *identity.IdentifierCommand) {
				s.Binding.CommandID = "AAAAAAAAAAAAAAAAAAAABw"
				if changed {
					s.Change.CanonicalValue = "changed@example.test"
				}
			}, nil)
		},
		func(changed bool) identity.Command {
			return recordPrivacy(t, func(s *identity.PrivacyExportRequestCommand) {
				if changed {
					s.ExpectedPrivacyEpoch++
				}
			}, nil, "privacy-key")
		},
	} {
		q, err := prepareClaim(build(false), keys.retained[keys.current])
		if err != nil {
			t.Fatal("record command preparation failed")
		}
		if got, err := execute(q, keys, true); err != nil || got != claimNew {
			t.Fatal("record claim failed")
		}
		q, err = prepareClaim(build(false), rotated.retained[rotated.current])
		if err != nil {
			t.Fatal("rotated record preparation failed")
		}
		if got, err := execute(q, rotated, true); err != nil || got != claimReplay {
			t.Fatal("rotated record replay failed")
		}
		q, err = prepareClaim(build(true), rotated.retained[rotated.current])
		if err != nil {
			t.Fatal("changed record preparation failed")
		}
		if got, err := execute(q, rotated, true); err != nil || got != claimConflict {
			t.Fatal("record ID acquired different meaning")
		}
	}
	if got, err := execute(request, rotated, true); err != nil || got != claimReplay {
		t.Fatal("retained-key replay failed")
	}
	t.Run("password signin retained paired custody", func(t *testing.T) {
		for _, anonymous := range []bool{false, true} {
			s := passwordSigninCodecSpec(anonymous)
			s.Binding.CommandID, err = identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte("synthetic-primary-password")
			wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
			command, owner := passwordSigninCodecCommand(t, s, raw, wire)
			initial, err := prepareClaim(command, keys.retained[1])
			if err != nil {
				t.Fatal(err)
			}
			if got, err := execute(initial, keys, true); err != nil || got != claimNew {
				t.Fatal("original paired signin denied", err)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(s.Binding.CommandID))
			var before, after, safe []byte
			var version int64
			if err := pool.Raw().QueryRow(ctx, `SELECT fingerprint,fingerprint_key_version,safe_fields FROM identity.identity_command_id_claims WHERE command_id=$1`, id).Scan(&before, &version, &safe); err != nil || version != 1 || bytes.Contains(safe, raw) || bytes.Contains(safe, []byte(wire)) {
				t.Fatal("original private claim not retained safely", err)
			}
			for _, change := range []struct {
				raw  []byte
				wire string
			}{{append(bytes.Clone(raw), 'x'), wire}, {raw, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32))}} {
				changed, _ := passwordSigninCodecCommand(t, s, change.raw, change.wire)
				q, err := prepareClaim(changed, rotated.retained[2])
				if err != nil {
					t.Fatal(err)
				}
				if got, err := execute(q, rotated, true); err != nil || got != claimConflict {
					t.Fatal("different signin secret replayed claim", err)
				}
			}
			current, err := prepareClaim(command, rotated.retained[2])
			if err != nil {
				t.Fatal(err)
			}
			if got, err := execute(current, rotated, true); err != nil || got != claimReplay {
				t.Fatal("paired signin lost stored-key replay", err)
			}
			if err := pool.Raw().QueryRow(ctx, `SELECT fingerprint,fingerprint_key_version FROM identity.identity_command_id_claims WHERE command_id=$1`, id).Scan(&after, &version); err != nil || version != 1 || !bytes.Equal(before, after) {
				t.Fatal("signin substitutions rewrote original claim", err)
			}
			var count int
			if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1`, id).Scan(&count); err != nil || count != 1 {
				t.Fatal("signin replay duplicated journal", err)
			}
			// The retained source remains the original live owner, not a digest
			// from which destroyed credentials can be reconstructed.
			borrowed, cookie, ok := current.source.PasswordSigninCustody()
			if !ok || cookie.Token() != auth.NewBearerCredential(wire).Token() || borrowed.Len() != len(raw) {
				t.Fatal("primary replay lost original paired custody")
			}
			owner.Destroy()
			if got, err := execute(current, rotated, true); err == nil || got != claimInvalid {
				t.Fatal("destroyed source reconstructed from retained digest")
			}
		}
	})
	// Denied substitutions cannot replace the original privacy claim or add a
	// scoped journal. Key rotation must preserve its original fingerprint key.
	privacyCommand := recordPrivacy(t, nil, nil, "privacy-key")
	privacy, err := prepareClaim(privacyCommand, keys.retained[1])
	if err != nil {
		t.Fatal(err)
	}
	privacyID, _ := base64.RawURLEncoding.DecodeString(string(privacy.commandID))
	var before, after []byte
	var keyVersion int64
	if err := pool.Raw().QueryRow(ctx, `SELECT fingerprint,fingerprint_key_version FROM identity.identity_command_id_claims WHERE command_id=$1`, privacyID).Scan(&before, &keyVersion); err != nil || keyVersion != 1 || len(before) != 32 {
		t.Fatal("original privacy claim missing", err)
	}
	for _, change := range []func(*identity.PrivacyExportRequestCommand){
		func(c *identity.PrivacyExportRequestCommand) { c.SessionID = "other-session" },
		func(c *identity.PrivacyExportRequestCommand) { c.SessionVersion++ },
		func(c *identity.PrivacyExportRequestCommand) { c.ExpectedIdentityVersion++ },
		func(c *identity.PrivacyExportRequestCommand) { c.ExpectedAuthorityVersion++ },
		func(c *identity.PrivacyExportRequestCommand) { c.Binding.TenantID = "AgICAgICAgICAgICAgICAg" },
		func(c *identity.PrivacyExportRequestCommand) {
			c.Binding.UserID = "AgICAgICAgICAgICAgICAg"
			c.Binding.ActorID = "AgICAgICAgICAgICAgICAg"
		},
		func(c *identity.PrivacyExportRequestCommand) { c.MaximumBytes++ },
		func(c *identity.PrivacyExportRequestCommand) { c.ArtifactTTL += time.Second },
		func(c *identity.PrivacyExportRequestCommand) {
			c.Projections[0].ProjectionID = identity.PrivacyExportStagedSubjectV1
		},
	} {
		changed, err := prepareClaim(recordPrivacy(t, change, nil, "privacy-key"), rotated.retained[2])
		if err != nil {
			t.Fatal(err)
		}
		if got, err := execute(changed, rotated, true); err != nil || got != claimConflict {
			t.Fatal("privacy scope/intent substituted", err)
		}
	}
	substituted, err := prepareClaim(recordPrivacy(t, nil, nil, "other-privacy-key"), rotated.retained[2])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := execute(substituted, rotated, true); err != nil || got != claimConflict {
		t.Fatal("privacy proof substituted", err)
	}
	privacy, err = prepareClaim(privacyCommand, rotated.retained[2])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := execute(privacy, rotated, true); err != nil || got != claimReplay {
		t.Fatal("denied substitution destroyed original replay", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT fingerprint,fingerprint_key_version FROM identity.identity_command_id_claims WHERE command_id=$1`, privacyID).Scan(&after, &keyVersion); err != nil || keyVersion != 1 || !bytes.Equal(before, after) {
		t.Fatal("retained fingerprint rewritten", err)
	}
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE command_id=$1`, privacyID).Scan(&count); err != nil || count != 1 {
		t.Fatal("privacy replay duplicated journal", err)
	}
	for _, change := range []func(*claimRequest){
		func(q *claimRequest) { q.tenant = "tenant-b" },
		func(q *claimRequest) { q.purpose = "identity.user.update-admin" },
		func(q *claimRequest) { q.canonical = []byte{0xa1, 0x61, 'a', 0x02} },
		func(q *claimRequest) { q.safeFields = []byte{0x80} },
	} {
		q := request
		change(&q)
		if got, err := execute(q, rotated, true); err != nil || got != claimConflict {
			t.Fatal("ID reused with different meaning")
		}
	}
	lost := claimKeys{current: 2, retained: map[uint32][32]byte{2: {2}}}
	var unavailable identity.UnavailableError
	if _, err := execute(request, lost, true); !errors.As(err, &unavailable) {
		t.Fatal("retired fingerprint key guessed")
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(request.commandID))
	if _, err := pool.Raw().Exec(ctx, "DELETE FROM identity.commands WHERE command_id=$1", id); err != nil {
		t.Fatal("integrity fixture failed")
	}
	if _, err := execute(request, keys, false); err == nil {
		t.Fatal("missing journal re-created authority")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identity_command_id_claims SET retired=true,tenant_id=NULL,purpose=NULL,fingerprint=NULL,fingerprint_key_version=NULL,safe_fields=NULL WHERE command_id=$1`, id); err != nil {
		t.Fatal("retirement fixture failed")
	}
	if got, err := execute(request, keys, true); err != nil || got != claimConflict {
		t.Fatal("retired ID reused")
	}
	q := request
	q.commandID = "AAAAAAAAAAAAAAAAAAAAAg"
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal("rollback transaction unavailable")
	}
	defer tx.Rollback(ctx)
	if got, err := lockCommandClaim(ctx, tx, q, keys); err != nil || got != claimNew {
		t.Fatal("rollback fixture failed")
	}
	if tx.Rollback(ctx) != nil {
		t.Fatal("rollback failed")
	}
	if got, err := execute(q, keys, true); err != nil || got != claimNew {
		t.Fatal("uncommitted claim survived rollback")
	}
	t.Run("concurrent single winner", func(t *testing.T) {
		q := request
		q.commandID = "AAAAAAAAAAAAAAAAAAAAAw"
		results := make(chan claimDisposition, 2)
		failures := make(chan error, 2)
		var workers sync.WaitGroup
		workers.Add(2)
		for range 2 {
			go func() {
				defer workers.Done()
				tx, err := pool.Raw().Begin(ctx)
				if err != nil {
					failures <- err
					return
				}
				defer tx.Rollback(ctx)
				got, err := lockCommandClaim(ctx, tx, q, keys)
				if err == nil && got == claimNew {
					id, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
					_, err = tx.Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) SELECT command_id,tenant_id,purpose FROM identity.identity_command_id_claims WHERE command_id=$1`, id)
				}
				if err == nil {
					err = tx.Commit(ctx)
				}
				if err != nil {
					failures <- err
					return
				}
				results <- got
			}()
		}
		// Buffered terminal outputs let both bounded workers finish before any
		// assertion can terminate the test and begin pool/database teardown.
		workers.Wait()
		newCount, replayCount := 0, 0
		for range 2 {
			select {
			case got := <-results:
				if got == claimNew {
					newCount++
				}
				if got == claimReplay {
					replayCount++
				}
			case <-failures:
				t.Fatal("concurrent claim failed")
			case <-ctx.Done():
				t.Fatal("claim workers did not terminate")
			}
		}
		if newCount != 1 || replayCount != 1 {
			t.Fatal("global claim did not serialize contenders")
		}
	})
	if _, err := lockCommandClaim(context.Background(), nil, request, keys); err == nil {
		t.Fatal("unbounded nil transaction admitted")
	}
}
