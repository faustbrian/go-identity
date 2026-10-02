//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

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
