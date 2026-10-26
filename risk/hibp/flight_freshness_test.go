package hibp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckerFlightValidatesClockBeforePublishingEvidence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		advance     time.Duration
		unavailable bool
	}{
		{name: "before-expiry", advance: time.Hour - time.Nanosecond},
		{name: "at-expiry", advance: time.Hour, unavailable: true},
		{name: "after-expiry", advance: time.Hour + time.Nanosecond, unavailable: true},
		{name: "regressed", advance: -time.Nanosecond, unavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			var wall *testClock
			client, fixtureClock := checkerFixture(t, func(w http.ResponseWriter, request *http.Request) {
				if calls.Add(1) == 1 {
					close(started)
					select {
					case <-release:
					case <-request.Context().Done():
						return
					}
					wall.nanos.Add(int64(tc.advance))
				}
				fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
			})
			wall = fixtureClock
			original := wall.Now()
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			request := requestFor(t, "synthetic-flight-clock")
			first := launch(client, context.Background(), request)
			receive(t, started)
			second := launch(client, context.Background(), request)
			awaitEnrollment(t, client, 2)
			close(release)
			for _, reply := range []checkReply{receive(t, first), receive(t, second)} {
				if tc.unavailable {
					if !errors.Is(reply.err, ErrProviderUnavailable) || reply.result.Outcome != OutcomeUnavailable || reply.result.BreachCount != 0 || !reply.result.ProviderValidUntil.IsZero() {
						t.Fatal("invalid or expired provider observation became usable checker evidence")
					}
				} else if reply.err != nil || reply.result.Outcome != OutcomeNoMatch || !reply.result.CheckedAt.Equal(original) || !reply.result.ProviderValidUntil.Equal(original.Add(time.Hour)) {
					t.Fatal("fresh shared evidence lost its original observation or validity", reply.err)
				}
			}
			if calls.Load() != 1 {
				t.Fatal("same-prefix waiters did not share the provider request")
			}
			if tc.advance < 0 {
				wall.nanos.Store(original.UnixNano())
			}
			retry, err := client.Check(context.Background(), request)
			wantCalls := int32(1)
			if tc.unavailable {
				wantCalls = 2
			}
			if err != nil || retry.Outcome != OutcomeNoMatch || calls.Load() != wantCalls {
				t.Fatal("invalid provider observation was cached or fresh evidence was not reusable", err)
			}
		})
	}
}

// Earlier callbacks may complete after a later observation without representing
// clock regression. Their old samples must not override the latest known expiry.
type overlappingExpiryClock struct {
	base             time.Time
	blockAt          int32
	calls            atomic.Int32
	entered, release chan struct{}
}

func (c *overlappingExpiryClock) Now() time.Time {
	n := c.calls.Add(1)
	if n < c.blockAt {
		return c.base
	}
	if n == c.blockAt {
		close(c.entered)
		<-c.release
		return c.base.Add(time.Hour - time.Nanosecond)
	}
	return c.base.Add(time.Hour)
}

func expiryClock(t *testing.T, client *Client, base time.Time, blockAt int32) *overlappingExpiryClock {
	t.Helper()
	wall := &overlappingExpiryClock{base: base, blockAt: blockAt, entered: make(chan struct{}), release: make(chan struct{})}
	client.clock = wall
	t.Cleanup(func() {
		select {
		case <-wall.release:
		default:
			close(wall.release)
		}
	})
	return wall
}

func assertUnavailableFlight(t *testing.T, reply checkReply) {
	t.Helper()
	if !errors.Is(reply.err, ErrProviderUnavailable) || reply.result.Outcome != OutcomeUnavailable || reply.result.BreachCount != 0 || !reply.result.ProviderValidUntil.IsZero() {
		t.Fatal("overlapping earlier clock sample restored expired flight evidence")
	}
}

func TestCheckerFlightPublicationUsesGreatestOverlappingClockObservation(t *testing.T) {
	var calls atomic.Int32
	client, original := checkerFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
	})
	// The first two observations admit the first caller. Its provider result
	// then pauses before publication while another same-prefix caller observes
	// the original expiry and joins the still-live flight.
	wall := expiryClock(t, client, original.Now(), 3)
	request := requestFor(t, "synthetic-overlapping-publication")
	first := launch(client, context.Background(), request)
	receive(t, wall.entered)
	second := launch(client, context.Background(), request)
	awaitEnrollment(t, client, 2)
	close(wall.release)
	assertUnavailableFlight(t, receive(t, first))
	assertUnavailableFlight(t, receive(t, second))
	client.mu.Lock()
	retained := len(client.cache)
	client.mu.Unlock()
	if retained != 0 {
		t.Fatal("expired flight retained private range data after a later clock observation")
	}
	result, err := client.Check(context.Background(), request)
	if err != nil || result.Outcome != OutcomeNoMatch || calls.Load() != 2 {
		t.Fatal("fresh retry did not obtain a new provider observation", err)
	}
}

func TestCheckerWaitersUseGreatestOverlappingClockObservation(t *testing.T) {
	providerRelease := make(chan struct{})
	client, original := checkerFixture(t, func(w http.ResponseWriter, request *http.Request) {
		select {
		case <-providerRelease:
		case <-request.Context().Done():
			return
		}
		fmt.Fprint(w, "00000000000000000000000000000000000:0\n")
	})
	t.Cleanup(func() {
		select {
		case <-providerRelease:
		default:
			close(providerRelease)
		}
	})
	// Both callers observe twice before enrollment. Provider publication is
	// observation five; only a returning waiter's sixth observation pauses.
	wall := expiryClock(t, client, original.Now(), 6)
	done := make(chan checkReply, 2)
	for range 2 {
		// Each caller owns a separate candidate with identical bytes. Secret
		// deliberately rejects concurrent borrowing of one shared owner.
		request := requestFor(t, "synthetic-overlapping-waiters")
		go func() {
			result, err := client.Check(context.Background(), request)
			done <- checkReply{result, err}
		}()
	}
	awaitEnrollment(t, client, 2)
	close(providerRelease)
	receive(t, wall.entered)
	// Whichever caller sampled expiry returns first. The blocked caller then
	// finishes its earlier, valid sample and must still respect known expiry.
	assertUnavailableFlight(t, receive(t, done))
	close(wall.release)
	assertUnavailableFlight(t, receive(t, done))
}
