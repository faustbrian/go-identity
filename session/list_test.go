package session_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

type sessionPageReader func(context.Context, session.SessionPageQuery) (session.SessionPage, error)

func (f sessionPageReader) ReadSessionPage(ctx context.Context, q session.SessionPageQuery) (session.SessionPage, error) {
	return f(ctx, q)
}

func allowListPolicy() listPolicy {
	return func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	}
}

func listRecord(t *testing.T, original session.Session, id string, mutate func(*session.SessionSpec)) session.Session {
	t.Helper()
	s, err := original.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	s.SessionID = id
	if mutate != nil {
		mutate(&s)
	}
	s.Authentication.Proof.Tenant = string(s.TenantID)
	s.Authentication.Proof.Subject = string(s.UserID)
	s.Authentication.Proof.Audience = s.Audience
	r, err := session.NewSession(s)
	if err != nil {
		t.Fatal("structural page fixture", err)
	}
	return r
}

func TestSessionListProjectsActiveAndInactiveTimesInUTC(t *testing.T) {
	reader, input, _, observed, _, _ := validationFixture(t)
	zone := time.FixedZone("recorded-offset", 3*60*60)
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			record := listRecord(t, observed.Session, "a", func(s *session.SessionSpec) {
				if expired {
					s.IssuedAt = s.IssuedAt.Add(-24 * time.Hour)
					s.LastActivityAt = s.LastActivityAt.Add(-24 * time.Hour)
					s.Authentication.Proof.IssuedAt = s.Authentication.Proof.IssuedAt.Add(-24 * time.Hour)
					s.Authentication.Proof.ExpiresAt = s.Authentication.Proof.ExpiresAt.Add(-24 * time.Hour)
				}
				s.LastActivityAt = s.LastActivityAt.In(zone)
				s.IssuedAt = s.IssuedAt.In(zone)
			})
			spec, _ := record.Bindings()
			lifetime, err := record.Lifetime(spec.LastActivityAt)
			if err != nil {
				t.Fatal(err)
			}
			pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
				return session.SessionPage{Entries: []session.SessionListEntry{{Session: record}}}, nil
			})
			service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.List(context.Background(), session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "utc-list", Limit: 1, IncludeInactive: true})
			if err != nil || len(out.Sessions) != 1 {
				t.Fatal("projection", err)
			}
			device := out.Sessions[0]
			if device.LastSeenAt.Location() != time.UTC || device.ExpiresAt.Location() != time.UTC || !device.LastSeenAt.Equal(spec.LastActivityAt) || !device.ExpiresAt.Equal(lifetime.ExpiresAt) || device.Inactive != expired {
				t.Fatal("projection must preserve instants and normalize both timestamps to UTC")
			}
		})
	}
}

func TestSessionListInactiveFilteringAndStableRawScanCursor(t *testing.T) {
	reader, input, clock, observed, _, _ := validationFixture(t)
	revoked := listRecord(t, observed.Session, "a", nil)
	expired := listRecord(t, observed.Session, "b", func(s *session.SessionSpec) {
		s.IssuedAt = s.IssuedAt.Add(-24 * time.Hour)
		s.LastActivityAt = s.LastActivityAt.Add(-24 * time.Hour)
		s.Authentication.Proof.IssuedAt = s.Authentication.Proof.IssuedAt.Add(-24 * time.Hour)
		s.Authentication.Proof.ExpiresAt = s.Authentication.Proof.ExpiresAt.Add(-24 * time.Hour)
	})
	active := listRecord(t, observed.Session, "c", nil)
	pages := sessionPageReader(func(_ context.Context, q session.SessionPageQuery) (session.SessionPage, error) {
		switch q.AfterSessionID {
		case "":
			return session.SessionPage{Entries: []session.SessionListEntry{{Session: revoked, Revoked: true}, {Session: expired}}, HasMore: true}, nil
		case "b":
			return session.SessionPage{Entries: []session.SessionListEntry{{Session: active}}}, nil
		default:
			t.Fatal("cursor lost last raw row")
			return session.SessionPage{}, nil
		}
	})
	service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	r := session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "list", Limit: 2}
	first, err := service.List(context.Background(), r)
	if err != nil || len(first.Sessions) != 0 || first.NextCursor == "" {
		t.Fatal("filtered raw scan skipped continuation", err)
	}
	r.Cursor = first.NextCursor
	second, err := service.List(context.Background(), r)
	if err != nil || len(second.Sessions) != 1 || second.Sessions[0].SessionID != "c" || second.Sessions[0].Inactive || second.NextCursor != "" {
		t.Fatal("keyset continuation", err)
	}
	r.Cursor, r.IncludeInactive = "", true
	all, err := service.List(context.Background(), r)
	if err != nil || len(all.Sessions) != 2 || !all.Sessions[0].Inactive || !all.Sessions[1].Inactive || !all.Sessions[1].ExpiresAt.Before(clock.now) {
		t.Fatal("inactive projection", err)
	}
	r.Cursor = first.NextCursor
	if out, err := service.List(context.Background(), r); !errors.Is(err, session.ErrInvalidInput) || len(out.Sessions) != 0 {
		t.Fatal("cursor changed inactive scope", err)
	}
}

func TestSessionListRejectsHostilePagesWithoutPartialDisclosure(t *testing.T) {
	for _, mode := range []string{"tenant", "user", "audience", "zero", "duplicate", "unordered", "too many", "empty continuation", "short continuation", "label too long", "label control", "label utf8", "future", "current revoked", "current substituted", "outage", "panic", "expired admission", "backward clock"} {
		t.Run(mode, func(t *testing.T) {
			reader, input, clock, observed, _, _ := validationFixture(t)
			pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
				entry := session.SessionListEntry{Session: listRecord(t, observed.Session, "a", nil)}
				page := session.SessionPage{Entries: []session.SessionListEntry{entry}}
				switch mode {
				case "tenant":
					page.Entries[0].Session = listRecord(t, observed.Session, "a", func(s *session.SessionSpec) { s.TenantID = "foreign" })
				case "user":
					page.Entries[0].Session = listRecord(t, observed.Session, "a", func(s *session.SessionSpec) { s.UserID = "foreign" })
				case "audience":
					page.Entries[0].Session = listRecord(t, observed.Session, "a", func(s *session.SessionSpec) { s.Audience = "foreign" })
				case "zero":
					page.Entries[0].Session = session.Session{}
				case "duplicate":
					page.Entries = append(page.Entries, entry)
				case "unordered":
					page.Entries = []session.SessionListEntry{{Session: listRecord(t, observed.Session, "b", nil)}, entry}
				case "too many":
					page.Entries = make([]session.SessionListEntry, 3)
				case "empty continuation":
					page.Entries = nil
					page.HasMore = true
				case "short continuation":
					page.HasMore = true
				case "label too long":
					page.Entries[0].Label = strings.Repeat("x", 129)
				case "label control":
					page.Entries[0].Label = "private\nlabel"
				case "label utf8":
					page.Entries[0].Label = string([]byte{255})
				case "future":
					page.Entries[0].Session = listRecord(t, observed.Session, "a", func(s *session.SessionSpec) { s.LastActivityAt = clock.now.Add(time.Second) })
				case "current revoked":
					page.Entries[0] = session.SessionListEntry{Session: observed.Session, Revoked: true}
				case "current substituted":
					spec, _ := observed.Session.Bindings()
					page.Entries[0].Session = listRecord(t, observed.Session, spec.SessionID, func(s *session.SessionSpec) { s.LastActivityAt = clock.now })
				case "outage":
					return session.SessionPage{}, errors.New("private storage detail")
				case "panic":
					panic("private panic")
				case "expired admission":
					clock.now = observed.ValidUntil
				case "backward clock":
					clock.now = observed.ReadStartedAt.Add(-time.Second)
				}
				return page, nil
			})
			service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.List(context.Background(), session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "list", Limit: 2})
			if err == nil || len(out.Sessions) != 0 || out.NextCursor != "" || strings.Contains(err.Error(), "private") {
				t.Fatal("hostile page disclosed partial result", err)
			}
		})
	}
}

func TestSessionListDeniesBeforePageOnInvalidCallerPolicyOrCursor(t *testing.T) {
	for _, mode := range []string{"absent", "limit zero", "limit large", "bad correlation", "bad cursor", "oversize cursor", "newline cursor", "deny", "revision", "policy error", "policy panic", "cancel", "expiry before scan"} {
		t.Run(mode, func(t *testing.T) {
			reader, input, clock, observed, _, _ := validationFixture(t)
			request := session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "list", Limit: 10}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "absent":
				observed.Active = false
			case "limit zero":
				request.Limit = 0
			case "limit large":
				request.Limit = 101
			case "bad correlation":
				request.CorrelationID = "bad\ncorrelation"
			case "bad cursor":
				request.Cursor = "not a cursor"
			case "oversize cursor":
				request.Cursor = strings.Repeat("x", 217)
			case "newline cursor":
				request.Cursor = base64.RawURLEncoding.EncodeToString(append(append([]byte{1}, make([]byte, 32)...), 'a')) + "\n"
			case "cancel":
				cancel()
			}
			policy := listPolicy(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				switch mode {
				case "deny":
					return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
				case "revision":
					return authorization.Decision{Outcome: authorization.Allow, Revision: 2}, nil
				case "policy error":
					return authorization.Decision{}, errors.New("private detail")
				case "policy panic":
					panic("private detail")
				case "expiry before scan":
					clock.now = observed.ValidUntil
				}
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})
			reads := 0
			pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
				reads++
				return session.SessionPage{}, nil
			})
			service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: policy, PolicyRevision: 1, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.List(ctx, request)
			if err == nil || reads != 0 || len(out.Sessions) != 0 || out.NextCursor != "" || strings.Contains(err.Error(), "private") {
				t.Fatal("denied input reached page reader", err, reads)
			}
		})
	}
}

func TestSessionListConstructorAndRedaction(t *testing.T) {
	reader, _, _, _, _, _ := validationFixture(t)
	pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
		return session.SessionPage{}, nil
	})
	valid := session.ListConfig{Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: time.Second}
	for _, c := range []session.ListConfig{{}, {Authorization: listPolicy(nil), PolicyRevision: 1, MaximumDuration: time.Second}, {Authorization: allowListPolicy(), MaximumDuration: time.Second}, {Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: 6 * time.Second}} {
		if s, err := session.NewListService(reader, pages, c); s != nil || !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("invalid list config accepted")
		}
	}
	for _, p := range []sessionPageReader{nil} {
		if s, err := session.NewListService(reader, p, valid); s != nil || !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("typed nil page reader accepted")
		}
	}
	if s, err := session.NewListService(nil, pages, valid); s != nil || err == nil {
		t.Fatal("missing authentication accepted")
	}
	for _, value := range []any{valid, session.ListRequest{TenantID: "private", CorrelationID: "private", Cursor: "private"}, session.ListResult{NextCursor: "private"}, session.Device{SessionID: "private", Label: "private"}, session.SessionPageQuery{Audience: "private"}, session.SessionListEntry{Label: "private"}, session.SessionPage{Entries: []session.SessionListEntry{{Label: "private"}}}} {
		if strings.Contains(fmt.Sprintf("%#v", value), "private") {
			t.Fatal("list formatting disclosed scope")
		}
		if _, err := json.Marshal(value); !errors.Is(err, session.ErrSecretSerialization) {
			t.Fatal("list implicitly serialized")
		}
	}
}

func TestSessionListConcurrentResultsHaveIndependentOwnership(t *testing.T) {
	reader, input, _, observed, _, _ := validationFixture(t)
	pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
		return session.SessionPage{Entries: []session.SessionListEntry{{Session: observed.Session, Label: "original"}}}, nil
	})
	service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	r := session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "list", Limit: 1}
	errorsFound := make(chan error, 16)
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			out, err := service.List(context.Background(), r)
			if err != nil {
				errorsFound <- err
				return
			}
			if len(out.Sessions) != 1 || out.Sessions[0].Label != "original" {
				errorsFound <- fmt.Errorf("result ownership changed")
				return
			}
			out.Sessions[0].Label = "changed"
		}()
	}
	workers.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func FuzzSessionListCursorBoundedParsing(f *testing.F) {
	for _, seed := range []string{"", "invalid", "AQ", strings.Repeat("x", 217), "\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cursor string) {
		reader, input, _, _, _, _ := validationFixture(t)
		pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
			return session.SessionPage{}, nil
		})
		service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: allowListPolicy(), PolicyRevision: 1, MaximumDuration: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		out, err := service.List(context.Background(), session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "list", Cursor: cursor, Limit: 1})
		if len(out.Sessions) != 0 || out.NextCursor != "" {
			t.Fatal("cursor fabricated page state")
		}
		if len(cursor) > 216 && !errors.Is(err, session.ErrInvalidInput) {
			t.Fatal("oversize cursor accepted")
		}
	})
}

func TestSessionListCancellationDuringClockCannotReadOrDisclose(t *testing.T) {
	for _, stage := range []string{"before page", "final disclosure"} {
		t.Run(stage, func(t *testing.T) {
			_, input, clock, observed, config, source := validationFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			armed, after := false, 0
			config.Clock = validationClock(func() time.Time {
				if armed {
					after++
					if stage == "before page" || after == 2 {
						cancel()
					}
				}
				return clock.now
			})
			reader, err := session.NewSessionService(source, config)
			if err != nil {
				t.Fatal(err)
			}
			policy := listPolicy(func(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
				armed = stage == "before page"
				return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
			})
			reads := 0
			pages := sessionPageReader(func(context.Context, session.SessionPageQuery) (session.SessionPage, error) {
				reads++
				armed = true
				return session.SessionPage{Entries: []session.SessionListEntry{{Session: observed.Session}}}, nil
			})
			service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: policy, PolicyRevision: 1, MaximumDuration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			out, err := service.List(ctx, session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "list-request", Limit: 10})
			var cancelled identity.CancelledError
			if !errors.As(err, &cancelled) || len(out.Sessions) != 0 || out.NextCursor != "" || (stage == "before page" && reads != 0) {
				t.Fatal("cancelled list read/disclosed metadata", err, reads)
			}
		})
	}
}

type listPolicy func(context.Context, authorization.DecisionContext) (authorization.Decision, error)

func (f listPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	return f(ctx, d)
}

func TestSessionListAuthenticatesAuthorizesAndReturnsSafeOwnedMetadata(t *testing.T) {
	reader, input, _, observed, _, _ := validationFixture(t)
	spec, _ := observed.Session.Bindings()
	policy := listPolicy(func(_ context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
		if d.Request.Subject.ID != authorization.SubjectID(spec.UserID) || d.Request.Tenant != authorization.TenantID(spec.TenantID) || d.Request.Action != "identity.session.list" || d.Request.Resource.ID != authorization.ResourceID(spec.UserID) {
			t.Fatal("list policy scope substituted")
		}
		return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
	})
	pages := sessionPageReader(func(_ context.Context, q session.SessionPageQuery) (session.SessionPage, error) {
		if q.TenantID != spec.TenantID || q.UserID != spec.UserID || q.Audience != spec.Audience || q.Limit != 10 || q.AfterSessionID != "" {
			t.Fatal("list target not derived from authenticated owner")
		}
		return session.SessionPage{Entries: []session.SessionListEntry{{Session: observed.Session, Label: "browser"}}}, nil
	})
	service, err := session.NewListService(reader, pages, session.ListConfig{Authorization: policy, PolicyRevision: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	out, err := service.List(context.Background(), session.ListRequest{TenantID: input.TenantID, Credential: input.Credential, CorrelationID: "list-request", Limit: 10})
	if err != nil || len(out.Sessions) != 1 || out.Sessions[0].SessionID != spec.SessionID || out.Sessions[0].Label != "browser" || !out.Sessions[0].Current || out.Sessions[0].Inactive || !out.Sessions[0].LastSeenAt.Equal(spec.LastActivityAt) || out.NextCursor != "" {
		t.Fatal("safe list projection", err)
	}
}
