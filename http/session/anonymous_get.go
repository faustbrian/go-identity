package sessionhttp

import (
	"time"

	"github.com/faustbrian/go-identity/session"
)

// AnonymousGetConfig explicitly selects unprivileged guest recognition beside
// the permanent cookie profile. Sessions is a constructed, borrowed anonymous
// owner; Cookie must be valid and named differently from the permanent cookie.
// Both cookies are decoded strictly. A present permanent cookie selects only
// permanent validation, even if inactive or unavailable: no guest fallback.
// This option is cookie-only and never enables a route, signout or metadata
// administration by itself. Construction copies it without owner IO.
type AnonymousGetConfig struct {
	Sessions *session.AnonymousSessionService
	Cookie   session.CookiePolicy
}

// AnonymousResponse is explicit, credential-free guest metadata. Recognized
// means only a live unprivileged guest session; it is never authenticated-user
// admission, an upgrade proof or refresh authority. The original owner lifetime
// is retained. Omitted entirely when this profile is unselected or inactive.
type AnonymousResponse struct {
	Recognized bool      `json:"recognized"`
	Principal  Principal `json:"principal"`
	Session    Session   `json:"session"`
}

func anonymousResponse(result session.AnonymousGetResult, principal Principal, now time.Time) (AnonymousResponse, error) {
	if err := result.ValidateAt(now); err != nil {
		return AnonymousResponse{}, err
	}
	spec, err := result.Session.Bindings()
	if err != nil {
		return AnonymousResponse{}, err
	}
	lifetime, err := result.Session.Lifetime(now)
	if err != nil {
		return AnonymousResponse{}, err
	}
	return AnonymousResponse{Recognized: true, Principal: principal, Session: Session{
		ID: spec.SessionID, IssuedAt: spec.IssuedAt.UTC(), LastActivityAt: spec.LastActivityAt.UTC(), ExpiresAt: lifetime.ExpiresAt.UTC(), AbsoluteExpiresAt: lifetime.AbsoluteExpiresAt.UTC(),
	}}, nil
}
