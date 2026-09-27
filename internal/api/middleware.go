package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ac1965/riskforge/internal/application"
	"github.com/ac1965/riskforge/internal/domain/authn"
)

// AuthnService is the subset of *application.Service RequireScope needs
// (ADR 0012). Declaring it as a narrow interface here, rather than
// depending on *application.Service directly, lets this middleware be
// tested without building a full Service.
type AuthnService interface {
	AuthenticateToken(ctx context.Context, rawToken string) (*authn.Principal, []string, error)
}

type principalContextKey struct{}

// PrincipalFromContext returns the Principal RequireScope authenticated
// for this request, if any. No handler in this package's current scope
// (the five read-only endpoints) needs it, but write endpoints added
// later will.
func PrincipalFromContext(ctx context.Context) (*authn.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(*authn.Principal)
	return p, ok
}

var (
	errMissingBearerToken = errors.New("missing bearer token")
	errInvalidToken       = errors.New("invalid or expired token")
	errInsufficientScope  = errors.New("insufficient scope")
)

// RequireScope wraps next so a request must present a bearer token
// (Authorization: Bearer <token>) that authnSvc.AuthenticateToken
// resolves to a Principal carrying scope, before next runs (ADR 0012).
// A missing, malformed, unknown, expired, or revoked token gets 401; a
// valid token that lacks scope gets 403; either way the body is ADR
// 0011's {"error": "..."} form. An unexpected error from
// AuthenticateToken itself (e.g. a real database failure, not "no such
// token") gets 500, matching ADR 0011's convention for the read
// handlers.
func RequireScope(authnSvc AuthnService, scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := bearerToken(r)
			if !ok {
				writeError(w, http.StatusUnauthorized, errMissingBearerToken)
				return
			}

			principal, scopes, err := authnSvc.AuthenticateToken(r.Context(), raw)
			switch {
			case errors.Is(err, application.ErrUnauthenticated):
				writeError(w, http.StatusUnauthorized, errInvalidToken)
				return
			case err != nil:
				writeError(w, http.StatusInternalServerError, err)
				return
			}

			if !hasScope(scopes, scope) {
				writeError(w, http.StatusForbidden, errInsufficientScope)
				return
			}

			ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>"
// header. The scheme is matched case-insensitively (RFC 6750); an empty
// or missing header, a different scheme, or an empty token all count as
// absent.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
