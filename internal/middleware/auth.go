package middleware

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"
	"go.opencensus.io/trace"

	"github.com/noelruault/golang-authentication/internal/models"
	"github.com/noelruault/golang-authentication/internal/web"
)

// viewErr is a global Error view to be used by middleware when returning errors
// to users.
var viewErr = func() web.Error {
	var ev web.Error
	ev.SetCode(models.ErrUnauthorised, http.StatusUnauthorized)
	ev.SetCode(ErrForbidden, http.StatusForbidden)

	return ev
}()

// UserService is a subset of the models.UserService interface, containing only
// the methods required to run middleware.
type UserService interface {
	Validate(context.Context, string) (models.Claims, error)
}

// Authenticate validates a JWT from the `Authorization` header.
// Status code of the errors used on this method need to be set at middleware level.
func Authenticate(us UserService) web.Middleware {

	// This is the actual middleware function to be executed.
	f := func(after web.Handler) web.Handler {

		// Wrap this handler around the next one provided.
		h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			ctx, span := trace.StartSpan(ctx, "internal.middleware.Authenticate")
			defer span.End()

			// Parse the authorization header. Expected header is of
			// the format `Bearer <token>`.
			token := strings.Split(r.Header.Get("Authorization"), " ")
			if len(token) != 2 || strings.ToLower(token[0]) != "bearer" {
				viewErr.JSON(ctx, w, ErrTokenFormat)
				return nil
			}

			claims, err := us.Validate(ctx, token[1])
			if err != nil {
				viewErr.JSON(ctx, w, err)
				return nil
			}

			// Add claims to the context so they can be retrieved later.
			ctx = context.WithValue(ctx, models.KeyClaims, claims)

			return after(ctx, w, r)
		}

		return h
	}

	return f
}

// Me validates that an authenticated user is accessing a resource of his own
func Me() web.Middleware {

	// This is the actual middleware function to be executed.
	f := func(after web.Handler) web.Handler {

		h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			ctx, span := trace.StartSpan(ctx, "internal.middleware.Me")
			defer span.End()

			urlUserID, err := strconv.ParseInt(chi.URLParam(r, "user_id"), 10, 64)
			if err != nil || urlUserID < 1 {
				viewErr.JSON(ctx, w, ErrMalformedURLUserIDRequired)
				return nil
			}

			claims, ok := ctx.Value(models.KeyClaims).(models.Claims)
			if !ok {
				return errors.New("claims missing from context: Me called without/before Authenticate")
			}

			// If user ID get from url path is not user owner
			if claims.User.ID != urlUserID {
				viewErr.JSON(ctx, w, ErrForbidden)
				return nil
			}

			return after(ctx, w, r)
		}

		return h
	}

	return f
}
