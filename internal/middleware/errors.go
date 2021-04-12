package middleware

import (
	"context"
	"log"
	"net/http"

	"go.opencensus.io/trace"

	"github.com/noelruault/golang-authentication/internal/web"
)

const (
	ErrTokenFormat                MiddlewareError = "middleware: invalid_token_format, expected authorization header format: Bearer <token>"
	ErrMalformedURLUserIDRequired MiddlewareError = "middleware: malformed_url, the URL must contain a user ID"
	ErrForbidden                  MiddlewareError = "middleware: forbidden, this resource can not be accessed"
)

// MiddlewareError defines errors exported by this package. This type implement a Public() method that
// extracts a unique error code defined for each error value exported.
type MiddlewareError string

// Error returns the exact original message of the e value.
func (e MiddlewareError) Error() string {
	return string(e)
}

// Public extracts the error code string present on the value of e.
//
// An error code is defined as the string after the package prefix and colon, and before the comma that follows
// this string. Example:
//		"models: error_code, this is a validation error"
func (e MiddlewareError) Public() string {
	// remove the prefix
	s := string(e)[len("middleware: "):]

	// extract the error code
	for i := 1; i < len(s); i++ {
		if s[i] == ',' {
			s = s[:i]
			break
		}
	}

	return s
}

type privateError string

func (e privateError) Error() string {
	return string(e)
}

// Errors handles errors coming out of the call chain. It detects normal
// application errors which are used to respond to the client in a uniform way.
// Unexpected errors (status >= 500) are logged.
func Errors(log *log.Logger) web.Middleware {

	// This is the actual middleware function to be executed.
	f := func(before web.Handler) web.Handler {

		h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			ctx, span := trace.StartSpan(ctx, "internal.middleware.Errors")
			defer span.End()

			// If the context is missing this value, request the service
			// to be shutdown gracefully.
			v, ok := ctx.Value(web.KeyValues).(*web.Values)
			if !ok {
				return web.NewShutdownError("web value missing from context")
			}

			// Run the handler chain and catch any propagated error.
			if err := before(ctx, w, r); err != nil {

				// Log the error.
				log.Printf("%s : ERROR : %+v", v.TraceID, err)

				viewErr.JSON(ctx, w, err)

				// If we receive the shutdown err we need to return it
				// back to the base handler to shutdown the service.
				if ok := web.IsShutdown(err); ok {
					return err
				}
			}

			// Return nil to indicate the error has been handled.
			return nil
		}

		return h
	}

	return f
}
