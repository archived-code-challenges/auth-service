package web

import (
	"context"
	"net/http"

	"github.com/pkg/errors"

	"github.com/noelruault/golang-authentication/internal/models"
)

// shutdown is a type used to help with the graceful termination of the service.
type shutdown struct {
	Message string
}

// Error is the implementation of the error interface.
func (s *shutdown) Error() string {
	return s.Message
}

// NewShutdownError returns an error that causes the framework to signal
// a graceful shutdown.
func NewShutdownError(message string) error {
	return &shutdown{message}
}

// IsShutdown checks to see if the shutdown error is contained
// in the specified error value.
func IsShutdown(err error) bool {
	if _, ok := errors.Cause(err).(*shutdown); ok {
		return true
	}
	return false
}

// Error is a view that converts errors into API HTTP responses.
type Error struct {
	codes map[string]int
}

// SetCode defines a default HTTP error code to be returned when err is found. The result of calling err.Public()
// must match any other error instances of the same type.
//
// For models.ValidationError fields, the specific field error should be passed as err. Note that if
// multiple errors as fields have a customised code, the returned HTTP error code is umpredictable and
// may be of any one of the fields.
func (e *Error) SetCode(err models.PublicError, code int) {
	if e.codes == nil {
		e.codes = make(map[string]int)
	}

	e.codes[err.Public()] = code
}

// JSON returns a JSON document with an error response to a requester.
//
// In case err has a "Public() string" method, it returns by default an HTTP Bad Request code and the
// JSON "error" field receives the result of calling Public(). You may use e.SetCode() to change the
// default HTTP status code for a specific public error string. Specifically for models.ValidationError,
// the specific errors for each field are included as the value of the JSON "fields" field. The status
// code may be modified by e.SetCode by passing field errors.
//
// In case err does not have a "Public() string" method, it returns an HTTP Internal Server
// Error code and the JSON "error" field receives a "server_error" value.
//
// In case err is a models.ValidationError, it returns by default an HTTP Bad Request doce an error code of "validation_error"
// is returned, and the specific errors for each field are included as the
// value of the JSON "fields" field.
func (e Error) JSON(ctx context.Context, w http.ResponseWriter, err error) error {
	// set the defaults we are going to return
	status := http.StatusInternalServerError
	data := map[string]interface{}{"error": "server_error"}

	// if it is a public error, must check if there's a different HTTP code set in the map
	if pe, ok := err.(models.PublicError); ok {
		status = http.StatusBadRequest

		public := pe.Public()
		data["error"] = public

		if s := e.codes[public]; s != 0 {
			status = s
		}
	}

	// if it's a validation error, we also need to check for codes and also add the fields to the output
	if ve, ok := err.(models.ValidationError); ok {
		vem := make(map[string]string, len(ve))

		for field, err := range ve {
			public := err.Public()

			if s := e.codes[public]; s != 0 {
				status = s
			}

			vem[field] = public
		}

		data["fields"] = vem
	}

	return Respond(ctx, w, data, status)
}
