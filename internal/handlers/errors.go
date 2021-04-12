package handlers

import (
	"github.com/noelruault/golang-authentication/internal/errors"
	"github.com/noelruault/golang-authentication/internal/models"
)

var (
	wrap = errors.Wrapper("handlers")
)

// These errors are returned by the controllers and can be used to provide error codes to the
// API results.
const (
	ErrNotFound               ControllerError   = "handlers: not_found, resource not found"
	ErrInvalidFormInput       ControllerError   = "handlers: invalid_form, provided input cannot be parsed"
	ErrContentTypeNotAccepted ControllerError   = "handlers: content_type_not_accepted, the content-type provided is not supported"
	ErrGrantTypeNotAccepted   ControllerError   = "handlers: unsupported_grant_type, the grant-type provided is not supported"
	ErrParseError             models.ModelError = "models: invalid_parse, contents are not in appropriate format"
)

// ControllerError defines errors exported by this package. This type implement a Public() method that
// extracts a unique error code defined for each error value exported.
type ControllerError string

// Error returns the exact original message of the e value.
func (e ControllerError) Error() string {
	return string(e)
}

// Public extracts the error code string present on the value of e.
//
// An error code is defined as the string after the package prefix and colon, and before the comma that follows
// this string. Example:
//		"models: error_code, this is a validation error"
func (e ControllerError) Public() string {
	// remove the prefix
	s := string(e)[len("handlers: "):]

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
