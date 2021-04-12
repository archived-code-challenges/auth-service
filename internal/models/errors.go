package models

import (
	"github.com/noelruault/golang-authentication/internal/errors"
)

var (
	wrap = errors.Wrapper("models")
)

// These errors are returned by the services and can be used to provide error codes to the
// API results.
const (
	ErrNotFound         ModelError = "models: not_found, resource not found"
	ErrReadOnly         ModelError = "models: read_only, resource cannot be modified or deleted"
	ErrUnauthorised     ModelError = "models: unauthorised, username, password or refresh token are invalid, user does not exist or validation failed"
	ErrInvalidURLFormat ModelError = "models: invalid_url_format, url is not in a valid format"
	ErrInvalidField     ModelError = "models: invalid_field, provided field is not valid"
	ErrInvalidCountry   ModelError = "models: invalid_country_code, provided country code is not valid. Must be in ISO 3166-1 format"
	ErrInvalidJSON      ModelError = "models: invalid_json, provided input cannot be parsed"

	ErrIDTaken   ModelError = "models: id_taken, primary key already exists"
	ErrTooShort  ModelError = "models: too_short, value is shorter than required"
	ErrTooLong   ModelError = "models: too_long, value is longer than required"
	ErrRequired  ModelError = "models: required, value cannot be empty"
	ErrInvalid   ModelError = "models: invalid, value does not match its specification"
	ErrDuplicate ModelError = "models: is_duplicate, value already exists in the system and cannot be a duplicate"

	ErrNoCredentials     ModelError = "models: credentials_not_provided, username, password or refresh token are empty"
	ErrRefreshInvalid    ModelError = "models: invalid_refresh_token, refresh token is not valid"
	ErrRefreshExpired    ModelError = "models: expired_refresh_token, refresh token has expired"
	ErrPasswordIncorrect ModelError = "models: incorrect_password, incorrect password provided"
)

// PublicError is an error that returns a string code that can be presented to the API user.
type PublicError interface {
	error
	Public() string
}

// ModelError defines errors exported by this package. This type implement a Public() method that
// extracts a unique error code defined for each error value exported.
type ModelError string

// Error returns the exact original message of the e value.
func (e ModelError) Error() string {
	return string(e)
}

// Public extracts the error code string present on the value of e.
//
// An error code is defined as the string after the package prefix and colon, and before the comma that follows
// this string. Example:
//		"models: error_code, this is a validation error"
func (e ModelError) Public() string {
	// remove the prefix
	s := string(e)[len("models: "):]

	// extract the error code
	for i := 1; i < len(s); i++ {
		if s[i] == ',' {
			s = s[:i]
			break
		}
	}

	return s
}

// A ValidationError contains a set of error values related to a model's field names. The
// field names used on the map are equal to their JSON names.
//
// ValidationError values are only returned when all errors relate to specific fields. When a model's value
// has an error relating to multiple fields, a ModelError value is returned instead covering the specific
// situation.
type ValidationError map[string]PublicError

// Error returns the list of fields with validation errors. The specific error for each field is not included.
func (v ValidationError) Error() string {
	ret := "models: validation error on fields "
	for k := range v {
		ret += k + ", "
	}

	return ret[:len(ret)-2]
}

// Public returns the error code used for validation errors, that is "validation_error".
func (v ValidationError) Public() string {
	return "validation_error"
}

// Is helps xerrors.Is check if a target error is a ValidationError. If err (the target) contains
// fields, the error values for each field are compared to the ones in v and their values must
// match. If err contains a subset of the fields in v, it is considered to match.
func (v ValidationError) Is(err error) bool {
	ve, ok := err.(ValidationError)
	if !ok {
		return false
	}

	for k := range ve {
		if v[k] != ve[k] {
			return false
		}
	}

	return true
}

type privateError string

func (e privateError) Error() string {
	return string(e)
}
