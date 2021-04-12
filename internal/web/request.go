package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	en "github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	validator "gopkg.in/go-playground/validator.v9"
	en_translations "gopkg.in/go-playground/validator.v9/translations/en"

	"github.com/noelruault/golang-authentication/internal/models"
)

// validate holds the settings and caches for validating request struct values.
var validate = validator.New()

// translator is a cache of locale and translation information.
var translator *ut.UniversalTranslator

func init() {

	// Instantiate the english locale for the validator library.
	enLocale := en.New()

	// Create a value using English as the fallback locale (first argument).
	// Provide one or more arguments for additional supported locales.
	translator = ut.New(enLocale, enLocale)

	// Register the english error messages for validation errors.
	lang, _ := translator.GetTranslator("en")
	en_translations.RegisterDefaultTranslations(validate, lang)

	// Use JSON tag names for errors instead of Go struct names.
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
}

// fieldError is used to indicate an error with a specific request field.
type fieldError struct {
	Field string `json:"field"`
	Error string `json:"error"`
}

// Error is used to pass an error during the request through the
// application with web specific context.
type decodeError struct {
	Err    error
	Status int
	Fields []fieldError
}

// Error implements the error interface. It uses the default message of the
// wrapped error. This is what will be shown in the services' logs.
func (err *decodeError) Error() string {
	return err.Err.Error()
}

// Decode reads the body of an HTTP request looking for a JSON document. The
// body is decoded into the provided value.
//
// If the provided value is a struct then it is checked for validation tags.
func Decode(r *http.Request, val interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields() // return an error when the destination is a struct and the input
	// contains object keys which do not match the destination.

	if err := decoder.Decode(val); err != nil {
		if strings.Contains(err.Error(), "json: unknown field") { // Used alongside DisallowUnknownFields to return an idiomatic error
			uf := strings.Trim(strings.ReplaceAll(err.Error(), "json: unknown field ", ""), "\"") // Gets the unknown field name from the error
			return models.ValidationError{uf: models.ErrInvalidField}
		}
		return models.ErrInvalidJSON
	}

	if err := validate.Struct(val); err != nil {

		// Use a type assertion to get the real error value.
		verrors, ok := err.(validator.ValidationErrors)
		if !ok {
			return err
		}

		// lang controls the language of the error messages. You could look at the
		// Accept-Language header if you intend to support multiple languages.
		lang, _ := translator.GetTranslator("en")

		var fields []fieldError
		for _, verror := range verrors {
			field := fieldError{
				Field: verror.Field(),
				Error: verror.Translate(lang),
			}
			fields = append(fields, field)
		}

		return &decodeError{
			Err:    errors.New("field validation error"),
			Status: http.StatusBadRequest,
			Fields: fields,
		}
	}

	return nil
}
