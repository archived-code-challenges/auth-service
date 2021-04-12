package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gorilla/schema"
	"go.opencensus.io/trace"

	"github.com/noelruault/golang-authentication/internal/models"
	"github.com/noelruault/golang-authentication/internal/web"
)

// Users implements a controller for authentication, authorisation and
// user management.
type Users struct {
	us models.UserService

	viewErr web.Error
	log     *log.Logger
}

// NewUsers creates a new Users controller.
func NewUsers(us models.UserService, log *log.Logger) *Users {
	var ev web.Error
	ev.SetCode(models.ErrDuplicate, http.StatusConflict)
	ev.SetCode(ErrNotFound, http.StatusNotFound)
	ev.SetCode(models.ErrNotFound, http.StatusNotFound)
	ev.SetCode(models.ErrUnauthorised, http.StatusUnauthorized)

	return &Users{
		us:      us,
		viewErr: ev,
		log:     log,
	}
}

// Login takes a username and password or a refresh token and returns a set of
// access and refresh tokens.
//
// Login takes care of its own Content-Types as it is not a standard API call. No
// middlewares for content types should be applied to Login.
//
// POST /oauth/login/
func (u *Users) Login(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.User.Login")
	defer span.End()

	var decoder = schema.NewDecoder()
	var auth struct {
		Email        string `schema:"email"`
		GrantType    string `schema:"grant_type, required"` // password, refresh_token
		Password     string `schema:"password"`
		RefreshToken string `schema:"refresh_token"`
	}

	if !strings.Contains(r.Header.Get("Content-type"), "application/x-www-form-urlencoded") {
		return ErrContentTypeNotAccepted
	}

	err := r.ParseForm()
	if err != nil {
		u.viewErr.JSON(ctx, w, fmt.Errorf("ParseForm: couldn't parse given form %w", err))
		return nil
	}

	// r.PostForm is a map of POST form values
	err = decoder.Decode(&auth, r.PostForm)
	if err != nil {
		u.viewErr.JSON(ctx, w, ErrInvalidFormInput)
		return nil
	}

	var user models.User
	if auth.GrantType == "password" {
		user, err = u.us.Authenticate(ctx, auth.Email, auth.Password)
		if err != nil {
			u.viewErr.JSON(ctx, w, err)
			return nil
		}
	} else if auth.GrantType == "refresh_token" {
		user, err = u.us.Refresh(ctx, auth.RefreshToken)
		if err != nil {
			u.viewErr.JSON(ctx, w, err)
			return nil
		}
	} else {
		u.viewErr.JSON(ctx, w, ErrGrantTypeNotAccepted)
		return nil
	}

	token, err := u.us.Token(ctx, &user)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, token, http.StatusOK)
}

// Create adds a new user to the system.
//
// POST /api/users/
func (u *Users) Create(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.Users.Create")
	defer span.End()

	nu := models.NewUser()
	if err := web.Decode(r, &nu); err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	err := u.us.Create(ctx, &nu)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, &nu, http.StatusCreated)
}

// Update updates system existing user.
//
// PUT api/users/:id
func (u *Users) Update(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.Users.Update")
	defer span.End()

	requestID, err := strconv.ParseInt(path.Base(r.URL.Path), 10, 64)
	if err != nil {
		u.viewErr.JSON(ctx, w, ErrNotFound)
		return nil
	}

	var user models.User
	if err := web.Decode(r, &user); err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}
	user.ID = requestID

	err = u.us.Update(ctx, &user)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, &user, http.StatusOK)
}

// Get returns one user by ID to the requester.
//
// GET /api/v1/users/:id
func (u *Users) ByID(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.User.ByID")
	defer span.End()

	id, err := strconv.ParseInt(path.Base(r.URL.Path), 10, 64)
	if err != nil {
		u.viewErr.JSON(ctx, w, ErrNotFound)
		return nil
	}

	user, err := u.us.ByID(ctx, id)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, user, http.StatusOK)
}

// List returns a list of users, optionally filteres by IDs or countries, to the requester.
func (u *Users) List(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.User.List")
	defer span.End()

	if r.URL.Query().Get("country") != "" {
		return u.ListByCountries(ctx, w, r)
	}

	if r.URL.Query().Get("id") != "" {
		return u.ListByIDs(ctx, w, r)
	}

	users, err := u.us.ByIDs(ctx, []int64{}...)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, users, http.StatusOK)
}

// ListByIDs returns a list of users, filtering by IDs, to the requester.
//
// The IDs are passed as a comma-separated list of user IDs, as the "id" query parameter.
// If any ID passed are not found, those are not shown on the returned list.
//
// This handler will never return a NotFound error, instead returning an empty list.
//
// GET /api/v1/users/?id=1,2,3
func (u *Users) ListByIDs(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.User.ListByIDs")
	defer span.End()

	requestIDs, err := getQueryList(r, "id", []int64{})
	if err != nil {
		u.viewErr.JSON(ctx, w, ErrNotFound)
		return nil
	}

	ids := requestIDs.([]int64)
	if len(ids) == 0 {
		u.viewErr.JSON(ctx, w, models.ValidationError{"id": models.ErrRequired})
		return nil
	}

	users, err := u.us.ByIDs(ctx, ids...)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, users, http.StatusOK)
}

// ListByIDs returns a list of users, filtering by countries, to the requester.
//
// The countries are passed as a comma-separated list of country codes, as the "country" query parameter.
// If any country passed are not found, those are not shown on the returned list.
//
// This handler will never return a NotFound error, instead returning an empty list.
//
// GET /api/v1/users/?country=CO,DE
func (u *Users) ListByCountries(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.User.ListByCountries")
	defer span.End()

	requestCountries, err := getQueryList(r, "country", []string{})
	if err != nil {
		u.viewErr.JSON(ctx, w, models.ValidationError{"country": models.ErrInvalidURLFormat})
		return nil
	}

	countries := requestCountries.([]string)
	if len(countries) == 0 {
		u.viewErr.JSON(ctx, w, models.ValidationError{"country": models.ErrRequired})
		return nil
	}

	users, err := u.us.ByCountries(ctx, countries...)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, users, http.StatusOK)
}

// Delete removes an existing user in the system.
//
// DELETE api/users/:id
func (u *Users) Delete(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.Users.Delete")
	defer span.End()

	requestID, err := strconv.ParseInt(path.Base(r.URL.Path), 10, 64)
	if err != nil {
		u.viewErr.JSON(ctx, w, ErrNotFound)
		return nil
	}

	err = u.us.Delete(ctx, requestID)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, "", http.StatusNoContent)
}

// BenchLogin would make a login request. It needs a specific user created in the database:
// - email:    api-client@test.com
// - password: secret01234
//
// IMPORTANT: Instructional use only
func (u *Users) BenchLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	ctx, span := trace.StartSpan(ctx, "handlers.User.Login")
	defer span.End()

	var auth struct {
		Email        string `schema:"email"`
		GrantType    string `schema:"grant_type, required"` // password, refresh_token
		Password     string `schema:"password"`
		RefreshToken string `schema:"refresh_token"`
	}

	auth.GrantType = "password"
	auth.Email = "api-client@test.com"
	auth.Password = "secret01234"

	var err error
	var user models.User
	if auth.GrantType == "password" {
		user, err = u.us.Authenticate(ctx, auth.Email, auth.Password)
		if err != nil {
			u.viewErr.JSON(ctx, w, err)
			return nil
		}
	} else if auth.GrantType == "refresh_token" {
		user, err = u.us.Refresh(ctx, auth.RefreshToken)
		if err != nil {
			u.viewErr.JSON(ctx, w, err)
			return nil
		}
	} else {
		u.viewErr.JSON(ctx, w, ErrGrantTypeNotAccepted)
		return nil
	}

	token, err := u.us.Token(ctx, &user)
	if err != nil {
		u.viewErr.JSON(ctx, w, err)
		return nil
	}

	return web.Respond(ctx, w, token, http.StatusOK)
}
