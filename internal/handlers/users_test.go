package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/noelruault/golang-authentication/internal/models"
	"github.com/noelruault/golang-authentication/internal/web"
)

type testUserService struct {
	models.UserService
	auth        func(ctx context.Context, username, password string) (models.User, error)
	refresh     func(ctx context.Context, refreshToken string) (models.User, error)
	token       func(context.Context, *models.User) (models.Token, error)
	byID        func(context.Context, int64) (models.User, error)
	byIDs       func(context.Context, ...int64) ([]models.User, error)
	byCountries func(context.Context, ...string) ([]models.User, error)
	delete      func(context.Context, int64) error
	create      func(context.Context, *models.User) error
	update      func(context.Context, *models.User) error
}

func (t *testUserService) Authenticate(ctx context.Context, username, password string) (models.User, error) {
	if t.auth != nil {
		return t.auth(ctx, username, password)
	}

	panic("not provided")
}

func (t *testUserService) Refresh(ctx context.Context, refreshToken string) (models.User, error) {
	if t.refresh != nil {
		return t.refresh(ctx, refreshToken)
	}

	panic("not provided")
}

func (t *testUserService) Token(ctx context.Context, u *models.User) (models.Token, error) {
	if t.token != nil {
		return t.token(ctx, u)
	}

	panic("not provided")
}

func (t *testUserService) ByID(ctx context.Context, id int64) (models.User, error) {
	if t.byID != nil {
		return t.byID(ctx, id)
	}

	panic("not provided")
}

func (t *testUserService) ByIDs(ctx context.Context, id ...int64) ([]models.User, error) {
	if t.byIDs != nil {
		return t.byIDs(ctx, id...)
	}

	panic("not provided")
}

func (t *testUserService) ByCountries(ctx context.Context, countries ...string) ([]models.User, error) {
	if t.byCountries != nil {
		return t.byCountries(ctx, countries...)
	}

	panic("not provided")
}

func (t *testUserService) Delete(ctx context.Context, id int64) error {
	if t.delete != nil {
		return t.delete(ctx, id)
	}

	panic("not provided")
}

func (t *testUserService) Create(ctx context.Context, u *models.User) error {
	if t.create != nil {
		return t.create(ctx, u)
	}

	panic("not provided")
}

func (t *testUserService) Update(ctx context.Context, u *models.User) error {
	if t.update != nil {
		return t.update(ctx, u)
	}

	panic("not provided")
}

func testContext() context.Context {
	return context.WithValue(context.Background(), web.KeyValues, &web.Values{})
}

func TestUsers_Login(t *testing.T) {
	us := &testUserService{}
	u := NewUsers(us, nil)

	var cases = []struct {
		name        string
		contentType string
		content     string
		outStatus   int
		outJSON     string
		setup       func(*testing.T)
	}{
		{
			"badContent",
			"application/x-www-form-urlencoded",
			"graskdfhjglk!@98574sjdgfh ksdhf lksdfghlksjkl",
			http.StatusBadRequest,
			`{"error": "invalid_form"}`,
			nil,
		},
		{
			"badGrantTypeDevice",
			"application/x-www-form-urlencoded",
			"grant_type=device",
			http.StatusBadRequest,
			`{"error": "unsupported_grant_type"}`,
			nil,
		},
		{
			"badGrantTypeAuthCode",
			"application/x-www-form-urlencoded",
			"grant_type=authorization_code",
			http.StatusBadRequest,
			`{"error": "unsupported_grant_type"}`,
			nil,
		},
		{
			"validationFails",
			"application/x-www-form-urlencoded",
			"grant_type=password",
			http.StatusBadRequest,
			`{"error":"credentials_not_provided"}`,
			func(*testing.T) {
				us.auth = func(ctx context.Context, username, password string) (models.User, error) {
					return models.User{}, models.ErrNoCredentials
				}
			},
		},
		{
			"authInternalError",
			"application/x-www-form-urlencoded",
			"grant_type=password",
			http.StatusInternalServerError,
			`{"error": "server_error"}`,
			func(*testing.T) {
				us.auth = func(ctx context.Context, username, password string) (models.User, error) {
					return models.User{}, privateError("models: some type of internal error")
				}
			},
		},
		{
			"tokInternalError",
			"application/x-www-form-urlencoded",
			"grant_type=password",
			http.StatusInternalServerError,
			`{"error": "server_error"}`,
			func(*testing.T) {
				us.auth = func(ctx context.Context, username, password string) (models.User, error) {
					return models.User{}, nil
				}
				us.token = func(ctx context.Context, u *models.User) (models.Token, error) {
					return models.Token{}, privateError("models: some type of internal error")
				}
			},
		},
		{
			"unauthorisedBadPass",
			"application/x-www-form-urlencoded",
			"grant_type=password",
			http.StatusUnauthorized,
			`{"error": "unauthorised"}`,
			func(*testing.T) {
				us.auth = func(ctx context.Context, username, password string) (models.User, error) {
					return models.User{}, models.ErrUnauthorised
				}
			},
		},
		{
			"unauthorisedNoUser",
			"application/x-www-form-urlencoded",
			"grant_type=password",
			http.StatusUnauthorized,
			`{"error": "unauthorised"}`,
			func(*testing.T) {
				us.auth = func(ctx context.Context, username, password string) (models.User, error) {
					return models.User{}, models.ErrUnauthorised
				}
			},
		},
		{
			"unauthorisedBadEmail",
			"application/x-www-form-urlencoded",
			"grant_type=password",
			http.StatusUnauthorized,
			`{"error": "unauthorised"}`,
			func(*testing.T) {
				us.auth = func(ctx context.Context, username, password string) (models.User, error) {
					return models.User{}, models.ErrUnauthorised
				}
			},
		},
		{
			"grantedPassword",
			"application/x-www-form-urlencoded",
			"grant_type=password&email=user%40example.com&password=1234luggage",
			http.StatusOK,
			`{"access_token": "test access token", "refresh_token": "test token", "expires_in": 900, "token_type": "bearer"}`,
			func(t *testing.T) {
				us.auth = func(ctx context.Context, username, password string) (models.User, error) {
					assert.Equal(t, username, "user@example.com")
					assert.Equal(t, password, "1234luggage")

					return models.User{
						ID:       99,
						Email:    username,
						Password: password,
					}, nil
				}
				us.token = func(ctx context.Context, u *models.User) (models.Token, error) {
					assert.Equal(t, int64(99), u.ID)

					return models.Token{
						RefreshToken: "test token",
						AccessToken:  "test access token",
						ExpiresIn:    900,
						TokenType:    "bearer",
					}, nil
				}
			},
		},
		{
			"refreshValidationFails",
			"application/x-www-form-urlencoded",
			"grant_type=refresh_token",
			http.StatusBadRequest,
			`{"error":"credentials_not_provided"}`,
			func(*testing.T) {
				us.refresh = func(ctx context.Context, r string) (models.User, error) {
					return models.User{}, models.ErrNoCredentials
				}
			},
		},
		{
			"refreshInternalError",
			"application/x-www-form-urlencoded",
			"grant_type=refresh_token",
			http.StatusInternalServerError,
			`{"error": "server_error"}`,
			func(*testing.T) {
				us.refresh = func(ctx context.Context, r string) (models.User, error) {
					return models.User{}, privateError("models: some type of internal error")
				}
			},
		},
		{
			"tokRefreshInternalError",
			"application/x-www-form-urlencoded",
			"grant_type=refresh_token",
			http.StatusInternalServerError,
			`{"error": "server_error"}`,
			func(*testing.T) {
				us.refresh = func(ctx context.Context, r string) (models.User, error) {
					return models.User{}, privateError("models: some type of internal error")
				}
			},
		},
		{
			"unauthorisedExpiredToken",
			"application/x-www-form-urlencoded",
			"grant_type=refresh_token",
			http.StatusUnauthorized,
			`{"error": "unauthorised"}`,
			func(*testing.T) {
				us.refresh = func(ctx context.Context, r string) (models.User, error) {
					return models.User{}, models.ErrUnauthorised
				}
			},
		},
		{
			"refreshUnauthorisedNoUser",
			"application/x-www-form-urlencoded",
			"grant_type=refresh_token",
			http.StatusUnauthorized,
			`{"error": "unauthorised"}`,
			func(*testing.T) {
				us.refresh = func(ctx context.Context, r string) (models.User, error) {
					return models.User{}, models.ErrUnauthorised
				}
			},
		},
		{
			"unauthorisedBadToken",
			"application/x-www-form-urlencoded",
			"grant_type=refresh_token",
			http.StatusUnauthorized,
			`{"error": "unauthorised"}`,
			func(*testing.T) {
				us.refresh = func(ctx context.Context, r string) (models.User, error) {
					return models.User{}, models.ErrUnauthorised
				}
			},
		},
		{
			"grantedRefresh",
			"application/x-www-form-urlencoded",
			"grant_type=refresh_token&refresh_token=k%40sjdhdfgkjsgfkj",
			http.StatusOK,
			`{"access_token": "test access token", "refresh_token": "test token", "expires_in": 900, "token_type": "bearer"}`,
			func(t *testing.T) {
				us.refresh = func(ctx context.Context, r string) (models.User, error) {
					assert.Equal(t, r, "k@sjdhdfgkjsgfkj")

					return models.User{
						ID: 99,
					}, nil

				}
				us.token = func(ctx context.Context, u *models.User) (models.Token, error) {
					assert.Equal(t, int64(99), u.ID)

					return models.Token{
						RefreshToken: "test token",
						AccessToken:  "test access token",
						ExpiresIn:    900,
						TokenType:    "bearer",
					}, nil
				}
			},
		},
	}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/oauth/login/", bytes.NewReader([]byte(cs.content)))
			r.Header.Add("Content-Type", cs.contentType)

			if cs.setup != nil {
				cs.setup(t)
			}

			err := u.Login(testContext(), w, r)
			require.NoError(t, err)

			assert.Equal(t, cs.outStatus, w.Result().StatusCode)
			assert.JSONEq(t, cs.outJSON, w.Body.String())

			*us = testUserService{}
		})
	}
}

func TestUsers_Create(t *testing.T) {
	us := &testUserService{}
	u := NewUsers(us, nil)

	var cases = []struct {
		name      string
		input     string
		outStatus int
		outJSON   string
		setup     func(*testing.T)
	}{
		{
			"notJSON",
			"a dalhd lkald fkjahd lfkjasdlf ",
			http.StatusBadRequest,
			`{"error":"invalid_json"}`,
			nil,
		},
		{
			"validationError",
			`{"email":"someone@somewhere.com","firstName":"John","lastName":"Dear"}`,
			http.StatusBadRequest,
			`{"error":"validation_error","fields":{"email":"invalid","password":"required"}}`,
			func(t *testing.T) {
				us.create = func(ctx context.Context, u *models.User) error {
					user := models.NewUser()
					user.Email = "someone@somewhere.com"
					user.FirstName = "John"
					user.LastName = "Dear"

					assert.Equal(t, &user, u)
					return models.ValidationError{
						"email":    models.ErrInvalid,
						"password": models.ErrRequired,
					}
				}
			},
		},
		{
			"internalError",
			`{"email":"someone@somewhere.com","firstName":"John","lastName":"Dear"}`,
			http.StatusInternalServerError,
			`{"error":"server_error"}`,
			func(t *testing.T) {
				us.create = func(ctx context.Context, u *models.User) error {
					user := models.NewUser()
					user.Email = "someone@somewhere.com"
					user.FirstName = "John"
					user.LastName = "Dear"

					assert.Equal(t, &user, u)
					return privateError("test error message")
				}
			},
		},
		{
			"emailTaken",
			`{"email":"someone@somewhere.com","firstName":"John","lastName":"Dear"}`,
			http.StatusConflict,
			`{"error":"validation_error","fields":{"email":"is_duplicate","password":"required"}}`,
			func(t *testing.T) {
				us.create = func(ctx context.Context, u *models.User) error {
					user := models.NewUser()
					user.Email = "someone@somewhere.com"
					user.FirstName = "John"
					user.LastName = "Dear"

					assert.Equal(t, &user, u)
					return models.ValidationError{
						"email":    models.ErrDuplicate,
						"password": models.ErrRequired,
					}
				}
			},
		},
		{
			"ok",
			`{"active":true,"country":"UK","email":"someone@somewhere.com","firstName":"John","lastName":"Dear","nickname":"jondy","password":"testpassword"}`,
			http.StatusCreated,
			`{"id":88,"active":true,"country":"UK","email":"someone@somewhere.com","firstName":"John","lastName":"Dear","nickname":"jondy","password":"testpassword"}`,
			func(t *testing.T) {
				us.create = func(ctx context.Context, u *models.User) error {
					assert.Equal(t, &models.User{
						Active:    true,
						Email:     "someone@somewhere.com",
						FirstName: "John",
						LastName:  "Dear",
						Nickname:  "jondy",
						Password:  "testpassword",
						Country:   "UK",
					}, u)

					u.ID = 88
					return nil
				}
			},
		},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/users/", bytes.NewReader([]byte(cs.input)))

			if cs.setup != nil {
				cs.setup(t)
			}

			err := u.Create(testContext(), w, r)
			require.NoError(t, err)

			assert.Equal(t, cs.outStatus, w.Result().StatusCode)
			assert.JSONEq(t, cs.outJSON, w.Body.String())

			*us = testUserService{}
		})
	}
}

func TestUsers_Update(t *testing.T) {
	us := &testUserService{}
	u := NewUsers(us, nil)

	var cases = []struct {
		name      string
		path      string
		input     string
		outStatus int
		outJSON   string
		setup     func(*testing.T)
	}{
		{
			"badPathID",
			"/api/users/lksdjflk",
			"",
			http.StatusNotFound,
			`{"error":"not_found"}`,
			nil,
		},
		{
			"notJSON",
			"/api/users/99",
			"a dalhd lkald fkjahd lfkjasdlf ",
			http.StatusBadRequest,
			`{"error":"invalid_json"}`,
			nil,
		},
		{
			"notFound",
			"/api/users/99",
			`{"email":"someone@somewhere.com","active":true}`,
			http.StatusNotFound,
			`{"error":"not_found"}`,
			func(t *testing.T) {
				us.update = func(ctx context.Context, u *models.User) error {
					user := models.NewUser()
					user.ID = 99
					user.Email = "someone@somewhere.com"

					assert.Equal(t, &user, u)
					return models.ErrNotFound
				}
			},
		},
		{
			"validationError",
			"/api/users/99",
			`{"email":"someone@somewhere.com","firstName":"John","lastName":"Dear","active":true}`,
			http.StatusBadRequest,
			`{"error":"validation_error","fields":{"email":"invalid","password":"required"}}`,
			func(t *testing.T) {
				us.update = func(ctx context.Context, u *models.User) error {
					user := models.NewUser()
					user.ID = 99
					user.Email = "someone@somewhere.com"
					user.FirstName = "John"
					user.LastName = "Dear"

					assert.Equal(t, &user, u)
					return models.ValidationError{
						"email":    models.ErrInvalid,
						"password": models.ErrRequired,
					}
				}
			},
		},
		{
			"emailAlreadyUsed",
			"/api/users/1",
			`{"email":"someone@somewhere.com","firstName":"John","lastName":"Dear","active":true}`,
			http.StatusConflict,
			`{"error":"validation_error", "fields":{"email":"is_duplicate"}}`,
			func(t *testing.T) {
				us.update = func(ctx context.Context, u *models.User) error {
					user := models.NewUser()
					user.ID = 1
					user.Email = "someone@somewhere.com"
					user.FirstName = "John"
					user.LastName = "Dear"

					assert.Equal(t, &user, u)
					return models.ValidationError{"email": models.ErrDuplicate}
				}
			},
		},
		{
			"ok",
			"/api/users/99",
			`{"active":true,"country":"ESP","email":"someone@somewhere.com",
				"firstName":"John","lastName":"Doe","nickname":"jonydi","password":"testpassword",
				"settings":"a string of preferences"}`,
			http.StatusOK,
			`{"id":99,"active":true,"country":"ESP","email":"someone@somewhere.com",
				"firstName":"John","lastName":"Doe","nickname":"jonydi","password":"testpassword",
				"settings":"a string of preferences"}`,
			func(t *testing.T) {
				us.update = func(ctx context.Context, u *models.User) error {
					assert.Equal(t, &models.User{
						ID:        99,
						Active:    true,
						Country:   "ESP",
						Email:     "someone@somewhere.com",
						FirstName: "John",
						LastName:  "Doe",
						Nickname:  "jonydi",
						Password:  "testpassword",
						Settings:  "a string of preferences",
					}, u)

					return nil
				}
			},
		},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPut, cs.path, bytes.NewReader([]byte(cs.input)))

			if cs.setup != nil {
				cs.setup(t)
			}

			err := u.Update(testContext(), w, r)
			require.NoError(t, err)

			assert.Equal(t, cs.outStatus, w.Result().StatusCode)
			assert.JSONEq(t, cs.outJSON, w.Body.String())

			*us = testUserService{}
		})
	}
}

func TestUsers_Delete(t *testing.T) {
	us := &testUserService{}
	u := NewUsers(us, nil)

	var cases = []struct {
		name      string
		path      string
		outStatus int
		outJSON   string
		setup     func(*testing.T)
	}{
		{
			"badPathID",
			"/api/users/lksdjflk",
			http.StatusNotFound,
			`{"error":"not_found"}`,
			nil,
		},
		{
			"notInStore",
			"/api/users/999",
			http.StatusNotFound,
			`{"error":"not_found"}`,
			func(t *testing.T) {
				us.delete = func(ctx context.Context, id int64) error {
					assert.Equal(t, int64(999), id)
					return models.ErrNotFound
				}
			},
		},
		{
			"storeInternalError",
			"/api/users/999",
			http.StatusInternalServerError,
			`{"error":"server_error"}`,
			func(t *testing.T) {
				us.delete = func(ctx context.Context, id int64) error {
					assert.Equal(t, int64(999), id)
					return wrap("test internal error", nil)
				}
			},
		},
		{
			"ok",
			"/api/users/999",
			http.StatusNoContent,
			`{}`,
			func(t *testing.T) {
				us.delete = func(ctx context.Context, id int64) error {
					assert.Equal(t, int64(999), id)
					return nil
				}
			},
		},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodDelete, cs.path, nil)

			if cs.setup != nil {
				cs.setup(t)
			}

			err := u.Delete(testContext(), w, r)
			require.NoError(t, err)

			assert.Equal(t, cs.outStatus, w.Result().StatusCode)

			if w.Result().StatusCode != 204 {
				assert.JSONEq(t, cs.outJSON, w.Body.String())
			} else {
				assert.Equal(t, "", w.Body.String())
			}

			*us = testUserService{}
		})
	}
}

func TestUsers_Get(t *testing.T) {
	us := &testUserService{}
	u := NewUsers(us, nil)

	var cases = []struct {
		name      string
		path      string
		outStatus int
		outJSON   string
		setup     func(*testing.T)
	}{
		{
			"badPathID",
			"/api/users/lksdjflk",
			http.StatusNotFound,
			`{"error":"not_found"}`,
			nil,
		},
		{
			"notInStore",
			"/api/users/999",
			http.StatusNotFound,
			`{"error":"not_found"}`,
			func(t *testing.T) {
				us.byID = func(ctx context.Context, id int64) (models.User, error) {
					assert.Equal(t, int64(999), id)
					return models.User{}, models.ErrNotFound
				}
			},
		},
		{
			"storeInternalError",
			"/api/users/999",
			http.StatusInternalServerError,
			`{"error":"server_error"}`,
			func(t *testing.T) {
				us.byID = func(ctx context.Context, id int64) (models.User, error) {
					assert.Equal(t, int64(999), id)
					return models.User{}, wrap("test internal error", nil)
				}
			},
		},
		{
			"ok",
			"/api/users/999",
			http.StatusOK,
			`{
				"active":true,
				"country":"ESP",
				"email":"test@email.com",
				"firstName":"Test",
				"id":999,
				"lastName":"User",
				"nickname":"usy",
				"settings":"settings_string"
			}`,
			func(t *testing.T) {
				us.byID = func(ctx context.Context, id int64) (models.User, error) {
					assert.Equal(t, int64(999), id)
					return models.User{
						ID:        999,
						Active:    true,
						Country:   "ESP",
						Email:     "test@email.com",
						FirstName: "Test",
						Nickname:  "usy",
						LastName:  "User",
						Settings:  "settings_string",
					}, nil
				}
			},
		},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, cs.path, nil)

			if cs.setup != nil {
				cs.setup(t)
			}

			err := u.ByID(testContext(), w, r)
			require.NoError(t, err)

			assert.Equal(t, cs.outStatus, w.Result().StatusCode)
			assert.JSONEq(t, cs.outJSON, w.Body.String())

			*us = testUserService{}
		})
	}
}

func TestUsers_ListByIDs(t *testing.T) {
	us := &testUserService{}
	u := NewUsers(us, nil)

	var cases = []struct {
		name      string
		path      string
		outStatus int
		outJSON   string
		setup     func(*testing.T)
	}{
		{
			"notInStore",
			"/api/users/?id=999,1000",
			http.StatusOK,
			`null`,
			func(t *testing.T) {
				us.byIDs = func(ctx context.Context, id ...int64) ([]models.User, error) {
					assert.Equal(t, []int64{999, 1000}, id)
					return nil, nil
				}
			},
		},
		{
			"storeInternalError",
			"/api/users/?id=999",
			http.StatusInternalServerError,
			`{"error":"server_error"}`,
			func(t *testing.T) {
				us.byIDs = func(ctx context.Context, id ...int64) ([]models.User, error) {
					assert.Equal(t, []int64{999}, id)
					return nil, wrap("test internal error", nil)
				}
			},
		},
		{
			"blankQuery",
			"/api/users/?id=",
			http.StatusBadRequest,
			`{"error":"validation_error", "fields":{"id":"required"}}`,
			func(t *testing.T) {
				us.byIDs = func(ctx context.Context, id ...int64) ([]models.User, error) {
					assert.Len(t, id, 0)
					return []models.User{
						{
							ID:        999,
							Active:    true,
							Country:   "ESP",
							Email:     "test@email.com",
							FirstName: "Test",
							Nickname:  "tuser",
							LastName:  "User",
							Settings:  "settings_string",
						},
					}, nil
				}
			},
		},
		{
			"ok",
			"/api/users/?id=999,888",
			http.StatusOK,
			`[{
				"active":true,
				"country":"ESP",
				"email":"test@email.com",
				"firstName":"Test",
				"id":999,
				"lastName":"User",
				"nickname":"usy",
				"settings":"settings_string"
			}]`,
			func(t *testing.T) {
				us.byIDs = func(ctx context.Context, id ...int64) ([]models.User, error) {
					assert.Equal(t, []int64{999, 888}, id)
					return []models.User{
						{
							ID:        999,
							Active:    true,
							Country:   "ESP",
							Email:     "test@email.com",
							FirstName: "Test",
							Nickname:  "usy",
							LastName:  "User",
							Settings:  "settings_string",
						},
					}, nil
				}
			},
		},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, cs.path, nil)

			if cs.setup != nil {
				cs.setup(t)
			}

			err := u.ListByIDs(testContext(), w, r)
			require.NoError(t, err)

			assert.Equal(t, cs.outStatus, w.Result().StatusCode)
			assert.JSONEq(t, cs.outJSON, w.Body.String())

			*us = testUserService{}
		})
	}
}

func TestUsers_ListByCountries(t *testing.T) {
	us := &testUserService{}
	u := NewUsers(us, nil)

	var cases = []struct {
		name      string
		path      string
		outStatus int
		outJSON   string
		setup     func(*testing.T)
	}{
		{
			"notInStore",
			"/api/users/?country=ES,UK",
			http.StatusOK,
			`null`,
			func(t *testing.T) {
				us.byCountries = func(ctx context.Context, countries ...string) ([]models.User, error) {
					assert.Equal(t, []string{"ES", "UK"}, countries)
					return nil, nil
				}
			},
		},
		{
			"storeInternalError",
			"/api/users/?country=ES",
			http.StatusInternalServerError,
			`{"error":"server_error"}`,
			func(t *testing.T) {
				us.byCountries = func(ctx context.Context, countries ...string) ([]models.User, error) {
					assert.Equal(t, []string{"ES"}, countries)
					return nil, wrap("test internal error", nil)
				}
			},
		},
		{
			"blankQuery",
			"/api/users/?country=",
			http.StatusBadRequest,
			`{"error":"validation_error", "fields":{"country":"required"}}`,
			func(t *testing.T) {
				us.byCountries = func(ctx context.Context, countries ...string) ([]models.User, error) {
					assert.Len(t, countries, 0)
					return []models.User{
						{
							ID:        999,
							Active:    true,
							Country:   "ESP",
							Email:     "test@email.com",
							FirstName: "Test",
							Nickname:  "tuser",
							LastName:  "User",
							Settings:  "settings_string",
						},
					}, nil
				}
			},
		},
		{
			"ok",
			"/api/users/?country=ES,UK",
			http.StatusOK,
			`[{
				"active":true,
				"country":"ES",
				"email":"test@email.com",
				"firstName":"Test",
				"id":999,
				"lastName":"User",
				"nickname":"usy",
				"settings":"settings_string"
			}]`,
			func(t *testing.T) {
				us.byCountries = func(ctx context.Context, countries ...string) ([]models.User, error) {
					assert.Equal(t, []string{"ES", "UK"}, countries)
					return []models.User{
						{
							ID:        999,
							Active:    true,
							Country:   "ES",
							Email:     "test@email.com",
							FirstName: "Test",
							Nickname:  "usy",
							LastName:  "User",
							Settings:  "settings_string",
						},
					}, nil
				}
			},
		},
	}

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, cs.path, nil)

			if cs.setup != nil {
				cs.setup(t)
			}

			err := u.ListByCountries(testContext(), w, r)
			require.NoError(t, err)

			assert.Equal(t, cs.outStatus, w.Result().StatusCode)
			assert.JSONEq(t, cs.outJSON, w.Body.String())

			*us = testUserService{}
		})
	}
}
