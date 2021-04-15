package models

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgconn"
	"go.opencensus.io/trace"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/xerrors"
	jwtjose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"gorm.io/gorm"
)

const (
	// waitAfterAuthError is the period to sleep after a failed user authentication attempt.
	waitAfterAuthError = 500 * time.Millisecond

	jwtAccessDuration  = 6 * time.Hour
	jwtRefreshDuration = 10 * 24 * time.Hour

	tokenClaimsIssuer        = "goauthsvc"
	tokenClaimsIssuerRefresh = "goauthsvcrefresh"
)

// UserService defines a set of methods to be used when dealing with system users and authenticating them.
type UserService interface {
	// Authenticate returns a user based on provided username and password.
	//
	// Errors returned include ErrNoCredentials and ErrUnauthorised. Specific
	// validation errors are masked and not provided, being replaced by
	// ErrUnauthorised.
	Authenticate(ctx context.Context, username, password string) (User, error)

	// Refresh returns a user based on a valid refresh token.
	Refresh(ctx context.Context, refreshToken string) (User, error)

	// Validate return claims based on a valid access token.
	Validate(ctx context.Context, accessToken string) (Claims, error)

	// Token generates a set of tokens based on the user provided as
	// input.
	Token(ctx context.Context, u *User) (Token, error)

	UserDB
}

// UserDB defines how the service interacts with the database.
type UserDB interface {
	// Create adds a user to the system. For common users, the Email, FirstName and Password are mandatory.
	// The parameter u will be modified with normalised and validated values and ID will be set to the new user ID.
	//
	// Use NewUser() to use appropriate default values for the other fields.
	//
	// For application users, email and password will be generated.
	Create(context.Context, *User) error

	// Update updates a user in the system. For common users, the Email, FirstName and Password are mandatory.
	// The parameter u will be modified with normalised and validated
	// values.
	//
	// For application users, email and password cannot be updated.
	Update(context.Context, *User) error

	// Delete removes a user by ID.
	Delete(context.Context, int64) error

	// ByID retrieves a user by ID.
	ByID(context.Context, int64) (User, error)

	// ByIDs retrieves a list of users by their IDs. If no ID is supplied, all users in the database are returned.
	ByIDs(context.Context, ...int64) ([]User, error)

	// ByIDs retrieves a list of users by countries. If no country is is supplied
	// all users in the database are returned.
	ByCountries(context.Context, ...string) ([]User, error)

	// ByEmail retrieves a user by email address, as it is unique in the database.
	ByEmail(context.Context, string) (User, error)
}

// A User represents an application user, be it a human or another application
// that connects to this one.
type User struct {
	ID int64 `gorm:"primary_key;type:bigserial" json:"id"`

	// Active marks if the user is active in the system or disabled.
	// Inactive users are not able to login or use the system.
	Active bool `gorm:"not null" json:"active"`

	// Email is the actual user identifier in the system and must be unique.
	Email string `gorm:"unique;size:255;not null" json:"email"`

	// FirstName is the user's first name or an application user's description.
	FirstName string `gorm:"size:255;not null" json:"firstName"`

	// LastName is the user's last name or last names, and it may be left blank.
	LastName string `gorm:"size:255;not null" json:"lastName"`

	// Password stores the hashed user's password.
	// This value is always cleared when the services return a new user.
	Password string `gorm:"size:255;not null" json:"password,omitempty"`

	Nickname string `gorm:"size:255;not null" json:"nickname"`
	Country  string `gorm:"size:255;not null" json:"country"`

	// Settings is used by the frontend to store free-form contents related to user preferences.
	Settings string `gorm:"type:text;not null" json:"settings,omitempty"`
}

// NewUser creates a new User value with default field values applied.
func NewUser() User {
	return User{
		Active: true,
	}
}

// A Token is a set of tokens that represent a user logged in the system.
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

type authClaims struct {
	jwt.Claims
}

type userService struct {
	UserService

	signer jwtjose.Signer
	secret []byte
}

// NewUserService instantiates a new UserService implementation with db as the backing database.
func NewUserService(db *gorm.DB, jwtSecret []byte) UserService {
	sig, err := jwtjose.NewSigner(jwtjose.SigningKey{
		Algorithm: jwtjose.HS512,
		Key:       []byte(jwtSecret),
	}, (&jwtjose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		panic(fmt.Errorf("failed to instantiate JWT signer: %v", err))
	}

	return &userService{
		UserService: &userValidator{
			UserDB:     &userGorm{db},
			emailRegex: regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9._\-]+\.[a-z0-9._\-]{2,16}$`),
		},
		signer: sig,
		secret: jwtSecret,
	}
}

func (us *userService) Authenticate(ctx context.Context, username, password string) (User, error) {
	ctx, span := trace.StartSpan(ctx, "models.UserService.Authenticate")
	defer span.End()

	// hide the actual errors to reduce ease of BF attacks.
	user, err := us.UserService.Authenticate(ctx, username, password)
	if err != nil {
		if xerrors.Is(err, ValidationError{"email": ErrRequired}) ||
			xerrors.Is(err, ValidationError{"password": ErrRequired}) {
			return user, ErrNoCredentials

		} else if verr := ValidationError(nil); xerrors.As(err, &verr) {
			if verr["password"] == ErrPasswordIncorrect {
				return user, ErrUnauthorised
			}
			err = ErrUnauthorised

		} else if merr := ModelError(""); xerrors.As(err, &merr) {
			err = ErrUnauthorised
		}

		// sleep protection to reduce effectiveness of BF attacks
		time.Sleep(waitAfterAuthError)
		return User{}, err
	}

	return user, nil
}

func (us *userService) Refresh(ctx context.Context, refreshToken string) (User, error) {
	ctx, span := trace.StartSpan(ctx, "models.UserService.Refresh")
	defer span.End()

	if refreshToken == "" {
		return User{}, ErrNoCredentials
	}

	// validate the token
	uid, err := us.tokenValidate(ctx, refreshToken, true)
	if err != nil {
		if merr := ModelError(""); xerrors.As(err, &merr) {
			return User{}, ErrUnauthorised
		}

		return User{}, wrap("failed to validate refresh token", err)
	}

	// get the user from the database
	user, err := us.ByID(ctx, uid)
	if err != nil {
		if xerrors.Is(err, ErrNotFound) {
			return User{}, ErrUnauthorised
		}

		return User{}, wrap("on refresh, failed to obtain user from database", err)
	}

	if !user.Active {
		return User{}, ErrUnauthorised
	}

	return user, nil
}

func (us *userService) Validate(ctx context.Context, accessToken string) (Claims, error) {
	ctx, span := trace.StartSpan(ctx, "models.UserService.Validate")
	defer span.End()

	if accessToken == "" {
		return Claims{}, ErrUnauthorised
	}

	// validate the token
	uid, err := us.tokenValidate(ctx, accessToken, false)
	if err != nil {
		if merr := ModelError(""); xerrors.As(err, &merr) {
			return Claims{}, ErrUnauthorised
		}

		return Claims{}, wrap("failed to validate refresh token", err)
	}

	// get the user from the database
	user, err := us.ByID(ctx, uid)
	if err != nil {
		if xerrors.Is(err, ErrNotFound) {
			return Claims{}, ErrUnauthorised
		}

		return Claims{}, wrap("on validate, failed to obtain user from database", err)
	}

	if !user.Active {
		return Claims{}, ErrUnauthorised
	}

	return NewClaims(user), nil
}

func (us *userService) Token(ctx context.Context, u *User) (Token, error) {
	_, span := trace.StartSpan(ctx, "models.UserService.Token")
	defer span.End()

	claimsAccess := authClaims{
		Claims: jwt.Claims{
			Subject: strconv.FormatInt(u.ID, 10),
			Issuer:  tokenClaimsIssuer,
			Expiry:  jwt.NewNumericDate(time.Now().UTC().Add(jwtAccessDuration)),
		},
	}
	claimsRefresh := authClaims{
		Claims: jwt.Claims{
			Subject: strconv.FormatInt(u.ID, 10),
			Issuer:  tokenClaimsIssuerRefresh,
			Expiry:  jwt.NewNumericDate(time.Now().UTC().Add(jwtRefreshDuration)),
		},
	}

	accessTok, err := jwt.Signed(us.signer).Claims(claimsAccess).CompactSerialize()
	if err != nil {
		return Token{}, wrap("failed to generate access token", err)
	}

	refreshTok, err := jwt.Signed(us.signer).Claims(claimsRefresh).CompactSerialize()
	if err != nil {
		return Token{}, wrap("failed to generate refresh token", err)
	}

	return Token{
		AccessToken:  accessTok,
		RefreshToken: refreshTok,
		ExpiresIn:    int(jwtAccessDuration / time.Second),
		TokenType:    "bearer",
	}, nil
}

func (us *userService) ByID(ctx context.Context, id int64) (User, error) {
	ctx, span := trace.StartSpan(ctx, "models.UserService.ByID")
	defer span.End()

	u, err := us.UserService.ByID(ctx, id)

	u.Password = ""
	return u, err
}

func (us *userService) ByIDs(ctx context.Context, ids ...int64) ([]User, error) {
	ctx, span := trace.StartSpan(ctx, "models.UserService.ByIDs")
	defer span.End()

	u, err := us.UserService.ByIDs(ctx, ids...)

	for i := range u {
		u[i].Password = ""
	}

	return u, err
}

func (us *userService) ByCountries(ctx context.Context, countries ...string) ([]User, error) {
	ctx, span := trace.StartSpan(ctx, "models.UserService.ByCountries")
	defer span.End()

	u, err := us.UserService.ByCountries(ctx, countries...)

	for i := range u {
		u[i].Password = ""
	}

	return u, err
}

func (us *userService) ByEmail(ctx context.Context, e string) (User, error) {
	ctx, span := trace.StartSpan(ctx, "models.UserService.ByEmail")
	defer span.End()

	u, err := us.UserService.ByEmail(ctx, e)

	u.Password = ""
	return u, err
}

// tokenValidate validates token as a JWT. If refresh is true, it validates it as being a
// refresh token. The method returns the user id present in the token claims
func (us *userService) tokenValidate(ctx context.Context, token string, isRefresh bool) (uid int64, err error) {
	_, span := trace.StartSpan(ctx, "models.User.tokenValidate")
	defer span.End()

	var cl authClaims

	// parse the token first
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return 0, ErrRefreshInvalid
	}

	// verify the claims check with the signature key
	err = tok.Claims(us.secret, &cl)
	if err != nil {
		return 0, ErrRefreshInvalid
	}

	// verify the token has not expired
	iss := tokenClaimsIssuer
	if isRefresh {
		iss = tokenClaimsIssuerRefresh
	}

	err = cl.Validate(jwt.Expected{
		Issuer: iss,
		Time:   time.Now().UTC(),
	})
	if err != nil {
		if xerrors.Is(err, jwt.ErrExpired) {
			return 0, ErrRefreshExpired
		}

		return 0, ErrRefreshInvalid
	}

	// get the user ID in the claim, passed in the subject field
	id, err := strconv.ParseInt(cl.Subject, 10, 0)
	if err != nil {
		return 0, ErrRefreshInvalid
	}

	return id, nil
}

type userValidator struct {
	UserDB
	emailRegex *regexp.Regexp
	ctx        context.Context
}

func (uv *userValidator) Authenticate(ctx context.Context, username, password string) (User, error) {
	ctx, span := trace.StartSpan(ctx, "models.User.Authenticate")
	defer span.End()

	// create a simple user to apply validators
	user := User{
		Email:    username,
		Password: password,
	}

	uv.ctx = ctx

	err := uv.runValFuncs(&user,
		uv.emailRequired,
		uv.passwordRequired,
		uv.passwordLength,
		uv.normaliseEmail,
		uv.emailFormat,
	)
	if err != nil {
		return User{}, err
	}

	// fetch real user from DB after basic validation passes
	user, err = uv.UserDB.ByEmail(ctx, user.Email)
	if err != nil {
		return User{}, err
	}

	if !user.Active {
		return User{}, ErrInvalid
	}

	// check the password matches
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		if xerrors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return User{}, ValidationError{"password": ErrPasswordIncorrect}
		}

		return User{}, wrap("failed to compare password hashes", err)
	}

	return user, nil
}

func (uv *userValidator) Refresh(ctx context.Context, refreshToken string) (User, error) {
	panic("method Refresh of userValidator must never be called")
}

func (uv *userValidator) Validate(ctx context.Context, accessToken string) (Claims, error) {
	panic("method Validate of userValidator must never be called")
}

func (uv *userValidator) Token(ctx context.Context, u *User) (Token, error) {
	panic("method Token of userValidator must never be called")
}

func (uv *userValidator) Create(ctx context.Context, u *User) error {
	ctx, span := trace.StartSpan(ctx, "models.User.Create")
	defer span.End()

	defer func() {
		u.Password = ""
	}()

	uv.ctx = ctx

	if err := uv.runValFuncs(u,
		uv.idSetToZero,
		uv.countryCodeIsValid,
		uv.firstNameRequired,
		uv.firstNameLength,
		uv.settingsLength,
		uv.passwordRequired,
		uv.passwordLength,
		uv.passwordHash,
		uv.emailRequired,
		uv.normaliseEmail,
		uv.emailFormat,
		uv.emailIsTaken,
	); err != nil {
		return err
	}

	return uv.UserDB.Create(ctx, u)
}

func (uv *userValidator) Update(ctx context.Context, u *User) error {
	ctx, span := trace.StartSpan(ctx, "models.User.ListByCountries")
	defer span.End()

	defer func() {
		u.Password = ""
	}()

	uv.ctx = ctx

	// we can then use the standard validation process here.
	uc := userValWithCurrent{uv: uv}
	if err := uv.runValFuncs(u,
		uc.fetchUser,
		uv.countryCodeIsValid,
		uv.firstNameRequired,
		uv.firstNameLength,
		uv.settingsLength,
		uv.emailRequired,
		uv.normaliseEmail,
		uv.emailFormat,
		uv.passwordLength,
		uv.passwordHash,
		uc.preservePassword,
		uc.emailIsTaken,
	); err != nil {
		return err
	}

	return uv.UserDB.Update(ctx, u)
}

func (uv *userValidator) ByEmail(ctx context.Context, e string) (User, error) {
	ctx, span := trace.StartSpan(ctx, "models.User.ByEmail")
	defer span.End()

	user := User{
		Email: e,
	}

	uv.ctx = ctx

	if err := uv.runValFuncs(&user,
		uv.emailRequired,
		uv.normaliseEmail,
		uv.emailFormat,
	); err != nil {
		return User{}, err
	}

	return uv.UserDB.ByEmail(ctx, user.Email)
}

type userValFn func(u *User) error

type userValWithCurrent struct {
	uv      *userValidator
	current User
}

// fetchUser must be called before any of the other validators implemented by the receiver type. It
// retrieves the current user value from the database.
func (uc *userValWithCurrent) fetchUser() (string, userValFn) {
	return "", func(u *User) error {
		var err error
		uc.current, err = uc.uv.ByID(uc.uv.ctx, u.ID)
		if err != nil {
			return err
		}

		return nil
	}
}

// emailIsTaken makes sure u.Email is not taken in the database by other user that is not the one being updated
// now. It returns nil if the address is not taken. It may return ErrDuplicate.
func (uc *userValWithCurrent) emailIsTaken() (string, userValFn) {
	return "email", func(u *User) error {
		if uc.current.Email != u.Email {
			cu, err := uc.uv.UserDB.ByEmail(uc.uv.ctx, u.Email)
			if err == nil && u.ID != 0 && u.ID != cu.ID {
				return ErrDuplicate
			}
		}

		return nil
	}
}

// preservePassword makes sure an existing user's password is preserved if a new one is not provided.
// It does not return any errors.
//
// This method must be called AFTER the password hashing validators as it preserves the previous password for
// application users.
func (uc *userValWithCurrent) preservePassword() (string, userValFn) {
	return "", func(u *User) error {
		if u.Password == "" {
			u.Password = uc.current.Password
		}

		return nil
	}
}

func (uv *userValidator) runValFuncs(u *User, fns ...func() (string, userValFn)) error {
	return runValidationFunctions(u, fns)
}

// idSetToZero sets the user's ID to 0. It does not return any errors.
func (uv *userValidator) idSetToZero() (string, userValFn) {
	return "", func(u *User) error {
		u.ID = 0
		return nil
	}
}

// passwordRequired makes sure u.Password is not empty. It may return ErrRequired.
func (uv *userValidator) passwordRequired() (string, userValFn) {
	return "password", func(u *User) error {
		if u.Password == "" {
			return ErrRequired
		}

		return nil
	}
}

// passwordLength makes sure u.Password has at least 8 characters. It may return ErrTooShort
func (uv *userValidator) passwordLength() (string, userValFn) {
	return "password", func(u *User) error {
		if u.Password != "" && len(u.Password) < 8 {
			return ErrTooShort
		}

		return nil
	}
}

// passwordHash hashes the password. It may return private errors.
func (uv *userValidator) passwordHash() (string, userValFn) {
	return "", func(u *User) error {
		if u.Password == "" {
			return nil
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost+2)
		if err != nil {
			return wrap("failed to hash password", err)
		}

		u.Password = string(hash)

		return nil
	}
}

//  countryCodeIsInvalid makes sure u.Country is a supported country code. It may return ErrInvalidCountry.
func (uv *userValidator) countryCodeIsValid() (string, userValFn) {
	return "country", func(u *User) error {
		if _, ok := countryCodes[u.Country]; !ok {
			return ErrInvalidCountry
		}

		return nil
	}
}

// normalizeEmail modifies u.Email to remove excess space and have all characters lowercase.
func (uv *userValidator) normaliseEmail() (string, userValFn) {
	return "email", func(u *User) error {
		u.Email = strings.ToLower(u.Email)
		u.Email = strings.TrimSpace(u.Email)
		return nil
	}
}

// emailRequired makes sure u.Email address is not empty. It may return ErrRequired.
func (uv *userValidator) emailRequired() (string, userValFn) {
	return "email", func(u *User) error {
		if u.Email == "" {
			return ErrRequired
		}

		return nil
	}
}

// emailFormat makes sure u.Email looks like an email address. It returns nil if the address
// is empty. It may return ErrInvalid.
func (uv *userValidator) emailFormat() (string, userValFn) {
	return "email", func(u *User) error {
		if u.Email == "" {
			return nil
		}

		if !uv.emailRegex.MatchString(u.Email) {
			return ErrInvalid
		}
		return nil
	}
}

// emailIsTaken makes sure u.Email is not taken in the database. It returns nil if the address
// is not taken. It may return ErrDuplicate.
func (uv *userValidator) emailIsTaken() (string, userValFn) {
	return "email", func(u *User) error {
		_, err := uv.UserDB.ByEmail(uv.ctx, u.Email)
		if err == nil {
			return ErrDuplicate
		}

		return nil
	}
}

// firstNameRequired makes sure u.FirstName is not empty. It may return ErrRequired.
func (uv *userValidator) firstNameRequired() (string, userValFn) {
	return "firstName", func(u *User) error {
		if u.FirstName == "" {
			return ErrRequired
		}

		return nil
	}
}

// firstNameLength makes sure u.FirstName has at least two characters. It may return ErrTooShort.
func (uv *userValidator) firstNameLength() (string, userValFn) {
	return "firstName", func(u *User) error {
		if len(u.FirstName) < 2 {
			return ErrTooShort
		}

		return nil
	}
}

// settingsLength makes sure that the text contained in settings is not greater
// than X bytes. It may return ErrTooLong.
func (uv *userValidator) settingsLength() (string, userValFn) {
	return "settings", func(u *User) error {
		if len(u.Settings) > 8192 {
			return ErrTooLong
		}

		return nil
	}
}

type userGorm struct {
	db *gorm.DB
}

func (ug *userGorm) Create(ctx context.Context, u *User) error {
	ctx, span := trace.StartSpan(ctx, "user.Database.Create")
	defer span.End()
	ug.db.WithContext(ctx)

	res := ug.db.Create(u)
	if res.Error != nil {
		if pgerr := (*pgconn.PgError)(nil); xerrors.As(res.Error, &pgerr) {
			switch {
			// Info about error codes can be found at https://github.com/lib/pq/blob/master/error.go#L78
			case pgerr.Code == "23505" && pgerr.ConstraintName == "users_pkey":
				return ValidationError{"id": ErrIDTaken}
			case pgerr.Code == "23505" && pgerr.ConstraintName == "users_email_key":
				return ValidationError{"email": ErrDuplicate}
			}
		}

		return wrap("could not create user", res.Error)
	}

	return nil
}

func (ug *userGorm) Update(ctx context.Context, u *User) error {
	ctx, span := trace.StartSpan(ctx, "user.Database.Update")
	defer span.End()
	ug.db.WithContext(ctx)

	err := ug.db.Transaction(func(tx *gorm.DB) error {
		// Checks if the user exists
		var count int64
		tx.Model(User{}).Where("id = ?", u.ID).Count(&count)
		if count < 1 {
			return ErrNotFound
		}

		// Updates the user
		if err := tx.Model(User{}).Where("id = ?", u.ID).Save(&u).Error; err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		if xerrors.Is(err, ErrNotFound) {
			return ErrNotFound
		}

		if pgerr := (*pgconn.PgError)(nil); xerrors.As(err, &pgerr) {
			switch {
			// Info about error codes can be found at https://github.com/lib/pq/blob/master/error.go#L78
			case pgerr.Code == "23505" && pgerr.ConstraintName == "users_email_key":
				return ValidationError{"email": ErrDuplicate}
			}
		}

		return wrap("could not update user", err)
	}

	return nil
}

func (ug *userGorm) Delete(ctx context.Context, id int64) error {
	ctx, span := trace.StartSpan(ctx, "user.Database.Delete")
	defer span.End()
	ug.db.WithContext(ctx)

	res := ug.db.Delete(&User{}, id)
	if res.Error != nil {
		return wrap("could not delete user by id", res.Error)

	} else if res.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

func (ug *userGorm) ByEmail(ctx context.Context, e string) (User, error) {
	ctx, span := trace.StartSpan(ctx, "user.Database.ByEmail")
	defer span.End()
	ug.db.WithContext(ctx)

	var user User
	err := ug.db.Where("email = ?", e).First(&user).Error
	if err != nil {
		if xerrors.Is(err, gorm.ErrRecordNotFound) {
			return User{}, ErrNotFound
		}

		return User{}, wrap("could not get user by email", err)
	}

	return user, nil
}

func (ug *userGorm) ByID(ctx context.Context, id int64) (User, error) {
	ctx, span := trace.StartSpan(ctx, "user.Database.ByID")
	defer span.End()
	ug.db.WithContext(ctx)

	var user User
	err := ug.db.First(&user, id).Error
	if err != nil {
		if xerrors.Is(err, gorm.ErrRecordNotFound) {
			return User{}, ErrNotFound
		}

		return User{}, wrap("could not get user by id", err)
	}

	return user, nil
}

func (ug *userGorm) ByIDs(ctx context.Context, ids ...int64) ([]User, error) {
	ctx, span := trace.StartSpan(ctx, "user.Database.ByIDs")
	defer span.End()
	ug.db.WithContext(ctx)

	var users []User

	qb := ug.db
	if len(ids) > 0 {
		qb = qb.Where(ids)
	}

	err := qb.Find(&users).Error
	if err != nil {
		return nil, wrap("failed to list users by ids", err)
	}

	return users, nil
}

func (ug *userGorm) ByCountries(ctx context.Context, countries ...string) ([]User, error) {
	ctx, span := trace.StartSpan(ctx, "user.Database.ByCountries")
	defer span.End()
	ug.db.WithContext(ctx)

	var users []User

	qb := ug.db
	if len(countries) > 0 {
		qb = qb.Where("country IN ?", countries)
	}

	err := qb.Find(&users).Error
	if err != nil {
		return nil, wrap("failed to list users by countries", err)
	}

	return users, nil
}
