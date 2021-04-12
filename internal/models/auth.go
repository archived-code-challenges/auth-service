package models

// ctxKey represents the type of value for the context key.
type ctxKey int

// KeyClaims is used to store/retrieve a Claims value from a context.Context.
const KeyClaims ctxKey = 1

// Claims represents the authorization claims transmitted via a JWT.
type Claims struct {
	User User
}

// NewClaims constructs a Claims value for the identified user.
func NewClaims(u User) Claims {
	return Claims{
		User: u,
	}
}
