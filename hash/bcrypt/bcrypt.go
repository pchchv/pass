// The bcrypt package implements the bcrypt password hashing mechanism.
//
// Note that bcrypt truncates passwords to 72 characters in length.
// Consider using a more modern hashing scheme, such as scrypt or sha-crypt.
// If you must use bcrypt, use bcrypt-sha256 instead.
package bcrypt

import (
	"fmt"

	"github.com/pchchv/pass/scheme"
	"golang.org/x/crypto/bcrypt"
)

// New creates a new scheme implementing bcrypt.
// The recommended cost is RecommendedCost.
func New(cost int) scheme.Scheme {
	return &bcryptScheme{
		Cost: cost,
	}
}
type bcryptScheme struct {
	Cost int
}

func (s *bcryptScheme) Hash(password string) (hash string, err error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), s.Cost)
	if err != nil {
		return
	}

	return string(h), nil
}

func (s *bcryptScheme) Verify(password, hash string) (err error) {
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return scheme.ErrInvalidPassword
	}

	return
}

func (s *bcryptScheme) SupportsStub(stub string) bool {
	return len(stub) >= 3 && stub[0] == '$' && stub[1] == '2' &&
		(stub[2] == '$' || (len(stub) >= 4 && stub[3] == '$' &&
			(stub[2] == 'a' || stub[2] == 'b' || stub[2] == 'y')))
}

func (s *bcryptScheme) String() string {
	return fmt.Sprintf("bcrypt(%d)", s.Cost)
}

func (s *bcryptScheme) NeedsUpdate(stub string) bool {
	cost, err := bcrypt.Cost([]byte(stub))
	if err != nil {
		return false
	}

	return cost < s.Cost
}
