// The bcrypt package implements the bcrypt password hashing mechanism.
//
// Note that bcrypt truncates passwords to 72 characters in length.
// Consider using a more modern hashing scheme, such as scrypt or sha-crypt.
// If you must use bcrypt, use bcrypt-sha256 instead.
package bcrypt

import (
	"github.com/pchchv/pass/scheme"
	"golang.org/x/crypto/bcrypt"
)

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
