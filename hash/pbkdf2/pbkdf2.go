// Package pbkdf2 implements a modular crypt format for
// PBKDF2-SHA1, PBKDF2-SHA256 and PBKDF-SHA512.
//
// The format is similar to the one used in Python's passlib,
// and is compatible.
package pbkdf2

import (
	"crypto/rand"
	"fmt"
	"hash"

	"github.com/pchchv/pass/hash/pbkdf2/raw"
)

const SaltLength = 16

type pbkdf2Scheme struct {
	Ident    string
	HashFunc func() hash.Hash
	Rounds   int
}

func (s *pbkdf2Scheme) Hash(password string) (string, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := raw.Hash([]byte(password), salt, s.Rounds, s.HashFunc)
	newHash := fmt.Sprintf("%s%d$%s$%s", s.Ident, s.Rounds, raw.Base64Encode(salt), hash)

	return newHash, nil
}
