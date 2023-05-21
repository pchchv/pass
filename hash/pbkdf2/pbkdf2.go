// Package pbkdf2 implements a modular crypt format for
// PBKDF2-SHA1, PBKDF2-SHA256 and PBKDF-SHA512.
//
// The format is similar to the one used in Python's passlib,
// and is compatible.
package pbkdf2

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"

	"github.com/pchchv/pass/hash/pbkdf2/raw"
	"github.com/pchchv/pass/scheme"
)

const (
	SaltLength              = 16
	RecommendedRoundsSHA1   = 131000
	RecommendedRoundsSHA256 = 29000
	RecommendedRoundsSHA512 = 25000
)

var (
	// Scheme implementation implementing a number of
	// PBKDF2 modular crypt formats used by Python's passlib
	// ($pbkdf2$, $pbkdf2-sha256$, $pbkdf2-sha512$).
	// Uses RecommendedRounds.
	// WARNING: SHA1 should never be used in new applications.
	// It should only be used for compatibility with legacy applications.
	SHA1Crypter   scheme.Scheme
	SHA256Crypter scheme.Scheme
	SHA512Crypter scheme.Scheme
)

type pbkdf2Scheme struct {
	Ident    string
	HashFunc func() hash.Hash
	Rounds   int
}

func New(ident string, hf func() hash.Hash, rounds int) scheme.Scheme {
	return &pbkdf2Scheme{
		Ident:    ident,
		HashFunc: hf,
		Rounds:   rounds,
	}
}

func init() {
	SHA1Crypter = New("$pbkdf2$", sha1.New, RecommendedRoundsSHA1)
	SHA256Crypter = New("$pbkdf2-sha256$", sha256.New, RecommendedRoundsSHA256)
	SHA512Crypter = New("$pbkdf2-sha512$", sha512.New, RecommendedRoundsSHA512)
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

func (s *pbkdf2Scheme) Verify(password, stub string) error {
	_, rounds, salt, oldHash, err := raw.Parse(stub)
	if err != nil {
		return err
	}

	newHash := raw.Hash([]byte(password), salt, rounds, s.HashFunc)

	if len(newHash) == 0 || !scheme.SecureCompare(oldHash, newHash) {
		return scheme.ErrInvalidPassword
	}

	return nil
}

func (s *pbkdf2Scheme) SupportsStub(stub string) bool {
	return strings.HasPrefix(stub, s.Ident)
}

func (s *pbkdf2Scheme) NeedsUpdate(stub string) bool {
	_, rounds, salt, _, err := raw.Parse(stub)
	return err == raw.ErrInvalidRounds || rounds < s.Rounds || len(salt) < SaltLength
}
