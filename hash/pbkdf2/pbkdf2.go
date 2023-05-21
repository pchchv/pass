// Package pbkdf2 implements a modular crypt format for
// PBKDF2-SHA1, PBKDF2-SHA256 and PBKDF-SHA512.
//
// The format is similar to the one used in Python's passlib,
// and is compatible.
package pbkdf2

import "hash"

type pbkdf2Scheme struct {
	Ident    string
	HashFunc func() hash.Hash
	Rounds   int
}
