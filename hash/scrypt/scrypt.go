// Package scrypt implements the scrypt password hashing mechanism,
// wrapped in the modular crypt format.
package scrypt

type scryptSHA256Crypter struct {
	nN int
	r  int
	p  int
}
