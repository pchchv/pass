package scheme

import "crypto/subtle"

// Compares two strings (typical password hashes)
// in safe mode with constant time.
// Returns true if they are equal.
func SecureCompare(a, b string) bool {
	aByte := []byte(a)
	bByte := []byte(b)
	return subtle.ConstantTimeCompare(aByte, bByte) == 1
}
