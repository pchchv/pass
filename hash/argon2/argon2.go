// Package argon2 implements the argon2 password hashing mechanism,
// wrapped in the argon2 encoded format.
package argon2

type argon2Scheme struct {
	time, memory uint32
	threads      uint8
}

const saltLength = 16
