// The scheme package contains an abstract description of the
// Scheme interface and additional error definitions.
package scheme

// The Scheme interface provides an
// abstract interface for implementing
// a particular password hashing scheme.
// The Scheme generates password hashes,
// verifies passwords using hashes,
// randomly generates new stubs and can determine if
// it recognizes a given stub or hash.
// It can also decide to issue upgrades.
type Scheme interface {
	// Hash hashes a plaintext UTF-8 password using a modular crypt stub.
	// Returns the hashed password in modular crypt format.
	//
	// The modular crypt stub is a hash prefix in modular crypt format,
	// which expresses all necessary configuration information,
	// such as salt and iterations.
	// Example of a stub for sha256-crypt:
	//     $5$rounds=6000$salt
	//
	// A full modular crypt hash can also be passed as the stub,
	// in which case the hash is ignored.
	Hash(password string) (string, error)

	// Verify verifies a password in UTF-8 format using a modular crypt hash.
	// Returns an error if the input data are malformed or the password does not match.
	Verify(password, hash string) (err error)

	// SupportsStub returns true if this crypter supports the given stub.
	SupportsStub(stub string) bool

	// NeedsUpdate returns true if this stub needs an update.
	NeedsUpdate(stub string) bool
}
