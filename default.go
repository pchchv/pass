package pass

var (
	// Default schemes, the most preferred ones first.
	// The first scheme will be used to hash passwords,
	// and any of the schemes can be used to validate existing passwords.
	// The contents of this value may change in future releases.
	//
	// If you want to change this value, set DefaultSchemes to
	// a slice of the scheme.Scheme array of your construction,
	// rather than changing the array that the slice points to.
	//
	// See the UseDefaults function for more information on how the default schema list is defined.
	// The DefaultSchemes value will not change.
	// You need to call UseDefaults to allow your application to switch to newer hash schemes
	// (either set DefaultSchemes manually, or create a custom context with its own set of schemes).
	DefaultSchemes []scheme.Scheme
)
