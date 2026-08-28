package auth

// ContextKey is a type for context keys used by the auth package.
type ContextKey string

const (
	// ClientCertContextKey is the context key for the verified leaf client
	// certificate (*x509.Certificate). The HTTPS listener stores the leaf here
	// (internal/proxy/http.go) and the mtls plugin reads it back.
	ClientCertContextKey ContextKey = "auth_client_cert"
	// ClientCertChainContextKey is the context key for the full client
	// certificate chain as presented during the TLS handshake
	// ([]*x509.Certificate, leaf first). When present, element 0 is the leaf
	// and elements 1.. are intermediate CAs needed to build a path to a
	// trusted root. Authenticators use this to populate
	// x509.VerifyOptions.Intermediates so chains that rely on intermediates
	// (not just a directly-issued leaf) verify correctly.
	ClientCertChainContextKey ContextKey = "auth_client_cert_chain"
)
