// Package jwt provides JWT token authentication for Bifrost.
// It supports JWKS-based key discovery and static key configuration.
package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rennerdo30/bifrost-proxy/internal/auth"
)

func init() {
	auth.RegisterPlugin("jwt", &plugin{})
}

// plugin implements the auth.Plugin interface for JWT authentication.
type plugin struct{}

// Type returns the plugin type.
func (p *plugin) Type() string {
	return "jwt"
}

// Description returns a human-readable description.
func (p *plugin) Description() string {
	return "JWT token authentication with JWKS and static key support"
}

// Create creates a new JWT authenticator from the configuration.
func (p *plugin) Create(config map[string]any) (auth.Authenticator, error) {
	cfg, err := parseConfig(config)
	if err != nil {
		return nil, err
	}

	authenticator := &Authenticator{
		config:     cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]any),
	}

	// Load static keys if provided
	if cfg.PublicKeyPEM != "" {
		key, err := parsePublicKey(cfg.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		authenticator.keys["static"] = key
	}

	// Fetch JWKS if URL is provided
	if cfg.JWKSURL != "" {
		if err := authenticator.refreshJWKS(); err != nil {
			slog.Warn("failed to fetch initial JWKS, will retry on auth",
				"url", cfg.JWKSURL,
				"error", err,
			)
		}

		// Initialize stopCh before starting goroutine
		authenticator.stopCh = make(chan struct{})
		// Start background refresh
		go authenticator.startJWKSRefresh()
	}

	return authenticator, nil
}

// ValidateConfig validates the configuration.
func (p *plugin) ValidateConfig(config map[string]any) error {
	_, err := parseConfig(config)
	return err
}

// DefaultConfig returns the default configuration.
func (p *plugin) DefaultConfig() map[string]any {
	return map[string]any{
		"jwks_url":       "https://auth.example.com/.well-known/jwks.json",
		"issuer":         "https://auth.example.com",
		"audience":       "bifrost-proxy",
		"algorithms":     []string{"RS256", "ES256"},
		"username_claim": "sub",
		"groups_claim":   "groups",
	}
}

// ConfigSchema returns the JSON schema for configuration.
func (p *plugin) ConfigSchema() string {
	return `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "jwks_url": {
      "type": "string",
      "description": "URL to fetch JSON Web Key Set"
    },
    "public_key_pem": {
      "type": "string",
      "description": "Static PEM-encoded public key"
    },
    "issuer": {
      "type": "string",
      "description": "Expected token issuer (iss claim)"
    },
    "audience": {
      "type": "string",
      "description": "Expected token audience (aud claim)"
    },
    "algorithms": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Allowed signing algorithms",
      "default": ["RS256"]
    },
    "username_claim": {
      "type": "string",
      "description": "Claim to use as username",
      "default": "sub"
    },
    "groups_claim": {
      "type": "string",
      "description": "Claim to use for groups",
      "default": "groups"
    },
    "email_claim": {
      "type": "string",
      "description": "Claim to use for email",
      "default": "email"
    },
    "leeway_seconds": {
      "type": "integer",
      "description": "Clock skew tolerance in seconds",
      "default": 60
    },
    "jwks_refresh_interval": {
      "type": "string",
      "description": "Interval for JWKS refresh",
      "default": "1h"
    }
  }
}`
}

// jwtConfig represents the parsed configuration.
type jwtConfig struct {
	JWKSURL             string
	PublicKeyPEM        string
	Issuer              string
	Audience            string
	Algorithms          []string
	UsernameClaim       string
	GroupsClaim         string
	EmailClaim          string
	LeewaySeconds       int64
	JWKSRefreshInterval time.Duration
}

// parseConfig parses the configuration map.
func parseConfig(config map[string]any) (*jwtConfig, error) {
	if config == nil {
		return nil, fmt.Errorf("jwt auth config is required")
	}

	cfg := &jwtConfig{
		Algorithms:          []string{"RS256"},
		UsernameClaim:       "sub",
		GroupsClaim:         "groups",
		EmailClaim:          "email",
		LeewaySeconds:       60,
		JWKSRefreshInterval: time.Hour,
	}

	if jwksURL, ok := config["jwks_url"].(string); ok {
		cfg.JWKSURL = jwksURL
	}

	if publicKeyPEM, ok := config["public_key_pem"].(string); ok {
		cfg.PublicKeyPEM = publicKeyPEM
	}

	if cfg.JWKSURL == "" && cfg.PublicKeyPEM == "" {
		return nil, fmt.Errorf("jwt auth config: either 'jwks_url' or 'public_key_pem' is required")
	}

	if issuer, ok := config["issuer"].(string); ok {
		cfg.Issuer = issuer
	}

	if audience, ok := config["audience"].(string); ok {
		cfg.Audience = audience
	}

	if algorithms, ok := config["algorithms"].([]any); ok {
		cfg.Algorithms = make([]string, 0, len(algorithms))
		for _, a := range algorithms {
			if s, ok := a.(string); ok {
				cfg.Algorithms = append(cfg.Algorithms, s)
			}
		}
	} else if algorithms, ok := config["algorithms"].([]string); ok {
		cfg.Algorithms = algorithms
	}

	if usernameClaim, ok := config["username_claim"].(string); ok && usernameClaim != "" {
		cfg.UsernameClaim = usernameClaim
	}

	if groupsClaim, ok := config["groups_claim"].(string); ok && groupsClaim != "" {
		cfg.GroupsClaim = groupsClaim
	}

	if emailClaim, ok := config["email_claim"].(string); ok && emailClaim != "" {
		cfg.EmailClaim = emailClaim
	}

	if leeway, ok := config["leeway_seconds"].(int); ok {
		cfg.LeewaySeconds = int64(leeway)
	} else if leeway, ok := config["leeway_seconds"].(float64); ok {
		cfg.LeewaySeconds = int64(leeway)
	}

	if refreshStr, ok := config["jwks_refresh_interval"].(string); ok && refreshStr != "" {
		d, err := time.ParseDuration(refreshStr)
		if err != nil {
			return nil, fmt.Errorf("jwt auth config: invalid jwks_refresh_interval: %w", err)
		}
		cfg.JWKSRefreshInterval = d
	}

	return cfg, nil
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(pemData string) (any, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub, nil
}

// Authenticator provides JWT token authentication.
type Authenticator struct {
	config     *jwtConfig
	httpClient *http.Client
	keys       map[string]any
	keysMu     sync.RWMutex
	stopCh     chan struct{}
	closeOnce  sync.Once
}

// Authenticate validates a JWT token.
// The username parameter is ignored; the password parameter should contain the JWT.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (*auth.UserInfo, error) {
	token := password

	// Strip "Bearer " prefix if present
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = token[7:]
	}

	if token == "" {
		return nil, auth.NewAuthError("jwt", "authenticate", auth.ErrInvalidCredentials)
	}

	// Parse and validate the token
	claims, err := a.validateToken(token)
	if err != nil {
		return nil, auth.NewAuthError("jwt", "authenticate", err)
	}

	// Extract user info from claims
	userInfo := &auth.UserInfo{
		Metadata: map[string]string{
			"auth_type": "jwt",
		},
	}

	// Username
	if un, ok := claims[a.config.UsernameClaim].(string); ok {
		userInfo.Username = un
	} else {
		return nil, auth.NewAuthError("jwt", "authenticate", fmt.Errorf("missing username claim: %s", a.config.UsernameClaim))
	}

	// Groups
	if groups, ok := claims[a.config.GroupsClaim]; ok {
		userInfo.Groups = toStringSlice(groups)
	}

	// Email
	if email, ok := claims[a.config.EmailClaim].(string); ok {
		userInfo.Email = email
	}

	// Full name
	if name, ok := claims["name"].(string); ok {
		userInfo.FullName = name
	}

	return userInfo, nil
}

// validateToken parses and validates a JWT token, returning the claims.
func (a *Authenticator) validateToken(tokenString string) (map[string]any, error) {
	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if unmarshalErr := json.Unmarshal(headerJSON, &header); unmarshalErr != nil {
		return nil, fmt.Errorf("invalid header JSON: %w", unmarshalErr)
	}

	// Check algorithm
	algAllowed := false
	for _, allowed := range a.config.Algorithms {
		if header.Alg == allowed {
			algAllowed = true
			break
		}
	}
	if !algAllowed {
		return nil, fmt.Errorf("algorithm not allowed: %s", header.Alg)
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var claims map[string]any
	if claimsErr := json.Unmarshal(payloadJSON, &claims); claimsErr != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", claimsErr)
	}

	// Get the signing key
	key, err := a.getSigningKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Verify signature
	if err := a.verifySignature(parts[0]+"."+parts[1], parts[2], header.Alg, key); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Validate standard claims
	now := time.Now().Unix()

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp)+a.config.LeewaySeconds < now {
			return nil, fmt.Errorf("token expired")
		}
	}

	// Check not before
	if nbf, ok := claims["nbf"].(float64); ok {
		if int64(nbf)-a.config.LeewaySeconds > now {
			return nil, fmt.Errorf("token not yet valid")
		}
	}

	// Check issuer
	if a.config.Issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != a.config.Issuer {
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	// Check audience
	if a.config.Audience != "" {
		audValid := false
		switch aud := claims["aud"].(type) {
		case string:
			audValid = aud == a.config.Audience
		case []any:
			for _, audItem := range aud {
				if s, ok := audItem.(string); ok && s == a.config.Audience {
					audValid = true
					break
				}
			}
		}
		if !audValid {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	return claims, nil
}

// getSigningKey returns the key to use for signature verification.
func (a *Authenticator) getSigningKey(kid string) (any, error) {
	a.keysMu.RLock()
	defer a.keysMu.RUnlock()

	if kid != "" {
		if key, ok := a.keys[kid]; ok {
			return key, nil
		}
	}

	// Try static key
	if key, ok := a.keys["static"]; ok {
		return key, nil
	}

	// Return first available key
	for _, key := range a.keys {
		return key, nil
	}

	return nil, fmt.Errorf("no signing key available")
}

// verifySignature verifies the JWT signature.
func (a *Authenticator) verifySignature(signingInput, signature, alg string, key any) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	switch alg {
	case "RS256", "RS384", "RS512":
		return a.verifyRSA(signingInput, sigBytes, alg, key)
	case "ES256", "ES384", "ES512":
		return a.verifyECDSA(signingInput, sigBytes, alg, key)
	case "HS256", "HS384", "HS512":
		return a.verifyHMAC(signingInput, sigBytes, alg, key)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// verifyRSA verifies an RSA signature.
func (a *Authenticator) verifyRSA(signingInput string, signature []byte, alg string, key any) error {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type for RSA")
	}

	var hashFunc, cryptoHash = getHashFunc(alg)
	if hashFunc == nil {
		return fmt.Errorf("unsupported hash algorithm")
	}

	h := hashFunc()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaKey, cryptoHash, hashed, signature)
}

// verifyECDSA verifies an ECDSA signature.
func (a *Authenticator) verifyECDSA(signingInput string, signature []byte, alg string, key any) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid key type for ECDSA: expected *ecdsa.PublicKey, got %T", key)
	}

	// Determine the expected signature length and hash function based on algorithm
	hashFunc, cryptoHash := getHashFunc(alg)
	var sigLen int

	switch alg {
	case "ES256":
		sigLen = 64 // 32 bytes for R + 32 bytes for S
	case "ES384":
		sigLen = 96 // 48 bytes for R + 48 bytes for S
	case "ES512":
		sigLen = 132 // 66 bytes for R + 66 bytes for S
	default:
		return fmt.Errorf("unsupported ECDSA algorithm: %s", alg)
	}

	if hashFunc == nil || !cryptoHash.Available() {
		return fmt.Errorf("hash algorithm not available for %s", alg)
	}

	// ECDSA signatures in JWT are in R||S format (raw concatenated big integers)
	// Each component is keyLen bytes
	if len(signature) != sigLen {
		return fmt.Errorf("invalid ECDSA signature length: expected %d, got %d", sigLen, len(signature))
	}

	// Split signature into R and S components
	keyLen := sigLen / 2
	r := new(big.Int).SetBytes(signature[:keyLen])
	s := new(big.Int).SetBytes(signature[keyLen:])

	// Hash the signing input
	h := hashFunc()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	// Verify the signature
	if !ecdsa.Verify(ecdsaKey, hashed, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// verifyHMAC verifies an HMAC signature.
func (a *Authenticator) verifyHMAC(signingInput string, signature []byte, alg string, key any) error {
	// HMAC verification requires the key to be a byte slice
	keyBytes, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("invalid key type for HMAC")
	}

	hashFunc, _ := getHashFunc(alg)
	if hashFunc == nil {
		return fmt.Errorf("unsupported hash algorithm")
	}

	mac := hmacNew(hashFunc, keyBytes)
	mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)

	if !hmacEqual(signature, expected) {
		return fmt.Errorf("signature mismatch")
	}

	return nil
}

// refreshJWKS fetches and updates the JWKS.
func (a *Authenticator) refreshJWKS() error {
	if a.config.JWKSURL == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.config.JWKSURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	newKeys := make(map[string]any)

	for _, keyJSON := range jwks.Keys {
		var keyInfo struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			// RSA fields
			N string `json:"n"`
			E string `json:"e"`
			// EC fields
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}
		if err := json.Unmarshal(keyJSON, &keyInfo); err != nil {
			slog.Warn("failed to parse JWK", "error", err)
			continue
		}

		// Skip non-signing keys
		if keyInfo.Use != "" && keyInfo.Use != "sig" {
			continue
		}

		switch keyInfo.Kty {
		case "RSA":
			key, err := parseRSAKey(keyInfo.N, keyInfo.E)
			if err != nil {
				slog.Warn("failed to parse RSA key", "kid", keyInfo.Kid, "error", err)
				continue
			}
			newKeys[keyInfo.Kid] = key
		case "EC":
			key, err := parseECKey(keyInfo.Crv, keyInfo.X, keyInfo.Y)
			if err != nil {
				slog.Warn("failed to parse EC key", "kid", keyInfo.Kid, "error", err)
				continue
			}
			newKeys[keyInfo.Kid] = key
		default:
			slog.Warn("unsupported key type", "kty", keyInfo.Kty)
		}
	}

	a.keysMu.Lock()
	// Preserve static key if present
	if staticKey, ok := a.keys["static"]; ok {
		newKeys["static"] = staticKey
	}
	a.keys = newKeys
	a.keysMu.Unlock()

	slog.Debug("JWKS refreshed", "key_count", len(newKeys))
	return nil
}

// startJWKSRefresh starts the background JWKS refresh goroutine.
func (a *Authenticator) startJWKSRefresh() {
	ticker := time.NewTicker(a.config.JWKSRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := a.refreshJWKS(); err != nil {
				slog.Warn("failed to refresh JWKS", "error", err)
			}
		case <-a.stopCh:
			return
		}
	}
}

// parseRSAKey parses RSA key components from base64url encoded strings.
func parseRSAKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("invalid n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("invalid e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// parseECKey parses EC key components from base64url encoded strings.
func parseECKey(crv, xStr, yStr string) (*ecdsa.PublicKey, error) {
	// Determine the curve based on the crv parameter
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	// Decode X coordinate
	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("invalid x coordinate: %w", err)
	}

	// Decode Y coordinate
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("invalid y coordinate: %w", err)
	}

	// Create the public key
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point is not on the curve")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// Name returns the authenticator name.
func (a *Authenticator) Name() string {
	return "jwt"
}

// Type returns the authenticator type.
func (a *Authenticator) Type() string {
	return "jwt"
}

// Close stops background tasks. Safe to call multiple times.
func (a *Authenticator) Close() error {
	a.closeOnce.Do(func() {
		if a.stopCh != nil {
			close(a.stopCh)
		}
	})
	return nil
}

// toStringSlice converts an any to []string.
func toStringSlice(v any) []string {
	if v == nil {
		return nil
	}

	if ss, ok := v.([]string); ok {
		return ss
	}

	if slice, ok := v.([]any); ok {
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// getHashFunc returns the hash function for the given algorithm.
func getHashFunc(alg string) (func() hash.Hash, crypto.Hash) {
	switch alg {
	case "RS256", "ES256", "HS256":
		return crypto.SHA256.New, crypto.SHA256
	case "RS384", "ES384", "HS384":
		return crypto.SHA384.New, crypto.SHA384
	case "RS512", "ES512", "HS512":
		return crypto.SHA512.New, crypto.SHA512
	default:
		return nil, 0
	}
}

// hmacNew creates a new HMAC.
func hmacNew(h func() hash.Hash, key []byte) hash.Hash {
	return hmac.New(h, key)
}

// hmacEqual compares two MACs in constant time.
func hmacEqual(a, b []byte) bool {
	return hmac.Equal(a, b)
}
