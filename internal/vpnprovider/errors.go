package vpnprovider

import "errors"

// Common provider errors.
var (
	// ErrProviderUnavailable indicates the provider API is not reachable.
	ErrProviderUnavailable = errors.New("provider API unavailable")

	// ErrAuthenticationFailed indicates invalid or expired credentials.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrNoServersAvailable indicates no servers match the selection criteria.
	ErrNoServersAvailable = errors.New("no servers available matching criteria")

	// ErrInvalidAccountID indicates the account ID format is invalid.
	ErrInvalidAccountID = errors.New("invalid account ID")

	// ErrInvalidCredentials indicates username/password are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrKeyRegistrationFailed indicates WireGuard key registration failed.
	ErrKeyRegistrationFailed = errors.New("WireGuard key registration failed")

	// ErrServerListFetchFailed indicates failure to fetch server list.
	ErrServerListFetchFailed = errors.New("failed to fetch server list")

	// ErrUnsupportedProtocol indicates the requested protocol is not available.
	ErrUnsupportedProtocol = errors.New("protocol not supported by provider")

	// ErrConfigGenerationFailed indicates failure to generate VPN config.
	ErrConfigGenerationFailed = errors.New("failed to generate VPN configuration")

	// ErrTokenExpired indicates the authentication token has expired.
	ErrTokenExpired = errors.New("authentication token expired")

	// ErrTokenRefreshFailed indicates failure to refresh authentication token.
	ErrTokenRefreshFailed = errors.New("failed to refresh authentication token")

	// ErrRateLimited indicates the provider API rate limited the request.
	ErrRateLimited = errors.New("rate limited by provider API")

	// ErrInvalidServerID indicates the specified server ID doesn't exist.
	ErrInvalidServerID = errors.New("invalid server ID")

	// ErrCountryNotFound indicates the specified country is not available.
	ErrCountryNotFound = errors.New("country not found")

	// ErrCityNotFound indicates the specified city is not available.
	ErrCityNotFound = errors.New("city not found")
)
