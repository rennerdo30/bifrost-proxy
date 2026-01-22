# Authentication Guide

Bifrost supports multiple authentication modes.

## No Authentication

Default mode - allows all connections.

```yaml
auth:
  mode: none
```

## Native Authentication

Username/password authentication with bcrypt hashes.

```yaml
auth:
  mode: native
  native:
    users:
      - username: admin
        password_hash: "$2a$10$..."
        groups:
          - admins
        email: admin@example.com
        full_name: "Admin User"
      - username: user1
        password_hash: "$2a$10$..."
        disabled: false
```

### Generating Password Hashes

Using the bcrypt tool:
```bash
# Using htpasswd
htpasswd -bnBC 10 "" password | tr -d ':\n'

# Using Python
python3 -c "import bcrypt; print(bcrypt.hashpw(b'password', bcrypt.gensalt()).decode())"

# Using Go
go run -mod=mod github.com/bifrost-proxy/bifrost/tools/hashpw password
```

## LDAP Authentication

Authenticate against an LDAP directory.

```yaml
auth:
  mode: ldap
  ldap:
    url: "ldap://ldap.example.com:389"
    base_dn: "dc=example,dc=com"
    bind_dn: "cn=service,dc=example,dc=com"
    bind_password: "${LDAP_BIND_PASSWORD}"
    user_filter: "(uid=%s)"
    group_filter: "(memberUid=%s)"
    require_group: "proxy-users"
    tls: false
    insecure_skip_verify: false
```

### LDAP Configuration

| Field | Description |
|-------|-------------|
| `url` | LDAP server URL |
| `base_dn` | Base DN for searches |
| `bind_dn` | DN for service account |
| `bind_password` | Service account password |
| `user_filter` | Filter to find users (`%s` = username) |
| `group_filter` | Filter to find user groups |
| `require_group` | Only allow users in this group |

## System Authentication

Authenticate against the operating system's user database (PAM on Linux, Directory Services on macOS).

!!! warning "Platform Support"
    System authentication is **only supported on Linux and macOS**. Windows is not currently supported.
    If you need authentication on Windows, use `native`, `ldap`, or `oauth` mode instead.

```yaml
auth:
  mode: system
  system:
    service: "login"           # PAM service name (Linux only)
    allowed_users:             # Optional: restrict to specific users
      - alice
      - bob
    allowed_groups:            # Optional: restrict to specific groups
      - admin
      - staff
```

### Platform Support Matrix

| Platform | Support | Method |
|----------|---------|--------|
| Linux    | ✅ Supported | PAM via `su` command |
| macOS    | ✅ Supported | Directory Services (`dscl`) |
| Windows  | ❌ Not Supported | Use native/ldap/oauth instead |

### System Authentication Configuration

| Field | Description |
|-------|-------------|
| `service` | PAM service name (default: `login`) - Linux only |
| `allowed_users` | Optional list of allowed usernames |
| `allowed_groups` | Optional list of allowed groups (user must be in at least one) |

### Requirements

- **Linux**: Requires that the Bifrost process can execute `su` (typically needs to run as root or with appropriate privileges)
- **macOS**: Requires access to Directory Services via `dscl`

## OAuth/OIDC Authentication

Authenticate using OAuth 2.0 or OpenID Connect.

```yaml
auth:
  mode: oauth
  oauth:
    provider: "generic"
    client_id: "${OAUTH_CLIENT_ID}"
    client_secret: "${OAUTH_CLIENT_SECRET}"
    issuer_url: "https://auth.example.com"
    redirect_url: "http://localhost:7081/callback"
    scopes:
      - openid
      - profile
      - email
```

## Using Authentication with Proxy

### HTTP Proxy Authentication

Clients authenticate using `Proxy-Authorization` header:

```bash
curl -x http://user:pass@localhost:7080 http://example.com
```

### SOCKS5 Authentication

```bash
curl --socks5 user:pass@localhost:7180 http://example.com
```

## Client Authentication

The client can authenticate with the server:

```yaml
server:
  address: "proxy.example.com:7080"
  username: "myuser"
  password: "mypass"
```

## API Key Authentication

Authenticate using API keys passed in headers.

```yaml
auth:
  mode: apikey
  apikey:
    header: "X-API-Key"  # Header name to check
    keys:
      - name: "service-a"
        key_hash: "$2a$10$..."  # bcrypt hash of the API key
        groups: ["api-access"]
      - name: "service-b"
        key_hash: "$2a$10$..."
        groups: ["api-access", "admin"]
```

### Generating API Key Hashes

```bash
# Generate a random API key
openssl rand -base64 32

# Hash the key for storage
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-api-key', bcrypt.gensalt()).decode())"
```

## JWT Authentication

Validate JWT tokens with JWKS support for key rotation.

```yaml
auth:
  mode: jwt
  jwt:
    issuer: "https://auth.example.com"
    audience: "bifrost-proxy"
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
    # Or use static key:
    # signing_key: "${JWT_SIGNING_KEY}"
    username_claim: "sub"
    groups_claim: "groups"
    allowed_algorithms:
      - RS256
      - ES256
```

### JWT Configuration

| Field | Description |
|-------|-------------|
| `issuer` | Expected issuer (iss claim) |
| `audience` | Expected audience (aud claim) |
| `jwks_url` | URL to fetch JSON Web Key Set |
| `signing_key` | Static signing key (alternative to JWKS) |
| `username_claim` | Claim to use as username |
| `groups_claim` | Claim containing user groups |

## TOTP Authentication

Time-based One-Time Password authentication, compatible with Google Authenticator.

```yaml
auth:
  mode: totp
  totp:
    issuer: "Bifrost Proxy"
    digits: 6
    period: 30
    algorithm: "SHA1"
    secrets:
      user1: "JBSWY3DPEHPK3PXP"  # Base32-encoded secret
      user2: "GEZDGNBVGY3TQOJQ"
```

### Setting Up TOTP

1. Generate a secret for each user
2. Share the secret with the user via QR code or manual entry
3. User scans with authenticator app (Google Authenticator, Authy, etc.)

```bash
# Generate a random TOTP secret
python3 -c "import secrets; import base64; print(base64.b32encode(secrets.token_bytes(20)).decode())"
```

## HOTP Authentication

Counter-based One-Time Password authentication, compatible with YubiKey and similar hardware tokens.

```yaml
auth:
  mode: hotp
  hotp:
    digits: 6
    algorithm: "SHA1"
    secrets:
      user1:
        secret: "JBSWY3DPEHPK3PXP"
        counter: 0
      user2:
        secret: "GEZDGNBVGY3TQOJQ"
        counter: 100
    look_ahead: 10  # Accept codes within this window
```

## mTLS Certificate Authentication

Client certificate authentication for mutual TLS.

```yaml
auth:
  mode: mtls
  mtls:
    ca_cert: "/path/to/ca.crt"
    # Optional: require specific certificate attributes
    require_cn: true
    allowed_cns:
      - "client1.example.com"
      - "*.internal.example.com"
    # Map certificate subject to user
    username_from: "cn"  # cn, email, or custom OID
```

### Certificate Requirements

- Client must present a valid certificate signed by the configured CA
- Certificate must not be expired or revoked
- Subject CN or email is used as username

## Kerberos/SPNEGO Authentication

Enterprise SSO using Kerberos with SPNEGO (HTTP Negotiate).

```yaml
auth:
  mode: kerberos
  kerberos:
    keytab: "/etc/krb5.keytab"
    service_principal: "HTTP/proxy.example.com@EXAMPLE.COM"
    realm: "EXAMPLE.COM"
    # Optional: allowed principals
    allowed_principals:
      - "*@EXAMPLE.COM"
```

### Kerberos Setup

1. Create a service principal for the proxy
2. Export the keytab file
3. Configure the client to use Kerberos (kinit)

```bash
# Create service principal (on KDC)
kadmin -q "addprinc -randkey HTTP/proxy.example.com"
kadmin -q "ktadd -k /etc/krb5.keytab HTTP/proxy.example.com"
```

## NTLM Authentication

Windows domain authentication fallback.

```yaml
auth:
  mode: ntlm
  ntlm:
    domain: "EXAMPLE"
    # Use local SAM database or domain controller
    use_domain_controller: true
    domain_controller: "dc.example.com"
```

!!! warning "Security Note"
    NTLM is considered legacy. Prefer Kerberos when possible.

## MFA Wrapper (Two-Factor Authentication)

Combine a primary authentication method with an OTP provider for two-factor authentication.

```yaml
auth:
  mode: mfa_wrapper
  mfa_wrapper:
    # Primary authentication (username/password)
    primary:
      mode: native
      native:
        users:
          - username: admin
            password_hash: "$2a$10$..."
          - username: user1
            password_hash: "$2a$10$..."

    # Secondary authentication (OTP)
    secondary:
      mode: totp
      totp:
        issuer: "Bifrost"
        secrets:
          admin: "JBSWY3DPEHPK3PXP"
          user1: "GEZDGNBVGY3TQOJQ"

    # How to submit OTP
    otp_header: "X-OTP"  # Or append to password with separator
    otp_separator: ":"   # password:123456
```

### MFA Authentication Flow

1. Client sends username and password
2. If OTP header is present, validate both
3. If OTP is appended to password (password:123456), split and validate
4. Both factors must pass for authentication to succeed

## Session Management

Sessions can be stored in memory or Redis for persistence across restarts.

```yaml
session:
  store: redis  # or "memory"
  redis:
    address: "localhost:6379"
    password: "${REDIS_PASSWORD}"
    db: 0
    key_prefix: "bifrost:session:"
  ttl: "24h"
  cookie_name: "bifrost_session"
  cookie_secure: true
  cookie_http_only: true
```

### Session Stores

| Store | Persistence | Scaling | Use Case |
|-------|-------------|---------|----------|
| `memory` | No | Single instance | Development, simple deployments |
| `redis` | Yes | Multi-instance | Production, HA deployments |

## Authentication Plugin System

The authentication system uses a plugin architecture. Custom authentication providers can be registered:

```go
import "github.com/rennerdo30/bifrost-proxy/internal/auth"

func init() {
    auth.RegisterPlugin("custom", &CustomAuthPlugin{})
}

type CustomAuthPlugin struct{}

func (p *CustomAuthPlugin) Name() string { return "custom" }

func (p *CustomAuthPlugin) Init(config map[string]interface{}) error {
    // Initialize plugin
    return nil
}

func (p *CustomAuthPlugin) Authenticate(ctx context.Context, creds auth.Credentials) (*auth.User, error) {
    // Validate credentials
    return &auth.User{Username: creds.Username}, nil
}

func (p *CustomAuthPlugin) Close() error {
    return nil
}
```
