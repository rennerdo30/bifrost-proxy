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
    redirect_url: "http://localhost:8081/callback"
    scopes:
      - openid
      - profile
      - email
```

## Using Authentication with Proxy

### HTTP Proxy Authentication

Clients authenticate using `Proxy-Authorization` header:

```bash
curl -x http://user:pass@localhost:8080 http://example.com
```

### SOCKS5 Authentication

```bash
curl --socks5 user:pass@localhost:1080 http://example.com
```

## Client Authentication

The client can authenticate with the server:

```yaml
server:
  address: "proxy.example.com:8080"
  username: "myuser"
  password: "mypass"
```
