# Security Guide

This guide covers security best practices for deploying and operating Bifrost in production environments.

## TLS/HTTPS Configuration

### Enabling TLS on Listeners

```yaml
server:
  http:
    listen: ":8443"
    tls:
      enabled: true
      cert_file: "/etc/bifrost/certs/server.crt"
      key_file: "/etc/bifrost/certs/server.key"
```

### Generating Self-Signed Certificates

For testing only:

```bash
# Generate private key
openssl genrsa -out server.key 4096

# Generate certificate
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365 \
  -subj "/CN=bifrost.example.com"
```

### Using Let's Encrypt

For production, use certificates from Let's Encrypt:

```bash
# Install certbot
sudo apt install certbot

# Obtain certificate
sudo certbot certonly --standalone -d bifrost.example.com

# Certificate location
# /etc/letsencrypt/live/bifrost.example.com/fullchain.pem
# /etc/letsencrypt/live/bifrost.example.com/privkey.pem
```

```yaml
server:
  http:
    tls:
      enabled: true
      cert_file: "/etc/letsencrypt/live/bifrost.example.com/fullchain.pem"
      key_file: "/etc/letsencrypt/live/bifrost.example.com/privkey.pem"
```

### Certificate Permissions

```bash
# Secure key file
chmod 600 /etc/bifrost/certs/server.key
chown bifrost:bifrost /etc/bifrost/certs/server.key
```

---

## Authentication

### Choosing an Authentication Mode

| Mode | Use Case | Security Level |
|------|----------|----------------|
| `none` | Internal networks only | Low |
| `native` | Small deployments | Medium |
| `system` | Unix/PAM integration | Medium-High |
| `ldap` | Enterprise/AD integration | High |
| `oauth` | SSO/Modern apps | High |

### Native Authentication

Generate secure password hashes using bcrypt:

```bash
# Using htpasswd (Apache utils)
htpasswd -nbBC 12 "" "your-password" | cut -d: -f2

# Using Python
python3 -c "import bcrypt; print(bcrypt.hashpw(b'your-password', bcrypt.gensalt(rounds=12)).decode())"
```

!!! warning "Password Hash Security"
    - Always use bcrypt cost factor of 12 or higher
    - Never store plaintext passwords in config files
    - Rotate passwords regularly

```yaml
auth:
  mode: native
  native:
    users:
      - username: admin
        password_hash: "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.gS6T9I2P9z8K2G"
```

### LDAP Security

```yaml
auth:
  mode: ldap
  ldap:
    url: "ldaps://ldap.example.com:636"  # Use LDAPS
    tls: true
    insecure_skip_verify: false  # Always verify in production
    bind_dn: "cn=bifrost-svc,ou=services,dc=example,dc=com"
    bind_password: "${LDAP_BIND_PASSWORD}"  # Use environment variable
```

!!! tip "LDAP Best Practices"
    - Use a dedicated service account with minimal permissions
    - Store bind password in environment variable
    - Use LDAPS (port 636) instead of StartTLS
    - Verify server certificates

### OAuth/OIDC Security

```yaml
auth:
  mode: oauth
  oauth:
    client_id: "${OAUTH_CLIENT_ID}"
    client_secret: "${OAUTH_CLIENT_SECRET}"  # Never commit to git
    issuer_url: "https://auth.example.com"
    redirect_url: "https://bifrost.example.com/callback"
    scopes:
      - openid
      - profile
```

---

## API Security

### API Token Authentication

Always set an API token for production:

```yaml
api:
  enabled: true
  listen: ":8082"
  token: "${BIFROST_API_TOKEN}"
```

Generate a secure token:

```bash
# Generate random token
openssl rand -hex 32
```

### Using the API Token

```bash
# Header authentication (recommended)
curl -H "Authorization: Bearer your-token" http://localhost:8082/api/v1/status

# Query parameter (less secure, avoid in production)
curl "http://localhost:8082/api/v1/status?token=your-token"
```

### Restrict API Access

Bind the API to localhost if only local access is needed:

```yaml
api:
  listen: "127.0.0.1:8082"  # Only localhost
```

---

## Network Security

### Firewall Configuration

#### Linux (UFW)

```bash
# Allow proxy ports from specific networks
sudo ufw allow from 10.0.0.0/8 to any port 8080 proto tcp
sudo ufw allow from 10.0.0.0/8 to any port 1080 proto tcp

# Allow Web UI from admin network only
sudo ufw allow from 192.168.1.0/24 to any port 8081 proto tcp

# Block API from external access
sudo ufw deny 8082/tcp
```

#### Linux (iptables)

```bash
# Allow proxy from internal network
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### IP Access Control

Configure allowed/denied IP ranges:

```yaml
access_control:
  enabled: true
  default_action: deny
  rules:
    - cidr: "10.0.0.0/8"
      action: allow
    - cidr: "192.168.0.0/16"
      action: allow
    - cidr: "0.0.0.0/0"
      action: deny
```

---

## Rate Limiting

Protect against abuse with rate limiting:

```yaml
rate_limit:
  enabled: true
  requests_per_second: 100
  burst_size: 200
  per_ip: true
  per_user: true
```

### Bandwidth Throttling

Prevent bandwidth abuse:

```yaml
rate_limit:
  bandwidth:
    enabled: true
    upload: "10Mbps"
    download: "100Mbps"
```

---

## Secrets Management

### Environment Variables

Never commit secrets to version control. Use environment variables:

```yaml
# config.yaml
auth:
  ldap:
    bind_password: "${LDAP_PASSWORD}"

api:
  token: "${API_TOKEN}"
```

```bash
# Set environment variables
export LDAP_PASSWORD="secret"
export API_TOKEN="your-secure-token"

# Run with environment
bifrost-server -c config.yaml
```

### Systemd Environment Files

Create `/etc/bifrost/env`:

```bash
LDAP_PASSWORD=secret
API_TOKEN=your-secure-token
```

Add to service file:

```ini
[Service]
EnvironmentFile=/etc/bifrost/env
```

Secure the file:

```bash
chmod 600 /etc/bifrost/env
chown root:bifrost /etc/bifrost/env
```

### Docker Secrets

```yaml
# docker-compose.yml
services:
  bifrost-server:
    environment:
      - API_TOKEN_FILE=/run/secrets/api_token
    secrets:
      - api_token

secrets:
  api_token:
    file: ./secrets/api_token.txt
```

---

## Logging Security

### Sensitive Data

Bifrost automatically redacts sensitive data from logs, but review your configuration:

```yaml
logging:
  level: info  # Avoid 'debug' in production
  format: json
```

!!! warning "Log Review"
    - Regularly review logs for sensitive data leaks
    - Don't log full request/response bodies in production
    - Secure log files with appropriate permissions

### Log File Permissions

```bash
chmod 640 /var/log/bifrost/*.log
chown bifrost:bifrost /var/log/bifrost/*.log
```

---

## Security Checklist

### Pre-Production

- [ ] TLS enabled on all public listeners
- [ ] Valid certificates (not self-signed)
- [ ] Authentication enabled
- [ ] API token set
- [ ] Secrets in environment variables (not config)
- [ ] Config file permissions restricted (600)
- [ ] Firewall rules configured
- [ ] Rate limiting enabled

### Regular Maintenance

- [ ] Rotate API tokens quarterly
- [ ] Update TLS certificates before expiry
- [ ] Review access logs for anomalies
- [ ] Update to latest Bifrost version
- [ ] Audit user accounts
- [ ] Test backup and recovery procedures

### Incident Response

- [ ] Document API endpoints and access
- [ ] Have a process for revoking tokens
- [ ] Know how to disable authentication temporarily
- [ ] Have backup configurations ready
- [ ] Know how to review logs quickly

---

## Security Vulnerabilities

### Reporting

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email the maintainers directly
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Updates

Subscribe to releases to stay informed about security updates:

```bash
# Watch the repository on GitHub
# Or check releases periodically
curl -s https://api.github.com/repos/rennerdo30/bifrost-proxy/releases/latest | jq -r .tag_name
```
