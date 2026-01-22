# Backend Configuration Guide

Bifrost supports multiple backend types for routing traffic.

## Direct Backend

Routes traffic directly without any tunnel.

```yaml
backends:
  - name: direct
    type: direct
    enabled: true
    config:
      connect_timeout: "30s"
      keep_alive: "30s"
```

## WireGuard Backend

Routes traffic through a WireGuard tunnel using userspace networking.

```yaml
backends:
  - name: wg-vpn
    type: wireguard
    enabled: true
    config:
      private_key: "YOUR_PRIVATE_KEY_BASE64"
      address: "10.0.0.2/24"
      dns:
        - "1.1.1.1"
        - "8.8.8.8"
      mtu: 1420
      peer:
        public_key: "PEER_PUBLIC_KEY_BASE64"
        endpoint: "vpn.example.com:51820"
        allowed_ips:
          - "0.0.0.0/0"
        persistent_keepalive: 25
        preshared_key: "OPTIONAL_PSK_BASE64"
```

### Generating Keys

```bash
# Generate private key
wg genkey > private.key

# Generate public key
wg pubkey < private.key > public.key

# Generate preshared key (optional)
wg genpsk > preshared.key
```

## OpenVPN Backend

Routes traffic through an OpenVPN tunnel.

```yaml
backends:
  - name: ovpn-vpn
    type: openvpn
    enabled: true
    config:
      config_file: "/etc/bifrost/vpn.ovpn"
      auth_file: "/etc/bifrost/vpn-auth.txt"
      binary: "/usr/sbin/openvpn"
      management_addr: "127.0.0.1"
      management_port: 7505
      connect_timeout: "60s"
```

The auth file format:
```
username
password
```

## HTTP Proxy Backend

Routes traffic through an upstream HTTP proxy.

```yaml
backends:
  - name: upstream-http
    type: http_proxy
    enabled: true
    config:
      address: "proxy.example.com:7080"
      username: "user"
      password: "pass"
      connect_timeout: "30s"
```

## SOCKS5 Proxy Backend

Routes traffic through an upstream SOCKS5 proxy.

```yaml
backends:
  - name: upstream-socks
    type: socks5_proxy
    enabled: true
    config:
      address: "socks.example.com:7180"
      username: "user"
      password: "pass"
      connect_timeout: "30s"
```

## Load Balancing

Route to multiple backends with load balancing:

```yaml
routes:
  - domains: ["*"]
    backends:
      - backend1
      - backend2
      - backend3
    load_balance: round_robin  # round_robin, least_conn, ip_hash
```

## Health Checks

Configure health checks for backends:

```yaml
backends:
  - name: my-backend
    type: direct
    health_check:
      type: tcp      # tcp, http, ping
      interval: "30s"
      timeout: "5s"
      target: "example.com:443"
```
