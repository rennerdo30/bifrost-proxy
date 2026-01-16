# REST API Reference

Both server and client expose REST APIs for management and monitoring.

## Authentication

If API token is configured:

```bash
curl -H "Authorization: Bearer your-token" http://localhost:8082/api/v1/status
```

Or via query parameter:

```bash
curl "http://localhost:8082/api/v1/status?token=your-token"
```

## Server API

Default: `http://localhost:8082`

### Health Check

```http
GET /api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "time": "2024-01-01T00:00:00Z"
}
```

### Version

```http
GET /api/v1/version
```

Response:
```json
{
  "version": "1.0.0",
  "git_commit": "abc123",
  "build_time": "2024-01-01T00:00:00Z",
  "go_version": "go1.22.0",
  "platform": "linux/amd64"
}
```

### Status

```http
GET /api/v1/status
```

Response:
```json
{
  "status": "running",
  "time": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "backends": 3
}
```

### Server Statistics

```http
GET /api/v1/stats
```

Response:
```json
{
  "total_connections": 5000,
  "active_connections": 25,
  "bytes_sent": 104857600,
  "bytes_received": 209715200,
  "backends": {
    "total": 3,
    "healthy": 3
  },
  "time": "2024-01-01T00:00:00Z"
}
```

### List Backends

```http
GET /api/v1/backends
```

Response:
```json
[
  {
    "name": "direct",
    "type": "direct",
    "healthy": true,
    "stats": {
      "active_connections": 5,
      "total_connections": 100,
      "bytes_sent": 1024000,
      "bytes_received": 2048000
    }
  }
]
```

### Get Backend

```http
GET /api/v1/backends/{name}
```

### Backend Stats

```http
GET /api/v1/backends/{name}/stats
```

### Configuration

Get sanitized config (safe to display):
```http
GET /api/v1/config
```

Get full config for editing:
```http
GET /api/v1/config/full
```

Get config section metadata (hot-reload info):
```http
GET /api/v1/config/meta
```

Save configuration:
```http
PUT /api/v1/config
Content-Type: application/json

{
  "config": { ... },
  "create_backup": true
}
```

Validate config without saving:
```http
POST /api/v1/config/validate
Content-Type: application/json

{ ... config object ... }
```

Reload configuration:
```http
POST /api/v1/config/reload
```

### Request Log

Get recent requests (requires `enable_request_log: true` in config):
```http
GET /api/v1/requests
GET /api/v1/requests?limit=50
GET /api/v1/requests?since=123  # Get requests since ID
```

Response:
```json
{
  "enabled": true,
  "requests": [
    {
      "id": 1,
      "timestamp": "2024-01-01T00:00:00Z",
      "method": "GET",
      "host": "example.com",
      "path": "/api/data",
      "backend": "direct",
      "status_code": 200,
      "duration_ms": 150,
      "bytes_sent": 1024,
      "bytes_recv": 2048
    }
  ]
}
```

Get request log stats:
```http
GET /api/v1/requests/stats
```

Clear request log:
```http
DELETE /api/v1/requests
```

### Active Connections

Get all active connections:
```http
GET /api/v1/connections
```

Response:
```json
{
  "connections": [
    {
      "id": "20240115100000-1",
      "client_ip": "192.168.1.100",
      "client_port": "54321",
      "host": "example.com:443",
      "backend": "direct",
      "protocol": "CONNECT",
      "start_time": "2024-01-15T10:00:00Z",
      "bytes_sent": 1024,
      "bytes_recv": 2048
    }
  ],
  "count": 1,
  "time": "2024-01-15T10:00:05Z"
}
```

### Connected Clients

Get unique connected clients with aggregated stats:
```http
GET /api/v1/connections/clients
```

Response:
```json
{
  "clients": [
    {
      "client_ip": "192.168.1.100",
      "connections": 5,
      "bytes_sent": 10240,
      "bytes_recv": 20480,
      "first_seen": "2024-01-15T09:00:00Z"
    }
  ],
  "count": 1,
  "time": "2024-01-15T10:00:05Z"
}
```

### Cache Management

Get cache statistics:
```http
GET /api/v1/cache/stats
```

Response:
```json
{
  "enabled": true,
  "hit_rate": 0.85,
  "total_requests": 12450,
  "cache_hits": 10582,
  "cache_misses": 1868,
  "storage_type": "tiered",
  "rules_count": 5,
  "memory": {
    "entries": 4521,
    "size_bytes": 1073741824,
    "max_size_bytes": 2147483648
  },
  "disk": {
    "entries": 892,
    "size_bytes": 107374182400,
    "max_size_bytes": 536870912000
  }
}
```

List cached entries:
```http
GET /api/v1/cache/entries
GET /api/v1/cache/entries?domain=*.steamcontent.com
GET /api/v1/cache/entries?limit=10&offset=0
```

Response:
```json
{
  "entries": [
    {
      "key": "ab12cd34...",
      "url": "http://cdn.steamcontent.com/depot/123/chunk/abc",
      "host": "cdn.steamcontent.com",
      "size": 1048576,
      "content_type": "application/octet-stream",
      "created_at": "2024-01-15T10:30:00Z",
      "expires_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 892,
  "offset": 0,
  "limit": 10
}
```

Get single entry metadata:
```http
GET /api/v1/cache/entries/{key}
```

Delete single entry:
```http
DELETE /api/v1/cache/entries/{key}
```

Clear all cache:
```http
DELETE /api/v1/cache/entries?confirm=true
```

Purge entries for a domain:
```http
DELETE /api/v1/cache/domain/{domain}
```

List caching rules:
```http
GET /api/v1/cache/rules
```

Response:
```json
{
  "rules": [
    {
      "name": "steam",
      "domains": ["*.steamcontent.com", "content*.steampowered.com"],
      "enabled": true,
      "ttl": "8760h0m0s",
      "priority": 100,
      "preset": "steam"
    }
  ]
}
```

Add custom rule:
```http
POST /api/v1/cache/rules
Content-Type: application/json

{
  "name": "my-cdn",
  "domains": ["cdn.example.com"],
  "enabled": true,
  "ttl": "168h",
  "priority": 50
}
```

Update rule:
```http
PUT /api/v1/cache/rules/{name}
```

Delete rule:
```http
DELETE /api/v1/cache/rules/{name}
```

List available presets:
```http
GET /api/v1/cache/presets
```

Response:
```json
{
  "presets": [
    {
      "name": "steam",
      "description": "Steam game downloads and updates",
      "domains": ["*.steamcontent.com", "content*.steampowered.com"],
      "ttl": "8760h0m0s",
      "priority": 100
    }
  ]
}
```

Enable/disable preset:
```http
POST /api/v1/cache/presets/{name}
Content-Type: application/json

{"enabled": true}
```

### PAC File (Proxy Auto-Configuration)

Bifrost automatically generates a PAC file based on your routing rules:

```http
GET /proxy.pac
GET /wpad.dat
```

The PAC file contains JavaScript that browsers use for automatic proxy configuration. Example output:

```javascript
function FindProxyForURL(url, host) {
    if (shExpMatch(host, "*.internal.company.com")) {
        return "PROXY bifrost.example.com:8080; DIRECT";
    }
    return "DIRECT";
}
```

**Using the PAC file:**

- **macOS**: System Preferences → Network → Advanced → Proxies → Automatic Proxy Configuration
- **Windows**: Settings → Network → Proxy → Use setup script
- **Firefox**: Settings → Network Settings → Automatic proxy configuration URL
- **Chrome**: Uses system settings, or use Proxy SwitchyOmega extension

## Client API

Default: `http://localhost:3130`

### Status

```http
GET /api/v1/status
```

Response:
```json
{
  "status": "running",
  "server_status": "connected",
  "time": "2024-01-01T00:00:00Z",
  "version": "1.0.0",
  "debug_entries": 150
}
```

### Debug Entries

Get all debug entries:
```http
GET /api/v1/debug/entries
```

Get last N entries:
```http
GET /api/v1/debug/entries/last/100
```

Clear entries:
```http
DELETE /api/v1/debug/entries
```

Get errors only:
```http
GET /api/v1/debug/errors
```

### Routes

List routes:
```http
GET /api/v1/routes
```

Test a domain:
```http
GET /api/v1/routes/test?domain=example.com
```

Response:
```json
{
  "domain": "example.com",
  "action": "server"
}
```

## WebSocket API

Real-time updates are available via WebSocket:

```javascript
const ws = new WebSocket('ws://localhost:8082/api/v1/ws');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

Events:
- `connection.new` - New connection established
- `connection.close` - Connection closed
- `backend.health` - Backend health changed
- `config.reload` - Configuration reloaded
