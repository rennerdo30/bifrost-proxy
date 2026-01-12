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
