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
