# Monitoring Guide

This guide covers monitoring Bifrost using Prometheus metrics, Grafana dashboards, and health checks.

## Prometheus Metrics

Bifrost exposes metrics in Prometheus format at the configured metrics endpoint.

### Configuration

```yaml
metrics:
  enabled: true
  listen: ":7090"
  path: "/metrics"
```

### Scrape Configuration

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'bifrost-server'
    static_configs:
      - targets: ['bifrost-server:7090']
    scrape_interval: 15s

  - job_name: 'bifrost-client'
    static_configs:
      - targets: ['bifrost-client:7090']
    scrape_interval: 15s
```

### Available Metrics

#### Connection Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `bifrost_connections_total` | Counter | Total connections handled |
| `bifrost_connections_active` | Gauge | Current active connections |
| `bifrost_connections_errors_total` | Counter | Total connection errors |

#### Request Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bifrost_requests_total` | Counter | `method`, `backend`, `status` | Total requests |
| `bifrost_request_duration_seconds` | Histogram | `method`, `backend` | Request duration |
| `bifrost_request_size_bytes` | Histogram | `direction` | Request/response size |

#### Backend Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bifrost_backend_connections_total` | Counter | `backend` | Connections per backend |
| `bifrost_backend_connections_active` | Gauge | `backend` | Active connections per backend |
| `bifrost_backend_healthy` | Gauge | `backend` | Backend health (1=healthy, 0=unhealthy) |
| `bifrost_backend_latency_seconds` | Histogram | `backend` | Backend response latency |

#### Traffic Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bifrost_bytes_total` | Counter | `direction`, `backend` | Total bytes transferred |
| `bifrost_bandwidth_bytes_per_second` | Gauge | `direction` | Current bandwidth usage |

#### Cache Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `bifrost_cache_hits_total` | Counter | `domain` | Total cache hits |
| `bifrost_cache_misses_total` | Counter | `domain`, `reason` | Total cache misses |
| `bifrost_cache_bytes_served_total` | Counter | `source` | Bytes served (cache vs origin) |
| `bifrost_cache_storage_size_bytes` | Gauge | `tier` | Current storage size |
| `bifrost_cache_storage_entries` | Gauge | `tier` | Current entry count |
| `bifrost_cache_storage_usage_percent` | Gauge | `tier` | Storage usage percentage |
| `bifrost_cache_evictions_total` | Counter | `tier`, `reason` | Cache evictions |
| `bifrost_cache_operation_duration_seconds` | Histogram | `operation` | Cache operation latency |
| `bifrost_cache_active_rules` | Gauge | | Number of active cache rules |
| `bifrost_cache_active_presets` | Gauge | | Number of enabled presets |

#### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `bifrost_uptime_seconds` | Gauge | Server uptime |
| `bifrost_goroutines` | Gauge | Number of goroutines |
| `bifrost_memory_bytes` | Gauge | Memory usage |

### Example Queries

```promql
# Request rate per second
rate(bifrost_requests_total[5m])

# Average request duration
rate(bifrost_request_duration_seconds_sum[5m]) / rate(bifrost_request_duration_seconds_count[5m])

# Error rate
rate(bifrost_connections_errors_total[5m]) / rate(bifrost_connections_total[5m])

# Active connections by backend
bifrost_backend_connections_active

# Bandwidth usage (MB/s)
rate(bifrost_bytes_total[5m]) / 1024 / 1024

# Unhealthy backends
bifrost_backend_healthy == 0

# Cache hit rate
bifrost_cache_hits_total / (bifrost_cache_hits_total + bifrost_cache_misses_total)

# Cache storage usage
bifrost_cache_storage_usage_percent{tier="memory"}
bifrost_cache_storage_usage_percent{tier="disk"}

# Bytes saved by cache (vs fetching from origin)
rate(bifrost_cache_bytes_served_total{source="cache"}[1h])
```

---

## Grafana Dashboards

### Docker Compose Setup

The included Docker Compose file starts Grafana with Prometheus:

```bash
cd docker
docker-compose up -d grafana prometheus
```

Access Grafana at `http://localhost:3000` (default: admin/admin).

### Add Prometheus Data Source

1. Go to Configuration → Data Sources
2. Add data source → Prometheus
3. URL: `http://prometheus:7090`
4. Save & Test

### Dashboard Panels

#### Overview Panel

```json
{
  "title": "Active Connections",
  "type": "stat",
  "targets": [{
    "expr": "bifrost_connections_active",
    "legendFormat": "Connections"
  }]
}
```

#### Request Rate Panel

```json
{
  "title": "Request Rate",
  "type": "graph",
  "targets": [{
    "expr": "rate(bifrost_requests_total[5m])",
    "legendFormat": "{{method}} - {{backend}}"
  }]
}
```

#### Backend Health Panel

```json
{
  "title": "Backend Health",
  "type": "table",
  "targets": [{
    "expr": "bifrost_backend_healthy",
    "format": "table",
    "instant": true
  }]
}
```

#### Latency Heatmap

```json
{
  "title": "Request Latency",
  "type": "heatmap",
  "targets": [{
    "expr": "rate(bifrost_request_duration_seconds_bucket[5m])",
    "format": "heatmap"
  }]
}
```

---

## Health Checks

### HTTP Health Endpoint

```bash
curl http://localhost:7082/api/v1/health
```

Response:
```json
{
  "status": "healthy",
  "time": "2024-01-15T10:30:00Z"
}
```

Status values:

- `healthy` - All backends healthy
- `degraded` - Some backends unhealthy

### Backend Health

```bash
curl http://localhost:7082/api/v1/backends
```

Response:
```json
[
  {
    "name": "direct",
    "type": "direct",
    "healthy": true,
    "stats": {
      "total_connections": 1234,
      "active_connections": 5,
      "bytes_sent": 1048576,
      "bytes_received": 2097152
    }
  }
]
```

### Docker Health Check

```yaml
healthcheck:
  test: ["CMD", "wget", "-q", "--spider", "http://localhost:7090/metrics"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 5s
```

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/health
    port: 8082
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /api/v1/health
    port: 8082
  initialDelaySeconds: 5
  periodSeconds: 5
```

---

## Alerting

### Prometheus Alerting Rules

Create `alerts.yml`:

```yaml
groups:
  - name: bifrost
    rules:
      # High error rate
      - alert: BifrostHighErrorRate
        expr: rate(bifrost_connections_errors_total[5m]) / rate(bifrost_connections_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on Bifrost"
          description: "Error rate is {{ $value | humanizePercentage }}"

      # Backend down
      - alert: BifrostBackendDown
        expr: bifrost_backend_healthy == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Bifrost backend {{ $labels.backend }} is down"

      # High latency
      - alert: BifrostHighLatency
        expr: histogram_quantile(0.95, rate(bifrost_request_duration_seconds_bucket[5m])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency on Bifrost"
          description: "P95 latency is {{ $value | humanizeDuration }}"

      # No connections
      - alert: BifrostNoConnections
        expr: bifrost_connections_active == 0
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "No active connections on Bifrost"

      # High connection count
      - alert: BifrostHighConnections
        expr: bifrost_connections_active > 10000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High connection count"
          description: "{{ $value }} active connections"
```

### Grafana Alerts

1. Edit a panel
2. Go to Alert tab
3. Create alert rule
4. Set conditions and notifications

---

## Logging

### Structured Logging

```yaml
logging:
  level: info
  format: json
  output: stdout  # or file path
```

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Verbose debugging information |
| `info` | Normal operational messages |
| `warn` | Warning conditions |
| `error` | Error conditions |

### Log Aggregation

#### Loki (with Docker)

```yaml
# docker-compose.yml
services:
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    volumes:
      - loki-data:/loki

  bifrost-server:
    logging:
      driver: loki
      options:
        loki-url: "http://localhost:3100/loki/api/v1/push"
        labels: "app=bifrost,service=server"
```

#### Elasticsearch

```yaml
logging:
  format: json
  output: stdout
```

Use Filebeat to ship logs to Elasticsearch:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: container
    paths:
      - '/var/lib/docker/containers/*/*.log'

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
```

---

## Best Practices

### Metrics

1. **Scrape interval**: 15-30 seconds for most use cases
2. **Retention**: Keep at least 15 days of metrics
3. **Labels**: Avoid high-cardinality labels (e.g., user IDs)

### Alerting

1. **Start simple**: Begin with basic alerts, add more as needed
2. **Avoid alert fatigue**: Only alert on actionable issues
3. **Document runbooks**: Link alerts to troubleshooting guides

### Dashboards

1. **Overview first**: Start with high-level health metrics
2. **Drill-down**: Allow navigation to detailed views
3. **Time ranges**: Support common ranges (1h, 6h, 24h, 7d)

### Logging

1. **Structured logs**: Use JSON format for parsing
2. **Correlation IDs**: Include request IDs for tracing
3. **Log rotation**: Prevent disk space issues
