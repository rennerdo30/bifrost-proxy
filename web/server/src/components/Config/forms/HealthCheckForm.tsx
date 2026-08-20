import type { HealthCheckConfig, HealthCheckScheme } from '../../../api/types'
import {
  DEFAULT_HEALTH_CHECK,
  HEALTH_CHECK_SCHEME_HTTP,
  HEALTH_CHECK_SCHEME_HTTPS,
  HEALTH_CHECK_TYPE_HTTP,
  withHealthCheckScheme,
  withHealthCheckType,
} from '../healthCheck'

interface HealthCheckFormProps {
  config?: HealthCheckConfig
  onChange: (config: HealthCheckConfig | undefined) => void
  optional?: boolean
}

export function HealthCheckForm({ config, onChange, optional = true }: HealthCheckFormProps) {
  const enabled = !!config

  const toggleEnabled = (enable: boolean) => {
    onChange(enable ? { ...DEFAULT_HEALTH_CHECK } : undefined)
  }

  const update = (field: keyof HealthCheckConfig, value: unknown) => {
    if (config) {
      onChange({ ...config, [field]: value })
    }
  }

  // Thresholds are stored as numbers; an empty field means "unset", which the
  // server treats as 1 (transition immediately).
  const updateThreshold = (field: 'healthy_threshold' | 'unhealthy_threshold', raw: string) => {
    if (!config) return
    const next: HealthCheckConfig = { ...config }
    const parsed = Number.parseInt(raw, 10)
    if (raw === '' || Number.isNaN(parsed)) delete next[field]
    else next[field] = parsed
    onChange(next)
  }

  return (
    <div className="space-y-3">
      {optional && (
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => toggleEnabled(e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-bifrost-text">Custom Health Check</span>
        </label>
      )}

      {enabled && config && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-7">
          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Type</label>
            <select
              value={config.type || 'tcp'}
              onChange={(e) => onChange(withHealthCheckType(config, e.target.value as HealthCheckConfig['type']))}
              className="input"
            >
              <option value="tcp">TCP</option>
              <option value="http">HTTP</option>
              <option value="ping">Ping</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Interval</label>
            <input
              type="text"
              value={config.interval || ''}
              onChange={(e) => update('interval', e.target.value)}
              placeholder="10s"
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Timeout</label>
            <input
              type="text"
              value={config.timeout || ''}
              onChange={(e) => update('timeout', e.target.value)}
              placeholder="5s"
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Target</label>
            <input
              type="text"
              value={config.target || ''}
              onChange={(e) => update('target', e.target.value)}
              placeholder="host:port"
              className="input"
            />
          </div>
          {config.type === HEALTH_CHECK_TYPE_HTTP && (
            <>
              <div>
                <label className="block text-sm font-medium text-bifrost-text mb-1">HTTP Path</label>
                <input
                  type="text"
                  value={config.path || ''}
                  onChange={(e) => update('path', e.target.value)}
                  placeholder="/health"
                  className="input"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-bifrost-text mb-1">Scheme</label>
                <select
                  value={config.scheme || HEALTH_CHECK_SCHEME_HTTP}
                  onChange={(e) => onChange(withHealthCheckScheme(config, e.target.value as HealthCheckScheme))}
                  className="input"
                >
                  <option value={HEALTH_CHECK_SCHEME_HTTP}>HTTP</option>
                  <option value={HEALTH_CHECK_SCHEME_HTTPS}>HTTPS</option>
                </select>
              </div>
              {config.scheme === HEALTH_CHECK_SCHEME_HTTPS && (
                <div className="md:col-span-2">
                  <label className="flex items-start gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={!!config.insecure_skip_verify}
                      onChange={(e) => update('insecure_skip_verify', e.target.checked)}
                      className="mt-0.5 w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                    />
                    <span>
                      <span className="text-sm font-medium text-bifrost-text">
                        Skip TLS certificate verification
                      </span>
                      <span className="block text-xs text-bifrost-muted mt-0.5">
                        Accepts a self-signed or expired backend certificate. The probe no
                        longer authenticates the backend.
                      </span>
                    </span>
                  </label>
                </div>
              )}
            </>
          )}
          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Healthy Threshold</label>
            <input
              type="number"
              min={0}
              value={config.healthy_threshold ?? ''}
              onChange={(e) => updateThreshold('healthy_threshold', e.target.value)}
              placeholder="1"
              className="input"
            />
            <p className="mt-1 text-xs text-bifrost-muted">
              Consecutive successes before marking healthy
            </p>
          </div>
          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Unhealthy Threshold</label>
            <input
              type="number"
              min={0}
              value={config.unhealthy_threshold ?? ''}
              onChange={(e) => updateThreshold('unhealthy_threshold', e.target.value)}
              placeholder="1"
              className="input"
            />
            <p className="mt-1 text-xs text-bifrost-muted">
              Consecutive failures before marking unhealthy
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
