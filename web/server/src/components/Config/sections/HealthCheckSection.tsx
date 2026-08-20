import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { HealthCheckConfig, HealthCheckScheme } from '../../../api/types'

interface HealthCheckSectionProps {
  config?: HealthCheckConfig
  onChange: (config: HealthCheckConfig | undefined) => void
}

type HealthCheckValidationKeys = {
  interval: string
  timeout: string
  target: string
  path: string
}

export function HealthCheckSection({ config, onChange }: HealthCheckSectionProps) {
  const enabled = !!config

  const { errors, handleFieldChange, clearErrors } = useValidation<HealthCheckValidationKeys>({
    interval: [validators.duration()],
    timeout: [validators.duration()],
    target: [validators.pattern(/^[\w.-]+:\d+$/, 'Format: host:port')],
    path: [validators.pattern(/^\//, 'Path must start with /')],
  })

  const toggleEnabled = (enable: boolean) => {
    if (enable) {
      clearErrors()
      onChange({
        type: 'tcp',
        interval: '10s',
        timeout: '5s',
      })
    } else {
      clearErrors()
      onChange(undefined)
    }
  }

  const update = (field: string, value: unknown) => {
    if (config) {
      if (field === 'interval' || field === 'timeout' || field === 'target' || field === 'path') {
        handleFieldChange(field as keyof HealthCheckValidationKeys, value as never)
      }
      onChange({ ...config, [field]: value })
    }
  }

  // The server rejects scheme / insecure_skip_verify on non-HTTP checks and
  // insecure_skip_verify without HTTPS, because they would be silently inert.
  // Drop them here so switching the type never produces a config that fails
  // validation on save.
  const updateType = (type: HealthCheckConfig['type']) => {
    if (!config) return
    const next: HealthCheckConfig = { ...config, type }
    if (type !== 'http') {
      delete next.scheme
      delete next.insecure_skip_verify
    }
    onChange(next)
  }

  const updateScheme = (scheme: HealthCheckScheme) => {
    if (!config) return
    const next: HealthCheckConfig = { ...config, scheme }
    if (scheme !== 'https') {
      delete next.insecure_skip_verify
    }
    onChange(next)
  }

  return (
    <Section sectionKey="health_check" title="Global Health Checks">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => toggleEnabled(e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-bifrost-text">Enable Global Health Checks</span>
        </label>
        <p className="text-xs text-bifrost-muted pl-7">
          Applied to all backends without their own health check configuration
        </p>

        {enabled && config && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <ValidatedSelect
              label="Type"
              value={config.type || 'tcp'}
              onChange={(e) => updateType(e.target.value as HealthCheckConfig['type'])}
            >
              <option value="tcp">TCP</option>
              <option value="http">HTTP</option>
              <option value="ping">Ping</option>
            </ValidatedSelect>
            <ValidatedInput
              label="Interval"
              value={config.interval || ''}
              onChange={(e) => update('interval', e.target.value)}
              placeholder="10s"
              error={errors.interval}
              helpText="Time between checks (e.g., 10s, 1m)"
            />
            <ValidatedInput
              label="Timeout"
              value={config.timeout || ''}
              onChange={(e) => update('timeout', e.target.value)}
              placeholder="5s"
              error={errors.timeout}
              helpText="Maximum time to wait for response"
            />
            <ValidatedInput
              label="Target"
              value={config.target || ''}
              onChange={(e) => update('target', e.target.value)}
              placeholder="host:port"
              error={errors.target}
              helpText="Health check endpoint (optional)"
            />
            {config.type === 'http' && (
              <>
                <ValidatedInput
                  label="HTTP Path"
                  value={config.path || ''}
                  onChange={(e) => update('path', e.target.value)}
                  placeholder="/health"
                  error={errors.path}
                  helpText="URL path for HTTP health checks"
                />
                <ValidatedSelect
                  label="Scheme"
                  value={config.scheme || 'http'}
                  onChange={(e) => updateScheme(e.target.value as HealthCheckScheme)}
                  helpText="Use HTTPS to probe a TLS-terminating backend"
                >
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                </ValidatedSelect>
                {config.scheme === 'https' && (
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
                          Accepts self-signed and expired backend certificates. The health
                          probe no longer authenticates the backend &mdash; only enable it for
                          backends you control on a trusted network.
                        </span>
                      </span>
                    </label>
                  </div>
                )}
              </>
            )}
            <ValidatedInput
              label="Healthy Threshold"
              type="number"
              value={config.healthy_threshold ?? 0}
              onChange={(e) => update('healthy_threshold', parseInt(e.target.value) || 0)}
              placeholder="1"
              helpText="Consecutive successes before marking healthy (0 = 1)"
            />
            <ValidatedInput
              label="Unhealthy Threshold"
              type="number"
              value={config.unhealthy_threshold ?? 0}
              onChange={(e) => update('unhealthy_threshold', parseInt(e.target.value) || 0)}
              placeholder="1"
              helpText="Consecutive failures before marking unhealthy (0 = 1)"
            />
          </div>
        )}
      </div>
    </Section>
  )
}
