import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { HealthCheckConfig } from '../../../api/types'

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

  return (
    <Section title="Global Health Checks" badge="restart-required">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => toggleEnabled(e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable Global Health Checks</span>
        </label>
        <p className="text-xs text-bifrost-muted pl-7">
          Applied to all backends without their own health check configuration
        </p>

        {enabled && config && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <ValidatedSelect
              label="Type"
              value={config.type || 'tcp'}
              onChange={(e) => update('type', e.target.value)}
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
              <div className="md:col-span-2">
                <ValidatedInput
                  label="HTTP Path"
                  value={config.path || ''}
                  onChange={(e) => update('path', e.target.value)}
                  placeholder="/health"
                  error={errors.path}
                  helpText="URL path for HTTP health checks"
                />
              </div>
            )}
          </div>
        )}
      </div>
    </Section>
  )
}
