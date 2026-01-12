import { Section } from '../Section'
import type { HealthCheckConfig } from '../../../api/types'

interface HealthCheckSectionProps {
  config?: HealthCheckConfig
  onChange: (config: HealthCheckConfig | undefined) => void
}

export function HealthCheckSection({ config, onChange }: HealthCheckSectionProps) {
  const enabled = !!config

  const toggleEnabled = (enable: boolean) => {
    if (enable) {
      onChange({
        type: 'tcp',
        interval: '10s',
        timeout: '5s',
      })
    } else {
      onChange(undefined)
    }
  }

  const update = (field: string, value: unknown) => {
    if (config) {
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
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
              <select
                value={config.type || 'tcp'}
                onChange={(e) => update('type', e.target.value)}
                className="input"
              >
                <option value="tcp">TCP</option>
                <option value="http">HTTP</option>
                <option value="ping">Ping</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Interval</label>
              <input
                type="text"
                value={config.interval || ''}
                onChange={(e) => update('interval', e.target.value)}
                placeholder="10s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Timeout</label>
              <input
                type="text"
                value={config.timeout || ''}
                onChange={(e) => update('timeout', e.target.value)}
                placeholder="5s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Target</label>
              <input
                type="text"
                value={config.target || ''}
                onChange={(e) => update('target', e.target.value)}
                placeholder="host:port"
                className="input"
              />
            </div>
            {config.type === 'http' && (
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-gray-300 mb-1">HTTP Path</label>
                <input
                  type="text"
                  value={config.path || ''}
                  onChange={(e) => update('path', e.target.value)}
                  placeholder="/health"
                  className="input"
                />
              </div>
            )}
          </div>
        )}
      </div>
    </Section>
  )
}
