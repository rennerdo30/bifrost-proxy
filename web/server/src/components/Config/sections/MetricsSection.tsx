import { Section } from '../Section'
import type { MetricsConfig } from '../../../api/types'

interface MetricsSectionProps {
  config: MetricsConfig
  onChange: (config: MetricsConfig) => void
}

export function MetricsSection({ config, onChange }: MetricsSectionProps) {
  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <Section title="Prometheus Metrics" badge="restart-required">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable Prometheus Metrics</span>
        </label>

        {config.enabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Listen Address</label>
              <input
                type="text"
                value={config.listen || ''}
                onChange={(e) => update('listen', e.target.value)}
                placeholder=":9090"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Metrics Path</label>
              <input
                type="text"
                value={config.path || ''}
                onChange={(e) => update('path', e.target.value)}
                placeholder="/metrics"
                className="input"
              />
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
