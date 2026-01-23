import { Section } from '../Section'
import { ValidatedInput } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { MetricsConfig } from '../../../api/types'

interface MetricsSectionProps {
  config: MetricsConfig
  onChange: (config: MetricsConfig) => void
}

type MetricsValidationKeys = {
  listen: string
  path: string
  collection_interval: string
}

export function MetricsSection({ config, onChange }: MetricsSectionProps) {
  const { errors, handleFieldChange } = useValidation<MetricsValidationKeys>({
    listen: [validators.listenAddress()],
    path: [validators.pattern(/^\//, 'Path must start with /')],
    collection_interval: [validators.duration()],
  })

  const update = (field: string, value: unknown) => {
    if (field === 'listen' || field === 'path' || field === 'collection_interval') {
      handleFieldChange(field as keyof MetricsValidationKeys, value as never)
    }
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
            <ValidatedInput
              label="Listen Address"
              value={config.listen || ''}
              onChange={(e) => update('listen', e.target.value)}
              placeholder=":9090"
              error={errors.listen}
              helpText="Format: :port or host:port"
            />
            <ValidatedInput
              label="Metrics Path"
              value={config.path || ''}
              onChange={(e) => update('path', e.target.value)}
              placeholder="/metrics"
              error={errors.path}
              helpText="URL path for metrics endpoint"
            />
            <ValidatedInput
              label="Collection Interval"
              value={config.collection_interval || ''}
              onChange={(e) => update('collection_interval', e.target.value)}
              placeholder="15s"
              error={errors.collection_interval}
              helpText="e.g., 15s, 1m, 5m"
            />
          </div>
        )}
      </div>
    </Section>
  )
}
