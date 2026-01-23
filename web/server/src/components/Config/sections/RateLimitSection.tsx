import { Section } from '../Section'
import { ValidatedInput } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { RateLimitConfig } from '../../../api/types'

interface RateLimitSectionProps {
  config: RateLimitConfig
  onChange: (config: RateLimitConfig) => void
}

type RateLimitValidationKeys = {
  requests_per_second: number
  burst_size: number
  'bandwidth.upload': string
  'bandwidth.download': string
}

export function RateLimitSection({ config, onChange }: RateLimitSectionProps) {
  const { errors, handleFieldChange } = useValidation<RateLimitValidationKeys>({
    requests_per_second: [validators.min(0.1, 'Must be at least 0.1')],
    burst_size: [validators.positiveInteger(), validators.min(1, 'Must be at least 1')],
    'bandwidth.upload': [validators.byteSize()],
    'bandwidth.download': [validators.byteSize()],
  })

  const update = (field: string, value: unknown) => {
    if (field === 'requests_per_second' || field === 'burst_size') {
      handleFieldChange(field as keyof RateLimitValidationKeys, value as never)
    }
    onChange({ ...config, [field]: value })
  }

  const updateBandwidth = (field: string, value: unknown) => {
    handleFieldChange(`bandwidth.${field}` as keyof RateLimitValidationKeys, value as never)
    onChange({
      ...config,
      bandwidth: { ...(config.bandwidth || {}), [field]: value } as RateLimitConfig['bandwidth'],
    })
  }

  const toggleBandwidth = (enabled: boolean) => {
    if (enabled) {
      onChange({
        ...config,
        bandwidth: { enabled: true, upload: '10Mbps', download: '100Mbps' },
      })
    } else {
      onChange({ ...config, bandwidth: undefined })
    }
  }

  return (
    <Section title="Rate Limiting" badge="hot-reload">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable Rate Limiting</span>
        </label>

        {config.enabled && (
          <div className="space-y-4 pl-7">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ValidatedInput
                label="Requests per Second"
                type="number"
                value={config.requests_per_second || 100}
                onChange={(e) => update('requests_per_second', parseFloat(e.target.value) || 100)}
                error={errors.requests_per_second}
                helpText="Maximum requests allowed per second"
              />
              <ValidatedInput
                label="Burst Size"
                type="number"
                value={config.burst_size || 200}
                onChange={(e) => update('burst_size', parseInt(e.target.value) || 0)}
                error={errors.burst_size}
                helpText="Maximum burst of requests allowed"
              />
            </div>

            <div className="flex flex-wrap gap-6">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.per_ip}
                  onChange={(e) => update('per_ip', e.target.checked)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm text-gray-300">Limit per IP</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.per_user}
                  onChange={(e) => update('per_user', e.target.checked)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm text-gray-300">Limit per User</span>
              </label>
            </div>

            {/* Bandwidth Throttling */}
            <div className="mt-4 p-4 bg-bifrost-bg rounded-lg">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.bandwidth?.enabled || false}
                  onChange={(e) => toggleBandwidth(e.target.checked)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm font-medium text-gray-300">Enable Bandwidth Throttling</span>
              </label>
              {config.bandwidth?.enabled && (
                <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                  <ValidatedInput
                    label="Upload Limit"
                    value={config.bandwidth.upload || ''}
                    onChange={(e) => updateBandwidth('upload', e.target.value)}
                    placeholder="10Mbps"
                    error={errors['bandwidth.upload']}
                    helpText="e.g., 10Mbps, 1Gbps, 100KB"
                  />
                  <ValidatedInput
                    label="Download Limit"
                    value={config.bandwidth.download || ''}
                    onChange={(e) => updateBandwidth('download', e.target.value)}
                    placeholder="100Mbps"
                    error={errors['bandwidth.download']}
                    helpText="e.g., 100Mbps, 1Gbps, 500KB"
                  />
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
