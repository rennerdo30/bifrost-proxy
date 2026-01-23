import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { AutoUpdateConfig } from '../../../api/types'

interface AutoUpdateSectionProps {
  config: AutoUpdateConfig
  onChange: (config: AutoUpdateConfig) => void
}

type AutoUpdateValidationKeys = {
  check_interval: string
}

export function AutoUpdateSection({ config, onChange }: AutoUpdateSectionProps) {
  const { errors, handleFieldChange } = useValidation<AutoUpdateValidationKeys>({
    check_interval: [validators.duration()],
  })

  const update = (field: string, value: unknown) => {
    if (field === 'check_interval') {
      handleFieldChange(field as keyof AutoUpdateValidationKeys, value as never)
    }
    onChange({ ...config, [field]: value })
  }

  return (
    <Section title="Auto Update" badge="restart-required">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable Auto Update</span>
        </label>

        {config.enabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <ValidatedInput
              label="Check Interval"
              value={config.check_interval || ''}
              onChange={(e) => update('check_interval', e.target.value)}
              placeholder="24h"
              error={errors.check_interval}
              helpText="How often to check for updates (e.g., 1h, 24h, 7d)"
            />
            <ValidatedSelect
              label="Channel"
              value={config.channel || 'stable'}
              onChange={(e) => update('channel', e.target.value)}
              helpText="Update channel to follow"
            >
              <option value="stable">Stable</option>
              <option value="prerelease">Pre-release</option>
            </ValidatedSelect>
          </div>
        )}
      </div>
    </Section>
  )
}
