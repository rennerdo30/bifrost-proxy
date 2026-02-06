import {
  FormToggle,
  FormDuration,
  FormSelect,
  ConfigSection,
} from '../form'
import { UpdateIcon } from '../icons'
import { useSettings } from './SettingsContext'

export function AutoUpdateSection() {
  const { getValue, updateField } = useSettings()

  return (
    <ConfigSection
      title="Auto-Update"
      icon={<UpdateIcon />}
      description="Automatic update settings"
      defaultOpen={false}
    >
      <div className="space-y-4">
        <FormToggle
          label="Enable Auto-Update"
          description="Automatically check for and install updates"
          checked={getValue('auto_update', 'enabled', false) as boolean}
          onChange={(v) => updateField('auto_update', 'enabled', v)}
        />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormDuration
            label="Check Interval"
            value={getValue('auto_update', 'check_interval', '24h') as string}
            onChange={(v) => updateField('auto_update', 'check_interval', v)}
          />
          <FormSelect
            label="Update Channel"
            value={getValue('auto_update', 'channel', 'stable') as string}
            onChange={(v) => updateField('auto_update', 'channel', v)}
            options={[
              { value: 'stable', label: 'Stable' },
              { value: 'beta', label: 'Beta' },
              { value: 'nightly', label: 'Nightly' },
            ]}
          />
        </div>
      </div>
    </ConfigSection>
  )
}
