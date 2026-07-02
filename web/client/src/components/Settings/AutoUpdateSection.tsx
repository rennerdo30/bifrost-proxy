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
        {/* The client daemon does not yet run a background update checker, so
            these values are persisted but currently have no runtime effect.
            Keep this notice honest until the daemon wires up the updater. */}
        <div className="rounded-md border border-bifrost-warning/30 bg-bifrost-warning/10 px-3 py-2 text-sm text-bifrost-warning">
          Automatic update checks are not yet performed by the client daemon.
          These settings are saved but currently have no runtime effect.
        </div>
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
