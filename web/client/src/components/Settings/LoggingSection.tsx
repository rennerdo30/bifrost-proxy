import {
  FormInput,
  FormSelect,
  ConfigSection,
} from '../form'
import { LogIcon } from '../icons'
import { useSettings } from './SettingsContext'

export function LoggingSection() {
  const { getValue, updateField } = useSettings()

  return (
    <ConfigSection
      title="Logging"
      icon={<LogIcon />}
      description="Application logging settings"
      defaultOpen={false}
    >
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <FormSelect
          label="Log Level"
          value={getValue('logging', 'level', 'info') as string}
          onChange={(v) => updateField('logging', 'level', v)}
          options={[
            { value: 'debug', label: 'Debug' },
            { value: 'info', label: 'Info' },
            { value: 'warn', label: 'Warning' },
            { value: 'error', label: 'Error' },
          ]}
        />
        <FormSelect
          label="Log Format"
          value={getValue('logging', 'format', 'text') as string}
          onChange={(v) => updateField('logging', 'format', v)}
          options={[
            { value: 'text', label: 'Text' },
            { value: 'json', label: 'JSON' },
          ]}
        />
        <FormSelect
          label="Output"
          value={getValue('logging', 'output', 'stderr') as string}
          onChange={(v) => updateField('logging', 'output', v)}
          options={[
            { value: 'stdout', label: 'Stdout' },
            { value: 'stderr', label: 'Stderr' },
            { value: 'file', label: 'File' },
          ]}
        />
        <FormInput
          label="Time Format"
          placeholder="2006-01-02T15:04:05.000Z07:00"
          value={getValue('logging', 'time_format', '') as string}
          onChange={(v) => updateField('logging', 'time_format', v)}
        />
      </div>
    </ConfigSection>
  )
}
