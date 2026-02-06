import {
  FormInput,
  FormNumber,
  FormSelect,
  FormPassword,
  FormDuration,
  ConfigSection,
} from '../form'
import { ServerIcon } from '../icons'
import { useSettings } from './SettingsContext'

export function ServerSection() {
  const { getValue, getNestedValue, updateField, updateNestedField } = useSettings()

  return (
    <ConfigSection
      title="Bifrost Server"
      icon={<ServerIcon />}
      description="Connect to your Bifrost server to route traffic securely"
    >
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <FormInput
          label="Server Address"
          description="Your Bifrost server address and port"
          placeholder="bifrost.example.com:8080"
          value={getValue('server', 'address', '') as string}
          onChange={(v) => updateField('server', 'address', v)}
        />
        <FormSelect
          label="Connection Protocol"
          value={getValue('server', 'protocol', 'http') as string}
          onChange={(v) => updateField('server', 'protocol', v)}
          options={[
            { value: 'http', label: 'HTTP' },
            { value: 'socks5', label: 'SOCKS5' },
          ]}
        />
        <FormInput
          label="Username"
          placeholder="Optional"
          value={getValue('server', 'username', '') as string}
          onChange={(v) => updateField('server', 'username', v)}
        />
        <FormPassword
          label="Password"
          placeholder="Optional"
          value={getValue('server', 'password', '') as string}
          onChange={(v) => updateField('server', 'password', v)}
        />
        <FormDuration
          label="Timeout"
          description="Connection timeout"
          value={getValue('server', 'timeout', '30s') as string}
          onChange={(v) => updateField('server', 'timeout', v)}
        />
        <FormNumber
          label="Retry Count"
          value={getValue('server', 'retry_count', 3) as number}
          onChange={(v) => updateField('server', 'retry_count', v)}
          min={0}
          max={10}
        />
        <FormDuration
          label="Retry Delay"
          value={getValue('server', 'retry_delay', '1s') as string}
          onChange={(v) => updateField('server', 'retry_delay', v)}
        />
      </div>

      <div className="mt-4 border-t border-bifrost-border pt-4">
        <h4 className="text-sm font-medium text-bifrost-text mb-3">Health Check</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormSelect
            label="Type"
            value={getNestedValue('server', ['health_check', 'type'], 'tcp') as string}
            onChange={(v) => updateNestedField('server', ['health_check', 'type'], v)}
            options={[
              { value: 'tcp', label: 'TCP' },
              { value: 'http', label: 'HTTP' },
              { value: 'ping', label: 'Ping' },
            ]}
          />
          <FormDuration
            label="Interval"
            value={getNestedValue('server', ['health_check', 'interval'], '30s') as string}
            onChange={(v) => updateNestedField('server', ['health_check', 'interval'], v)}
          />
          <FormDuration
            label="Timeout"
            value={getNestedValue('server', ['health_check', 'timeout'], '5s') as string}
            onChange={(v) => updateNestedField('server', ['health_check', 'timeout'], v)}
          />
          <FormInput
            label="Target"
            placeholder="e.g., google.com:80"
            value={getNestedValue('server', ['health_check', 'target'], '') as string}
            onChange={(v) => updateNestedField('server', ['health_check', 'target'], v)}
          />
        </div>
      </div>
    </ConfigSection>
  )
}
