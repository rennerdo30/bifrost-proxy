import {
  FormInput,
  FormNumber,
  FormToggle,
  FormPassword,
  ConfigSection,
} from '../form'
import { WebIcon } from '../icons'
import { useSettings } from './SettingsContext'

export function WebUISection() {
  const { getValue, updateField } = useSettings()

  return (
    <ConfigSection
      title="Web UI & API"
      icon={<WebIcon />}
      description="Web dashboard and API settings"
      restartRequired
      defaultOpen={false}
    >
      <div className="space-y-6">
        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Web UI</h4>
          <div className="space-y-4">
            <FormToggle
              label="Enable Web UI"
              checked={getValue('web_ui', 'enabled', true) as boolean}
              onChange={(v) => updateField('web_ui', 'enabled', v)}
            />
            <FormInput
              label="Listen Address"
              placeholder="127.0.0.1:3129"
              value={getValue('web_ui', 'listen', '127.0.0.1:3129') as string}
              onChange={(v) => updateField('web_ui', 'listen', v)}
            />
          </div>
        </div>
        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">API</h4>
          <div className="space-y-4">
            <FormToggle
              label="Enable API"
              checked={getValue('api', 'enabled', true) as boolean}
              onChange={(v) => updateField('api', 'enabled', v)}
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormInput
                label="Listen Address"
                placeholder="127.0.0.1:7383"
                value={getValue('api', 'listen', '127.0.0.1:7383') as string}
                onChange={(v) => updateField('api', 'listen', v)}
              />
              <FormPassword
                label="API Token"
                description="Leave empty for no authentication"
                placeholder="Optional"
                value={getValue('api', 'token', '') as string}
                onChange={(v) => updateField('api', 'token', v)}
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormToggle
                label="Enable Request Logging"
                checked={getValue('api', 'enable_request_log', false) as boolean}
                onChange={(v) => updateField('api', 'enable_request_log', v)}
              />
              <FormNumber
                label="Request Log Size"
                value={getValue('api', 'request_log_size', 1000) as number}
                onChange={(v) => updateField('api', 'request_log_size', v)}
                min={0}
              />
              <FormNumber
                label="Max WebSocket Clients"
                value={getValue('api', 'websocket_max_clients', 100) as number}
                onChange={(v) => updateField('api', 'websocket_max_clients', v)}
                min={1}
              />
            </div>
          </div>
        </div>
      </div>
    </ConfigSection>
  )
}
