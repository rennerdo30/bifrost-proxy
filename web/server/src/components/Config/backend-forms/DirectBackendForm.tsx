import { DirectBackendConfig } from '../../../api/types'

interface DirectBackendFormProps {
  config: DirectBackendConfig
  onChange: (config: DirectBackendConfig) => void
}

export function DirectBackendForm({ config, onChange }: DirectBackendFormProps) {
  const update = <K extends keyof DirectBackendConfig>(field: K, value: DirectBackendConfig[K]) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Direct connection to the internet without any proxy.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Connect Timeout</label>
          <input
            type="text"
            value={config.connect_timeout || ''}
            onChange={(e) => update('connect_timeout', e.target.value)}
            placeholder="10s"
            className="input"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Keep Alive</label>
          <input
            type="text"
            value={config.keep_alive || ''}
            onChange={(e) => update('keep_alive', e.target.value)}
            placeholder="30s"
            className="input"
          />
        </div>
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-300 mb-1">Local Address</label>
          <input
            type="text"
            value={config.local_addr || ''}
            onChange={(e) => update('local_addr', e.target.value)}
            placeholder="Optional: bind to specific interface"
            className="input"
          />
        </div>
      </div>
    </div>
  )
}
