import { useState } from 'react'
import { ArrayInput } from '../ArrayInput'
import { NordVPNBackendConfig } from '../../../api/types'

interface NordVPNBackendFormProps {
  config: NordVPNBackendConfig
  onChange: (config: NordVPNBackendConfig) => void
}

// Common VPN countries
const COUNTRIES = [
  { value: '', label: 'Auto Select' },
  { value: 'us', label: 'United States' },
  { value: 'uk', label: 'United Kingdom' },
  { value: 'de', label: 'Germany' },
  { value: 'nl', label: 'Netherlands' },
  { value: 'ch', label: 'Switzerland' },
  { value: 'ca', label: 'Canada' },
  { value: 'au', label: 'Australia' },
  { value: 'fr', label: 'France' },
  { value: 'se', label: 'Sweden' },
  { value: 'jp', label: 'Japan' },
  { value: 'sg', label: 'Singapore' },
]

// Common NordVPN features
const FEATURES = [
  'p2p',
  'dedicated_ip',
  'double_vpn',
  'onion_over_vpn',
  'obfuscated',
]

export function NordVPNBackendForm({ config, onChange }: NordVPNBackendFormProps) {
  const [protocol, setProtocol] = useState<'wireguard' | 'openvpn'>(config.protocol || 'wireguard')

  const update = <K extends keyof NordVPNBackendConfig>(field: K, value: NordVPNBackendConfig[K]) => {
    onChange({ ...config, [field]: value })
  }

  const handleProtocolChange = (newProtocol: 'wireguard' | 'openvpn') => {
    setProtocol(newProtocol)
    // Clear credentials when switching protocols
    if (newProtocol === 'wireguard') {
      onChange({
        ...config,
        protocol: newProtocol,
        username: undefined,
        password: undefined,
      })
    } else {
      onChange({
        ...config,
        protocol: newProtocol,
        access_token: undefined,
      })
    }
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-bifrost-muted">
        Route traffic through NordVPN servers with automatic server selection.
      </p>

      {/* Server Selection */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Server Selection</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Country</label>
            <select
              value={config.country || ''}
              onChange={(e) => update('country', e.target.value || undefined)}
              className="input"
            >
              {COUNTRIES.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">City</label>
            <input
              type="text"
              value={config.city || ''}
              onChange={(e) => update('city', e.target.value || undefined)}
              placeholder="e.g., New York, London"
              className="input"
            />
            <p className="text-xs text-bifrost-muted mt-1">Optional: specific city</p>
          </div>
          <div>
            <label className="flex items-center gap-3 cursor-pointer mt-6">
              <input
                type="checkbox"
                checked={config.auto_select !== false}
                onChange={(e) => update('auto_select', e.target.checked)}
                className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
              />
              <span className="text-sm font-medium text-gray-300">Auto-select best server</span>
            </label>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Max Server Load (%)</label>
            <input
              type="range"
              min="10"
              max="100"
              step="5"
              value={config.max_load ?? 70}
              onChange={(e) => update('max_load', parseInt(e.target.value))}
              className="w-full h-2 bg-bifrost-bg-tertiary rounded-lg appearance-none cursor-pointer"
            />
            <div className="flex justify-between text-xs text-bifrost-muted mt-1">
              <span>10%</span>
              <span className="font-medium text-white">{config.max_load ?? 70}%</span>
              <span>100%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Protocol Selection */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Protocol</h4>
        <div className="flex gap-4 mb-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="nordProtocol"
              checked={protocol === 'wireguard'}
              onChange={() => handleProtocolChange('wireguard')}
              className="form-radio text-bifrost-purple"
            />
            <span className="text-sm text-gray-300">WireGuard (Recommended)</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="nordProtocol"
              checked={protocol === 'openvpn'}
              onChange={() => handleProtocolChange('openvpn')}
              className="form-radio text-bifrost-purple"
            />
            <span className="text-sm text-gray-300">OpenVPN</span>
          </label>
        </div>

        {/* Credentials based on protocol */}
        {protocol === 'wireguard' ? (
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Access Token (Private Key)</label>
            <textarea
              value={config.access_token || ''}
              onChange={(e) => update('access_token', e.target.value || undefined)}
              placeholder="Generate from NordVPN dashboard"
              rows={2}
              className="input font-mono text-xs"
              autoComplete="off"
            />
            <p className="text-xs text-bifrost-muted mt-1">
              Get your WireGuard private key from the NordVPN dashboard
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
              <input
                type="text"
                value={config.username || ''}
                onChange={(e) => update('username', e.target.value || undefined)}
                placeholder="NordVPN service username"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
              <input
                type="password"
                value={config.password || ''}
                onChange={(e) => update('password', e.target.value || undefined)}
                placeholder="NordVPN service password"
                autoComplete="off"
                className="input"
              />
            </div>
            <p className="md:col-span-2 text-xs text-bifrost-muted">
              Use your NordVPN service credentials (not your account login)
            </p>
          </div>
        )}
      </div>

      {/* Advanced Settings */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Advanced Settings</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Refresh Interval</label>
            <input
              type="text"
              value={config.refresh_interval || ''}
              onChange={(e) => update('refresh_interval', e.target.value || undefined)}
              placeholder="5m (default)"
              className="input"
            />
            <p className="text-xs text-bifrost-muted mt-1">How often to refresh server list</p>
          </div>
          <div className="md:col-span-2">
            <ArrayInput
              label="Features"
              values={config.features ?? []}
              onChange={(features) => update('features', features)}
              placeholder="p2p, dedicated_ip, double_vpn..."
            />
            <p className="text-xs text-bifrost-muted mt-1">
              Available: {FEATURES.join(', ')}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
