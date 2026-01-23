import { useState } from 'react'
import { ArrayInput } from '../ArrayInput'
import { MullvadBackendConfig } from '../../../api/types'

interface MullvadBackendFormProps {
  config: MullvadBackendConfig
  onChange: (config: MullvadBackendConfig) => void
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

// Mullvad features
const FEATURES = [
  'ownership_mullvad',
  'ownership_rented',
  'openvpn_tcp',
  'openvpn_udp',
]

export function MullvadBackendForm({ config, onChange }: MullvadBackendFormProps) {
  const [protocol, setProtocol] = useState<'wireguard' | 'openvpn'>(config.protocol || 'wireguard')

  const update = <K extends keyof MullvadBackendConfig>(field: K, value: MullvadBackendConfig[K]) => {
    onChange({ ...config, [field]: value })
  }

  const handleProtocolChange = (newProtocol: 'wireguard' | 'openvpn') => {
    setProtocol(newProtocol)
    update('protocol', newProtocol)
  }

  // Validate account ID format (16 digits)
  const validateAccountId = (value: string): boolean => {
    return /^\d{0,16}$/.test(value.replace(/\s/g, ''))
  }

  const formatAccountId = (value: string): string => {
    // Remove all non-digits and spaces
    const digits = value.replace(/\D/g, '').slice(0, 16)
    // Format as groups of 4
    return digits.match(/.{1,4}/g)?.join(' ') || digits
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-bifrost-muted">
        Route traffic through Mullvad VPN servers. Anonymous account-based authentication.
      </p>

      {/* Account ID */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Account</h4>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Account ID</label>
          <input
            type="text"
            value={formatAccountId(config.account_id || '')}
            onChange={(e) => {
              const raw = e.target.value.replace(/\s/g, '')
              if (validateAccountId(raw)) {
                update('account_id', raw)
              }
            }}
            placeholder="1234 5678 9012 3456"
            className="input font-mono tracking-wider"
            maxLength={19} // 16 digits + 3 spaces
          />
          <p className="text-xs text-bifrost-muted mt-1">
            16-digit Mullvad account number
          </p>
        </div>
      </div>

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
        <div className="flex gap-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="mullvadProtocol"
              checked={protocol === 'wireguard'}
              onChange={() => handleProtocolChange('wireguard')}
              className="form-radio text-bifrost-purple"
            />
            <span className="text-sm text-gray-300">WireGuard (Recommended)</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="mullvadProtocol"
              checked={protocol === 'openvpn'}
              onChange={() => handleProtocolChange('openvpn')}
              className="form-radio text-bifrost-purple"
            />
            <span className="text-sm text-gray-300">OpenVPN</span>
          </label>
        </div>
        <p className="text-xs text-bifrost-muted mt-2">
          {protocol === 'wireguard'
            ? 'WireGuard offers better performance and modern encryption'
            : 'OpenVPN is available for legacy compatibility'}
        </p>
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
              placeholder="ownership_mullvad, openvpn_tcp..."
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
