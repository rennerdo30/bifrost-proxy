import { ArrayInput } from '../ArrayInput'
import { ProtonVPNBackendConfig } from '../../../api/types'

interface ProtonVPNBackendFormProps {
  config: ProtonVPNBackendConfig
  onChange: (config: ProtonVPNBackendConfig) => void
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

// ProtonVPN tiers
const TIERS = [
  { value: 0, label: 'Free', description: 'Free servers only' },
  { value: 1, label: 'Basic', description: 'Basic servers' },
  { value: 2, label: 'Plus', description: 'Plus and Visionary servers' },
]

// ProtonVPN features
const FEATURES = [
  'p2p',
  'streaming',
  'tor',
]

export function ProtonVPNBackendForm({ config, onChange }: ProtonVPNBackendFormProps) {
  const update = <K extends keyof ProtonVPNBackendConfig>(field: K, value: ProtonVPNBackendConfig[K]) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-bifrost-muted">
        Route traffic through ProtonVPN servers using OpenVPN protocol.
      </p>

      {/* Credentials */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Credentials</h4>
        <div className="bg-bifrost-bg-tertiary rounded-lg p-3 mb-4">
          <p className="text-xs text-yellow-400">
            Important: Use your ProtonVPN OpenVPN credentials, not your Proton account password.
            Generate these from the ProtonVPN dashboard under Account &gt; OpenVPN / IKEv2 username.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">OpenVPN Username</label>
            <input
              type="text"
              value={config.username || ''}
              onChange={(e) => update('username', e.target.value || undefined)}
              placeholder="ProtonVPN OpenVPN username"
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">OpenVPN Password</label>
            <input
              type="password"
              value={config.password || ''}
              onChange={(e) => update('password', e.target.value || undefined)}
              placeholder="ProtonVPN OpenVPN password"
              autoComplete="off"
              className="input"
            />
          </div>
        </div>
      </div>

      {/* Subscription Tier */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Subscription Tier</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {TIERS.map((tier) => (
            <label
              key={tier.value}
              className={`flex flex-col p-4 rounded-lg border cursor-pointer transition-colors ${
                config.tier === tier.value
                  ? 'border-bifrost-purple bg-bifrost-purple/10'
                  : 'border-bifrost-border bg-bifrost-bg-tertiary hover:border-bifrost-muted'
              }`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name="protonTier"
                  checked={config.tier === tier.value}
                  onChange={() => update('tier', tier.value)}
                  className="form-radio text-bifrost-purple"
                />
                <span className="text-sm font-medium text-white">{tier.label}</span>
              </div>
              <p className="text-xs text-bifrost-muted mt-1 ml-6">{tier.description}</p>
            </label>
          ))}
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

      {/* Secure Core */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Security Features</h4>
        <div className="space-y-3">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.secure_core === true}
              onChange={(e) => update('secure_core', e.target.checked)}
              className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
              disabled={(config.tier ?? 0) < 2}
            />
            <div>
              <span className={`text-sm font-medium ${(config.tier ?? 0) < 2 ? 'text-gray-500' : 'text-gray-300'}`}>
                Secure Core
              </span>
              <p className="text-xs text-bifrost-muted">
                Route through privacy-friendly countries first (Plus tier required)
              </p>
            </div>
          </label>
        </div>
      </div>

      {/* Protocol Info */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Protocol</h4>
        <div className="bg-bifrost-bg-tertiary rounded-lg p-3">
          <p className="text-sm text-gray-300">OpenVPN (UDP)</p>
          <p className="text-xs text-bifrost-muted mt-1">
            ProtonVPN backend uses OpenVPN protocol for maximum compatibility
          </p>
        </div>
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
              placeholder="p2p, streaming, tor..."
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
