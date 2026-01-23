import { useState } from 'react'
import { SOCKS5ProxyBackendConfig } from '../../../api/types'

interface SOCKS5ProxyBackendFormProps {
  config: SOCKS5ProxyBackendConfig
  onChange: (config: SOCKS5ProxyBackendConfig) => void
}

export function SOCKS5ProxyBackendForm({ config, onChange }: SOCKS5ProxyBackendFormProps) {
  const [showPassword, setShowPassword] = useState(false)

  const update = <K extends keyof SOCKS5ProxyBackendConfig>(field: K, value: SOCKS5ProxyBackendConfig[K]) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Route traffic through an upstream SOCKS5 proxy.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-300 mb-1">Proxy Address</label>
          <input
            type="text"
            value={config.address || ''}
            onChange={(e) => update('address', e.target.value)}
            placeholder="socks.example.com:1080"
            className="input"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
          <input
            type="text"
            value={config.username || ''}
            onChange={(e) => update('username', e.target.value)}
            placeholder="Optional"
            className="input"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              value={config.password || ''}
              onChange={(e) => update('password', e.target.value)}
              placeholder="Optional"
              className="input pr-10"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-white"
            >
              {showPassword ? (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              )}
            </button>
          </div>
        </div>
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
      </div>
    </div>
  )
}
