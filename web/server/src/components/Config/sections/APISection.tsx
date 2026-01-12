import { useState } from 'react'
import { Section } from '../Section'
import type { APIConfig } from '../../../api/types'

interface APISectionProps {
  config: APIConfig
  onChange: (config: APIConfig) => void
}

export function APISection({ config, onChange }: APISectionProps) {
  const [showToken, setShowToken] = useState(false)

  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <Section title="REST API" badge="restart-required">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable REST API</span>
        </label>

        {config.enabled && (
          <div className="space-y-4 pl-7">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Listen Address</label>
                <input
                  type="text"
                  value={config.listen || ''}
                  onChange={(e) => update('listen', e.target.value)}
                  placeholder=":8082"
                  className="input"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">API Token</label>
                <div className="relative">
                  <input
                    type={showToken ? 'text' : 'password'}
                    value={config.token || ''}
                    onChange={(e) => update('token', e.target.value)}
                    placeholder="Optional authentication token"
                    className="input pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-white"
                  >
                    {showToken ? (
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
                <p className="text-xs text-bifrost-muted mt-1">Leave empty to disable token auth</p>
              </div>
            </div>

            <div className="p-4 bg-bifrost-bg rounded-lg space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.enable_request_log ?? true}
                  onChange={(e) => update('enable_request_log', e.target.checked)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm font-medium text-gray-300">Enable Request Log (for Web UI)</span>
              </label>
              {config.enable_request_log !== false && (
                <div className="pl-7">
                  <label className="block text-sm font-medium text-gray-300 mb-1">Max Requests to Keep</label>
                  <input
                    type="number"
                    value={config.request_log_size || 1000}
                    onChange={(e) => update('request_log_size', parseInt(e.target.value))}
                    className="input max-w-xs"
                  />
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
