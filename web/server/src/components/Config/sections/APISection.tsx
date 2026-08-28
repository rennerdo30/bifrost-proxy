import { useEffect, useState } from 'react'
import { Section } from '../Section'
import { ValidatedInput } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { APIConfig } from '../../../api/types'

interface APISectionProps {
  config: APIConfig
  onChange: (config: APIConfig) => void
}

type APIValidationKeys = {
  listen: string
  websocket_max_clients: number
  request_log_size: number
}

const parseOrigins = (text: string): string[] =>
  text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)

export function APISection({ config, onChange }: APISectionProps) {
  const [showToken, setShowToken] = useState(false)

  // The textarea keeps its own raw text so Enter (a momentarily empty line)
  // is not stripped by the parser on every keystroke. The parsed list is
  // pushed to the config on change; external config changes (discard,
  // reload) resync the text when their parsed content actually differs.
  const [originsText, setOriginsText] = useState(() => (config.allowed_origins || []).join('\n'))
  useEffect(() => {
    setOriginsText((current) => {
      const fromConfig = (config.allowed_origins || []).join('\n')
      return parseOrigins(current).join('\n') === fromConfig ? current : fromConfig
    })
  }, [config.allowed_origins])

  const { errors, handleFieldChange } = useValidation<APIValidationKeys>({
    listen: [validators.listenAddress()],
    websocket_max_clients: [validators.positiveInteger(), validators.min(1, 'Must be at least 1')],
    request_log_size: [validators.positiveInteger()],
  })

  const update = (field: string, value: unknown) => {
    if (field in errors || field === 'listen' || field === 'websocket_max_clients' || field === 'request_log_size') {
      handleFieldChange(field as keyof APIValidationKeys, value as never)
    }
    onChange({ ...config, [field]: value })
  }

  return (
    <Section sectionKey="api" title="REST API">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-bifrost-text">Enable REST API</span>
        </label>

        {config.enabled && (
          <div className="space-y-4 pl-7">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ValidatedInput
                label="Listen Address"
                value={config.listen || ''}
                onChange={(e) => update('listen', e.target.value)}
                placeholder=":8082"
                error={errors.listen}
                helpText="Format: :port or host:port"
              />
              <div>
                <label className="block text-sm font-medium text-bifrost-text mb-1">API Token</label>
                <div className="relative">
                  <input
                    type={showToken ? 'text' : 'password'}
                    value={config.token || ''}
                    onChange={(e) => update('token', e.target.value)}
                    placeholder="Optional authentication token"
                    autoComplete="off"
                    className="input pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-bifrost-heading"
                    aria-label={showToken ? 'Hide token' : 'Show token'}
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
              <ValidatedInput
                label="WebSocket Max Clients"
                type="number"
                value={config.websocket_max_clients || 100}
                onChange={(e) => update('websocket_max_clients', parseInt(e.target.value) || 100)}
                error={errors.websocket_max_clients}
                helpText="Maximum concurrent WebSocket connections"
              />
            </div>

            <div className="p-4 bg-bifrost-bg rounded-lg space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.enable_request_log ?? true}
                  onChange={(e) => update('enable_request_log', e.target.checked)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm font-medium text-bifrost-text">Enable Request Log (for Web UI)</span>
              </label>
              {config.enable_request_log !== false && (
                <div className="pl-7">
                  <ValidatedInput
                    label="Max Requests to Keep"
                    type="number"
                    value={config.request_log_size || 1000}
                    onChange={(e) => update('request_log_size', parseInt(e.target.value) || 0)}
                    className="max-w-xs"
                    error={errors.request_log_size}
                    helpText="Number of recent requests to store in memory"
                  />
                </div>
              )}
            </div>

            <div className="p-4 bg-bifrost-bg rounded-lg space-y-2">
              <label htmlFor="api-allowed-origins" className="block text-sm font-medium text-bifrost-text">
                WebSocket Allowed Origins
              </label>
              <textarea
                id="api-allowed-origins"
                rows={3}
                value={originsText}
                onChange={(e) => {
                  setOriginsText(e.target.value)
                  update('allowed_origins', parseOrigins(e.target.value))
                }}
                placeholder={'https://bifrost.example.com\nhomeassistant.local:8123'}
                spellCheck={false}
                className="input font-mono text-sm"
              />
              <p className="text-xs text-bifrost-muted">
                One origin per line. Only needed when a reverse proxy rewrites <code className="font-mono">Host</code>{' '}
                (Home Assistant Ingress, Traefik, nginx) — this server&apos;s own address is always allowed. Include the
                port if the browser URL shows one. A single <code className="font-mono">*</code> disables the origin
                check for the live event stream. Requires a restart.
              </p>
              {(config.allowed_origins || []).includes('*') && (
                <p className="text-xs text-bifrost-warning" role="alert">
                  Origin checking is disabled. Any web page opened in a browser that can reach this server may connect
                  to the event stream and read live traffic. Prefer naming the real origins.
                </p>
              )}
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
