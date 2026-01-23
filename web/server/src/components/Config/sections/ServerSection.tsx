import { Section } from '../Section'
import type { ServerSettings, TLSConfig } from '../../../api/types'

interface ServerSectionProps {
  config: ServerSettings
  onChange: (config: ServerSettings) => void
}

export function ServerSection({ config, onChange }: ServerSectionProps) {
  const updateHTTP = (field: string, value: unknown) => {
    onChange({
      ...config,
      http: { ...(config.http || {}), [field]: value },
    })
  }

  const updateSOCKS5 = (field: string, value: unknown) => {
    onChange({
      ...config,
      socks5: { ...(config.socks5 || {}), [field]: value },
    })
  }

  const updateHTTPTLS = (tls: TLSConfig | undefined) => {
    onChange({
      ...config,
      http: { ...(config.http || {}), tls },
    })
  }

  const toggleHTTPTLS = (enabled: boolean) => {
    if (enabled) {
      updateHTTPTLS({ enabled: true, cert_file: '', key_file: '' })
    } else {
      updateHTTPTLS(undefined)
    }
  }

  return (
    <Section title="Server Settings" badge="restart-required">
      <div className="space-y-6">
        {/* HTTP Listener */}
        <div>
          <h4 className="text-sm font-semibold text-white mb-3">HTTP Proxy</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Listen Address</label>
              <input
                type="text"
                value={config.http?.listen || ''}
                onChange={(e) => updateHTTP('listen', e.target.value)}
                placeholder=":8080"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Read Timeout</label>
              <input
                type="text"
                value={config.http?.read_timeout || ''}
                onChange={(e) => updateHTTP('read_timeout', e.target.value)}
                placeholder="30s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Write Timeout</label>
              <input
                type="text"
                value={config.http?.write_timeout || ''}
                onChange={(e) => updateHTTP('write_timeout', e.target.value)}
                placeholder="30s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Idle Timeout</label>
              <input
                type="text"
                value={config.http?.idle_timeout || ''}
                onChange={(e) => updateHTTP('idle_timeout', e.target.value)}
                placeholder="60s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Max Connections</label>
              <input
                type="number"
                value={config.http?.max_connections || 0}
                onChange={(e) => updateHTTP('max_connections', parseInt(e.target.value))}
                placeholder="0 (unlimited)"
                className="input"
              />
            </div>
          </div>

          {/* TLS */}
          <div className="mt-4 p-4 bg-bifrost-bg rounded-lg">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.http?.tls?.enabled || false}
                onChange={(e) => toggleHTTPTLS(e.target.checked)}
                className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
              />
              <span className="text-sm font-medium text-gray-300">Enable TLS</span>
            </label>
            {config.http?.tls?.enabled && (
              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Certificate File</label>
                  <input
                    type="text"
                    value={config.http.tls.cert_file || ''}
                    onChange={(e) => updateHTTPTLS({ ...config.http.tls!, cert_file: e.target.value })}
                    placeholder="/path/to/cert.pem"
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Key File</label>
                  <input
                    type="text"
                    value={config.http.tls.key_file || ''}
                    onChange={(e) => updateHTTPTLS({ ...config.http.tls!, key_file: e.target.value })}
                    placeholder="/path/to/key.pem"
                    className="input"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* SOCKS5 Listener */}
        <div>
          <h4 className="text-sm font-semibold text-white mb-3">SOCKS5 Proxy</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Listen Address</label>
              <input
                type="text"
                value={config.socks5?.listen || ''}
                onChange={(e) => updateSOCKS5('listen', e.target.value)}
                placeholder=":1080"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Read Timeout</label>
              <input
                type="text"
                value={config.socks5?.read_timeout || ''}
                onChange={(e) => updateSOCKS5('read_timeout', e.target.value)}
                placeholder="30s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Write Timeout</label>
              <input
                type="text"
                value={config.socks5?.write_timeout || ''}
                onChange={(e) => updateSOCKS5('write_timeout', e.target.value)}
                placeholder="30s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Idle Timeout</label>
              <input
                type="text"
                value={config.socks5?.idle_timeout || ''}
                onChange={(e) => updateSOCKS5('idle_timeout', e.target.value)}
                placeholder="60s"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Max Connections</label>
              <input
                type="number"
                value={config.socks5?.max_connections || 0}
                onChange={(e) => updateSOCKS5('max_connections', parseInt(e.target.value))}
                placeholder="0 (unlimited)"
                className="input"
              />
            </div>
          </div>

          {/* SOCKS5 TLS */}
          <div className="mt-4 p-4 bg-bifrost-bg rounded-lg">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.socks5?.tls?.enabled || false}
                onChange={(e) => {
                  const tls = e.target.checked
                    ? { enabled: true, cert_file: '', key_file: '' }
                    : undefined
                  onChange({
                    ...config,
                    socks5: { ...(config.socks5 || {}), tls },
                  })
                }}
                className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
              />
              <span className="text-sm font-medium text-gray-300">Enable TLS for SOCKS5</span>
            </label>
            {config.socks5?.tls?.enabled && (
              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Certificate File</label>
                  <input
                    type="text"
                    value={config.socks5.tls.cert_file || ''}
                    onChange={(e) =>
                      onChange({
                        ...config,
                        socks5: {
                          ...(config.socks5 || {}),
                          tls: { ...config.socks5.tls!, cert_file: e.target.value },
                        },
                      })
                    }
                    placeholder="/path/to/cert.pem"
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-1">Key File</label>
                  <input
                    type="text"
                    value={config.socks5.tls.key_file || ''}
                    onChange={(e) =>
                      onChange({
                        ...config,
                        socks5: {
                          ...(config.socks5 || {}),
                          tls: { ...config.socks5.tls!, key_file: e.target.value },
                        },
                      })
                    }
                    placeholder="/path/to/key.pem"
                    className="input"
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Graceful Period */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Graceful Shutdown Period</label>
          <input
            type="text"
            value={config.graceful_period || ''}
            onChange={(e) => onChange({ ...config, graceful_period: e.target.value })}
            placeholder="30s"
            className="input max-w-xs"
          />
          <p className="text-xs text-bifrost-muted mt-1">Time to wait for connections to close during shutdown</p>
        </div>
      </div>
    </Section>
  )
}
