import { Section } from '../Section'
import { ValidatedInput } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { ServerSettings, TLSConfig } from '../../../api/types'

interface ServerSectionProps {
  config: ServerSettings
  onChange: (config: ServerSettings) => void
}

// Flat keys for validation - using dot notation for nested fields
type ServerValidationKeys = {
  'http.listen': string
  'http.read_timeout': string
  'http.write_timeout': string
  'http.idle_timeout': string
  'http.max_connections': number
  'http.tls.cert_file': string
  'http.tls.key_file': string
  'socks5.listen': string
  'socks5.read_timeout': string
  'socks5.write_timeout': string
  'socks5.idle_timeout': string
  'socks5.max_connections': number
  'socks5.tls.cert_file': string
  'socks5.tls.key_file': string
  'graceful_period': string
}

export function ServerSection({ config, onChange }: ServerSectionProps) {
  const { errors, handleFieldChange } = useValidation<ServerValidationKeys>({
    'http.listen': [validators.listenAddress()],
    'http.read_timeout': [validators.duration()],
    'http.write_timeout': [validators.duration()],
    'http.idle_timeout': [validators.duration()],
    'http.max_connections': [validators.positiveInteger()],
    'http.tls.cert_file': [validators.filePath()],
    'http.tls.key_file': [validators.filePath()],
    'socks5.listen': [validators.listenAddress()],
    'socks5.read_timeout': [validators.duration()],
    'socks5.write_timeout': [validators.duration()],
    'socks5.idle_timeout': [validators.duration()],
    'socks5.max_connections': [validators.positiveInteger()],
    'socks5.tls.cert_file': [validators.filePath()],
    'socks5.tls.key_file': [validators.filePath()],
    'graceful_period': [validators.duration()],
  })

  const updateHTTP = (field: string, value: unknown) => {
    handleFieldChange(`http.${field}` as keyof ServerValidationKeys, value as never)
    onChange({
      ...config,
      http: { ...(config.http || {}), [field]: value },
    })
  }

  const updateSOCKS5 = (field: string, value: unknown) => {
    handleFieldChange(`socks5.${field}` as keyof ServerValidationKeys, value as never)
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

  const handleGracefulPeriodChange = (value: string) => {
    handleFieldChange('graceful_period', value)
    onChange({ ...config, graceful_period: value })
  }

  return (
    <Section title="Server Settings" badge="restart-required">
      <div className="space-y-6">
        {/* HTTP Listener */}
        <div>
          <h4 className="text-sm font-semibold text-white mb-3">HTTP Proxy</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ValidatedInput
              label="Listen Address"
              value={config.http?.listen || ''}
              onChange={(e) => updateHTTP('listen', e.target.value)}
              placeholder=":8080"
              error={errors['http.listen']}
              helpText="Format: :port or host:port"
            />
            <ValidatedInput
              label="Read Timeout"
              value={config.http?.read_timeout || ''}
              onChange={(e) => updateHTTP('read_timeout', e.target.value)}
              placeholder="30s"
              error={errors['http.read_timeout']}
              helpText="e.g., 30s, 1m, 1h30m"
            />
            <ValidatedInput
              label="Write Timeout"
              value={config.http?.write_timeout || ''}
              onChange={(e) => updateHTTP('write_timeout', e.target.value)}
              placeholder="30s"
              error={errors['http.write_timeout']}
            />
            <ValidatedInput
              label="Idle Timeout"
              value={config.http?.idle_timeout || ''}
              onChange={(e) => updateHTTP('idle_timeout', e.target.value)}
              placeholder="60s"
              error={errors['http.idle_timeout']}
            />
            <ValidatedInput
              label="Max Connections"
              type="number"
              value={config.http?.max_connections || 0}
              onChange={(e) => updateHTTP('max_connections', parseInt(e.target.value) || 0)}
              placeholder="0 (unlimited)"
              error={errors['http.max_connections']}
              helpText="0 for unlimited"
            />
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
                <ValidatedInput
                  label="Certificate File"
                  value={config.http.tls.cert_file || ''}
                  onChange={(e) => {
                    handleFieldChange('http.tls.cert_file', e.target.value)
                    updateHTTPTLS({ ...config.http.tls!, cert_file: e.target.value })
                  }}
                  placeholder="/path/to/cert.pem"
                  error={errors['http.tls.cert_file']}
                />
                <ValidatedInput
                  label="Key File"
                  value={config.http.tls.key_file || ''}
                  onChange={(e) => {
                    handleFieldChange('http.tls.key_file', e.target.value)
                    updateHTTPTLS({ ...config.http.tls!, key_file: e.target.value })
                  }}
                  placeholder="/path/to/key.pem"
                  error={errors['http.tls.key_file']}
                />
              </div>
            )}
          </div>
        </div>

        {/* SOCKS5 Listener */}
        <div>
          <h4 className="text-sm font-semibold text-white mb-3">SOCKS5 Proxy</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ValidatedInput
              label="Listen Address"
              value={config.socks5?.listen || ''}
              onChange={(e) => updateSOCKS5('listen', e.target.value)}
              placeholder=":1080"
              error={errors['socks5.listen']}
              helpText="Format: :port or host:port"
            />
            <ValidatedInput
              label="Read Timeout"
              value={config.socks5?.read_timeout || ''}
              onChange={(e) => updateSOCKS5('read_timeout', e.target.value)}
              placeholder="30s"
              error={errors['socks5.read_timeout']}
            />
            <ValidatedInput
              label="Write Timeout"
              value={config.socks5?.write_timeout || ''}
              onChange={(e) => updateSOCKS5('write_timeout', e.target.value)}
              placeholder="30s"
              error={errors['socks5.write_timeout']}
            />
            <ValidatedInput
              label="Idle Timeout"
              value={config.socks5?.idle_timeout || ''}
              onChange={(e) => updateSOCKS5('idle_timeout', e.target.value)}
              placeholder="60s"
              error={errors['socks5.idle_timeout']}
            />
            <ValidatedInput
              label="Max Connections"
              type="number"
              value={config.socks5?.max_connections || 0}
              onChange={(e) => updateSOCKS5('max_connections', parseInt(e.target.value) || 0)}
              placeholder="0 (unlimited)"
              error={errors['socks5.max_connections']}
              helpText="0 for unlimited"
            />
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
                <ValidatedInput
                  label="Certificate File"
                  value={config.socks5.tls.cert_file || ''}
                  onChange={(e) => {
                    handleFieldChange('socks5.tls.cert_file', e.target.value)
                    onChange({
                      ...config,
                      socks5: {
                        ...(config.socks5 || {}),
                        tls: { ...config.socks5.tls!, cert_file: e.target.value },
                      },
                    })
                  }}
                  placeholder="/path/to/cert.pem"
                  error={errors['socks5.tls.cert_file']}
                />
                <ValidatedInput
                  label="Key File"
                  value={config.socks5.tls.key_file || ''}
                  onChange={(e) => {
                    handleFieldChange('socks5.tls.key_file', e.target.value)
                    onChange({
                      ...config,
                      socks5: {
                        ...(config.socks5 || {}),
                        tls: { ...config.socks5.tls!, key_file: e.target.value },
                      },
                    })
                  }}
                  placeholder="/path/to/key.pem"
                  error={errors['socks5.tls.key_file']}
                />
              </div>
            )}
          </div>
        </div>

        {/* Graceful Period */}
        <ValidatedInput
          label="Graceful Shutdown Period"
          value={config.graceful_period || ''}
          onChange={(e) => handleGracefulPeriodChange(e.target.value)}
          placeholder="30s"
          className="max-w-xs"
          error={errors['graceful_period']}
          helpText="Time to wait for connections to close during shutdown"
        />
      </div>
    </Section>
  )
}
