import { useState } from 'react'
import type { ServerConfig } from '../../api/types'

interface ConfigEditorProps {
  config: ServerConfig | undefined
  isLoading: boolean
  onSave: (config: ServerConfig, backup: boolean) => Promise<void>
  onReload: () => Promise<void>
}

interface SectionProps {
  title: string
  description: string
  hotReload?: boolean
  children: React.ReactNode
  defaultOpen?: boolean
}

function Section({ title, description, hotReload, children, defaultOpen = false }: SectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className="border border-bifrost-border rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-4 bg-bifrost-card hover:bg-bifrost-card-hover transition-colors"
      >
        <div className="flex items-center gap-3">
          <svg
            className={`w-5 h-5 text-gray-400 transition-transform ${isOpen ? 'rotate-90' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
          </svg>
          <div className="text-left">
            <h4 className="font-medium text-white">{title}</h4>
            <p className="text-xs text-bifrost-muted">{description}</p>
          </div>
        </div>
        {hotReload !== undefined && (
          <span className={`badge ${hotReload ? 'badge-success' : 'badge-warning'}`}>
            {hotReload ? 'Hot Reload' : 'Restart Required'}
          </span>
        )}
      </button>
      {isOpen && (
        <div className="p-4 bg-bifrost-bg/50 border-t border-bifrost-border">
          {children}
        </div>
      )}
    </div>
  )
}

export function ConfigEditor({ config, isLoading, onSave, onReload }: ConfigEditorProps) {
  const [isSaving, setIsSaving] = useState(false)
  const [createBackup, setCreateBackup] = useState(true)
  const [editedConfig, setEditedConfig] = useState<ServerConfig | null>(null)

  const currentConfig = editedConfig || config

  const handleSave = async () => {
    if (!currentConfig) return
    setIsSaving(true)
    try {
      await onSave(currentConfig, createBackup)
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="card animate-pulse">
            <div className="h-6 bg-bifrost-border rounded w-32 mb-2" />
            <div className="h-4 bg-bifrost-border rounded w-48" />
          </div>
        ))}
      </div>
    )
  }

  if (!config) {
    return (
      <div className="card text-center py-12">
        <p className="text-gray-400">Unable to load configuration</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Server Settings */}
      <Section
        title="Server Settings"
        description="HTTP and SOCKS5 listener configuration"
        hotReload={false}
        defaultOpen
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="label">HTTP Listen Address</label>
            <input
              type="text"
              className="input"
              value={currentConfig?.server?.http_listen || ':8080'}
              onChange={(e) =>
                setEditedConfig({
                  ...currentConfig,
                  server: { ...currentConfig?.server, http_listen: e.target.value },
                })
              }
              placeholder=":8080"
            />
          </div>
          <div>
            <label className="label">SOCKS5 Listen Address</label>
            <input
              type="text"
              className="input"
              value={currentConfig?.server?.socks5_listen || ':1080'}
              onChange={(e) =>
                setEditedConfig({
                  ...currentConfig,
                  server: { ...currentConfig?.server, socks5_listen: e.target.value },
                })
              }
              placeholder=":1080"
            />
          </div>
          <div>
            <label className="label">Connect Timeout</label>
            <input
              type="text"
              className="input"
              value={currentConfig?.server?.connect_timeout || '10s'}
              onChange={(e) =>
                setEditedConfig({
                  ...currentConfig,
                  server: { ...currentConfig?.server, connect_timeout: e.target.value },
                })
              }
              placeholder="10s"
            />
          </div>
          <div>
            <label className="label">Idle Timeout</label>
            <input
              type="text"
              className="input"
              value={currentConfig?.server?.idle_timeout || '60s'}
              onChange={(e) =>
                setEditedConfig({
                  ...currentConfig,
                  server: { ...currentConfig?.server, idle_timeout: e.target.value },
                })
              }
              placeholder="60s"
            />
          </div>
        </div>
      </Section>

      {/* Backends */}
      <Section
        title="Backends"
        description="Proxy backend connections"
        hotReload={false}
      >
        <div className="space-y-3">
          {currentConfig?.backends?.map((backend, index) => (
            <div
              key={index}
              className="p-3 bg-bifrost-card rounded-lg border border-bifrost-border"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-white">{backend.name}</span>
                <span className="badge badge-info">{backend.type}</span>
              </div>
              {backend.address && (
                <p className="text-sm text-bifrost-muted">Address: {backend.address}</p>
              )}
            </div>
          )) || <p className="text-bifrost-muted">No backends configured</p>}
        </div>
      </Section>

      {/* Routes */}
      <Section
        title="Routes"
        description="Domain routing rules"
        hotReload={true}
      >
        <div className="space-y-2">
          {currentConfig?.routes?.map((route, index) => (
            <div
              key={index}
              className="flex items-center justify-between p-2 bg-bifrost-card rounded"
            >
              <code className="text-sm text-gray-300">{route.pattern}</code>
              <span className="text-sm text-bifrost-accent">{route.backend}</span>
            </div>
          )) || <p className="text-bifrost-muted">No routes configured</p>}
        </div>
      </Section>

      {/* Rate Limiting */}
      <Section
        title="Rate Limiting"
        description="Request rate limiting settings"
        hotReload={true}
      >
        <div className="space-y-4">
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={currentConfig?.rate_limit?.enabled || false}
              onChange={(e) =>
                setEditedConfig({
                  ...currentConfig,
                  rate_limit: { ...currentConfig?.rate_limit, enabled: e.target.checked },
                })
              }
              className="rounded border-bifrost-border bg-bifrost-bg"
            />
            <span className="text-gray-300">Enable rate limiting</span>
          </label>
          {currentConfig?.rate_limit?.enabled && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="label">Requests per Second</label>
                <input
                  type="number"
                  className="input"
                  value={currentConfig?.rate_limit?.requests_per_second || 100}
                  onChange={(e) =>
                    setEditedConfig({
                      ...currentConfig,
                      rate_limit: {
                        ...currentConfig?.rate_limit,
                        enabled: true,
                        requests_per_second: Number(e.target.value),
                      },
                    })
                  }
                />
              </div>
              <div>
                <label className="label">Burst</label>
                <input
                  type="number"
                  className="input"
                  value={currentConfig?.rate_limit?.burst || 50}
                  onChange={(e) =>
                    setEditedConfig({
                      ...currentConfig,
                      rate_limit: {
                        ...currentConfig?.rate_limit,
                        enabled: true,
                        burst: Number(e.target.value),
                      },
                    })
                  }
                />
              </div>
            </div>
          )}
        </div>
      </Section>

      {/* Logging */}
      <Section
        title="Logging"
        description="Log level and format"
        hotReload={false}
      >
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="label">Log Level</label>
            <select
              className="select"
              value={currentConfig?.logging?.level || 'info'}
              onChange={(e) =>
                setEditedConfig({
                  ...currentConfig,
                  logging: {
                    ...currentConfig?.logging,
                    level: e.target.value as 'debug' | 'info' | 'warn' | 'error',
                  },
                })
              }
            >
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warn">Warning</option>
              <option value="error">Error</option>
            </select>
          </div>
          <div>
            <label className="label">Log Format</label>
            <select
              className="select"
              value={currentConfig?.logging?.format || 'text'}
              onChange={(e) =>
                setEditedConfig({
                  ...currentConfig,
                  logging: {
                    ...currentConfig?.logging,
                    level: currentConfig?.logging?.level || 'info',
                    format: e.target.value as 'text' | 'json',
                  },
                })
              }
            >
              <option value="text">Text</option>
              <option value="json">JSON</option>
            </select>
          </div>
        </div>
      </Section>

      {/* Actions */}
      <div className="flex items-center justify-between pt-4 border-t border-bifrost-border">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={createBackup}
            onChange={(e) => setCreateBackup(e.target.checked)}
            className="rounded border-bifrost-border bg-bifrost-bg"
          />
          <span className="text-sm text-gray-400">Create backup before saving</span>
        </label>
        <div className="flex items-center gap-3">
          <button
            onClick={onReload}
            className="btn btn-secondary"
          >
            Reload Config
          </button>
          <button
            onClick={handleSave}
            disabled={isSaving || !editedConfig}
            className="btn btn-primary"
          >
            {isSaving ? 'Saving...' : 'Save Changes'}
          </button>
        </div>
      </div>
    </div>
  )
}
