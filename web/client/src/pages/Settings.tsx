import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ClientConfig, ConfigUpdateResponse } from '../api/client'
import {
  FormInput,
  FormNumber,
  FormSelect,
  FormToggle,
  FormPassword,
  FormDuration,
  FormTagInput,
  ConfigSection,
} from '../components/form'

// Icons
const ServerIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
  </svg>
)

const ProxyIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
  </svg>
)

const RouteIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
  </svg>
)

const DebugIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
  </svg>
)

const TrayIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
  </svg>
)

const WebIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
  </svg>
)

const VPNIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
  </svg>
)

const MeshIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z" />
  </svg>
)

const LogIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
)

const UpdateIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
  </svg>
)

const ExportIcon = () => (
  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
)

export function Settings() {
  const queryClient = useQueryClient()
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [pendingChanges, setPendingChanges] = useState<Partial<ClientConfig>>({})
  const [hasChanges, setHasChanges] = useState(false)
  const [lastResponse, setLastResponse] = useState<ConfigUpdateResponse | null>(null)

  const { data: config, isLoading, isError, error } = useQuery({
    queryKey: ['config'],
    queryFn: api.getConfig,
  })

  const updateMutation = useMutation({
    mutationFn: (updates: Partial<ClientConfig>) => api.updateConfig(updates),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setLastResponse(response)
      setPendingChanges({})
      setHasChanges(false)
      setSaveStatus('saved')
      setTimeout(() => setSaveStatus('idle'), 3000)
    },
    onError: () => {
      setSaveStatus('error')
      setTimeout(() => setSaveStatus('idle'), 3000)
    },
  })

  const reloadMutation = useMutation({
    mutationFn: api.reloadConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setPendingChanges({})
      setHasChanges(false)
    },
  })

  // Deep merge helper
  const mergeDeep = useCallback((target: Record<string, unknown>, source: Record<string, unknown>): Record<string, unknown> => {
    const output = { ...target }
    for (const key in source) {
      if (source[key] !== null && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        if (typeof target[key] === 'object' && target[key] !== null) {
          output[key] = mergeDeep(target[key] as Record<string, unknown>, source[key] as Record<string, unknown>)
        } else {
          output[key] = source[key]
        }
      } else {
        output[key] = source[key]
      }
    }
    return output
  }, [])

  // Update field helper
  const updateField = useCallback(<K extends keyof ClientConfig>(
    section: K,
    field: string,
    value: unknown
  ) => {
    setPendingChanges(prev => {
      const newChanges = { ...prev }
      if (!newChanges[section]) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        newChanges[section] = {} as any
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (newChanges[section] as any)[field] = value
      return newChanges
    })
    setHasChanges(true)
  }, [])

  // Get current value (pending or config)
  const getValue = useCallback(<K extends keyof ClientConfig>(
    section: K,
    field: string,
    defaultValue: unknown = ''
  ): unknown => {
    const pending = pendingChanges[section] as Record<string, unknown> | undefined
    if (pending && field in pending) {
      return pending[field]
    }
    const configSection = config?.[section] as Record<string, unknown> | undefined
    return configSection?.[field] ?? defaultValue
  }, [config, pendingChanges])

  // Save changes
  const saveChanges = () => {
    if (!hasChanges) return
    setSaveStatus('saving')
    updateMutation.mutate(pendingChanges)
  }

  // Cancel changes
  const cancelChanges = () => {
    setPendingChanges({})
    setHasChanges(false)
  }

  // Reset to defaults
  const resetToDefaults = async () => {
    if (!confirm('Are you sure you want to reset all settings to defaults? This cannot be undone.')) return
    try {
      const defaults = await api.getConfigDefaults()
      updateMutation.mutate(defaults)
    } catch (err) {
      console.error('Failed to get defaults:', err)
    }
  }

  // Export config
  const exportConfig = async (format: 'json' | 'yaml') => {
    try {
      const blob = await api.exportConfig(format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `bifrost-client-config.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Failed to export:', err)
    }
  }

  // Import config
  const importConfig = async () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.yaml,.yml,.json'
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (!file) return

      const content = await file.text()
      const format = file.name.endsWith('.json') ? 'json' : 'yaml'

      try {
        const response = await api.importConfig(content, format)
        setLastResponse(response)
        queryClient.invalidateQueries({ queryKey: ['config'] })
        setSaveStatus('saved')
        setTimeout(() => setSaveStatus('idle'), 3000)
      } catch (err) {
        console.error('Failed to import:', err)
        setSaveStatus('error')
        setTimeout(() => setSaveStatus('idle'), 3000)
      }
    }
    input.click()
  }

  if (isLoading) {
    return (
      <div className="card text-center py-12">
        <div className="animate-spin w-8 h-8 border-2 border-bifrost-accent border-t-transparent rounded-full mx-auto" />
        <p className="text-bifrost-muted mt-4">Loading configuration...</p>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="card text-center py-12 border-bifrost-error/30">
        <svg className="w-12 h-12 mx-auto text-bifrost-error mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <p className="text-bifrost-error">Failed to load configuration</p>
        <p className="text-sm text-bifrost-muted mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h2 className="text-xl font-semibold text-bifrost-text">Settings</h2>
        <div className="flex flex-wrap items-center gap-3">
          {saveStatus === 'saved' && (
            <span className="text-sm text-bifrost-success flex items-center gap-1">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              Saved
            </span>
          )}
          {saveStatus === 'error' && (
            <span className="text-sm text-bifrost-error">Save failed</span>
          )}
          <button
            onClick={() => exportConfig('yaml')}
            className="btn btn-secondary text-sm"
            title="Export as YAML"
          >
            <ExportIcon />
            Export
          </button>
          <button
            onClick={importConfig}
            className="btn btn-secondary text-sm"
          >
            Import
          </button>
          <button
            onClick={resetToDefaults}
            className="btn btn-secondary text-sm"
          >
            Reset
          </button>
          {hasChanges && (
            <>
              <button
                onClick={cancelChanges}
                className="btn btn-secondary text-sm"
              >
                Cancel
              </button>
              <button
                onClick={saveChanges}
                disabled={updateMutation.isPending}
                className="btn btn-primary text-sm"
              >
                {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
              </button>
            </>
          )}
          <button
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
            className="btn btn-secondary text-sm"
          >
            {reloadMutation.isPending ? 'Reloading...' : 'Reload'}
          </button>
        </div>
      </div>

      {/* Unsaved Changes Banner */}
      {hasChanges && (
        <div className="px-4 py-3 bg-bifrost-warning/10 border border-bifrost-warning/30 rounded-lg flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-bifrost-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <span className="text-sm text-bifrost-warning">You have unsaved changes</span>
          </div>
          <button onClick={saveChanges} className="btn btn-primary text-sm">
            Save Now
          </button>
        </div>
      )}

      {/* Restart Required Banner */}
      {lastResponse?.restart_required && (
        <div className="px-4 py-3 bg-bifrost-accent/10 border border-bifrost-accent/30 rounded-lg">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            <span className="text-sm text-bifrost-accent">
              Restart required for changes to take effect
              {lastResponse.restart_fields && lastResponse.restart_fields.length > 0 && (
                <span className="text-bifrost-muted ml-1">
                  ({lastResponse.restart_fields.join(', ')})
                </span>
              )}
            </span>
          </div>
        </div>
      )}

      {/* Bifrost Server */}
      <ConfigSection
        title="Bifrost Server"
        icon={<ServerIcon />}
        description="Connect to your Bifrost server to route traffic securely"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormInput
            label="Server Address"
            description="Your Bifrost server address and port"
            placeholder="bifrost.example.com:8080"
            value={getValue('server', 'address', '') as string}
            onChange={(v) => updateField('server', 'address', v)}
          />
          <FormSelect
            label="Connection Protocol"
            value={getValue('server', 'protocol', 'http') as string}
            onChange={(v) => updateField('server', 'protocol', v)}
            options={[
              { value: 'http', label: 'HTTP' },
              { value: 'socks5', label: 'SOCKS5' },
            ]}
          />
          <FormInput
            label="Username"
            placeholder="Optional"
            value={getValue('server', 'username', '') as string}
            onChange={(v) => updateField('server', 'username', v)}
          />
          <FormPassword
            label="Password"
            placeholder="Optional"
            value={getValue('server', 'password', '') as string}
            onChange={(v) => updateField('server', 'password', v)}
          />
          <FormDuration
            label="Timeout"
            description="Connection timeout"
            value={getValue('server', 'timeout', '30s') as string}
            onChange={(v) => updateField('server', 'timeout', v)}
          />
          <FormNumber
            label="Retry Count"
            value={getValue('server', 'retry_count', 3) as number}
            onChange={(v) => updateField('server', 'retry_count', v)}
            min={0}
            max={10}
          />
        </div>
      </ConfigSection>

      {/* Local Proxy Listeners */}
      <ConfigSection
        title="Local Proxy"
        icon={<ProxyIcon />}
        description="Local ports that apps on this device connect to"
        restartRequired
      >
        <div className="space-y-6">
          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">HTTP Proxy</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormInput
                label="Listen Address"
                placeholder="127.0.0.1:3128"
                value={(config?.proxy?.http?.listen || '') as string}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    proxy: {
                      ...prev.proxy,
                      http: { ...(prev.proxy?.http || config?.proxy?.http || {}), listen: v }
                    } as ClientConfig['proxy']
                  }))
                  setHasChanges(true)
                }}
              />
              <FormDuration
                label="Read Timeout"
                value={(config?.proxy?.http?.read_timeout || '30s') as string}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    proxy: {
                      ...prev.proxy,
                      http: { ...(prev.proxy?.http || config?.proxy?.http || {}), read_timeout: v }
                    } as ClientConfig['proxy']
                  }))
                  setHasChanges(true)
                }}
              />
            </div>
          </div>
          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">SOCKS5 Proxy</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormInput
                label="Listen Address"
                placeholder="127.0.0.1:1081"
                value={(config?.proxy?.socks5?.listen || '') as string}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    proxy: {
                      ...prev.proxy,
                      socks5: { ...(prev.proxy?.socks5 || config?.proxy?.socks5 || {}), listen: v }
                    } as ClientConfig['proxy']
                  }))
                  setHasChanges(true)
                }}
              />
              <FormDuration
                label="Read Timeout"
                value={(config?.proxy?.socks5?.read_timeout || '30s') as string}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    proxy: {
                      ...prev.proxy,
                      socks5: { ...(prev.proxy?.socks5 || config?.proxy?.socks5 || {}), read_timeout: v }
                    } as ClientConfig['proxy']
                  }))
                  setHasChanges(true)
                }}
              />
            </div>
          </div>
        </div>
      </ConfigSection>

      {/* Routes */}
      <ConfigSection
        title="Routes"
        icon={<RouteIcon />}
        description="Domain routing rules"
      >
        <div className="space-y-4">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-bifrost-muted border-b border-bifrost-border">
                  <th className="pb-2 font-medium">Name</th>
                  <th className="pb-2 font-medium">Domains</th>
                  <th className="pb-2 font-medium">Action</th>
                  <th className="pb-2 font-medium">Priority</th>
                </tr>
              </thead>
              <tbody>
                {config?.routes?.map((route, index) => (
                  <tr key={index} className="border-b border-bifrost-border/50">
                    <td className="py-2 text-bifrost-text">{route.name || `Rule ${index + 1}`}</td>
                    <td className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {route.domains.slice(0, 3).map((d, i) => (
                          <span key={i} className="px-2 py-0.5 text-xs bg-bifrost-accent/20 text-bifrost-accent rounded">
                            {d}
                          </span>
                        ))}
                        {route.domains.length > 3 && (
                          <span className="text-xs text-bifrost-muted">+{route.domains.length - 3} more</span>
                        )}
                      </div>
                    </td>
                    <td className="py-2">
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        route.action === 'direct' ? 'bg-bifrost-success/20 text-bifrost-success' : 'bg-bifrost-accent/20 text-bifrost-accent'
                      }`}>
                        {route.action}
                      </span>
                    </td>
                    <td className="py-2 text-bifrost-muted">{route.priority}</td>
                  </tr>
                )) || (
                  <tr>
                    <td colSpan={4} className="py-4 text-center text-bifrost-muted">No routes configured</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-bifrost-muted">
            Edit routes in the configuration file for full control. Route management UI coming soon.
          </p>
        </div>
      </ConfigSection>

      {/* Debug Settings */}
      <ConfigSection
        title="Debug Settings"
        icon={<DebugIcon />}
        description="Traffic debugging and capture settings"
      >
        <div className="space-y-4">
          <FormToggle
            label="Enable Debugging"
            description="Capture and display traffic for debugging"
            checked={getValue('debug', 'enabled', true) as boolean}
            onChange={(v) => updateField('debug', 'enabled', v)}
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormNumber
              label="Max Entries"
              description="Maximum number of debug entries to keep"
              value={getValue('debug', 'max_entries', 1000) as number}
              onChange={(v) => updateField('debug', 'max_entries', v)}
              min={100}
              max={10000}
            />
            <FormNumber
              label="Max Body Size"
              description="Maximum body size to capture (bytes)"
              value={getValue('debug', 'max_body_size', 65536) as number}
              onChange={(v) => updateField('debug', 'max_body_size', v)}
              min={0}
              max={1048576}
            />
          </div>
          <FormToggle
            label="Capture Body"
            description="Capture request/response body content"
            checked={getValue('debug', 'capture_body', false) as boolean}
            onChange={(v) => updateField('debug', 'capture_body', v)}
          />
          <FormTagInput
            label="Filter Domains"
            description="Only capture traffic for these domains (leave empty for all)"
            value={(getValue('debug', 'filter_domains', []) as string[]) || []}
            onChange={(v) => updateField('debug', 'filter_domains', v)}
            placeholder="e.g., example.com"
          />
        </div>
      </ConfigSection>

      {/* Logging */}
      <ConfigSection
        title="Logging"
        icon={<LogIcon />}
        description="Application logging settings"
        defaultOpen={false}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormSelect
            label="Log Level"
            value={getValue('logging', 'level', 'info') as string}
            onChange={(v) => updateField('logging', 'level', v)}
            options={[
              { value: 'debug', label: 'Debug' },
              { value: 'info', label: 'Info' },
              { value: 'warn', label: 'Warning' },
              { value: 'error', label: 'Error' },
            ]}
          />
          <FormSelect
            label="Log Format"
            value={getValue('logging', 'format', 'text') as string}
            onChange={(v) => updateField('logging', 'format', v)}
            options={[
              { value: 'text', label: 'Text' },
              { value: 'json', label: 'JSON' },
            ]}
          />
          <FormSelect
            label="Output"
            value={getValue('logging', 'output', 'stderr') as string}
            onChange={(v) => updateField('logging', 'output', v)}
            options={[
              { value: 'stdout', label: 'Stdout' },
              { value: 'stderr', label: 'Stderr' },
              { value: 'file', label: 'File' },
            ]}
          />
        </div>
      </ConfigSection>

      {/* System Tray */}
      <ConfigSection
        title="System Tray"
        icon={<TrayIcon />}
        description="System tray and quick access settings"
        defaultOpen={false}
      >
        <div className="space-y-4">
          <FormToggle
            label="Enable System Tray"
            description="Show icon in system tray"
            checked={getValue('tray', 'enabled', true) as boolean}
            onChange={(v) => updateField('tray', 'enabled', v)}
          />
          <FormToggle
            label="Start Minimized"
            description="Start in system tray on launch"
            checked={getValue('tray', 'start_minimized', false) as boolean}
            onChange={(v) => updateField('tray', 'start_minimized', v)}
          />
          <FormToggle
            label="Show Quick GUI"
            description="Show quick access window on tray click"
            checked={getValue('tray', 'show_quick_gui', true) as boolean}
            onChange={(v) => updateField('tray', 'show_quick_gui', v)}
          />
          <FormToggle
            label="Auto-Connect"
            description="Connect to server on startup"
            checked={getValue('tray', 'auto_connect', false) as boolean}
            onChange={(v) => updateField('tray', 'auto_connect', v)}
          />
          <FormToggle
            label="Show Notifications"
            description="Show connection notifications"
            checked={getValue('tray', 'show_notifications', true) as boolean}
            onChange={(v) => updateField('tray', 'show_notifications', v)}
          />
        </div>
      </ConfigSection>

      {/* Web UI & API */}
      <ConfigSection
        title="Web UI & API"
        icon={<WebIcon />}
        description="Web dashboard and API settings"
        restartRequired
        defaultOpen={false}
      >
        <div className="space-y-6">
          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">Web UI</h4>
            <div className="space-y-4">
              <FormToggle
                label="Enable Web UI"
                checked={getValue('web_ui', 'enabled', true) as boolean}
                onChange={(v) => updateField('web_ui', 'enabled', v)}
              />
              <FormInput
                label="Listen Address"
                placeholder="127.0.0.1:3129"
                value={getValue('web_ui', 'listen', '127.0.0.1:3129') as string}
                onChange={(v) => updateField('web_ui', 'listen', v)}
              />
            </div>
          </div>
          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">API</h4>
            <div className="space-y-4">
              <FormToggle
                label="Enable API"
                checked={getValue('api', 'enabled', true) as boolean}
                onChange={(v) => updateField('api', 'enabled', v)}
              />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormInput
                  label="Listen Address"
                  placeholder="127.0.0.1:3130"
                  value={getValue('api', 'listen', '127.0.0.1:3130') as string}
                  onChange={(v) => updateField('api', 'listen', v)}
                />
                <FormPassword
                  label="API Token"
                  description="Leave empty for no authentication"
                  placeholder="Optional"
                  value={getValue('api', 'token', '') as string}
                  onChange={(v) => updateField('api', 'token', v)}
                />
              </div>
            </div>
          </div>
        </div>
      </ConfigSection>

      {/* Auto-Update */}
      <ConfigSection
        title="Auto-Update"
        icon={<UpdateIcon />}
        description="Automatic update settings"
        defaultOpen={false}
      >
        <div className="space-y-4">
          <FormToggle
            label="Enable Auto-Update"
            description="Automatically check for and install updates"
            checked={getValue('auto_update', 'enabled', false) as boolean}
            onChange={(v) => updateField('auto_update', 'enabled', v)}
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormDuration
              label="Check Interval"
              value={getValue('auto_update', 'check_interval', '24h') as string}
              onChange={(v) => updateField('auto_update', 'check_interval', v)}
            />
            <FormSelect
              label="Update Channel"
              value={getValue('auto_update', 'channel', 'stable') as string}
              onChange={(v) => updateField('auto_update', 'channel', v)}
              options={[
                { value: 'stable', label: 'Stable' },
                { value: 'beta', label: 'Beta' },
                { value: 'nightly', label: 'Nightly' },
              ]}
            />
          </div>
        </div>
      </ConfigSection>

      {/* VPN Mode */}
      <ConfigSection
        title="VPN Mode"
        icon={<VPNIcon />}
        description="TUN device and split tunneling"
        restartRequired
        defaultOpen={false}
      >
        <div className="space-y-6">
          <FormToggle
            label="Enable VPN Mode"
            description="Route traffic through TUN device"
            checked={getValue('vpn', 'enabled', false) as boolean}
            onChange={(v) => updateField('vpn', 'enabled', v)}
          />

          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">TUN Device</h4>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <FormInput
                label="Device Name"
                placeholder="bifrost0"
                value={(config?.vpn?.tun?.name || '') as string}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      tun: { ...(prev.vpn?.tun || config?.vpn?.tun || {}), name: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
              />
              <FormInput
                label="Address"
                placeholder="10.255.0.2/24"
                value={(config?.vpn?.tun?.address || '') as string}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      tun: { ...(prev.vpn?.tun || config?.vpn?.tun || {}), address: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
              />
              <FormNumber
                label="MTU"
                value={(config?.vpn?.tun?.mtu || 1500) as number}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      tun: { ...(prev.vpn?.tun || config?.vpn?.tun || {}), mtu: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
                min={576}
                max={9000}
              />
            </div>
          </div>

          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">Split Tunnel</h4>
            <div className="space-y-4">
              <FormSelect
                label="Mode"
                value={(config?.vpn?.split_tunnel?.mode || 'exclude') as string}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      split_tunnel: { ...(prev.vpn?.split_tunnel || config?.vpn?.split_tunnel || {}), mode: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
                options={[
                  { value: 'exclude', label: 'Exclude (bypass specified)' },
                  { value: 'include', label: 'Include (only specified)' },
                ]}
              />
              <FormTagInput
                label="Bypass Domains"
                description="Domains to always bypass the VPN"
                value={(config?.vpn?.split_tunnel?.always_bypass || []) as string[]}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      split_tunnel: { ...(prev.vpn?.split_tunnel || config?.vpn?.split_tunnel || {}), always_bypass: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
              />
            </div>
          </div>

          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">DNS</h4>
            <div className="space-y-4">
              <FormToggle
                label="Enable DNS Interception"
                checked={(config?.vpn?.dns?.enabled || false) as boolean}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      dns: { ...(prev.vpn?.dns || config?.vpn?.dns || {}), enabled: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
              />
              <FormTagInput
                label="Upstream DNS Servers"
                value={(config?.vpn?.dns?.upstream || []) as string[]}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      dns: { ...(prev.vpn?.dns || config?.vpn?.dns || {}), upstream: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
                placeholder="e.g., 8.8.8.8"
              />
            </div>
          </div>
        </div>
      </ConfigSection>

      {/* Mesh Networking */}
      <ConfigSection
        title="Mesh Networking"
        icon={<MeshIcon />}
        description="P2P mesh network settings (Advanced)"
        restartRequired
        defaultOpen={false}
      >
        <div className="space-y-6">
          <FormToggle
            label="Enable Mesh Networking"
            description="Connect to other Bifrost peers directly"
            checked={getValue('mesh', 'enabled', false) as boolean}
            onChange={(v) => updateField('mesh', 'enabled', v)}
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormInput
              label="Network ID"
              description="Unique identifier for your mesh network"
              placeholder="my-mesh-network"
              value={getValue('mesh', 'network_id', '') as string}
              onChange={(v) => updateField('mesh', 'network_id', v)}
            />
            <FormInput
              label="Network CIDR"
              description="IP range for mesh network"
              placeholder="10.254.0.0/16"
              value={getValue('mesh', 'network_cidr', '') as string}
              onChange={(v) => updateField('mesh', 'network_cidr', v)}
            />
            <FormInput
              label="Peer Name"
              description="This device's name in the mesh"
              placeholder="my-device"
              value={getValue('mesh', 'peer_name', '') as string}
              onChange={(v) => updateField('mesh', 'peer_name', v)}
            />
          </div>

          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">STUN Servers</h4>
            <FormTagInput
              label="STUN Server URLs"
              description="STUN servers for NAT traversal"
              value={(config?.mesh?.stun_servers || []) as string[]}
              onChange={(v) => {
                setPendingChanges(prev => ({
                  ...prev,
                  mesh: { ...prev.mesh, stun_servers: v } as ClientConfig['mesh']
                }))
                setHasChanges(true)
              }}
              placeholder="e.g., stun:stun.l.google.com:19302"
            />
          </div>
        </div>
      </ConfigSection>
    </div>
  )
}
