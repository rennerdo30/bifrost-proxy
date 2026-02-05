import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ClientConfig, ConfigUpdateResponse, ListenerConfig, TunConfig, DNSSettings, MeshDeviceConfig, MeshDiscoveryConfig, STUNConfig, MeshConnectionConfig, MeshSecurityConfig } from '../api/client'
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
import { useToast } from '../components/Toast'
import { ConfirmModal } from '../components/ConfirmModal'
import { validateDomain, validateIP, validateDomainOrIP } from '../utils/validation'
import {
  ServerIcon,
  ProxyIcon,
  RouteIcon,
  DebugIcon,
  TrayIcon,
  WebIcon,
  VPNIcon,
  MeshIcon,
  LogIcon,
  UpdateIcon,
  ExportIcon,
} from '../components/icons'

export function Settings() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [pendingChanges, setPendingChanges] = useState<Partial<ClientConfig>>({})
  const [hasChanges, setHasChanges] = useState(false)
  const [lastResponse, setLastResponse] = useState<ConfigUpdateResponse | null>(null)
  const [showResetConfirm, setShowResetConfirm] = useState(false)

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
      showToast('Configuration saved successfully', 'success')
      setTimeout(() => setSaveStatus('idle'), 3000)
    },
    onError: (err) => {
      setSaveStatus('error')
      showToast(`Failed to save configuration: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
      setTimeout(() => setSaveStatus('idle'), 3000)
    },
  })

  const reloadMutation = useMutation({
    mutationFn: api.reloadConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setPendingChanges({})
      setHasChanges(false)
      showToast('Configuration reloaded successfully', 'success')
    },
    onError: (err) => {
      showToast(`Failed to reload configuration: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
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

  // Nested config helpers
  const httpProxy = getValue('proxy', 'http', {}) as ListenerConfig
  const socks5Proxy = getValue('proxy', 'socks5', {}) as ListenerConfig
  const tunConfig = getValue('vpn', 'tun', {}) as TunConfig
  const vpnDns = getValue('vpn', 'dns', {}) as DNSSettings
  const meshDevice = getValue('mesh', 'device', {}) as MeshDeviceConfig
  const meshDiscovery = getValue('mesh', 'discovery', {}) as MeshDiscoveryConfig
  const meshStun = getValue('mesh', 'stun', {}) as STUNConfig
  const meshConnection = getValue('mesh', 'connection', {}) as MeshConnectionConfig
  const meshSecurity = getValue('mesh', 'security', {}) as MeshSecurityConfig

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
    try {
      const defaults = await api.getConfigDefaults()
      updateMutation.mutate(defaults)
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to reset to defaults:', err)
      showToast(`Failed to reset to defaults: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
    }
  }

  // Export config
  const exportConfig = async (format: 'json' | 'yaml') => {
    try {
      const blob = await api.exportConfig(format)
      try {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `bifrost-client-config.${format}`
        a.click()
        URL.revokeObjectURL(url)
        showToast('Configuration exported successfully', 'success')
      } catch (downloadErr) {
        if (import.meta.env.DEV) console.error('Failed to download exported configuration:', downloadErr)
        showToast('Failed to download file. Please check your browser settings.', 'error')
      }
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to export configuration:', err)
      showToast(`Failed to export configuration: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
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

      // Validate file size (max 1MB)
      const MAX_FILE_SIZE = 1024 * 1024 // 1MB
      if (file.size > MAX_FILE_SIZE) {
        showToast('Configuration file is too large. Maximum size is 1MB.', 'error')
        return
      }

      let content: string
      try {
        content = await file.text()
      } catch (readErr) {
        if (import.meta.env.DEV) console.error('Failed to read configuration file:', readErr)
        showToast('Failed to read the selected file. Please ensure the file is accessible.', 'error')
        return
      }

      const format = file.name.endsWith('.json') ? 'json' : 'yaml'

      try {
        const response = await api.importConfig(content, format)
        setLastResponse(response)
        queryClient.invalidateQueries({ queryKey: ['config'] })
        setSaveStatus('saved')
        showToast('Configuration imported successfully', 'success')
        setTimeout(() => setSaveStatus('idle'), 3000)
      } catch (err) {
        if (import.meta.env.DEV) console.error('Failed to import configuration:', err)
        showToast(`Failed to import configuration: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
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
            onClick={() => setShowResetConfirm(true)}
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
          <button
            onClick={saveChanges}
            disabled={updateMutation.isPending}
            className="btn btn-primary text-sm"
          >
            {updateMutation.isPending ? 'Saving...' : 'Save Now'}
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
          <FormDuration
            label="Retry Delay"
            value={getValue('server', 'retry_delay', '1s') as string}
            onChange={(v) => updateField('server', 'retry_delay', v)}
          />
        </div>

        <div className="mt-4 border-t border-bifrost-border pt-4">
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Health Check</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormSelect
              label="Type"
              value={(config?.server?.health_check?.type || 'tcp') as string}
              onChange={(v) => {
                setPendingChanges(prev => ({
                  ...prev,
                  server: {
                    ...prev.server,
                    health_check: { ...(prev.server?.health_check || config?.server?.health_check || {}), type: v }
                  } as ClientConfig['server']
                }))
                setHasChanges(true)
              }}
              options={[
                { value: 'tcp', label: 'TCP' },
                { value: 'http', label: 'HTTP' },
                { value: 'ping', label: 'Ping' },
              ]}
            />
            <FormDuration
              label="Interval"
              value={(config?.server?.health_check?.interval || '30s') as string}
              onChange={(v) => {
                setPendingChanges(prev => ({
                  ...prev,
                  server: {
                    ...prev.server,
                    health_check: { ...(prev.server?.health_check || config?.server?.health_check || {}), interval: v }
                  } as ClientConfig['server']
                }))
                setHasChanges(true)
              }}
            />
            <FormDuration
              label="Timeout"
              value={(config?.server?.health_check?.timeout || '5s') as string}
              onChange={(v) => {
                setPendingChanges(prev => ({
                  ...prev,
                  server: {
                    ...prev.server,
                    health_check: { ...(prev.server?.health_check || config?.server?.health_check || {}), timeout: v }
                  } as ClientConfig['server']
                }))
                setHasChanges(true)
              }}
            />
            <FormInput
              label="Target"
              placeholder="e.g., google.com:80"
              value={(config?.server?.health_check?.target || '') as string}
              onChange={(v) => {
                setPendingChanges(prev => ({
                  ...prev,
                  server: {
                    ...prev.server,
                    health_check: { ...(prev.server?.health_check || config?.server?.health_check || {}), target: v }
                  } as ClientConfig['server']
                }))
                setHasChanges(true)
              }}
            />
          </div>
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
                value={httpProxy.listen || ''}
                onChange={(v) => updateField('proxy', 'http', { ...httpProxy, listen: v })}
              />
              <FormDuration
                label="Read Timeout"
                value={httpProxy.read_timeout || '30s'}
                onChange={(v) => updateField('proxy', 'http', { ...httpProxy, read_timeout: v })}
              />
              <FormDuration
                label="Write Timeout"
                value={httpProxy.write_timeout || '30s'}
                onChange={(v) => updateField('proxy', 'http', { ...httpProxy, write_timeout: v })}
              />
              <FormDuration
                label="Idle Timeout"
                value={httpProxy.idle_timeout || '60s'}
                onChange={(v) => updateField('proxy', 'http', { ...httpProxy, idle_timeout: v })}
              />
            </div>
          </div>
          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">SOCKS5 Proxy</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormInput
                label="Listen Address"
                placeholder="127.0.0.1:1081"
                value={socks5Proxy.listen || ''}
                onChange={(v) => updateField('proxy', 'socks5', { ...socks5Proxy, listen: v })}
              />
              <FormDuration
                label="Read Timeout"
                value={socks5Proxy.read_timeout || '30s'}
                onChange={(v) => updateField('proxy', 'socks5', { ...socks5Proxy, read_timeout: v })}
              />
              <FormNumber
                label="Max Connections"
                value={socks5Proxy.max_connections || 0}
                onChange={(v) => updateField('proxy', 'socks5', { ...socks5Proxy, max_connections: v })}
                min={0}
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
                  <tr key={`${route.name || 'route'}-${route.priority}-${index}`} className="border-b border-bifrost-border/50">
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
                      <span className={`px-2 py-0.5 text-xs rounded ${route.action === 'direct' ? 'bg-bifrost-success/20 text-bifrost-success' : 'bg-bifrost-accent/20 text-bifrost-accent'
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
          <FormInput
            label="Time Format"
            placeholder="2006-01-02T15:04:05.000Z07:00"
            value={getValue('logging', 'time_format', '') as string}
            onChange={(v) => updateField('logging', 'time_format', v)}
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
                  placeholder="127.0.0.1:7383"
                  value={getValue('api', 'listen', '127.0.0.1:7383') as string}
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
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormToggle
                  label="Enable Request Logging"
                  checked={getValue('api', 'enable_request_log', false) as boolean}
                  onChange={(v) => updateField('api', 'enable_request_log', v)}
                />
                <FormNumber
                  label="Request Log Size"
                  value={getValue('api', 'request_log_size', 1000) as number}
                  onChange={(v) => updateField('api', 'request_log_size', v)}
                  min={0}
                />
                <FormNumber
                  label="Max WebSocket Clients"
                  value={getValue('api', 'websocket_max_clients', 100) as number}
                  onChange={(v) => updateField('api', 'websocket_max_clients', v)}
                  min={1}
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
                value={tunConfig.name || ''}
                onChange={(v) => updateField('vpn', 'tun', { ...tunConfig, name: v })}
              />
              <FormInput
                label="Address"
                placeholder="10.255.0.2/24"
                value={tunConfig.address || ''}
                onChange={(v) => updateField('vpn', 'tun', { ...tunConfig, address: v })}
              />
              <FormNumber
                label="MTU"
                value={tunConfig.mtu || 1500}
                onChange={(v) => updateField('vpn', 'tun', { ...tunConfig, mtu: v })}
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
                label="Split Tunnel Domains"
                description="Domains to include/exclude based on mode"
                value={(config?.vpn?.split_tunnel?.domains || []) as string[]}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      split_tunnel: { ...(prev.vpn?.split_tunnel || config?.vpn?.split_tunnel || {}), domains: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
                placeholder="e.g., internal.example.com"
                validate={validateDomain}
              />
              <FormTagInput
                label="Split Tunnel IPs"
                description="IPs/CIDRs to include/exclude based on mode"
                value={(config?.vpn?.split_tunnel?.ips || []) as string[]}
                onChange={(v) => {
                  setPendingChanges(prev => ({
                    ...prev,
                    vpn: {
                      ...prev.vpn,
                      split_tunnel: { ...(prev.vpn?.split_tunnel || config?.vpn?.split_tunnel || {}), ips: v }
                    } as ClientConfig['vpn']
                  }))
                  setHasChanges(true)
                }}
                placeholder="e.g., 10.0.0.0/8"
                validate={validateIP}
              />
              <FormTagInput
                label="Always Bypass"
                description="Destinations that ALWAYS bypass VPN (regardless of mode)"
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
                placeholder="e.g., 8.8.8.8"
                validate={validateDomainOrIP}
              />
            </div>
          </div>

          <div>
            <h4 className="text-sm font-medium text-bifrost-text mb-3">DNS</h4>
            <div className="space-y-4">
              <FormToggle
                label="Enable DNS Interception"
                checked={vpnDns.enabled !== false}
                onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, enabled: v })}
              />
              <FormTagInput
                label="Upstream DNS Servers"
                value={vpnDns.upstream || []}
                onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, upstream: v })}
                placeholder="e.g., 8.8.8.8"
              />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormInput
                  label="Listen Address"
                  placeholder="10.255.0.1:53"
                  value={vpnDns.listen || ''}
                  onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, listen: v })}
                />
                <FormDuration
                  label="Cache TTL"
                  value={vpnDns.cache_ttl || '5m'}
                  onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, cache_ttl: v })}
                />
                <FormSelect
                  label="Intercept Mode"
                  value={vpnDns.intercept_mode || 'all'}
                  onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, intercept_mode: v })}
                  options={[
                    { value: 'all', label: 'All Queries' },
                    { value: 'tunnel_only', label: 'Tunnel Only' },
                  ]}
                />
              </div>
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
            <h4 className="text-sm font-medium text-bifrost-text mb-3">Discovery</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormInput
              label="Discovery Server"
              placeholder="https://discovery.bifrost.com"
              value={meshDiscovery.server || ''}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, server: v })}
            />
            <FormInput
              label="Discovery Token"
              placeholder="Optional"
              type="password"
              autoComplete="off"
              value={meshDiscovery.token || ''}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, token: v })}
            />
            <FormDuration
              label="Heartbeat Interval"
              value={meshDiscovery.heartbeat_interval || '30s'}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, heartbeat_interval: v })}
            />
            <FormDuration
              label="Peer Timeout"
              value={meshDiscovery.peer_timeout || '120s'}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, peer_timeout: v })}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Common Settings</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormToggle
              label="Require Encryption"
              checked={meshSecurity.require_encryption !== false}
              onChange={(v) => updateField('mesh', 'security', { ...meshSecurity, require_encryption: v })}
            />
            <FormSelect
              label="Device Type"
              value={meshDevice.type || 'tun'}
              onChange={(v) => updateField('mesh', 'device', { ...meshDevice, type: v })}
              options={[
                { value: 'tun', label: 'TUN' },
                { value: 'tap', label: 'TAP' },
              ]}
            />
            <FormNumber
              label="Device MTU"
              value={meshDevice.mtu || 1350}
              onChange={(v) => updateField('mesh', 'device', { ...meshDevice, mtu: v })}
              min={576}
              max={9000}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Connection</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormToggle
              label="Allow Relay"
              checked={meshConnection.relay_enabled !== false}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, relay_enabled: v })}
            />
            <FormToggle
              label="Direct Connect"
              checked={meshConnection.direct_connect !== false}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, direct_connect: v })}
            />
            <FormDuration
              label="Keepalive"
              value={meshConnection.keepalive_interval || '15s'}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, keepalive_interval: v })}
            />
            <FormDuration
              label="Connect Timeout"
              value={meshConnection.connect_timeout || '10s'}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, connect_timeout: v })}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">STUN Servers</h4>
          <FormTagInput
            label="STUN Server URLs"
            description="STUN servers for NAT traversal"
            value={meshStun.servers || []}
            onChange={(v) => updateField('mesh', 'stun', { ...meshStun, servers: v })}
            placeholder="e.g., stun:stun.l.google.com:19302"
          />
        </div>
      </div>
      </ConfigSection>

      <ConfirmModal
        isOpen={showResetConfirm}
        onClose={() => setShowResetConfirm(false)}
        onConfirm={resetToDefaults}
        title="Reset Settings"
        message="Are you sure you want to reset all settings to defaults? This action cannot be undone."
        confirmLabel="Reset"
        variant="danger"
      />
    </div>
  )
}
