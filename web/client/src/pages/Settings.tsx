import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ClientConfig, ConfigUpdateResponse } from '../api/client'
import { ConfigSection } from '../components/form'
import { useToast } from '../components/Toast'
import { ConfirmModal } from '../components/ConfirmModal'
import { RouteManager } from '../components/Routes/RouteManager'
import { useUnsavedChanges } from '../hooks/useUnsavedChanges'
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts'
import { SettingsProvider } from '../components/Settings/SettingsContext'
import { ServerSection } from '../components/Settings/ServerSection'
import { ProxySection } from '../components/Settings/ProxySection'
import { DebugSection } from '../components/Settings/DebugSection'
import { LoggingSection } from '../components/Settings/LoggingSection'
import { TraySection } from '../components/Settings/TraySection'
import { WebUISection } from '../components/Settings/WebUISection'
import { AutoUpdateSection } from '../components/Settings/AutoUpdateSection'
import { VPNSection } from '../components/Settings/VPNSection'
import { MeshSection } from '../components/Settings/MeshSection'
import {
  RouteIcon,
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

  // Unsaved changes protection
  useUnsavedChanges(hasChanges)

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

  // Keyboard shortcuts
  const shortcuts = useMemo(() => ({
    'mod+s': () => { if (hasChanges) saveChanges() },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }), [hasChanges, pendingChanges])
  useKeyboardShortcuts(shortcuts)

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

      const MAX_FILE_SIZE = 1024 * 1024
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
    <SettingsProvider
      config={config}
      pendingChanges={pendingChanges}
      setPendingChanges={setPendingChanges}
      setHasChanges={setHasChanges}
    >
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
              <span className="text-sm text-bifrost-warning">
                You have unsaved changes. Press{' '}
                <kbd className="px-1.5 py-0.5 bg-bifrost-bg rounded text-xs border border-bifrost-border">
                  {navigator.platform.includes('Mac') ? '\u2318' : 'Ctrl'}+S
                </kbd>{' '}
                to save.
              </span>
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

        {/* Sections */}
        <ServerSection />
        <ProxySection />

        {/* Routes */}
        <ConfigSection
          title="Routes"
          icon={<RouteIcon />}
          description="Domain routing rules - control how traffic is routed based on domain patterns"
        >
          <RouteManager />
        </ConfigSection>

        <DebugSection />
        <LoggingSection />
        <TraySection />
        <WebUISection />
        <AutoUpdateSection />
        <VPNSection />
        <MeshSection />

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
    </SettingsProvider>
  )
}
