import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import yaml from 'js-yaml'
import { api } from '../api/client'
import { ConfigEditor } from '../components/Config/ConfigEditor'
import { useToast } from '../components/Toast'
import { useUnsavedChanges } from '../hooks/useUnsavedChanges'
import type { ServerConfig } from '../api/types'

// Sections definition for sidebar navigation
const sections = [
  { id: 'section-server-settings', label: 'Server', keywords: ['http', 'socks5', 'listen', 'tls', 'timeout'] },
  { id: 'section-backends', label: 'Backends', keywords: ['backend', 'wireguard', 'openvpn', 'proxy', 'vpn'] },
  { id: 'section-routes', label: 'Routes', keywords: ['route', 'domain', 'load balance'] },
  { id: 'section-authentication', label: 'Authentication', keywords: ['auth', 'native', 'ldap', 'oauth', 'user', 'password'] },
  { id: 'section-rate-limiting', label: 'Rate Limit', keywords: ['rate', 'limit', 'throttle', 'bandwidth'] },
  { id: 'section-access-control', label: 'Access Control', keywords: ['whitelist', 'blacklist', 'ip', 'acl'] },
  { id: 'section-access-logging', label: 'Access Log', keywords: ['access', 'log', 'format', 'apache'] },
  { id: 'section-prometheus-metrics', label: 'Metrics', keywords: ['prometheus', 'metrics', 'monitoring'] },
  { id: 'section-application-logging', label: 'Logging', keywords: ['log', 'level', 'debug', 'format'] },
  { id: 'section-web-ui', label: 'Web UI', keywords: ['web', 'ui', 'dashboard'] },
  { id: 'section-rest-api', label: 'API', keywords: ['api', 'rest', 'token', 'websocket'] },
  { id: 'section-health-checks', label: 'Health Check', keywords: ['health', 'check', 'tcp', 'ping'] },
  { id: 'section-auto-update', label: 'Auto Update', keywords: ['update', 'auto', 'channel'] },
  { id: 'section-cache', label: 'Cache', keywords: ['cache', 'memory', 'disk', 'ttl', 'evict'] },
]

// Hot-reloadable section IDs (these don't require restart)
const hotReloadSections = new Set([
  'section-routes', 'section-rate-limiting', 'section-access-control',
  'section-access-logging', 'section-health-checks',
])

export function Config() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [activeSection, setActiveSection] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [hasChanges, setHasChanges] = useState(false)
  const observerRef = useRef<IntersectionObserver | null>(null)

  const { data: config, isLoading } = useQuery({
    queryKey: ['config'],
    queryFn: api.getFullConfig,
  })

  // Track unsaved changes for navigation warning
  useUnsavedChanges(hasChanges)

  // IntersectionObserver for active section tracking
  useEffect(() => {
    observerRef.current = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id)
          }
        }
      },
      { rootMargin: '-80px 0px -60% 0px', threshold: 0.1 }
    )

    const timer = setTimeout(() => {
      for (const section of sections) {
        const el = document.getElementById(section.id)
        if (el) observerRef.current?.observe(el)
      }
    }, 500)

    return () => {
      clearTimeout(timer)
      observerRef.current?.disconnect()
    }
  }, [isLoading])

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  // Filter sections by search query
  const filteredSections = searchQuery
    ? sections.filter((s) => {
        const q = searchQuery.toLowerCase()
        return s.label.toLowerCase().includes(q) || s.keywords.some((k) => k.includes(q))
      })
    : sections

  const saveMutation = useMutation({
    mutationFn: async ({ config, backup }: { config: ServerConfig; backup: boolean }) => {
      return api.saveConfig({ config, create_backup: backup })
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setHasChanges(false)

      if (data.changed_sections && data.changed_sections.length > 0) {
        const hotReloaded = data.changed_sections.filter((s) =>
          hotReloadSections.has(`section-${s.toLowerCase().replace(/\s+/g, '-')}`)
        )
        const needsRestart = data.changed_sections.filter((s) =>
          !hotReloadSections.has(`section-${s.toLowerCase().replace(/\s+/g, '-')}`)
        )

        if (needsRestart.length > 0 && hotReloaded.length > 0) {
          showToast(
            `Saved. Hot-reloaded: ${hotReloaded.join(', ')}. Restart needed for: ${needsRestart.join(', ')}.`,
            'warning'
          )
        } else if (needsRestart.length > 0) {
          showToast(
            `Configuration saved. Restart required for: ${needsRestart.join(', ')}.`,
            'warning'
          )
        } else {
          showToast('Configuration saved and applied.', 'success')
        }
      } else if (data.requires_restart) {
        showToast('Configuration saved. Server restart required for changes to take effect.', 'warning')
      } else {
        showToast('Configuration saved and reloaded successfully.', 'success')
      }
    },
    onError: (error) => {
      showToast(`Failed to save configuration: ${error}`, 'error')
    },
  })

  const reloadMutation = useMutation({
    mutationFn: api.reloadConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      showToast('Configuration reloaded successfully.', 'success')
    },
    onError: (error) => {
      showToast(`Failed to reload configuration: ${error}`, 'error')
    },
  })

  const handleSave = async (config: ServerConfig, backup: boolean) => {
    setHasChanges(true) // Mark as changed during save for tracking
    await saveMutation.mutateAsync({ config, backup })
  }

  const handleReload = async () => {
    await reloadMutation.mutateAsync()
  }

  const handleValidate = useCallback(async (config: ServerConfig) => {
    try {
      const result = await api.validateConfig(config)
      if (!result.valid && result.errors) {
        result.errors.forEach((err) => showToast(`Validation: ${err}`, 'error'))
      }
      return result
    } catch {
      return { valid: true }
    }
  }, [showToast])

  // Export config as YAML
  const exportConfig = () => {
    if (!config) return
    try {
      const yamlStr = yaml.dump(config, { indent: 2, lineWidth: 120, noRefs: true })
      const blob = new Blob([yamlStr], { type: 'application/x-yaml' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'bifrost-server-config.yaml'
      a.click()
      URL.revokeObjectURL(url)
      showToast('Configuration exported as YAML.', 'success')
    } catch {
      showToast('Failed to export configuration.', 'error')
    }
  }

  // Import config from YAML/JSON file
  const importConfig = () => {
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

      try {
        const content = await file.text()
        let parsed: ServerConfig

        if (file.name.endsWith('.json')) {
          parsed = JSON.parse(content)
        } else {
          parsed = yaml.load(content) as ServerConfig
        }

        if (!parsed || typeof parsed !== 'object') {
          showToast('Invalid configuration file format.', 'error')
          return
        }

        // Save the imported config
        await saveMutation.mutateAsync({ config: parsed, backup: true })
        showToast('Configuration imported and saved.', 'success')
      } catch (err) {
        showToast(`Failed to import: ${err instanceof Error ? err.message : 'Invalid file'}`, 'error')
      }
    }
    input.click()
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Configuration</h2>
          <p className="text-bifrost-muted mt-1">View and edit server configuration</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={exportConfig} className="btn btn-secondary text-sm" title="Export config as YAML">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export
          </button>
          <button onClick={importConfig} className="btn btn-secondary text-sm" title="Import config from YAML/JSON">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Import
          </button>
        </div>
      </div>

      {/* Two-Column Layout: Sidebar + Content */}
      <div className="flex gap-6">
        {/* Sidebar Navigation */}
        <aside className="hidden lg:block w-52 flex-shrink-0">
          <div className="sticky top-4 space-y-2">
            {/* Search */}
            <div className="relative">
              <svg className="absolute left-3 top-2.5 w-4 h-4 text-bifrost-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter sections..."
                className="w-full pl-9 pr-3 py-2 text-sm bg-bifrost-bg border border-bifrost-border rounded-lg text-gray-100 placeholder-bifrost-muted focus:outline-none focus:ring-1 focus:ring-bifrost-accent/50"
              />
            </div>

            {/* Section Links */}
            <nav className="space-y-0.5">
              {filteredSections.map((section) => (
                <button
                  key={section.id}
                  onClick={() => scrollToSection(section.id)}
                  className={`section-nav-item ${activeSection === section.id ? 'section-nav-item-active' : ''}`}
                >
                  {section.label}
                </button>
              ))}
            </nav>
          </div>
        </aside>

        {/* Mobile Section Dropdown */}
        <div className="lg:hidden w-full mb-4">
          <select
            value={activeSection || ''}
            onChange={(e) => scrollToSection(e.target.value)}
            className="select text-sm"
          >
            <option value="">Jump to section...</option>
            {sections.map((section) => (
              <option key={section.id} value={section.id}>{section.label}</option>
            ))}
          </select>
        </div>

        {/* Config Editor */}
        <div className="flex-1 min-w-0">
          <ConfigEditor
            config={config}
            isLoading={isLoading}
            onSave={handleSave}
            onReload={handleReload}
            onValidate={handleValidate}
          />
        </div>
      </div>
    </div>
  )
}
