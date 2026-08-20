import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import * as yaml from 'js-yaml'
import { api } from '../api/client'
import { ConfigEditor } from '../components/Config/ConfigEditor'
import {
  CONFIG_SECTIONS,
  groupedSections,
  sectionLabel,
  sectionMatchesQuery,
  type ConfigSectionKey,
} from '../components/Config/sectionMeta'
import { useToast } from '../components/Toast'
import { useUnsavedChanges } from '../hooks/useUnsavedChanges'
import type { ServerConfig, ConfigValidateResponse } from '../api/types'

/** Maximum size of an imported config file. */
const MAX_IMPORT_FILE_SIZE = 1024 * 1024

/** Delay before wiring the scroll observer, so sections have mounted. */
const OBSERVER_ATTACH_DELAY_MS = 300

/** Viewport band that counts as "the section you are reading". */
const OBSERVER_ROOT_MARGIN = '-80px 0px -60% 0px'

const EXPORT_FILENAME = 'bifrost-server-config.yaml'

const YAML_DUMP_OPTIONS = { indent: 2, lineWidth: 120, noRefs: true } as const

/** Renders a comma-separated list of section labels for a toast message. */
function labelList(keys: string[]): string {
  return keys.map(sectionLabel).join(', ')
}

export function Config() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [activeSection, setActiveSection] = useState<ConfigSectionKey | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [hasChanges, setHasChanges] = useState(false)
  const [revealSection, setRevealSection] = useState<ConfigSectionKey | null>(null)
  // Bumped when the config is replaced wholesale (import), to discard the
  // editor's in-progress edits. Without this the editor keeps the pre-import
  // config, immediately reports every section as modified, and saving would
  // silently revert the import.
  const [editorResetKey, setEditorResetKey] = useState(0)
  const observerRef = useRef<IntersectionObserver | null>(null)

  const { data: config, isLoading, isError, refetch } = useQuery({
    queryKey: ['config'],
    queryFn: api.getFullConfig,
  })

  // Which sections the running server can apply without a restart. Fetched from
  // the server rather than hard-coded client-side, so the badges and the
  // post-save summary cannot contradict what the server actually does.
  const { data: configMeta } = useQuery({
    queryKey: ['config', 'meta'],
    queryFn: api.getConfigMeta,
    staleTime: Infinity,
  })

  const hotReloadableSections = useMemo(() => {
    if (!configMeta) return undefined
    return configMeta.reduce<Record<string, boolean>>((acc, entry) => {
      acc[entry.section] = entry.hot_reloadable
      return acc
    }, {})
  }, [configMeta])

  const isHotReloadable = useCallback(
    (section: string) => {
      const fromServer = hotReloadableSections?.[section]
      if (typeof fromServer === 'boolean') return fromServer
      return CONFIG_SECTIONS.find((s) => s.key === section)?.hotReloadable ?? false
    },
    [hotReloadableSections]
  )

  // Track unsaved changes for navigation warning
  useUnsavedChanges(hasChanges)

  // IntersectionObserver for active section tracking
  useEffect(() => {
    if (isLoading) return

    const byDomId = new Map(CONFIG_SECTIONS.map((s) => [s.domId, s.key]))
    observerRef.current = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            const key = byDomId.get(entry.target.id)
            if (key) setActiveSection(key)
          }
        }
      },
      { rootMargin: OBSERVER_ROOT_MARGIN, threshold: 0.1 }
    )

    const timer = setTimeout(() => {
      for (const section of CONFIG_SECTIONS) {
        const el = document.getElementById(section.domId)
        if (el) observerRef.current?.observe(el)
      }
    }, OBSERVER_ATTACH_DELAY_MS)

    return () => {
      clearTimeout(timer)
      observerRef.current?.disconnect()
    }
  }, [isLoading])

  // Ask the editor to expand + scroll to the section, so a collapsed panel is
  // actually revealed rather than scrolled to as a one-line header.
  const goToSection = useCallback((key: ConfigSectionKey) => {
    setActiveSection(key)
    setRevealSection(key)
  }, [])

  // Stable identity: this is a dependency of the editor's reveal effect, so an
  // inline arrow would let any unrelated re-render (e.g. the scroll observer
  // updating the active section) cancel and reschedule the pending scroll.
  const handleSectionRevealed = useCallback(() => setRevealSection(null), [])

  const filteredGroups = useMemo(
    () => groupedSections(CONFIG_SECTIONS.filter((s) => sectionMatchesQuery(s, searchQuery))),
    [searchQuery]
  )

  const saveMutation = useMutation({
    mutationFn: async ({ config, backup }: { config: ServerConfig; backup: boolean }) => {
      return api.saveConfig({ config, create_backup: backup })
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setHasChanges(false)

      // Prefer the server's own split. Older servers only send
      // changed_sections + requires_restart, so fall back to deriving it from
      // the section metadata the same server exposes.
      const changed = data.changed_sections ?? []
      const hotReloaded = data.hot_reloaded_sections ?? changed.filter(isHotReloadable)
      const needsRestart =
        data.restart_required_sections ?? changed.filter((s) => !isHotReloadable(s))

      if (data.errors && data.errors.length > 0) {
        for (const err of data.errors) {
          const prefix = err.section && err.section !== 'general' ? `${err.section}: ` : ''
          showToast(`${prefix}${err.message}`, 'error')
        }
        return
      }

      if (changed.length === 0) {
        showToast('Configuration saved. No changes were detected.', 'info')
        return
      }

      if (needsRestart.length > 0 && hotReloaded.length > 0) {
        showToast(
          `Saved. Applied now: ${labelList(hotReloaded)}. Restart required for: ${labelList(needsRestart)}.`,
          'warning'
        )
      } else if (needsRestart.length > 0) {
        showToast(`Configuration saved. Restart required for: ${labelList(needsRestart)}.`, 'warning')
      } else {
        showToast(`Configuration saved and applied: ${labelList(hotReloaded)}.`, 'success')
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
      showToast('Configuration reloaded from disk.', 'success')
    },
    onError: (error) => {
      showToast(`Failed to reload configuration: ${error}`, 'error')
    },
  })

  const handleSave = async (config: ServerConfig, backup: boolean) => {
    await saveMutation.mutateAsync({ config, backup })
  }

  const handleReload = async () => {
    await reloadMutation.mutateAsync()
  }

  const handleValidate = useCallback(async (config: ServerConfig): Promise<ConfigValidateResponse> => {
    try {
      const result = await api.validateConfig(config)
      if (!result.valid && result.errors) {
        // The server returns structured {section, field, message} errors; format
        // them into a readable string rather than rendering "[object Object]".
        result.errors.forEach((err) => {
          const scope = [err.section && err.section !== 'general' ? err.section : null, err.field]
            .filter(Boolean)
            .join('.')
          showToast(scope ? `${scope}: ${err.message}` : err.message, 'error')
        })
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
      const yamlStr = yaml.dump(config, YAML_DUMP_OPTIONS)
      const blob = new Blob([yamlStr], { type: 'application/x-yaml' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = EXPORT_FILENAME
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

      if (file.size > MAX_IMPORT_FILE_SIZE) {
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

        await saveMutation.mutateAsync({ config: parsed, backup: true })
        // Drop any in-progress edits so the editor shows the imported config
        // rather than offering to save the previous one over it.
        setEditorResetKey((key) => key + 1)
      } catch (err) {
        showToast(`Failed to import: ${err instanceof Error ? err.message : 'Invalid file'}`, 'error')
      }
    }
    input.click()
  }

  const navList = (
    <nav className="space-y-3" aria-label="Configuration sections">
      {filteredGroups.map(({ group, sections }) => (
        <div key={group}>
          <p className="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-bifrost-muted">
            {group}
          </p>
          <div className="space-y-0.5">
            {sections.map((section) => (
              <button
                key={section.key}
                onClick={() => goToSection(section.key)}
                aria-current={activeSection === section.key ? 'true' : undefined}
                className={`section-nav-item ${activeSection === section.key ? 'section-nav-item-active' : ''}`}
              >
                {section.label}
              </button>
            ))}
          </div>
        </div>
      ))}
      {filteredGroups.length === 0 && (
        <p className="px-3 py-4 text-sm text-bifrost-muted">
          No sections match “{searchQuery}”.
        </p>
      )}
    </nav>
  )

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="page-title">Configuration</h2>
          <p className="page-subtitle">
            Edit the server configuration. Each section shows whether saving applies it
            immediately or needs a restart.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={exportConfig}
            disabled={!config}
            className="btn btn-secondary text-sm"
            aria-label="Export configuration as YAML"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export
          </button>
          <button
            onClick={importConfig}
            className="btn btn-secondary text-sm"
            aria-label="Import configuration from a YAML or JSON file"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Import
          </button>
        </div>
      </div>

      {isError && (
        <div
          className="card border-bifrost-error/40 flex flex-wrap items-center justify-between gap-3"
          role="alert"
        >
          <p className="text-sm text-bifrost-error">
            Could not load the server configuration.
          </p>
          <button onClick={() => refetch()} className="btn btn-secondary text-sm">Retry</button>
        </div>
      )}

      {/* Two-Column Layout: Sidebar + Content */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar Navigation */}
        <aside className="hidden lg:block w-56 flex-shrink-0">
          <div className="sticky top-4 space-y-3">
            <div className="relative">
              <svg
                className="absolute left-3 top-2.5 w-4 h-4 text-bifrost-muted"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <label className="sr-only" htmlFor="config-section-filter">Filter configuration sections</label>
              <input
                id="config-section-filter"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter sections..."
                className="w-full pl-9 pr-3 py-2 text-sm bg-bifrost-bg border border-bifrost-border rounded-lg text-bifrost-heading placeholder-bifrost-muted focus:outline-none focus:ring-1 focus:ring-bifrost-accent/50"
              />
            </div>
            {navList}
          </div>
        </aside>

        {/* Mobile Section Dropdown */}
        <div className="lg:hidden w-full">
          <label className="sr-only" htmlFor="config-section-jump">Jump to configuration section</label>
          <select
            id="config-section-jump"
            value={activeSection || ''}
            onChange={(e) => {
              if (e.target.value) goToSection(e.target.value as ConfigSectionKey)
            }}
            className="select text-sm"
          >
            <option value="">Jump to section...</option>
            {groupedSections().map(({ group, sections }) => (
              <optgroup key={group} label={group}>
                {sections.map((section) => (
                  <option key={section.key} value={section.key}>{section.label}</option>
                ))}
              </optgroup>
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
            hotReloadableSections={hotReloadableSections}
            onDirtyChange={setHasChanges}
            revealSection={revealSection}
            onSectionRevealed={handleSectionRevealed}
            resetKey={editorResetKey}
          />
        </div>
      </div>
    </div>
  )
}
