import { useState } from 'react'
import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
import { ArrayInput } from '../ArrayInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { CacheConfig, CacheStorageConfig, CacheRuleConfig } from '../../../api/types'

interface CacheSectionProps {
  config: CacheConfig
  onChange: (config: CacheConfig) => void
}

// Available cache presets
const CACHE_PRESETS = [
  { value: 'steam', label: 'Steam', description: 'Steam game downloads' },
  { value: 'origin', label: 'Origin', description: 'EA Origin/App downloads' },
  { value: 'epic', label: 'Epic Games', description: 'Epic Games Store downloads' },
  { value: 'battlenet', label: 'Battle.net', description: 'Blizzard game downloads' },
  { value: 'windows', label: 'Windows Update', description: 'Microsoft Windows updates' },
  { value: 'playstation', label: 'PlayStation', description: 'PlayStation Network downloads' },
  { value: 'xbox', label: 'Xbox', description: 'Xbox Live downloads' },
  { value: 'nintendo', label: 'Nintendo', description: 'Nintendo eShop downloads' },
  { value: 'ubisoft', label: 'Ubisoft', description: 'Ubisoft Connect downloads' },
  { value: 'riot', label: 'Riot Games', description: 'League of Legends, Valorant, etc.' },
  { value: 'apple', label: 'Apple', description: 'iOS/macOS updates and App Store' },
  { value: 'google', label: 'Google', description: 'Android and Chrome updates' },
  { value: 'linux', label: 'Linux', description: 'Common Linux package repositories' },
]

// Default empty rule
const createEmptyRule = (): CacheRuleConfig => ({
  name: '',
  domains: [],
  enabled: true,
  ttl: '7d',
  priority: 100,
})

type CacheValidationKeys = {
  default_ttl: string
  max_file_size: string
  'memory.max_size': string
  'memory.max_entries': number
  'disk.path': string
  'disk.max_size': string
  'disk.cleanup_interval': string
  'tiered.memory_threshold': string
}

export function CacheSection({ config, onChange }: CacheSectionProps) {
  const { errors, handleFieldChange } = useValidation<CacheValidationKeys>({
    default_ttl: [validators.duration()],
    max_file_size: [validators.byteSize()],
    'memory.max_size': [validators.byteSize()],
    'memory.max_entries': [validators.positiveInteger()],
    'disk.path': [validators.filePath()],
    'disk.max_size': [validators.byteSize()],
    'disk.cleanup_interval': [validators.duration()],
    'tiered.memory_threshold': [validators.byteSize()],
  })

  const update = (field: string, value: unknown) => {
    if (field === 'default_ttl' || field === 'max_file_size') {
      handleFieldChange(field as keyof CacheValidationKeys, value as never)
    }
    onChange({ ...config, [field]: value })
  }

  const updateStorage = (type: CacheStorageConfig['type']) => {
    const storage: CacheStorageConfig = { ...config.storage, type }

    // Initialize defaults for new type if missing
    if (type === 'memory' && !storage.memory) {
      storage.memory = {
        max_size: '2GB',
        max_entries: 50000,
        evict_policy: 'lru',
      }
    } else if (type === 'disk' && !storage.disk) {
      storage.disk = {
        path: '/var/cache/bifrost',
        max_size: '500GB',
        cleanup_interval: '1h',
        shard_count: 256,
      }
    } else if (type === 'tiered') {
      if (!storage.tiered) {
        storage.tiered = { memory_threshold: '10MB' }
      }
      if (!storage.memory) {
        storage.memory = {
          max_size: '2GB',
          max_entries: 50000,
          evict_policy: 'lru',
        }
      }
      if (!storage.disk) {
        storage.disk = {
          path: '/var/cache/bifrost',
          max_size: '500GB',
          cleanup_interval: '1h',
          shard_count: 256,
        }
      }
    }

    onChange({ ...config, storage })
  }

  const updateMemoryConfig = (field: string, value: unknown) => {
    handleFieldChange(`memory.${field}` as keyof CacheValidationKeys, value as never)
    onChange({
      ...config,
      storage: {
        ...config.storage,
        memory: {
          ...(config.storage.memory || { max_size: '2GB', max_entries: 50000, evict_policy: 'lru' }),
          [field]: value,
        },
      },
    })
  }

  const updateDiskConfig = (field: string, value: unknown) => {
    handleFieldChange(`disk.${field}` as keyof CacheValidationKeys, value as never)
    onChange({
      ...config,
      storage: {
        ...config.storage,
        disk: {
          ...(config.storage.disk || {
            path: '/var/cache/bifrost',
            max_size: '500GB',
            cleanup_interval: '1h',
            shard_count: 256,
          }),
          [field]: value,
        },
      },
    })
  }

  const updateTieredConfig = (field: string, value: unknown) => {
    handleFieldChange(`tiered.${field}` as keyof CacheValidationKeys, value as never)
    onChange({
      ...config,
      storage: {
        ...config.storage,
        tiered: { ...(config.storage.tiered || { memory_threshold: '10MB' }), [field]: value },
      },
    })
  }

  return (
    <Section title="Cache" badge="restart-required">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable Caching</span>
        </label>

        {config.enabled && (
          <div className="space-y-6 pl-7">
            {/* General Settings */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ValidatedInput
                label="Default TTL"
                value={config.default_ttl || ''}
                onChange={(e) => update('default_ttl', e.target.value)}
                placeholder="30d"
                error={errors.default_ttl}
                helpText="Default time-to-live for cached items (e.g., 1h, 7d, 30d)"
              />
              <ValidatedInput
                label="Max File Size"
                value={config.max_file_size || ''}
                onChange={(e) => update('max_file_size', e.target.value)}
                placeholder="50GB"
                error={errors.max_file_size}
                helpText="Maximum size of a single cached file (e.g., 1GB, 50GB)"
              />
            </div>

            {/* Storage Configuration */}
            <div className="bg-bifrost-bg rounded-lg p-4 space-y-4">
              <h4 className="text-sm font-semibold text-white">Storage Backend</h4>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Storage Type</label>
                <div className="flex gap-4">
                  {(['memory', 'disk', 'tiered'] as const).map((type) => (
                    <label key={type} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="radio"
                        name="storage_type"
                        checked={config.storage.type === type}
                        onChange={() => updateStorage(type)}
                        className="w-4 h-4 border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                      />
                      <span className="text-sm text-gray-300 capitalize">{type}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Memory Settings */}
              {(config.storage.type === 'memory' || config.storage.type === 'tiered') && (
                <div className="space-y-4 border-t border-bifrost-border pt-4">
                  <h5 className="text-xs font-semibold text-bifrost-muted uppercase tracking-wider">
                    Memory Configuration
                  </h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <ValidatedInput
                      label="Max Size"
                      value={config.storage.memory?.max_size || ''}
                      onChange={(e) => updateMemoryConfig('max_size', e.target.value)}
                      error={errors['memory.max_size']}
                      helpText="Maximum memory cache size (e.g., 2GB)"
                    />
                    <ValidatedInput
                      label="Max Entries"
                      type="number"
                      value={config.storage.memory?.max_entries || 0}
                      onChange={(e) => updateMemoryConfig('max_entries', parseInt(e.target.value) || 0)}
                      error={errors['memory.max_entries']}
                      helpText="Maximum number of cached entries"
                    />
                    <ValidatedSelect
                      label="Eviction Policy"
                      value={config.storage.memory?.evict_policy || 'lru'}
                      onChange={(e) => updateMemoryConfig('evict_policy', e.target.value)}
                      helpText="Policy for removing old entries"
                    >
                      <option value="lru">LRU</option>
                      <option value="lfu">LFU</option>
                      <option value="fifo">FIFO</option>
                    </ValidatedSelect>
                  </div>
                </div>
              )}

              {/* Disk Settings */}
              {(config.storage.type === 'disk' || config.storage.type === 'tiered') && (
                <div className="space-y-4 border-t border-bifrost-border pt-4">
                  <h5 className="text-xs font-semibold text-bifrost-muted uppercase tracking-wider">
                    Disk Configuration
                  </h5>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="md:col-span-2">
                      <ValidatedInput
                        label="Cache Path"
                        value={config.storage.disk?.path || ''}
                        onChange={(e) => updateDiskConfig('path', e.target.value)}
                        error={errors['disk.path']}
                        helpText="Directory path for disk cache storage"
                      />
                    </div>
                    <ValidatedInput
                      label="Max Size"
                      value={config.storage.disk?.max_size || ''}
                      onChange={(e) => updateDiskConfig('max_size', e.target.value)}
                      error={errors['disk.max_size']}
                      helpText="Maximum disk cache size (e.g., 500GB)"
                    />
                    <ValidatedInput
                      label="Cleanup Interval"
                      value={config.storage.disk?.cleanup_interval || ''}
                      onChange={(e) => updateDiskConfig('cleanup_interval', e.target.value)}
                      error={errors['disk.cleanup_interval']}
                      helpText="How often to clean expired entries (e.g., 1h)"
                    />
                  </div>
                </div>
              )}

              {/* Tiered Settings */}
              {config.storage.type === 'tiered' && (
                <div className="space-y-4 border-t border-bifrost-border pt-4">
                  <h5 className="text-xs font-semibold text-bifrost-muted uppercase tracking-wider">
                    Tiered Configuration
                  </h5>
                  <ValidatedInput
                    label="Memory Threshold"
                    value={config.storage.tiered?.memory_threshold || ''}
                    onChange={(e) => updateTieredConfig('memory_threshold', e.target.value)}
                    placeholder="10MB"
                    error={errors['tiered.memory_threshold']}
                    helpText="Files smaller than this stay in memory (e.g., 10MB)"
                  />
                </div>
              )}
            </div>

            {/* Presets */}
            <div className="bg-bifrost-bg rounded-lg p-4 space-y-4">
              <h4 className="text-sm font-semibold text-white">Cache Presets</h4>
              <p className="text-xs text-bifrost-muted">
                Enable built-in cache rules for common content providers
              </p>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {CACHE_PRESETS.map((preset) => (
                  <label
                    key={preset.value}
                    className={`flex items-start gap-2 p-3 rounded-lg border cursor-pointer transition-colors ${
                      (config.presets || []).includes(preset.value)
                        ? 'border-bifrost-purple bg-bifrost-purple/10'
                        : 'border-bifrost-border bg-bifrost-bg-tertiary hover:border-bifrost-muted'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={(config.presets || []).includes(preset.value)}
                      onChange={(e) => {
                        const current = config.presets || []
                        const newPresets = e.target.checked
                          ? [...current, preset.value]
                          : current.filter((p) => p !== preset.value)
                        onChange({ ...config, presets: newPresets })
                      }}
                      className="w-4 h-4 mt-0.5 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                    />
                    <div>
                      <span className="text-sm font-medium text-white block">{preset.label}</span>
                      <span className="text-xs text-bifrost-muted">{preset.description}</span>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            {/* Custom Rules */}
            <div className="bg-bifrost-bg rounded-lg p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h4 className="text-sm font-semibold text-white">Custom Cache Rules</h4>
                  <p className="text-xs text-bifrost-muted">Define custom caching rules for specific domains</p>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const rules = [...(config.rules || []), createEmptyRule()]
                    onChange({ ...config, rules })
                  }}
                  className="btn btn-secondary text-sm"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                  </svg>
                  Add Rule
                </button>
              </div>

              {(config.rules || []).length === 0 ? (
                <div className="text-center py-8 text-bifrost-muted">
                  <p className="text-sm">No custom cache rules defined</p>
                  <p className="text-xs mt-1">Add rules to customize caching behavior for specific domains</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {(config.rules || []).map((rule, index) => (
                    <CacheRuleEditor
                      key={index}
                      rule={rule}
                      onChange={(updatedRule) => {
                        const rules = [...(config.rules || [])]
                        rules[index] = updatedRule
                        onChange({ ...config, rules })
                      }}
                      onDelete={() => {
                        const rules = (config.rules || []).filter((_, i) => i !== index)
                        onChange({ ...config, rules })
                      }}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}

// Cache Rule Editor Component
interface CacheRuleEditorProps {
  rule: CacheRuleConfig
  onChange: (rule: CacheRuleConfig) => void
  onDelete: () => void
}

function CacheRuleEditor({ rule, onChange, onDelete }: CacheRuleEditorProps) {
  const [expanded, setExpanded] = useState(false)

  const update = <K extends keyof CacheRuleConfig>(field: K, value: CacheRuleConfig[K]) => {
    onChange({ ...rule, [field]: value })
  }

  return (
    <div className="border border-bifrost-border rounded-lg overflow-hidden">
      {/* Header */}
      <div
        className={`flex items-center justify-between p-3 cursor-pointer ${
          rule.enabled ? 'bg-bifrost-bg-tertiary' : 'bg-bifrost-bg-tertiary/50'
        }`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          <input
            type="checkbox"
            checked={rule.enabled}
            onChange={(e) => {
              e.stopPropagation()
              update('enabled', e.target.checked)
            }}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <div>
            <span className={`text-sm font-medium ${rule.enabled ? 'text-white' : 'text-gray-500'}`}>
              {rule.name || 'Untitled Rule'}
            </span>
            <span className="text-xs text-bifrost-muted ml-2">
              {rule.domains.length} domain{rule.domains.length !== 1 ? 's' : ''} • TTL: {rule.ttl || 'default'}
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              onDelete()
            }}
            className="p-1 text-bifrost-muted hover:text-bifrost-error transition-colors"
            aria-label="Delete rule"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
          </button>
          <svg
            className={`w-4 h-4 text-bifrost-muted transition-transform ${expanded ? 'rotate-180' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div className="p-4 space-y-4 border-t border-bifrost-border">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Rule Name</label>
              <input
                type="text"
                value={rule.name}
                onChange={(e) => update('name', e.target.value)}
                placeholder="e.g., CDN Assets"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Priority</label>
              <input
                type="number"
                value={rule.priority}
                onChange={(e) => update('priority', parseInt(e.target.value) || 100)}
                className="input"
              />
              <p className="text-xs text-bifrost-muted mt-1">Higher priority rules take precedence</p>
            </div>
          </div>

          <ArrayInput
            label="Domains"
            values={rule.domains}
            onChange={(domains) => update('domains', domains)}
            placeholder="*.example.com, cdn.example.org"
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">TTL</label>
              <input
                type="text"
                value={rule.ttl}
                onChange={(e) => update('ttl', e.target.value)}
                placeholder="7d"
                className="input"
              />
              <p className="text-xs text-bifrost-muted mt-1">e.g., 1h, 7d, 30d</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Max File Size</label>
              <input
                type="text"
                value={rule.max_size || ''}
                onChange={(e) => update('max_size', e.target.value || undefined)}
                placeholder="Use global default"
                className="input"
              />
              <p className="text-xs text-bifrost-muted mt-1">e.g., 1GB, 10GB</p>
            </div>
          </div>

          {/* Advanced Options */}
          <div className="space-y-3 pt-2">
            <h5 className="text-xs font-semibold text-bifrost-muted uppercase tracking-wider">Advanced Options</h5>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ArrayInput
                label="HTTP Methods"
                values={rule.methods || []}
                onChange={(methods) => update('methods', methods.length ? methods : undefined)}
                placeholder="GET, HEAD (default: GET only)"
              />
              <ArrayInput
                label="Content Types"
                values={rule.content_types || []}
                onChange={(types) => update('content_types', types.length ? types : undefined)}
                placeholder="application/*, video/* (default: all)"
              />
            </div>

            <ArrayInput
              label="Strip Headers"
              values={rule.strip_headers || []}
              onChange={(headers) => update('strip_headers', headers.length ? headers : undefined)}
              placeholder="Set-Cookie, X-Request-Id"
            />

            <div className="flex flex-wrap gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rule.ignore_query === true}
                  onChange={(e) => update('ignore_query', e.target.checked || undefined)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm text-gray-300">Ignore query string</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={rule.respect_cache_control === true}
                  onChange={(e) => update('respect_cache_control', e.target.checked || undefined)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm text-gray-300">Respect Cache-Control headers</span>
              </label>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
