import { useState, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { formatBytes } from '../utils'
import { useToast } from '../components/Toast'
import { ConfirmModal } from '../components/Config/ConfirmModal'
import {
  CacheEntryList,
  CacheRulesList,
  CachePresetsList,
  AddCacheRuleDialog,
  PurgeDomainDialog,
} from '../components/Cache'
import type { AddCacheRuleRequest } from '../api/types'

type TabType = 'entries' | 'rules' | 'presets'

export function Cache() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()

  // Tab state
  const [activeTab, setActiveTab] = useState<TabType>('entries')

  // Dialog states
  const [isAddRuleOpen, setIsAddRuleOpen] = useState(false)
  const [isClearConfirmOpen, setIsClearConfirmOpen] = useState(false)
  const [isPurgeDomainOpen, setIsPurgeDomainOpen] = useState(false)
  const [purgeDomain, setPurgeDomain] = useState('')
  const [deletingEntry, setDeletingEntry] = useState<string | null>(null)
  const [deletingRule, setDeletingRule] = useState<string | null>(null)

  // Filter states
  const [domainFilter, setDomainFilter] = useState('')
  const [entryLimit, setEntryLimit] = useState(100)

  // Cache stats query
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['cacheStats'],
    queryFn: api.getCacheStats,
    refetchInterval: 5000,
  })

  // Cache entries query
  const { data: entriesData, isLoading: entriesLoading, refetch: refetchEntries } = useQuery({
    queryKey: ['cacheEntries', domainFilter, entryLimit],
    queryFn: () => api.getCacheEntries({ domain: domainFilter || undefined, limit: entryLimit }),
    refetchInterval: 10000,
  })

  // Cache rules query
  const { data: rulesData, isLoading: rulesLoading, refetch: refetchRules } = useQuery({
    queryKey: ['cacheRules'],
    queryFn: api.getCacheRules,
  })

  // Cache presets query
  const { data: presetsData, isLoading: presetsLoading, refetch: refetchPresets } = useQuery({
    queryKey: ['cachePresets'],
    queryFn: api.getCachePresets,
  })

  const existingRuleNames = rulesData?.rules.map((r) => r.name) || []

  // Action handlers
  const handleDeleteEntry = useCallback(async () => {
    if (!deletingEntry) return
    try {
      await api.deleteCacheEntry(deletingEntry)
      showToast('Cache entry deleted', 'success')
      queryClient.invalidateQueries({ queryKey: ['cacheEntries'] })
      queryClient.invalidateQueries({ queryKey: ['cacheStats'] })
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to delete entry', 'error')
    } finally {
      setDeletingEntry(null)
    }
  }, [deletingEntry, queryClient, showToast])

  const handleClearCache = useCallback(async () => {
    try {
      await api.clearCache()
      showToast('Cache cleared', 'success')
      queryClient.invalidateQueries({ queryKey: ['cacheEntries'] })
      queryClient.invalidateQueries({ queryKey: ['cacheStats'] })
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to clear cache', 'error')
    }
  }, [queryClient, showToast])

  const handlePurgeDomain = useCallback(async (domain: string) => {
    try {
      const result = await api.purgeDomain(domain)
      showToast(`Purged ${result.deleted || 0} entries for ${domain}`, 'success')
      queryClient.invalidateQueries({ queryKey: ['cacheEntries'] })
      queryClient.invalidateQueries({ queryKey: ['cacheStats'] })
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to purge domain', 'error')
      throw err
    }
  }, [queryClient, showToast])

  const handleOpenPurgeDomain = useCallback((domain: string) => {
    setPurgeDomain(domain)
    setIsPurgeDomainOpen(true)
  }, [])

  const handleAddRule = useCallback(async (rule: AddCacheRuleRequest) => {
    try {
      await api.addCacheRule(rule)
      showToast(`Rule "${rule.name}" added`, 'success')
      refetchRules()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to add rule', 'error')
      throw err
    }
  }, [refetchRules, showToast])

  const handleToggleRule = useCallback(async (name: string, enabled: boolean) => {
    try {
      await api.updateCacheRule(name, { enabled })
      showToast(`Rule "${name}" ${enabled ? 'enabled' : 'disabled'}`, 'success')
      refetchRules()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to update rule', 'error')
    }
  }, [refetchRules, showToast])

  const handleDeleteRule = useCallback(async () => {
    if (!deletingRule) return
    try {
      await api.deleteCacheRule(deletingRule)
      showToast(`Rule "${deletingRule}" deleted`, 'success')
      refetchRules()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to delete rule', 'error')
    } finally {
      setDeletingRule(null)
    }
  }, [deletingRule, refetchRules, showToast])

  const handleTogglePreset = useCallback(async (name: string, enable: boolean) => {
    try {
      if (enable) {
        await api.enableCachePreset(name)
        showToast(`Preset "${name}" enabled`, 'success')
      } else {
        await api.disableCachePreset(name)
        showToast(`Preset "${name}" disabled`, 'success')
      }
      refetchPresets()
      refetchRules()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to toggle preset', 'error')
    }
  }, [refetchPresets, refetchRules, showToast])

  const cacheDisabled = stats && !stats.enabled

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Cache</h2>
          <p className="text-bifrost-muted mt-1">
            Monitor and manage cached responses
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              refetchEntries()
              refetchRules()
              refetchPresets()
            }}
            className="btn btn-secondary"
            aria-label="Refresh cache data"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            Refresh
          </button>
          <button
            onClick={() => setIsPurgeDomainOpen(true)}
            className="btn btn-secondary"
            disabled={cacheDisabled}
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
              />
            </svg>
            Purge Domain
          </button>
          <button
            onClick={() => setIsClearConfirmOpen(true)}
            className="btn btn-secondary text-bifrost-error"
            disabled={cacheDisabled}
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
              />
            </svg>
            Clear All
          </button>
        </div>
      </div>

      {/* Cache Disabled Warning */}
      {cacheDisabled && (
        <div className="card bg-bifrost-warning/10 border-bifrost-warning/50">
          <div className="flex items-center gap-3">
            <svg
              className="w-6 h-6 text-bifrost-warning flex-shrink-0"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
            <div>
              <p className="font-medium text-bifrost-warning">Cache is disabled</p>
              <p className="text-sm text-bifrost-muted">
                Enable caching in your server configuration to use this feature
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Statistics Cards */}
      {stats && stats.enabled && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4">
          <div className="card py-3 bg-gradient-to-br from-bifrost-accent/10 to-transparent">
            <p className="text-sm text-gray-400">Storage Type</p>
            <p className="text-lg font-bold text-white capitalize mt-1">{stats.storage_type}</p>
          </div>
          <div className="card py-3 bg-gradient-to-br from-cyan-500/10 to-transparent">
            <p className="text-sm text-gray-400">Entries</p>
            <p className="text-lg font-bold text-cyan-400 mt-1">{stats.entries.toLocaleString()}</p>
          </div>
          <div className="card py-3 bg-gradient-to-br from-emerald-500/10 to-transparent">
            <p className="text-sm text-gray-400">Size Used</p>
            <p className="text-lg font-bold text-emerald-400 mt-1">
              {formatBytes(stats.total_size_bytes)}
            </p>
            <p className="text-xs text-bifrost-muted">
              of {formatBytes(stats.max_size_bytes)} ({stats.used_percent.toFixed(1)}%)
            </p>
          </div>
          <div className="card py-3 bg-gradient-to-br from-bifrost-success/10 to-transparent">
            <p className="text-sm text-gray-400">Hit Rate</p>
            <p className="text-lg font-bold text-bifrost-success mt-1">
              {(stats.hit_rate * 100).toFixed(1)}%
            </p>
            <p className="text-xs text-bifrost-muted">
              {stats.hit_count.toLocaleString()} hits
            </p>
          </div>
          <div className="card py-3 bg-gradient-to-br from-bifrost-error/10 to-transparent">
            <p className="text-sm text-gray-400">Misses</p>
            <p className="text-lg font-bold text-bifrost-error mt-1">
              {stats.miss_count.toLocaleString()}
            </p>
          </div>
          <div className="card py-3">
            <p className="text-sm text-gray-400">Evictions</p>
            <p className="text-lg font-bold text-white mt-1">
              {stats.eviction_count.toLocaleString()}
            </p>
          </div>
        </div>
      )}

      {/* Usage Bar */}
      {stats && stats.enabled && (
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-gray-400">Storage Usage</span>
            <span className="text-sm font-mono text-bifrost-muted">
              {formatBytes(stats.total_size_bytes)} / {formatBytes(stats.max_size_bytes)}
            </span>
          </div>
          <div className="h-3 bg-bifrost-bg rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                stats.used_percent > 90
                  ? 'bg-bifrost-error'
                  : stats.used_percent > 70
                    ? 'bg-bifrost-warning'
                    : 'bg-bifrost-success'
              }`}
              style={{ width: `${Math.min(stats.used_percent, 100)}%` }}
            />
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-bifrost-border">
        <button
          onClick={() => setActiveTab('entries')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'entries'
              ? 'border-bifrost-accent text-white'
              : 'border-transparent text-bifrost-muted hover:text-white'
          }`}
        >
          Cached Entries
          {entriesData && (
            <span className="ml-2 text-xs bg-bifrost-bg px-1.5 py-0.5 rounded">
              {entriesData.total}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'rules'
              ? 'border-bifrost-accent text-white'
              : 'border-transparent text-bifrost-muted hover:text-white'
          }`}
        >
          Rules
          {rulesData && (
            <span className="ml-2 text-xs bg-bifrost-bg px-1.5 py-0.5 rounded">
              {rulesData.count}
            </span>
          )}
        </button>
        <button
          onClick={() => setActiveTab('presets')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === 'presets'
              ? 'border-bifrost-accent text-white'
              : 'border-transparent text-bifrost-muted hover:text-white'
          }`}
        >
          Presets
          {presetsData && (
            <span className="ml-2 text-xs bg-bifrost-bg px-1.5 py-0.5 rounded">
              {presetsData.count}
            </span>
          )}
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'entries' && (
        <div className="space-y-4">
          {/* Entry Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1">
              <input
                type="text"
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
                placeholder="Filter by domain..."
                className="input w-full"
              />
            </div>
            <select
              value={entryLimit}
              onChange={(e) => setEntryLimit(Number(e.target.value))}
              className="select w-32"
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={250}>250</option>
              <option value={500}>500</option>
            </select>
          </div>

          <CacheEntryList
            entries={entriesData?.entries}
            total={entriesData?.total ?? 0}
            isLoading={statsLoading || entriesLoading}
            onDelete={(key) => setDeletingEntry(key)}
            onPurgeDomain={handleOpenPurgeDomain}
          />
        </div>
      )}

      {activeTab === 'rules' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              onClick={() => setIsAddRuleOpen(true)}
              className="btn btn-primary"
              disabled={cacheDisabled}
            >
              <svg
                className="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
              </svg>
              Add Rule
            </button>
          </div>

          <CacheRulesList
            rules={rulesData?.rules}
            isLoading={rulesLoading}
            onToggle={handleToggleRule}
            onDelete={(name) => setDeletingRule(name)}
          />
        </div>
      )}

      {activeTab === 'presets' && (
        <CachePresetsList
          presets={presetsData?.presets}
          isLoading={presetsLoading}
          onToggle={handleTogglePreset}
        />
      )}

      {/* Dialogs */}
      <AddCacheRuleDialog
        isOpen={isAddRuleOpen}
        onClose={() => setIsAddRuleOpen(false)}
        onSave={handleAddRule}
        existingNames={existingRuleNames}
      />

      <PurgeDomainDialog
        isOpen={isPurgeDomainOpen}
        onClose={() => {
          setIsPurgeDomainOpen(false)
          setPurgeDomain('')
        }}
        onPurge={handlePurgeDomain}
        initialDomain={purgeDomain}
      />

      <ConfirmModal
        isOpen={isClearConfirmOpen}
        onClose={() => setIsClearConfirmOpen(false)}
        onConfirm={handleClearCache}
        title="Clear All Cache"
        message="Are you sure you want to clear all cached entries? This action cannot be undone."
        confirmLabel="Clear All"
        variant="danger"
      />

      <ConfirmModal
        isOpen={deletingEntry !== null}
        onClose={() => setDeletingEntry(null)}
        onConfirm={handleDeleteEntry}
        title="Delete Cache Entry"
        message="Are you sure you want to delete this cache entry?"
        confirmLabel="Delete"
        variant="danger"
      />

      <ConfirmModal
        isOpen={deletingRule !== null}
        onClose={() => setDeletingRule(null)}
        onConfirm={handleDeleteRule}
        title="Delete Cache Rule"
        message={`Are you sure you want to delete the rule "${deletingRule}"?`}
        confirmLabel="Delete"
        variant="danger"
      />
    </div>
  )
}
