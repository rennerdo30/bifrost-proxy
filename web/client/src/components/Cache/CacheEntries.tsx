import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { CacheEntry } from '../../api/types'
import { api } from '../../api/client'
import { useToast } from '../Toast'

interface CacheEntriesProps {
  entries: CacheEntry[]
  total: number
  filter: string
  onFilterChange: (filter: string) => void
  onLoadMore: () => void
  hasMore: boolean
  isLoading: boolean
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr)
  return date.toLocaleString()
}

function truncateUrl(url: string, maxLength = 60): string {
  if (url.length <= maxLength) return url
  return url.substring(0, maxLength - 3) + '...'
}

export function CacheEntries({
  entries,
  total,
  filter,
  onFilterChange,
  onLoadMore,
  hasMore,
  isLoading,
}: CacheEntriesProps) {
  const [expandedEntry, setExpandedEntry] = useState<string | null>(null)
  const { showToast } = useToast()
  const queryClient = useQueryClient()

  const deleteMutation = useMutation({
    mutationFn: (key: string) => api.deleteCacheEntry(key),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cacheEntries'] })
      queryClient.invalidateQueries({ queryKey: ['cacheStats'] })
      showToast('Cache entry deleted', 'success')
    },
    onError: (err) => {
      showToast(`Failed to delete: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
    },
  })

  const handleDelete = (key: string, e: React.MouseEvent) => {
    e.stopPropagation()
    if (confirm('Delete this cache entry?')) {
      deleteMutation.mutate(key)
    }
  }

  const filteredEntries = filter
    ? entries.filter(
        (e) =>
          e.url.toLowerCase().includes(filter.toLowerCase()) ||
          e.host.toLowerCase().includes(filter.toLowerCase()) ||
          e.content_type.toLowerCase().includes(filter.toLowerCase())
      )
    : entries

  return (
    <div className="space-y-4">
      {/* Search/Filter */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-bifrost-muted"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
            />
          </svg>
          <input
            type="text"
            placeholder="Filter by URL, host, or content type..."
            value={filter}
            onChange={(e) => onFilterChange(e.target.value)}
            className="input pl-10"
          />
        </div>
        <span className="text-sm text-bifrost-muted">
          {filteredEntries.length} of {total} entries
        </span>
      </div>

      {/* Entries Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-bifrost-border bg-bifrost-bg/50">
                <th className="text-left py-3 px-4 text-xs font-medium text-bifrost-muted uppercase tracking-wider">
                  URL
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-bifrost-muted uppercase tracking-wider">
                  Content Type
                </th>
                <th className="text-right py-3 px-4 text-xs font-medium text-bifrost-muted uppercase tracking-wider">
                  Size
                </th>
                <th className="text-right py-3 px-4 text-xs font-medium text-bifrost-muted uppercase tracking-wider">
                  TTL
                </th>
                <th className="text-right py-3 px-4 text-xs font-medium text-bifrost-muted uppercase tracking-wider">
                  Hits
                </th>
                <th className="text-center py-3 px-4 text-xs font-medium text-bifrost-muted uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bifrost-border">
              {filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-bifrost-muted">
                    {filter ? 'No entries match your filter' : 'No cached entries'}
                  </td>
                </tr>
              ) : (
                filteredEntries.map((entry) => (
                  <>
                    <tr
                      key={entry.key}
                      className="hover:bg-bifrost-bg/50 cursor-pointer transition-colors"
                      onClick={() => setExpandedEntry(expandedEntry === entry.key ? null : entry.key)}
                    >
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <svg
                            className={`w-4 h-4 text-bifrost-muted transition-transform ${
                              expandedEntry === entry.key ? 'rotate-90' : ''
                            }`}
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                          <div>
                            <p className="text-sm font-mono truncate max-w-md" title={entry.url}>
                              {truncateUrl(entry.url)}
                            </p>
                            <p className="text-xs text-bifrost-muted">{entry.host}</p>
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-sm text-bifrost-muted">{entry.content_type || '-'}</span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span className="text-sm font-mono">{formatBytes(entry.size_bytes)}</span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span
                          className={`text-sm font-mono ${
                            entry.ttl_seconds <= 0
                              ? 'text-red-400'
                              : entry.ttl_seconds < 3600
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                          }`}
                        >
                          {entry.ttl_seconds <= 0 ? 'Expired' : formatDuration(entry.ttl_seconds)}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span className="text-sm font-mono">{entry.access_count}</span>
                      </td>
                      <td className="py-3 px-4 text-center">
                        <button
                          onClick={(e) => handleDelete(entry.key, e)}
                          disabled={deleteMutation.isPending}
                          className="btn btn-danger btn-sm"
                          aria-label="Delete cache entry"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                            />
                          </svg>
                        </button>
                      </td>
                    </tr>
                    {expandedEntry === entry.key && (
                      <tr key={`${entry.key}-details`} className="bg-bifrost-bg/30">
                        <td colSpan={6} className="py-4 px-4">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                            <div>
                              <p className="text-bifrost-muted text-xs">Full URL</p>
                              <p className="font-mono text-xs break-all">{entry.url}</p>
                            </div>
                            <div>
                              <p className="text-bifrost-muted text-xs">Cache Key</p>
                              <p className="font-mono text-xs break-all">{entry.key}</p>
                            </div>
                            <div>
                              <p className="text-bifrost-muted text-xs">Created</p>
                              <p className="font-mono text-xs">{formatDate(entry.created_at)}</p>
                            </div>
                            <div>
                              <p className="text-bifrost-muted text-xs">Expires</p>
                              <p className="font-mono text-xs">{formatDate(entry.expires_at)}</p>
                            </div>
                            <div>
                              <p className="text-bifrost-muted text-xs">Last Accessed</p>
                              <p className="font-mono text-xs">{formatDate(entry.accessed_at)}</p>
                            </div>
                            <div>
                              <p className="text-bifrost-muted text-xs">Storage Tier</p>
                              <p className="font-mono text-xs capitalize">{entry.tier || 'Unknown'}</p>
                            </div>
                            <div>
                              <p className="text-bifrost-muted text-xs">Content Length</p>
                              <p className="font-mono text-xs">{formatBytes(entry.content_length)}</p>
                            </div>
                            <div>
                              <p className="text-bifrost-muted text-xs">Access Count</p>
                              <p className="font-mono text-xs">{entry.access_count} hits</p>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Load More */}
      {hasMore && (
        <div className="flex justify-center">
          <button onClick={onLoadMore} disabled={isLoading} className="btn btn-secondary">
            {isLoading ? (
              <>
                <div className="animate-spin w-4 h-4 border-2 border-bifrost-accent border-t-transparent rounded-full" />
                Loading...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
                Load More
              </>
            )}
          </button>
        </div>
      )}
    </div>
  )
}
