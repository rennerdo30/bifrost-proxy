import React, { useState } from 'react'
import type { CacheEntry } from '../../api/types'
import { formatBytes } from '../../utils'

interface CacheEntryListProps {
  entries: CacheEntry[] | undefined
  total: number
  isLoading: boolean
  onDelete: (key: string) => void
  onPurgeDomain: (domain: string) => void
}

function getTierColor(tier: string): string {
  switch (tier.toLowerCase()) {
    case 'memory':
      return 'badge-success'
    case 'disk':
      return 'badge-info'
    default:
      return 'badge-secondary'
  }
}

function formatExpiry(expiresAt: string): { text: string; isExpired: boolean } {
  const now = new Date()
  const expiry = new Date(expiresAt)
  const diff = expiry.getTime() - now.getTime()

  if (diff < 0) {
    return { text: 'Expired', isExpired: true }
  }

  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return { text: `${seconds}s`, isExpired: false }
  if (seconds < 3600) return { text: `${Math.floor(seconds / 60)}m`, isExpired: false }
  if (seconds < 86400) return { text: `${Math.floor(seconds / 3600)}h`, isExpired: false }
  return { text: `${Math.floor(seconds / 86400)}d`, isExpired: false }
}

export function CacheEntryList({
  entries,
  total,
  isLoading,
  onDelete,
  onPurgeDomain,
}: CacheEntryListProps) {
  const [expandedKey, setExpandedKey] = useState<string | null>(null)

  if (isLoading) {
    return (
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-bifrost-border">
                <th className="table-header">Host</th>
                <th className="table-header">URL</th>
                <th className="table-header">Content Type</th>
                <th className="table-header text-right">Size</th>
                <th className="table-header text-right">Tier</th>
                <th className="table-header text-right">Expires</th>
                <th className="table-header text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {[...Array(5)].map((_, i) => (
                <tr key={i} className="border-b border-bifrost-border/50">
                  {[...Array(7)].map((__, j) => (
                    <td key={j} className="table-cell">
                      <div className="h-4 bg-bifrost-border rounded w-20 animate-pulse" />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  if (!entries || entries.length === 0) {
    return (
      <div className="card text-center py-12">
        <svg
          className="w-12 h-12 mx-auto text-bifrost-muted mb-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5m8.25 3v6.75m0 0l-3-3m3 3l3-3M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z"
          />
        </svg>
        <p className="text-gray-400">No cached entries</p>
        <p className="text-sm text-bifrost-muted mt-1">
          Cached responses will appear here as they are stored
        </p>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden">
      <div className="px-4 py-3 border-b border-bifrost-border flex items-center justify-between">
        <span className="text-sm text-bifrost-muted">
          Showing {entries.length} of {total} entries
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-bifrost-border">
              <th className="table-header">Host</th>
              <th className="table-header">URL</th>
              <th className="table-header">Content Type</th>
              <th className="table-header text-right">Size</th>
              <th className="table-header text-right">Tier</th>
              <th className="table-header text-right">Expires</th>
              <th className="table-header text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, index) => {
              const expiry = formatExpiry(entry.expires_at)
              return (
                <React.Fragment key={entry.key}>
                  <tr
                    onClick={() => setExpandedKey(expandedKey === entry.key ? null : entry.key)}
                    className="border-b border-bifrost-border/50 hover:bg-bifrost-card-hover transition-colors cursor-pointer animate-slide-up"
                    style={{ animationDelay: `${index * 20}ms` }}
                  >
                    <td className="table-cell">
                      <span className="font-medium text-white truncate max-w-[150px] block">
                        {entry.host}
                      </span>
                    </td>
                    <td className="table-cell">
                      <span className="text-gray-400 truncate max-w-[300px] block font-mono text-xs">
                        {entry.url}
                      </span>
                    </td>
                    <td className="table-cell">
                      <span className="text-bifrost-muted text-xs font-mono">
                        {entry.content_type || '-'}
                      </span>
                    </td>
                    <td className="table-cell text-right font-mono text-sm">
                      {formatBytes(entry.size)}
                    </td>
                    <td className="table-cell text-right">
                      <span className={`badge ${getTierColor(entry.tier)}`}>
                        {entry.tier}
                      </span>
                    </td>
                    <td className="table-cell text-right">
                      <span className={`text-sm ${expiry.isExpired ? 'text-bifrost-error' : 'text-bifrost-muted'}`}>
                        {expiry.text}
                      </span>
                    </td>
                    <td className="table-cell text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          onDelete(entry.key)
                        }}
                        className="p-1 text-bifrost-muted hover:text-bifrost-error transition-colors"
                        aria-label="Delete cache entry"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </td>
                  </tr>
                  {expandedKey === entry.key && (
                    <tr className="bg-bifrost-bg/50">
                      <td colSpan={7} className="p-4">
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <p className="text-bifrost-muted text-xs uppercase">Cache Key</p>
                            <p className="text-gray-300 font-mono text-xs break-all mt-1">
                              {entry.key}
                            </p>
                          </div>
                          <div>
                            <p className="text-bifrost-muted text-xs uppercase">Created</p>
                            <p className="text-gray-300 font-mono text-sm mt-1">
                              {new Date(entry.created_at).toLocaleString()}
                            </p>
                          </div>
                          <div>
                            <p className="text-bifrost-muted text-xs uppercase">Expires</p>
                            <p className="text-gray-300 font-mono text-sm mt-1">
                              {new Date(entry.expires_at).toLocaleString()}
                            </p>
                          </div>
                          <div>
                            <p className="text-bifrost-muted text-xs uppercase">Access Count</p>
                            <p className="text-gray-300 font-mono text-sm mt-1">
                              {entry.access_count}
                            </p>
                          </div>
                          <div className="col-span-2 md:col-span-4 flex gap-2 pt-2">
                            <button
                              onClick={() => onPurgeDomain(entry.host)}
                              className="btn btn-secondary text-sm"
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                              </svg>
                              Purge {entry.host}
                            </button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
