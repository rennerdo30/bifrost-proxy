import type { Backend } from '../../api/types'
import { formatBytes } from '../../utils'

interface BackendListProps {
  backends: Backend[] | undefined
  isLoading: boolean
  onEdit?: (name: string) => void
  onDelete?: (name: string) => void
  onTest?: (name: string) => void
}

export function BackendList({ backends, isLoading, onEdit, onDelete, onTest }: BackendListProps) {
  const hasActions = onEdit || onDelete || onTest

  if (isLoading) {
    return (
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-bifrost-border">
                <th className="table-header">Name</th>
                <th className="table-header">Type</th>
                <th className="table-header">Status</th>
                <th className="table-header">Connections</th>
                <th className="table-header">Data Transfer</th>
                <th className="table-header">Errors</th>
                {hasActions && <th className="table-header">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {[...Array(3)].map((_, i) => (
                <tr key={i} className="border-b border-bifrost-border/50">
                  <td className="table-cell">
                    <div className="h-4 bg-bifrost-border rounded w-24 animate-pulse" />
                  </td>
                  <td className="table-cell">
                    <div className="h-4 bg-bifrost-border rounded w-16 animate-pulse" />
                  </td>
                  <td className="table-cell">
                    <div className="h-4 bg-bifrost-border rounded w-16 animate-pulse" />
                  </td>
                  <td className="table-cell">
                    <div className="h-4 bg-bifrost-border rounded w-20 animate-pulse" />
                  </td>
                  <td className="table-cell">
                    <div className="h-4 bg-bifrost-border rounded w-24 animate-pulse" />
                  </td>
                  <td className="table-cell">
                    <div className="h-4 bg-bifrost-border rounded w-12 animate-pulse" />
                  </td>
                  {hasActions && (
                    <td className="table-cell">
                      <div className="h-4 bg-bifrost-border rounded w-20 animate-pulse" />
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  if (!backends || backends.length === 0) {
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
            d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z"
          />
        </svg>
        <p className="text-gray-400">No backends configured</p>
        <p className="text-sm text-bifrost-muted mt-1">
          Add backends to your configuration to get started
        </p>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-bifrost-border">
              <th className="table-header">Name</th>
              <th className="table-header">Type</th>
              <th className="table-header">Status</th>
              <th className="table-header text-right">Active</th>
              <th className="table-header text-right">Total</th>
              <th className="table-header text-right">Sent</th>
              <th className="table-header text-right">Received</th>
              <th className="table-header text-right">Errors</th>
              {hasActions && <th className="table-header text-center">Actions</th>}
            </tr>
          </thead>
          <tbody>
            {backends.map((backend, index) => (
              <tr
                key={backend.name}
                className="border-b border-bifrost-border/50 hover:bg-bifrost-card-hover transition-colors animate-slide-up"
                style={{ animationDelay: `${index * 30}ms` }}
              >
                <td className="table-cell">
                  <span className="font-medium text-white">{backend.name}</span>
                </td>
                <td className="table-cell">
                  <span className="badge badge-info">{backend.type}</span>
                </td>
                <td className="table-cell">
                  <span
                    className={`badge ${
                      backend.healthy ? 'badge-success' : 'badge-error'
                    }`}
                  >
                    {backend.healthy ? 'Healthy' : 'Unhealthy'}
                  </span>
                </td>
                <td className="table-cell text-right font-mono">
                  {backend.stats.active_connections}
                </td>
                <td className="table-cell text-right font-mono">
                  {backend.stats.total_connections.toLocaleString()}
                </td>
                <td className="table-cell text-right font-mono text-bifrost-accent">
                  {formatBytes(backend.stats.bytes_sent)}
                </td>
                <td className="table-cell text-right font-mono text-emerald-400">
                  {formatBytes(backend.stats.bytes_received)}
                </td>
                <td className="table-cell text-right">
                  {backend.stats.errors > 0 ? (
                    <span className="font-mono text-bifrost-error">
                      {backend.stats.errors}
                    </span>
                  ) : (
                    <span className="text-bifrost-muted">0</span>
                  )}
                </td>
                {hasActions && (
                  <td className="table-cell">
                    <div className="flex items-center justify-center gap-1">
                      {onTest && (
                        <button
                          onClick={() => onTest(backend.name)}
                          className="p-1.5 text-bifrost-muted hover:text-bifrost-accent hover:bg-bifrost-accent/10 rounded transition-colors"
                          title="Test backend connectivity"
                          aria-label={`Test backend ${backend.name}`}
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                          </svg>
                        </button>
                      )}
                      {onEdit && (
                        <button
                          onClick={() => onEdit(backend.name)}
                          className="p-1.5 text-bifrost-muted hover:text-white hover:bg-white/10 rounded transition-colors"
                          title="Edit backend"
                          aria-label={`Edit backend ${backend.name}`}
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                      )}
                      {onDelete && (
                        <button
                          onClick={() => onDelete(backend.name)}
                          className="p-1.5 text-bifrost-muted hover:text-bifrost-error hover:bg-bifrost-error/10 rounded transition-colors"
                          title="Delete backend"
                          aria-label={`Delete backend ${backend.name}`}
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      )}
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
