import type { DebugEntry } from '../../api/types'

interface TrafficTableProps {
  entries: DebugEntry[]
}

const methodColors: Record<string, string> = {
  GET: 'text-bifrost-success',
  POST: 'text-bifrost-accent',
  PUT: 'text-bifrost-warning',
  DELETE: 'text-bifrost-error',
  PATCH: 'text-purple-400',
  CONNECT: 'text-cyan-400',
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp)
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function formatDuration(ms: number): string {
  if (ms < 1) return '<1ms'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

export function TrafficTable({ entries }: TrafficTableProps) {
  if (entries.length === 0) {
    return (
      <div className="card text-center py-12">
        <svg className="w-12 h-12 mx-auto text-bifrost-muted mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4" />
        </svg>
        <p className="text-bifrost-muted">No traffic entries yet</p>
        <p className="text-sm text-bifrost-muted/60 mt-1">Requests will appear here as they are proxied</p>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden p-0">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-bifrost-bg/50 border-b border-bifrost-border">
            <tr>
              <th className="table-header">Time</th>
              <th className="table-header">Method</th>
              <th className="table-header">Host</th>
              <th className="table-header">Path</th>
              <th className="table-header">Status</th>
              <th className="table-header">Duration</th>
              <th className="table-header">Route</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bifrost-border">
            {entries.map((entry) => (
              <tr key={entry.id} className="hover:bg-bifrost-card-hover transition-colors">
                <td className="table-cell font-mono text-xs text-bifrost-muted">
                  {formatTime(entry.timestamp)}
                </td>
                <td className="table-cell">
                  <span className={`font-mono font-medium ${methodColors[entry.method] || 'text-gray-400'}`}>
                    {entry.method}
                  </span>
                </td>
                <td className="table-cell font-mono text-xs max-w-[200px] truncate" title={entry.host}>
                  {entry.host}
                </td>
                <td className="table-cell font-mono text-xs max-w-[250px] truncate text-bifrost-muted" title={entry.path}>
                  {entry.path}
                </td>
                <td className="table-cell">
                  <span className={`badge ${
                    entry.status_code >= 500 ? 'badge-error' :
                    entry.status_code >= 400 ? 'badge-warning' :
                    entry.status_code >= 300 ? 'badge-info' :
                    'badge-success'
                  }`}>
                    {entry.status_code || '—'}
                  </span>
                </td>
                <td className="table-cell font-mono text-xs text-bifrost-muted">
                  {formatDuration(entry.duration_ms)}
                </td>
                <td className="table-cell">
                  <span className={`badge ${entry.route === 'server' ? 'badge-server' : 'badge-direct'}`}>
                    {entry.route}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
