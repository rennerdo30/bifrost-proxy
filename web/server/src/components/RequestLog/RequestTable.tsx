import { useState } from 'react'
import type { RequestLogEntry } from '../../api/types'

interface RequestTableProps {
  requests: RequestLogEntry[] | undefined
  isLoading: boolean
  enabled: boolean
}

function formatDuration(ms: number): string {
  if (ms < 1) return '<1ms'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function getStatusColor(status: number): string {
  if (status >= 200 && status < 300) return 'badge-success'
  if (status >= 300 && status < 400) return 'badge-info'
  if (status >= 400 && status < 500) return 'badge-warning'
  return 'badge-error'
}

function getMethodColor(method: string): string {
  switch (method.toUpperCase()) {
    case 'GET':
      return 'text-bifrost-success'
    case 'POST':
      return 'text-bifrost-accent'
    case 'PUT':
      return 'text-bifrost-warning'
    case 'DELETE':
      return 'text-bifrost-error'
    case 'CONNECT':
      return 'text-purple-400'
    default:
      return 'text-gray-400'
  }
}

export function RequestTable({ requests, isLoading, enabled }: RequestTableProps) {
  const [expandedId, setExpandedId] = useState<number | null>(null)

  if (!enabled) {
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
            d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
          />
        </svg>
        <p className="text-gray-400">Request logging is disabled</p>
        <p className="text-sm text-bifrost-muted mt-1">
          Enable <code className="bg-bifrost-bg px-2 py-0.5 rounded">enable_request_log: true</code> in your config
        </p>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-bifrost-border">
                <th className="table-header">Time</th>
                <th className="table-header">Method</th>
                <th className="table-header">Host</th>
                <th className="table-header">Path</th>
                <th className="table-header">Status</th>
                <th className="table-header">Duration</th>
              </tr>
            </thead>
            <tbody>
              {[...Array(5)].map((_, i) => (
                <tr key={i} className="border-b border-bifrost-border/50">
                  {[...Array(6)].map((__, j) => (
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

  if (!requests || requests.length === 0) {
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
            d="M3.75 12h16.5m-16.5 3.75h16.5M3.75 19.5h16.5M5.625 4.5h12.75a1.875 1.875 0 010 3.75H5.625a1.875 1.875 0 010-3.75z"
          />
        </svg>
        <p className="text-gray-400">No requests logged yet</p>
        <p className="text-sm text-bifrost-muted mt-1">
          Requests will appear here as they are processed
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
              <th className="table-header">Time</th>
              <th className="table-header">Method</th>
              <th className="table-header">Host</th>
              <th className="table-header">Path</th>
              <th className="table-header text-right">Status</th>
              <th className="table-header text-right">Duration</th>
              <th className="table-header text-right">Size</th>
            </tr>
          </thead>
          <tbody>
            {requests.map((request, index) => (
              <>
                <tr
                  key={request.id}
                  onClick={() => setExpandedId(expandedId === request.id ? null : request.id)}
                  className="border-b border-bifrost-border/50 hover:bg-bifrost-card-hover transition-colors cursor-pointer animate-slide-up"
                  style={{ animationDelay: `${index * 20}ms` }}
                >
                  <td className="table-cell">
                    <span className="text-bifrost-muted text-xs font-mono">
                      {new Date(request.timestamp).toLocaleTimeString()}
                    </span>
                  </td>
                  <td className="table-cell">
                    <span className={`font-mono font-medium ${getMethodColor(request.method)}`}>
                      {request.method}
                    </span>
                  </td>
                  <td className="table-cell">
                    <span className="font-medium text-white truncate max-w-[200px] block">
                      {request.host}
                    </span>
                  </td>
                  <td className="table-cell">
                    <span className="text-gray-400 truncate max-w-[300px] block font-mono text-xs">
                      {request.path || '/'}
                    </span>
                  </td>
                  <td className="table-cell text-right">
                    {request.status_code > 0 ? (
                      <span className={`badge ${getStatusColor(request.status_code)}`}>
                        {request.status_code}
                      </span>
                    ) : (
                      <span className="badge badge-error">ERR</span>
                    )}
                  </td>
                  <td className="table-cell text-right font-mono text-sm">
                    {formatDuration(request.duration_ms)}
                  </td>
                  <td className="table-cell text-right font-mono text-sm text-bifrost-muted">
                    {formatBytes(request.bytes_sent + request.bytes_recv)}
                  </td>
                </tr>
                {expandedId === request.id && (
                  <tr className="bg-bifrost-bg/50">
                    <td colSpan={7} className="p-4">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div>
                          <p className="text-bifrost-muted text-xs uppercase">Full URL</p>
                          <p className="text-gray-300 font-mono text-xs break-all mt-1">
                            {request.url}
                          </p>
                        </div>
                        <div>
                          <p className="text-bifrost-muted text-xs uppercase">Client IP</p>
                          <p className="text-gray-300 font-mono mt-1">{request.client_ip || '-'}</p>
                        </div>
                        <div>
                          <p className="text-bifrost-muted text-xs uppercase">Backend</p>
                          <p className="text-gray-300 mt-1">{request.backend || '-'}</p>
                        </div>
                        <div>
                          <p className="text-bifrost-muted text-xs uppercase">Protocol</p>
                          <p className="text-gray-300 mt-1">{request.protocol || 'HTTP'}</p>
                        </div>
                        {request.user_agent && (
                          <div className="col-span-2 md:col-span-4">
                            <p className="text-bifrost-muted text-xs uppercase">User Agent</p>
                            <p className="text-gray-300 font-mono text-xs break-all mt-1">
                              {request.user_agent}
                            </p>
                          </div>
                        )}
                        {request.error && (
                          <div className="col-span-2 md:col-span-4">
                            <p className="text-bifrost-error text-xs uppercase">Error</p>
                            <p className="text-bifrost-error font-mono text-xs mt-1">
                              {request.error}
                            </p>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
