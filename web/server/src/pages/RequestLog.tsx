import { useState, useEffect, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { RequestTable } from '../components/RequestLog/RequestTable'

export function RequestLog() {
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [limit, setLimit] = useState(100)
  const queryClient = useQueryClient()

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['requests', limit],
    queryFn: () => api.getRequests(limit),
    refetchInterval: autoRefresh ? 2000 : false,
  })

  const handleClear = useCallback(async () => {
    await api.clearRequests()
    queryClient.invalidateQueries({ queryKey: ['requests'] })
  }, [queryClient])

  // Keyboard shortcut for refresh
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'r' && !e.metaKey && !e.ctrlKey) {
        refetch()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [refetch])

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Request Log</h2>
          <p className="text-bifrost-muted mt-1">
            View recent proxy requests in real-time
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          {/* Limit Selector */}
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="select w-24"
          >
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={250}>250</option>
            <option value={500}>500</option>
          </select>

          {/* Auto-refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`btn ${autoRefresh ? 'btn-primary' : 'btn-secondary'}`}
          >
            {autoRefresh ? (
              <>
                <span className="w-2 h-2 rounded-full bg-white animate-pulse" />
                Live
              </>
            ) : (
              <>
                <span className="w-2 h-2 rounded-full bg-bifrost-muted" />
                Paused
              </>
            )}
          </button>

          {/* Refresh Button */}
          <button onClick={() => refetch()} className="btn btn-secondary">
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
          </button>

          {/* Clear Button */}
          <button onClick={handleClear} className="btn btn-secondary text-bifrost-error">
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
          </button>
        </div>
      </div>

      {/* Stats Summary */}
      {data?.enabled && data.requests.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="card py-3">
            <p className="text-sm text-gray-400">Total Shown</p>
            <p className="text-xl font-bold text-white">{data.requests.length}</p>
          </div>
          <div className="card py-3">
            <p className="text-sm text-gray-400">Success (2xx)</p>
            <p className="text-xl font-bold text-bifrost-success">
              {data.requests.filter((r) => r.status_code >= 200 && r.status_code < 300).length}
            </p>
          </div>
          <div className="card py-3">
            <p className="text-sm text-gray-400">Redirects (3xx)</p>
            <p className="text-xl font-bold text-bifrost-accent">
              {data.requests.filter((r) => r.status_code >= 300 && r.status_code < 400).length}
            </p>
          </div>
          <div className="card py-3">
            <p className="text-sm text-gray-400">Errors (4xx/5xx)</p>
            <p className="text-xl font-bold text-bifrost-error">
              {data.requests.filter((r) => r.status_code >= 400 || r.status_code === 0).length}
            </p>
          </div>
        </div>
      )}

      {/* Request Table */}
      <RequestTable
        requests={data?.requests}
        isLoading={isLoading}
        enabled={data?.enabled ?? true}
      />
    </div>
  )
}
