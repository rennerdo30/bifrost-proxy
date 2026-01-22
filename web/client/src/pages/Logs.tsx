import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, LogEntry } from '../api/client'

export function Logs() {
  const [filter, setFilter] = useState('')
  const [level, setLevel] = useState<string>('')
  const [autoScroll, setAutoScroll] = useState(true)
  const [streaming, setStreaming] = useState(false)
  const [streamLogs, setStreamLogs] = useState<LogEntry[]>([])
  const logsEndRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Fetch historical logs
  const { data: logsData, isLoading, refetch } = useQuery({
    queryKey: ['logs', level],
    queryFn: () => api.getLogs(200, 0, level || undefined),
    refetchInterval: streaming ? false : 5000,
  })

  // Start/stop SSE streaming
  useEffect(() => {
    if (streaming) {
      const es = new EventSource('/api/v1/logs/stream')
      eventSourceRef.current = es

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (data.type !== 'connected') {
            setStreamLogs(prev => [...prev.slice(-499), data])
          }
        } catch {
          // Ignore parse errors
        }
      }

      es.onerror = () => {
        es.close()
        setStreaming(false)
      }

      return () => {
        es.close()
      }
    } else {
      if (eventSourceRef.current) {
        eventSourceRef.current.close()
        eventSourceRef.current = null
      }
    }
  }, [streaming])

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [streamLogs, logsData, autoScroll])

  const allLogs = streaming ? streamLogs : (logsData?.entries || [])

  const filteredLogs = filter
    ? allLogs.filter(log =>
        log.message.toLowerCase().includes(filter.toLowerCase()) ||
        JSON.stringify(log.fields).toLowerCase().includes(filter.toLowerCase())
      )
    : allLogs

  const getLevelColor = (logLevel: string) => {
    switch (logLevel.toLowerCase()) {
      case 'error': return 'text-bifrost-error'
      case 'warn': case 'warning': return 'text-bifrost-warning'
      case 'info': return 'text-bifrost-accent'
      case 'debug': return 'text-bifrost-muted'
      default: return 'text-bifrost-text'
    }
  }

  const getLevelBg = (logLevel: string) => {
    switch (logLevel.toLowerCase()) {
      case 'error': return 'bg-bifrost-error/10 border-bifrost-error/30'
      case 'warn': case 'warning': return 'bg-bifrost-warning/10 border-bifrost-warning/30'
      default: return 'bg-bifrost-card border-bifrost-border/50'
    }
  }

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-bifrost-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Filter logs..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="input pl-10"
          />
        </div>

        <select
          value={level}
          onChange={(e) => setLevel(e.target.value)}
          className="input w-auto"
        >
          <option value="">All Levels</option>
          <option value="error">Error</option>
          <option value="warn">Warning</option>
          <option value="info">Info</option>
          <option value="debug">Debug</option>
        </select>

        <button
          onClick={() => setStreaming(!streaming)}
          className={`btn ${streaming ? 'btn-success' : 'btn-secondary'}`}
        >
          <svg className={`w-4 h-4 mr-1 ${streaming ? 'animate-pulse' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.636 18.364a9 9 0 010-12.728m12.728 0a9 9 0 010 12.728m-9.9-2.829a5 5 0 010-7.07m7.072 0a5 5 0 010 7.07M13 12a1 1 0 11-2 0 1 1 0 012 0z" />
          </svg>
          {streaming ? 'Stop Stream' : 'Live Stream'}
        </button>

        <label className="flex items-center gap-2 text-sm text-bifrost-muted">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-card text-bifrost-accent focus:ring-bifrost-accent"
          />
          Auto-scroll
        </label>

        <button
          onClick={() => {
            setStreamLogs([])
            refetch()
          }}
          className="btn btn-secondary"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="flex items-center gap-4 text-sm">
        <span className="text-bifrost-muted">
          Showing {filteredLogs.length} logs
        </span>
        {streaming && (
          <span className="flex items-center gap-1 text-bifrost-success">
            <span className="w-2 h-2 bg-bifrost-success rounded-full animate-pulse" />
            Live
          </span>
        )}
      </div>

      {/* Log List */}
      <div className="card p-0 overflow-hidden">
        <div className="max-h-[600px] overflow-y-auto font-mono text-sm">
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin w-6 h-6 border-2 border-bifrost-accent border-t-transparent rounded-full" />
            </div>
          ) : filteredLogs.length === 0 ? (
            <div className="text-center py-12 text-bifrost-muted">
              {filter ? 'No logs match your filter' : 'No logs available'}
            </div>
          ) : (
            <div className="divide-y divide-bifrost-border/30">
              {filteredLogs.map((log, idx) => (
                <div key={idx} className={`p-3 ${getLevelBg(log.level)} border-l-2`}>
                  <div className="flex items-start gap-3">
                    <span className="text-xs text-bifrost-muted whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`text-xs font-semibold uppercase w-12 ${getLevelColor(log.level)}`}>
                      {log.level}
                    </span>
                    <span className="text-bifrost-text flex-1 break-all">
                      {log.message}
                    </span>
                  </div>
                  {log.fields && Object.keys(log.fields).length > 0 && (
                    <div className="mt-2 pl-[88px] flex flex-wrap gap-2">
                      {Object.entries(log.fields).map(([key, value]) => (
                        value !== '' && value !== null && (
                          <span key={key} className="text-xs px-1.5 py-0.5 bg-bifrost-border/50 rounded">
                            <span className="text-bifrost-muted">{key}:</span>
                            <span className="text-bifrost-text ml-1">{String(value)}</span>
                          </span>
                        )
                      ))}
                    </div>
                  )}
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-bifrost-muted">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded bg-bifrost-error" /> Error
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded bg-bifrost-warning" /> Warning
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded bg-bifrost-accent" /> Info
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded bg-bifrost-muted" /> Debug
        </span>
      </div>
    </div>
  )
}
