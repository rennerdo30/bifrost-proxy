import { useState, useEffect, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import type { Connection, ClientSummary } from '../api/types'
import { formatBytes, formatDuration } from '../utils'

function ConnectionRow({ conn }: { conn: Connection }) {
  return (
    <tr className="border-b border-bifrost-border hover:bg-bifrost-bg-tertiary/50">
      <td className="px-4 py-3">
        <div className="font-mono text-sm text-white">{conn.client_ip}</div>
        <div className="text-xs text-bifrost-muted">{conn.client_port}</div>
      </td>
      <td className="px-4 py-3">
        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
          conn.protocol === 'HTTP' ? 'bg-blue-500/20 text-blue-400' :
          conn.protocol === 'SOCKS5' ? 'bg-purple-500/20 text-purple-400' :
          'bg-gray-500/20 text-gray-400'
        }`}>
          {conn.protocol || 'UNKNOWN'}
        </span>
      </td>
      <td className="px-4 py-3 text-sm text-gray-300 truncate max-w-xs">
        {conn.host || '-'}
      </td>
      <td className="px-4 py-3 text-sm text-gray-300">
        {conn.backend || '-'}
      </td>
      <td className="px-4 py-3 text-sm text-gray-400">
        {formatDuration(conn.start_time)}
      </td>
      <td className="px-4 py-3 text-sm">
        <span className="text-bifrost-success">{formatBytes(conn.bytes_sent)}</span>
        <span className="text-bifrost-muted mx-1">/</span>
        <span className="text-blue-400">{formatBytes(conn.bytes_recv)}</span>
      </td>
    </tr>
  )
}

function ClientRow({ client }: { client: ClientSummary }) {
  return (
    <tr className="border-b border-bifrost-border hover:bg-bifrost-bg-tertiary/50">
      <td className="px-4 py-3">
        <div className="font-mono text-sm text-white">{client.client_ip}</div>
      </td>
      <td className="px-4 py-3 text-center">
        <span className="px-2 py-0.5 rounded bg-bifrost-purple/20 text-bifrost-purple font-medium">
          {client.connections}
        </span>
      </td>
      <td className="px-4 py-3 text-sm text-gray-400">
        {formatDuration(client.first_seen)}
      </td>
      <td className="px-4 py-3 text-sm">
        <span className="text-bifrost-success">{formatBytes(client.bytes_sent)}</span>
        <span className="text-bifrost-muted mx-1">/</span>
        <span className="text-blue-400">{formatBytes(client.bytes_recv)}</span>
      </td>
    </tr>
  )
}

export function Clients() {
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [view, setView] = useState<'connections' | 'clients'>('clients')

  const { data: connectionsData, isLoading: connectionsLoading, refetch: refetchConnections } = useQuery({
    queryKey: ['connections'],
    queryFn: () => api.getConnections(),
    refetchInterval: autoRefresh ? 2000 : false,
  })

  const { data: clientsData, isLoading: clientsLoading, refetch: refetchClients } = useQuery({
    queryKey: ['clients'],
    queryFn: () => api.getClients(),
    refetchInterval: autoRefresh ? 2000 : false,
  })

  const refetch = useCallback(() => {
    refetchConnections()
    refetchClients()
  }, [refetchConnections, refetchClients])

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

  const isLoading = view === 'connections' ? connectionsLoading : clientsLoading

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Connected Clients</h2>
          <p className="text-bifrost-muted mt-1">
            View active client connections in real-time
          </p>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3">
          {/* View Toggle */}
          <div className="flex rounded-lg bg-bifrost-bg-secondary border border-bifrost-border overflow-hidden">
            <button
              onClick={() => setView('clients')}
              className={`px-3 py-1.5 text-sm font-medium transition-colors ${
                view === 'clients'
                  ? 'bg-bifrost-purple text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              By Client
            </button>
            <button
              onClick={() => setView('connections')}
              className={`px-3 py-1.5 text-sm font-medium transition-colors ${
                view === 'connections'
                  ? 'bg-bifrost-purple text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              All Connections
            </button>
          </div>

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
          <button onClick={refetch} className="btn btn-secondary" aria-label="Refresh clients">
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
        </div>
      </div>

      {/* Stats Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card py-3">
          <p className="text-sm text-gray-400">Connected Clients</p>
          <p className="text-xl font-bold text-white">{clientsData?.count ?? 0}</p>
        </div>
        <div className="card py-3">
          <p className="text-sm text-gray-400">Active Connections</p>
          <p className="text-xl font-bold text-bifrost-purple">{connectionsData?.count ?? 0}</p>
        </div>
        <div className="card py-3">
          <p className="text-sm text-gray-400">HTTP</p>
          <p className="text-xl font-bold text-blue-400">
            {connectionsData?.connections?.filter(c => c.protocol === 'HTTP').length ?? 0}
          </p>
        </div>
        <div className="card py-3">
          <p className="text-sm text-gray-400">SOCKS5</p>
          <p className="text-xl font-bold text-purple-400">
            {connectionsData?.connections?.filter(c => c.protocol === 'SOCKS5').length ?? 0}
          </p>
        </div>
      </div>

      {/* Content */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="p-8 text-center text-bifrost-muted">
            <div className="animate-spin w-8 h-8 border-2 border-bifrost-purple border-t-transparent rounded-full mx-auto mb-4" />
            Loading...
          </div>
        ) : view === 'clients' ? (
          clientsData?.clients && clientsData.clients.length > 0 ? (
            <table className="w-full">
              <thead>
                <tr className="bg-bifrost-bg-tertiary text-left text-sm text-gray-400">
                  <th className="px-4 py-3 font-medium">Client IP</th>
                  <th className="px-4 py-3 font-medium text-center">Connections</th>
                  <th className="px-4 py-3 font-medium">Connected Since</th>
                  <th className="px-4 py-3 font-medium">Data (Sent / Recv)</th>
                </tr>
              </thead>
              <tbody>
                {clientsData.clients.map((client) => (
                  <ClientRow key={client.client_ip} client={client} />
                ))}
              </tbody>
            </table>
          ) : (
            <div className="p-8 text-center text-bifrost-muted">
              <svg
                className="w-12 h-12 mx-auto mb-4 opacity-50"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                />
              </svg>
              <p>No connected clients</p>
              <p className="text-sm mt-2">Clients will appear here when they connect to the proxy</p>
            </div>
          )
        ) : connectionsData?.connections && connectionsData.connections.length > 0 ? (
          <table className="w-full">
            <thead>
              <tr className="bg-bifrost-bg-tertiary text-left text-sm text-gray-400">
                <th className="px-4 py-3 font-medium">Client</th>
                <th className="px-4 py-3 font-medium">Protocol</th>
                <th className="px-4 py-3 font-medium">Host</th>
                <th className="px-4 py-3 font-medium">Backend</th>
                <th className="px-4 py-3 font-medium">Duration</th>
                <th className="px-4 py-3 font-medium">Data (Sent / Recv)</th>
              </tr>
            </thead>
            <tbody>
              {connectionsData.connections.map((conn) => (
                <ConnectionRow key={conn.id} conn={conn} />
              ))}
            </tbody>
          </table>
        ) : (
          <div className="p-8 text-center text-bifrost-muted">
            <svg
              className="w-12 h-12 mx-auto mb-4 opacity-50"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z"
              />
            </svg>
            <p>No active connections</p>
            <p className="text-sm mt-2">Connections will appear here in real-time</p>
          </div>
        )}
      </div>
    </div>
  )
}
