import type { MeshPeerInfo, MeshPeerStatus, MeshConnectionType } from '../../api/types'
import { formatBytes } from '../../utils'

interface ExtendedPeer extends MeshPeerInfo {
  status?: MeshPeerStatus
  connection_type?: MeshConnectionType
  latency?: number
  last_seen?: string
  joined_at?: string
  bytes_sent?: number
  bytes_received?: number
}

interface MeshPeerDetailsProps {
  peer: MeshPeerInfo | null
  onClose: () => void
  onRemove: (peerId: string) => void
}

function getStatusBadge(status: MeshPeerStatus | undefined) {
  switch (status) {
    case 'connected':
      return <span className="badge badge-success">Connected</span>
    case 'relayed':
      return <span className="badge badge-info">Relayed</span>
    case 'connecting':
      return <span className="badge badge-warning">Connecting</span>
    case 'discovered':
      return <span className="badge badge-secondary">Discovered</span>
    case 'unreachable':
      return <span className="badge badge-error">Unreachable</span>
    case 'offline':
      return <span className="badge badge-error">Offline</span>
    default:
      return <span className="badge badge-secondary">Unknown</span>
  }
}

function getConnectionTypeLabel(type: MeshConnectionType | undefined) {
  switch (type) {
    case 'direct':
      return 'Direct P2P'
    case 'relayed':
      return 'TURN Relay'
    case 'multi_hop':
      return 'Multi-hop'
    default:
      return 'Unknown'
  }
}

function formatDuration(ms: number | undefined): string {
  if (ms === undefined) return 'N/A'
  if (ms < 1) return '<1ms'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms / 1000).toFixed(2)}s`
}

function formatTimestamp(ts: string | undefined): string {
  if (!ts) return 'N/A'
  try {
    const date = new Date(ts)
    return date.toLocaleString()
  } catch {
    return ts
  }
}

export function MeshPeerDetails({ peer, onClose, onRemove }: MeshPeerDetailsProps) {
  if (!peer) {
    return (
      <div className="h-full flex items-center justify-center text-bifrost-muted">
        <div className="text-center">
          <svg
            className="w-12 h-12 mx-auto mb-3 opacity-50"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M15.75 6a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0zM4.501 20.118a7.5 7.5 0 0114.998 0A17.933 17.933 0 0112 21.75c-2.676 0-5.216-.584-7.499-1.632z"
            />
          </svg>
          <p>Select a peer to view details</p>
        </div>
      </div>
    )
  }

  const extPeer = peer as ExtendedPeer

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-full bg-gradient-to-br from-bifrost-accent/20 to-cyan-500/20 flex items-center justify-center">
            <span className="text-lg font-bold text-bifrost-accent">
              {(peer.name || peer.id).charAt(0).toUpperCase()}
            </span>
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">{peer.name || peer.id}</h3>
            {getStatusBadge(extPeer.status)}
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded hover:bg-bifrost-bg text-bifrost-muted hover:text-white transition-colors"
          aria-label="Close details"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto space-y-4">
        {/* Identity */}
        <div className="card bg-bifrost-bg/50">
          <h4 className="text-sm font-medium text-bifrost-muted mb-3">Identity</h4>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-bifrost-muted">ID</dt>
              <dd className="text-white font-mono text-xs truncate max-w-[200px]" title={peer.id}>
                {peer.id}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-bifrost-muted">Virtual IP</dt>
              <dd className="text-white font-mono">{peer.virtual_ip || 'N/A'}</dd>
            </div>
            {peer.public_key && (
              <div className="flex justify-between">
                <dt className="text-bifrost-muted">Public Key</dt>
                <dd className="text-white font-mono text-xs truncate max-w-[200px]" title={peer.public_key}>
                  {peer.public_key.slice(0, 16)}...
                </dd>
              </div>
            )}
          </dl>
        </div>

        {/* Connection */}
        <div className="card bg-bifrost-bg/50">
          <h4 className="text-sm font-medium text-bifrost-muted mb-3">Connection</h4>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-bifrost-muted">Type</dt>
              <dd className="text-white">{getConnectionTypeLabel(extPeer.connection_type)}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-bifrost-muted">Latency</dt>
              <dd className="text-white font-mono">{formatDuration(extPeer.latency)}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-bifrost-muted">Last Seen</dt>
              <dd className="text-white text-xs">{formatTimestamp(extPeer.last_seen)}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-bifrost-muted">Joined</dt>
              <dd className="text-white text-xs">{formatTimestamp(extPeer.joined_at)}</dd>
            </div>
          </dl>
        </div>

        {/* Throughput */}
        {(extPeer.bytes_sent !== undefined || extPeer.bytes_received !== undefined) && (
          <div className="card bg-bifrost-bg/50">
            <h4 className="text-sm font-medium text-bifrost-muted mb-3">Throughput</h4>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-bifrost-muted mb-1">Sent</p>
                <p className="text-lg font-bold text-bifrost-success">
                  {formatBytes(extPeer.bytes_sent || 0)}
                </p>
              </div>
              <div>
                <p className="text-xs text-bifrost-muted mb-1">Received</p>
                <p className="text-lg font-bold text-cyan-400">
                  {formatBytes(extPeer.bytes_received || 0)}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Endpoints */}
        {peer.endpoints && peer.endpoints.length > 0 && (
          <div className="card bg-bifrost-bg/50">
            <h4 className="text-sm font-medium text-bifrost-muted mb-3">
              Endpoints ({peer.endpoints.length})
            </h4>
            <div className="space-y-2">
              {peer.endpoints.map((ep, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between text-sm bg-bifrost-bg rounded px-2 py-1.5"
                >
                  <span className="font-mono text-white">
                    {ep.address}:{ep.port}
                  </span>
                  <span className={`badge ${
                    ep.type === 'local' ? 'badge-secondary' :
                    ep.type === 'reflexive' ? 'badge-info' :
                    'badge-warning'
                  }`}>
                    {ep.type}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Metadata */}
        {peer.metadata && Object.keys(peer.metadata).length > 0 && (
          <div className="card bg-bifrost-bg/50">
            <h4 className="text-sm font-medium text-bifrost-muted mb-3">Metadata</h4>
            <dl className="space-y-2 text-sm">
              {Object.entries(peer.metadata).map(([key, value]) => (
                <div key={key} className="flex justify-between">
                  <dt className="text-bifrost-muted">{key}</dt>
                  <dd className="text-white truncate max-w-[200px]" title={value}>
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="mt-4 pt-4 border-t border-bifrost-border">
        <button
          onClick={() => onRemove(peer.id)}
          className="btn btn-secondary text-bifrost-error w-full"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
          Remove Peer
        </button>
      </div>
    </div>
  )
}
