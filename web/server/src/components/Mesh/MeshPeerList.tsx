import type { MeshPeerInfo, MeshPeerStatus, MeshConnectionType } from '../../api/types'

interface ExtendedPeer extends MeshPeerInfo {
  status?: MeshPeerStatus
  connection_type?: MeshConnectionType
  latency?: number
  last_seen?: string
  bytes_sent?: number
  bytes_received?: number
}

interface MeshPeerListProps {
  peers?: MeshPeerInfo[]
  selectedPeerId?: string
  isLoading: boolean
  onSelect: (peer: MeshPeerInfo) => void
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

function getConnectionIcon(connectionType: MeshConnectionType | undefined) {
  switch (connectionType) {
    case 'direct':
      return (
        <svg className="w-4 h-4 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      )
    case 'relayed':
      return (
        <svg className="w-4 h-4 text-bifrost-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
        </svg>
      )
    case 'multi_hop':
      return (
        <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />
        </svg>
      )
    default:
      return (
        <svg className="w-4 h-4 text-bifrost-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
        </svg>
      )
  }
}

export function MeshPeerList({
  peers,
  selectedPeerId,
  isLoading,
  onSelect,
  onRemove,
}: MeshPeerListProps) {
  if (isLoading && !peers) {
    return (
      <div className="space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-20 bg-bifrost-bg rounded animate-pulse" />
        ))}
      </div>
    )
  }

  if (!peers || peers.length === 0) {
    return (
      <div className="card text-center py-8">
        <svg
          className="w-12 h-12 mx-auto text-bifrost-muted mb-3"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M18 18.72a9.094 9.094 0 003.741-.479 3 3 0 00-4.682-2.72m.94 3.198l.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0112 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 016 18.719m12 0a5.971 5.971 0 00-.941-3.197m0 0A5.995 5.995 0 0012 12.75a5.995 5.995 0 00-5.058 2.772m0 0a3 3 0 00-4.681 2.72 8.986 8.986 0 003.74.477m.94-3.197a5.971 5.971 0 00-.94 3.197M15 6.75a3 3 0 11-6 0 3 3 0 016 0zm6 3a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0zm-13.5 0a2.25 2.25 0 11-4.5 0 2.25 2.25 0 014.5 0z"
          />
        </svg>
        <p className="text-bifrost-muted">No peers in this network</p>
        <p className="text-sm text-bifrost-muted mt-1">
          Peers will appear here when they connect
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {peers.map((peer) => {
        const extPeer = peer as ExtendedPeer
        return (
          <div
            key={peer.id}
            onClick={() => onSelect(peer)}
            className={`card cursor-pointer transition-all hover:border-bifrost-accent/50 ${
              selectedPeerId === peer.id
                ? 'border-bifrost-accent bg-bifrost-accent/5'
                : ''
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-bifrost-accent/20 to-cyan-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <span className="text-sm font-bold text-bifrost-accent">
                    {(peer.name || peer.id).charAt(0).toUpperCase()}
                  </span>
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="font-medium text-white truncate">{peer.name || peer.id}</h3>
                    {getConnectionIcon(extPeer.connection_type)}
                  </div>
                  <p className="text-sm text-bifrost-muted font-mono truncate">{peer.virtual_ip}</p>
                  <div className="flex items-center gap-2 mt-1">
                    {getStatusBadge(extPeer.status)}
                    {extPeer.latency !== undefined && (
                      <span className="text-xs text-bifrost-muted">
                        {extPeer.latency}ms
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onRemove(peer.id)
                }}
                className="p-1.5 rounded hover:bg-bifrost-error/10 text-bifrost-muted hover:text-bifrost-error transition-colors flex-shrink-0"
                aria-label="Remove peer"
              >
                <svg
                  className="w-4 h-4"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {peer.endpoints && peer.endpoints.length > 0 && (
              <div className="mt-2 pt-2 border-t border-bifrost-border">
                <p className="text-xs text-bifrost-muted">
                  {peer.endpoints.length} endpoint{peer.endpoints.length !== 1 ? 's' : ''}: {' '}
                  {peer.endpoints.slice(0, 2).map((ep, i) => (
                    <span key={i} className="font-mono">
                      {ep.address}:{ep.port}
                      {i < Math.min(peer.endpoints.length - 1, 1) ? ', ' : ''}
                    </span>
                  ))}
                  {peer.endpoints.length > 2 && <span> +{peer.endpoints.length - 2}</span>}
                </p>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
