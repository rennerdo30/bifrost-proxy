import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import type { MeshPeer, MeshRoute } from '../api/types'
import { formatBytes } from '../utils/formatting'
import { useToast } from '../components/Toast'

export function Mesh() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [selectedPeer, setSelectedPeer] = useState<MeshPeer | null>(null)
  const [showTopology, setShowTopology] = useState(true)

  const { data: meshStatus, isLoading: statusLoading } = useQuery({
    queryKey: ['mesh-status'],
    queryFn: api.getMeshStatus,
    refetchInterval: 5000,
  })

  const { data: peers = [] } = useQuery({
    queryKey: ['mesh-peers'],
    queryFn: api.getMeshPeers,
    refetchInterval: 5000,
  })

  const { data: routes = [] } = useQuery({
    queryKey: ['mesh-routes'],
    queryFn: api.getMeshRoutes,
    refetchInterval: 10000,
  })

  const [meshError, setMeshError] = useState<string | null>(null)

  const enableMutation = useMutation({
    mutationFn: api.enableMesh,
    onSuccess: () => {
      setMeshError(null)
      queryClient.invalidateQueries({ queryKey: ['mesh-status'] })
      showToast('Mesh network enabled', 'success')
    },
    onError: (error: Error) => {
      setMeshError(error.message || 'Failed to enable mesh. Make sure mesh is configured in Settings.')
    },
  })

  const disableMutation = useMutation({
    mutationFn: api.disableMesh,
    onSuccess: () => {
      setMeshError(null)
      queryClient.invalidateQueries({ queryKey: ['mesh-status'] })
      showToast('Mesh network disabled', 'success')
    },
    onError: (error: Error) => {
      setMeshError(error.message || 'Failed to disable mesh')
    },
  })

  const isEnabled = meshStatus?.status === 'running'
  const isToggling = enableMutation.isPending || disableMutation.isPending

  return (
    <div className="space-y-6">
      {/* Mesh Status Card */}
      <div className="card">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center ${
              isEnabled ? 'bg-bifrost-success/20' : 'bg-bifrost-muted/20'
            }`}>
              <svg className={`w-8 h-8 ${isEnabled ? 'text-bifrost-success' : 'text-bifrost-muted'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
            </div>
            <div>
              <h2 className="text-xl font-semibold text-bifrost-text">Mesh Network</h2>
              <p className={`text-sm ${isEnabled ? 'text-bifrost-success' : 'text-bifrost-muted'}`}>
                {statusLoading ? 'Loading...' : isEnabled ? 'Running' : 'Stopped'}
              </p>
            </div>
          </div>
          <button
            onClick={() => isEnabled ? disableMutation.mutate() : enableMutation.mutate()}
            disabled={isToggling}
            className={`btn ${isEnabled ? 'btn-danger' : 'btn-success'} min-w-[120px]`}
          >
            {isToggling ? (
              <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full" />
            ) : isEnabled ? (
              'Disable'
            ) : (
              'Enable'
            )}
          </button>
        </div>

        {/* Network Details */}
        {meshStatus && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-bifrost-border">
            <div>
              <p className="text-xs text-bifrost-muted">Peer Name</p>
              <p className="text-sm font-medium text-bifrost-text">{meshStatus.peer_name || '-'}</p>
            </div>
            <div>
              <p className="text-xs text-bifrost-muted">Virtual IP</p>
              <p className="text-sm font-medium text-bifrost-text font-mono">{meshStatus.virtual_ip || '-'}</p>
            </div>
            <div>
              <p className="text-xs text-bifrost-muted">Network ID</p>
              <p className="text-sm font-medium text-bifrost-text font-mono truncate" title={meshStatus.network_id}>{meshStatus.network_id || '-'}</p>
            </div>
            <div>
              <p className="text-xs text-bifrost-muted">Network CIDR</p>
              <p className="text-sm font-medium text-bifrost-text font-mono">{meshStatus.network_cidr || '-'}</p>
            </div>
          </div>
        )}

        {/* Stats Row */}
        {meshStatus && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4 pt-4 border-t border-bifrost-border">
            <div className="bg-bifrost-bg rounded-lg p-3">
              <p className="text-xs text-bifrost-muted">Total Peers</p>
              <p className="text-2xl font-semibold text-bifrost-text">{meshStatus.peer_count}</p>
            </div>
            <div className="bg-bifrost-bg rounded-lg p-3">
              <p className="text-xs text-bifrost-muted">Connected</p>
              <p className="text-2xl font-semibold text-bifrost-success">{meshStatus.connected_peers}</p>
            </div>
            <div className="bg-bifrost-bg rounded-lg p-3">
              <p className="text-xs text-bifrost-muted">Direct</p>
              <p className="text-2xl font-semibold text-bifrost-accent">{meshStatus.direct_connections}</p>
            </div>
            <div className="bg-bifrost-bg rounded-lg p-3">
              <p className="text-xs text-bifrost-muted">Relayed</p>
              <p className="text-2xl font-semibold text-bifrost-warning">{meshStatus.relayed_connections}</p>
            </div>
          </div>
        )}

        {/* Traffic Stats */}
        {meshStatus && (
          <div className="flex items-center gap-6 mt-4 pt-4 border-t border-bifrost-border">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 11l5-5m0 0l5 5m-5-5v12" />
              </svg>
              <span className="text-sm text-bifrost-muted">Sent:</span>
              <span className="text-sm font-medium text-bifrost-text">{formatBytes(meshStatus.bytes_sent)}</span>
            </div>
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 13l-5 5m0 0l-5-5m5 5V6" />
              </svg>
              <span className="text-sm text-bifrost-muted">Received:</span>
              <span className="text-sm font-medium text-bifrost-text">{formatBytes(meshStatus.bytes_received)}</span>
            </div>
            {meshStatus.uptime && (
              <div className="flex items-center gap-2">
                <svg className="w-4 h-4 text-bifrost-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-sm text-bifrost-muted">Uptime:</span>
                <span className="text-sm font-medium text-bifrost-text">{meshStatus.uptime}</span>
              </div>
            )}
          </div>
        )}

        {/* Error */}
        {meshError && (
          <div className="mt-4 p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg">
            <p className="text-sm text-bifrost-error font-medium">Mesh Toggle Failed</p>
            <p className="text-sm text-bifrost-error mt-1">{meshError}</p>
            {meshError.includes('not configured') && (
              <p className="text-xs text-bifrost-muted mt-2">
                Go to <a href="/settings" className="text-bifrost-accent underline">Settings → Mesh Networking</a> and configure mesh first.
              </p>
            )}
          </div>
        )}

        {/* Not Configured Notice */}
        {!isEnabled && meshStatus?.status === 'disabled' && (
          <div className="mt-4 p-3 bg-bifrost-muted/10 border border-bifrost-border rounded-lg">
            <p className="text-sm text-bifrost-muted">
              Mesh networking is not configured. Enable it in <a href="/settings" className="text-bifrost-accent underline">Settings → Mesh Networking</a> to create peer-to-peer connections with other Bifrost clients.
            </p>
          </div>
        )}
      </div>

      {/* Mesh Topology Visualization */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium text-bifrost-text flex items-center gap-2">
            <svg className="w-5 h-5 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
            </svg>
            Network Topology
          </h3>
          <button
            onClick={() => setShowTopology(!showTopology)}
            className="text-sm text-bifrost-muted hover:text-bifrost-text"
          >
            {showTopology ? 'Hide' : 'Show'}
          </button>
        </div>

        {showTopology && (
          <div className="bg-bifrost-bg rounded-lg p-6 min-h-[200px] relative">
            {peers.length === 0 ? (
              <div className="flex items-center justify-center h-full text-bifrost-muted">
                <div className="text-center">
                  <svg className="w-12 h-12 mx-auto mb-2 text-bifrost-muted/50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                  </svg>
                  <p className="text-sm">No peers discovered yet</p>
                </div>
              </div>
            ) : (
              <TopologyVisualization
                localPeer={{
                  id: meshStatus?.peer_id || 'local',
                  name: meshStatus?.peer_name || 'Local',
                  virtual_ip: meshStatus?.virtual_ip,
                }}
                peers={peers}
                onSelectPeer={setSelectedPeer}
                selectedPeerId={selectedPeer?.id}
              />
            )}
          </div>
        )}
      </div>

      {/* Connected Peers */}
      <div className="card">
        <h3 className="text-lg font-medium text-bifrost-text mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
          </svg>
          Peers ({peers.length})
        </h3>

        {peers.length === 0 ? (
          <p className="text-sm text-bifrost-muted text-center py-4">No peers discovered</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-bifrost-muted border-b border-bifrost-border">
                  <th className="pb-2">Peer</th>
                  <th className="pb-2">Virtual IP</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Connection</th>
                  <th className="pb-2">Latency</th>
                  <th className="pb-2">Traffic</th>
                  <th className="pb-2">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {peers.map((peer: MeshPeer) => (
                  <tr
                    key={peer.id}
                    className={`border-b border-bifrost-border/50 text-sm cursor-pointer hover:bg-bifrost-bg/50 ${
                      selectedPeer?.id === peer.id ? 'bg-bifrost-accent/10' : ''
                    }`}
                    onClick={() => setSelectedPeer(selectedPeer?.id === peer.id ? null : peer)}
                  >
                    <td className="py-2">
                      <div className="flex items-center gap-2">
                        <StatusDot status={peer.status} />
                        <div>
                          <p className="font-medium text-bifrost-text">{peer.name || peer.id.slice(0, 8)}</p>
                          <p className="text-xs text-bifrost-muted font-mono">{peer.id.slice(0, 12)}...</p>
                        </div>
                      </div>
                    </td>
                    <td className="py-2 font-mono text-bifrost-text">{peer.virtual_ip || '-'}</td>
                    <td className="py-2">
                      <StatusBadge status={peer.status} />
                    </td>
                    <td className="py-2">
                      <ConnectionTypeBadge type={peer.connection_type} />
                    </td>
                    <td className="py-2 text-bifrost-muted">
                      {peer.latency_ms > 0 ? `${peer.latency_ms}ms` : '-'}
                    </td>
                    <td className="py-2 text-bifrost-muted text-xs">
                      <span className="text-bifrost-success">↑</span> {formatBytes(peer.bytes_sent)}
                      {' / '}
                      <span className="text-bifrost-accent">↓</span> {formatBytes(peer.bytes_received)}
                    </td>
                    <td className="py-2 text-bifrost-muted text-xs">
                      {formatTimeAgo(peer.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Peer Details Panel */}
        {selectedPeer && (
          <div className="mt-4 pt-4 border-t border-bifrost-border">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-medium text-bifrost-text">Peer Details: {selectedPeer.name || selectedPeer.id.slice(0, 8)}</h4>
              <button
                onClick={() => setSelectedPeer(null)}
                className="text-bifrost-muted hover:text-bifrost-text"
                aria-label="Close peer details"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <p className="text-xs text-bifrost-muted">Peer ID</p>
                <p className="font-mono text-bifrost-text break-all">{selectedPeer.id}</p>
              </div>
              <div>
                <p className="text-xs text-bifrost-muted">Virtual IP</p>
                <p className="font-mono text-bifrost-text">{selectedPeer.virtual_ip || '-'}</p>
              </div>
              <div>
                <p className="text-xs text-bifrost-muted">Virtual MAC</p>
                <p className="font-mono text-bifrost-text">{selectedPeer.virtual_mac || '-'}</p>
              </div>
              <div>
                <p className="text-xs text-bifrost-muted">Joined</p>
                <p className="text-bifrost-text">{new Date(selectedPeer.joined_at).toLocaleString()}</p>
              </div>
            </div>
            {selectedPeer.endpoints && selectedPeer.endpoints.length > 0 && (
              <div className="mt-3">
                <p className="text-xs text-bifrost-muted mb-1">Endpoints</p>
                <div className="flex flex-wrap gap-2">
                  {selectedPeer.endpoints.map((ep, idx) => (
                    <span key={idx} className="px-2 py-1 bg-bifrost-bg rounded text-xs font-mono">
                      {ep.address}:{ep.port} ({ep.type})
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Routing Table */}
      <div className="card">
        <h3 className="text-lg font-medium text-bifrost-text mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
          </svg>
          Routing Table
        </h3>

        {routes.length === 0 ? (
          <p className="text-sm text-bifrost-muted text-center py-4">No routes configured</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-bifrost-muted border-b border-bifrost-border">
                  <th className="pb-2">Destination</th>
                  <th className="pb-2">Dest IP</th>
                  <th className="pb-2">Next Hop</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Metric</th>
                  <th className="pb-2">Hops</th>
                  <th className="pb-2">Latency</th>
                  <th className="pb-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {routes.map((route: MeshRoute, idx: number) => (
                  <tr key={idx} className="border-b border-bifrost-border/50 text-sm">
                    <td className="py-2 font-mono text-bifrost-text">{route.dest_peer_id.slice(0, 12)}...</td>
                    <td className="py-2 font-mono text-bifrost-muted">{route.dest_ip || '-'}</td>
                    <td className="py-2 font-mono text-bifrost-muted">
                      {route.next_hop ? `${route.next_hop.slice(0, 12)}...` : 'direct'}
                    </td>
                    <td className="py-2">
                      <RouteTypeBadge type={route.type} />
                    </td>
                    <td className="py-2 text-bifrost-muted">{route.metric}</td>
                    <td className="py-2 text-bifrost-muted">{route.hop_count}</td>
                    <td className="py-2 text-bifrost-muted">
                      {route.latency_ms > 0 ? `${route.latency_ms}ms` : '-'}
                    </td>
                    <td className="py-2">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs ${
                        route.active
                          ? 'bg-bifrost-success/20 text-bifrost-success'
                          : 'bg-bifrost-muted/20 text-bifrost-muted'
                      }`}>
                        {route.active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// Helper Components

function StatusDot({ status }: { status: string }) {
  const colorClass = {
    connected: 'bg-bifrost-success',
    relayed: 'bg-bifrost-warning',
    connecting: 'bg-bifrost-accent animate-pulse',
    discovered: 'bg-bifrost-muted',
    unreachable: 'bg-bifrost-error',
    offline: 'bg-bifrost-error/50',
  }[status] || 'bg-bifrost-muted'

  return <div className={`w-2 h-2 rounded-full ${colorClass}`} />
}

function StatusBadge({ status }: { status: string }) {
  const styles = {
    connected: 'bg-bifrost-success/20 text-bifrost-success',
    relayed: 'bg-bifrost-warning/20 text-bifrost-warning',
    connecting: 'bg-bifrost-accent/20 text-bifrost-accent',
    discovered: 'bg-bifrost-muted/20 text-bifrost-muted',
    unreachable: 'bg-bifrost-error/20 text-bifrost-error',
    offline: 'bg-bifrost-error/20 text-bifrost-error/70',
  }[status] || 'bg-bifrost-muted/20 text-bifrost-muted'

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs ${styles}`}>
      {status}
    </span>
  )
}

function ConnectionTypeBadge({ type }: { type?: string }) {
  if (!type) return <span className="text-bifrost-muted text-xs">-</span>

  const styles = {
    direct: 'bg-bifrost-accent/20 text-bifrost-accent',
    relayed: 'bg-bifrost-warning/20 text-bifrost-warning',
    multi_hop: 'bg-bifrost-muted/20 text-bifrost-muted',
  }[type] || 'bg-bifrost-muted/20 text-bifrost-muted'

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs ${styles}`}>
      {type.replace('_', ' ')}
    </span>
  )
}

function RouteTypeBadge({ type }: { type: string }) {
  const styles = {
    direct: 'bg-bifrost-success/20 text-bifrost-success',
    next_hop: 'bg-bifrost-accent/20 text-bifrost-accent',
    relay: 'bg-bifrost-warning/20 text-bifrost-warning',
  }[type] || 'bg-bifrost-muted/20 text-bifrost-muted'

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs ${styles}`}>
      {type.replace('_', ' ')}
    </span>
  )
}

function formatTimeAgo(timestamp: string): string {
  const now = new Date()
  const then = new Date(timestamp)
  const seconds = Math.floor((now.getTime() - then.getTime()) / 1000)

  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

// Topology Visualization Component
interface TopologyVisualizationProps {
  localPeer: {
    id: string
    name: string
    virtual_ip?: string
  }
  peers: MeshPeer[]
  onSelectPeer: (peer: MeshPeer | null) => void
  selectedPeerId?: string
}

function TopologyVisualization({ localPeer, peers, onSelectPeer, selectedPeerId }: TopologyVisualizationProps) {
  // Simple radial layout visualization
  const centerX = 200
  const centerY = 100
  const radius = 80

  const connectedPeers = peers.filter(p => p.status === 'connected' || p.status === 'relayed')
  const disconnectedPeers = peers.filter(p => p.status !== 'connected' && p.status !== 'relayed')

  // Calculate positions for connected peers in a circle around local
  const getPosition = (index: number, total: number) => {
    if (total === 0) return { x: centerX, y: centerY }
    const angle = (2 * Math.PI * index) / total - Math.PI / 2
    return {
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
    }
  }

  return (
    <svg viewBox="0 0 400 200" className="w-full h-full">
      {/* Connection Lines */}
      {connectedPeers.map((peer, idx) => {
        const pos = getPosition(idx, connectedPeers.length)
        const isDirect = peer.connection_type === 'direct'
        return (
          <line
            key={`line-${peer.id}`}
            x1={centerX}
            y1={centerY}
            x2={pos.x}
            y2={pos.y}
            stroke={isDirect ? '#10b981' : '#f59e0b'}
            strokeWidth={selectedPeerId === peer.id ? 3 : 2}
            strokeDasharray={isDirect ? undefined : '4 2'}
            opacity={0.6}
          />
        )
      })}

      {/* Local Peer (Center) */}
      <g transform={`translate(${centerX}, ${centerY})`}>
        <circle
          r={24}
          fill="#1e1e2e"
          stroke="#8b5cf6"
          strokeWidth={3}
        />
        <text
          textAnchor="middle"
          dominantBaseline="middle"
          fill="#e2e8f0"
          fontSize="10"
          fontWeight="bold"
        >
          You
        </text>
        <text
          y={35}
          textAnchor="middle"
          fill="#94a3b8"
          fontSize="8"
        >
          {localPeer.virtual_ip || ''}
        </text>
      </g>

      {/* Connected Peers */}
      {connectedPeers.map((peer, idx) => {
        const pos = getPosition(idx, connectedPeers.length)
        const isSelected = selectedPeerId === peer.id
        const isDirect = peer.connection_type === 'direct'
        return (
          <g
            key={peer.id}
            transform={`translate(${pos.x}, ${pos.y})`}
            onClick={() => onSelectPeer(isSelected ? null : peer)}
            className="cursor-pointer"
          >
            <circle
              r={isSelected ? 22 : 18}
              fill="#1e1e2e"
              stroke={isDirect ? '#10b981' : '#f59e0b'}
              strokeWidth={isSelected ? 3 : 2}
            />
            <text
              textAnchor="middle"
              dominantBaseline="middle"
              fill="#e2e8f0"
              fontSize="8"
            >
              {(peer.name || peer.id).slice(0, 6)}
            </text>
            <text
              y={28}
              textAnchor="middle"
              fill="#94a3b8"
              fontSize="7"
            >
              {peer.latency_ms > 0 ? `${peer.latency_ms}ms` : ''}
            </text>
          </g>
        )
      })}

      {/* Disconnected Peers - smaller, on the side */}
      {disconnectedPeers.length > 0 && (
        <g transform="translate(350, 20)">
          <text fill="#64748b" fontSize="8" fontWeight="medium">Offline ({disconnectedPeers.length})</text>
          {disconnectedPeers.slice(0, 5).map((peer, idx) => (
            <g
              key={peer.id}
              transform={`translate(0, ${15 + idx * 20})`}
              onClick={() => onSelectPeer(peer)}
              className="cursor-pointer"
            >
              <circle r={6} fill="#1e1e2e" stroke="#64748b" strokeWidth={1} opacity={0.5} />
              <text x={12} y={3} fill="#64748b" fontSize="7">
                {(peer.name || peer.id).slice(0, 8)}
              </text>
            </g>
          ))}
          {disconnectedPeers.length > 5 && (
            <text y={15 + 5 * 20} fill="#64748b" fontSize="7">
              +{disconnectedPeers.length - 5} more
            </text>
          )}
        </g>
      )}

      {/* Legend */}
      <g transform="translate(10, 180)">
        <line x1="0" y1="0" x2="20" y2="0" stroke="#10b981" strokeWidth={2} />
        <text x="25" y="3" fill="#94a3b8" fontSize="7">Direct</text>
        <line x1="70" y1="0" x2="90" y2="0" stroke="#f59e0b" strokeWidth={2} strokeDasharray="4 2" />
        <text x="95" y="3" fill="#94a3b8" fontSize="7">Relayed</text>
      </g>
    </svg>
  )
}
