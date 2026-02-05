import { useState, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { useToast } from '../components/Toast'
import { ConfirmModal } from '../components/Config/ConfirmModal'
import {
  MeshNetworkList,
  MeshPeerList,
  MeshTopologyGraph,
  MeshPeerDetails,
  MeshEventLog,
  CreateNetworkDialog,
} from '../components/Mesh'
import type { MeshPeerInfo, CreateMeshNetworkRequest } from '../api/types'

type ViewMode = 'list' | 'topology'

export function Mesh() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()

  // State
  const [selectedNetworkId, setSelectedNetworkId] = useState<string | null>(null)
  const [selectedPeer, setSelectedPeer] = useState<MeshPeerInfo | null>(null)
  const [viewMode, setViewMode] = useState<ViewMode>('topology')
  const [isCreateNetworkOpen, setIsCreateNetworkOpen] = useState(false)
  const [deletingNetworkId, setDeletingNetworkId] = useState<string | null>(null)
  const [removingPeerId, setRemovingPeerId] = useState<string | null>(null)

  // Queries
  const { data: networksData, isLoading: networksLoading } = useQuery({
    queryKey: ['meshNetworks'],
    queryFn: api.listMeshNetworks,
    refetchInterval: 10000,
  })

  const { data: peersData, isLoading: peersLoading, refetch: refetchPeers } = useQuery({
    queryKey: ['meshPeers', selectedNetworkId],
    queryFn: () => (selectedNetworkId ? api.listMeshPeers(selectedNetworkId) : Promise.resolve({ peers: [] })),
    enabled: !!selectedNetworkId,
    refetchInterval: 5000,
  })

  const networks = networksData?.networks || []
  const peers = peersData?.peers || []

  // Handlers
  const handleCreateNetwork = useCallback(
    async (request: CreateMeshNetworkRequest) => {
      try {
        await api.createMeshNetwork(request)
        showToast(`Network "${request.name || request.id}" created`, 'success')
        queryClient.invalidateQueries({ queryKey: ['meshNetworks'] })
        setSelectedNetworkId(request.id)
      } catch (err) {
        showToast(err instanceof Error ? err.message : 'Failed to create network', 'error')
        throw err
      }
    },
    [queryClient, showToast]
  )

  const handleDeleteNetwork = useCallback(async () => {
    if (!deletingNetworkId) return
    try {
      await api.deleteMeshNetwork(deletingNetworkId)
      showToast('Network deleted', 'success')
      queryClient.invalidateQueries({ queryKey: ['meshNetworks'] })
      if (selectedNetworkId === deletingNetworkId) {
        setSelectedNetworkId(null)
        setSelectedPeer(null)
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to delete network', 'error')
    } finally {
      setDeletingNetworkId(null)
    }
  }, [deletingNetworkId, selectedNetworkId, queryClient, showToast])

  const handleRemovePeer = useCallback(async () => {
    if (!selectedNetworkId || !removingPeerId) return
    try {
      await api.deregisterMeshPeer(selectedNetworkId, removingPeerId)
      showToast('Peer removed', 'success')
      refetchPeers()
      if (selectedPeer?.id === removingPeerId) {
        setSelectedPeer(null)
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to remove peer', 'error')
    } finally {
      setRemovingPeerId(null)
    }
  }, [selectedNetworkId, removingPeerId, selectedPeer, refetchPeers, showToast])

  const handleSelectNetwork = useCallback((networkId: string) => {
    setSelectedNetworkId(networkId)
    setSelectedPeer(null)
  }, [])

  const handleSelectPeer = useCallback((peer: MeshPeerInfo) => {
    setSelectedPeer(peer)
  }, [])

  // Calculate stats
  const totalPeers = networks.reduce((sum, n) => sum + n.peer_count, 0)
  const connectedPeers = peers.filter((p) => {
    const extPeer = p as MeshPeerInfo & { status?: string }
    return extPeer.status === 'connected' || extPeer.status === 'relayed'
  }).length

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Mesh Networking</h2>
          <p className="text-bifrost-muted mt-1">
            Manage P2P mesh networks and peer connections
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ['meshNetworks'] })
              if (selectedNetworkId) {
                queryClient.invalidateQueries({ queryKey: ['meshPeers', selectedNetworkId] })
              }
            }}
            className="btn btn-secondary"
            aria-label="Refresh mesh data"
          >
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
            Refresh
          </button>
          <button
            onClick={() => setIsCreateNetworkOpen(true)}
            className="btn btn-primary"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Create Network
          </button>
        </div>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="card py-3 bg-gradient-to-br from-bifrost-accent/10 to-transparent">
          <p className="text-sm text-gray-400">Networks</p>
          <p className="text-2xl font-bold text-bifrost-accent mt-1">{networks.length}</p>
        </div>
        <div className="card py-3 bg-gradient-to-br from-cyan-500/10 to-transparent">
          <p className="text-sm text-gray-400">Total Peers</p>
          <p className="text-2xl font-bold text-cyan-400 mt-1">{totalPeers}</p>
        </div>
        <div className="card py-3 bg-gradient-to-br from-bifrost-success/10 to-transparent">
          <p className="text-sm text-gray-400">Connected</p>
          <p className="text-2xl font-bold text-bifrost-success mt-1">
            {selectedNetworkId ? connectedPeers : '-'}
          </p>
        </div>
        <div className="card py-3 bg-gradient-to-br from-emerald-500/10 to-transparent">
          <p className="text-sm text-gray-400">Selected Network</p>
          <p className="text-lg font-bold text-emerald-400 mt-1 truncate">
            {selectedNetworkId || 'None'}
          </p>
        </div>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Networks Sidebar */}
        <div className="lg:col-span-3">
          <div className="card h-full">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-white">Networks</h3>
              <span className="badge badge-info">{networks.length}</span>
            </div>
            <MeshNetworkList
              networks={networks}
              selectedNetworkId={selectedNetworkId || undefined}
              isLoading={networksLoading}
              onSelect={handleSelectNetwork}
              onDelete={setDeletingNetworkId}
            />
          </div>
        </div>

        {/* Main Area */}
        <div className="lg:col-span-6">
          {selectedNetworkId ? (
            <div className="card h-full flex flex-col" style={{ minHeight: '500px' }}>
              {/* View Toggle */}
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-medium text-white">
                  Peers ({peers.length})
                </h3>
                <div className="flex items-center gap-1 bg-bifrost-bg rounded-lg p-1">
                  <button
                    onClick={() => setViewMode('topology')}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
                      viewMode === 'topology'
                        ? 'bg-bifrost-accent text-white'
                        : 'text-bifrost-muted hover:text-white'
                    }`}
                  >
                    <svg className="w-4 h-4 inline-block mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
                    </svg>
                    Topology
                  </button>
                  <button
                    onClick={() => setViewMode('list')}
                    className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
                      viewMode === 'list'
                        ? 'bg-bifrost-accent text-white'
                        : 'text-bifrost-muted hover:text-white'
                    }`}
                  >
                    <svg className="w-4 h-4 inline-block mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 6.75h12M8.25 12h12m-12 5.25h12M3.75 6.75h.007v.008H3.75V6.75zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zM3.75 12h.007v.008H3.75V12zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0zm-.375 5.25h.007v.008H3.75v-.008zm.375 0a.375.375 0 11-.75 0 .375.375 0 01.75 0z" />
                    </svg>
                    List
                  </button>
                </div>
              </div>

              {/* Content */}
              <div className="flex-1 overflow-hidden">
                {viewMode === 'topology' ? (
                  <MeshTopologyGraph
                    peers={peers}
                    selectedPeerId={selectedPeer?.id}
                    onSelectPeer={handleSelectPeer}
                  />
                ) : (
                  <div className="h-full overflow-y-auto">
                    <MeshPeerList
                      peers={peers}
                      selectedPeerId={selectedPeer?.id}
                      isLoading={peersLoading}
                      onSelect={handleSelectPeer}
                      onRemove={setRemovingPeerId}
                    />
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="card h-full flex items-center justify-center" style={{ minHeight: '500px' }}>
              <div className="text-center">
                <svg
                  className="w-16 h-16 mx-auto text-bifrost-muted mb-4 opacity-50"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={1}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
                  />
                </svg>
                <p className="text-bifrost-muted">Select a network to view peers</p>
                <p className="text-sm text-bifrost-muted mt-1">
                  Or create a new network to get started
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Right Sidebar - Details & Events */}
        <div className="lg:col-span-3 space-y-6">
          {/* Peer Details */}
          <div className="card" style={{ minHeight: '280px' }}>
            <MeshPeerDetails
              peer={selectedPeer}
              onClose={() => setSelectedPeer(null)}
              onRemove={setRemovingPeerId}
            />
          </div>

          {/* Event Log */}
          <div className="card" style={{ minHeight: '280px' }}>
            <MeshEventLog networkId={selectedNetworkId} />
          </div>
        </div>
      </div>

      {/* Dialogs */}
      <CreateNetworkDialog
        isOpen={isCreateNetworkOpen}
        onClose={() => setIsCreateNetworkOpen(false)}
        onSave={handleCreateNetwork}
        existingIds={networks.map((n) => n.id)}
      />

      <ConfirmModal
        isOpen={deletingNetworkId !== null}
        onClose={() => setDeletingNetworkId(null)}
        onConfirm={handleDeleteNetwork}
        title="Delete Mesh Network"
        message="Are you sure you want to delete this network? All peers will be disconnected."
        confirmLabel="Delete"
        variant="danger"
      />

      <ConfirmModal
        isOpen={removingPeerId !== null}
        onClose={() => setRemovingPeerId(null)}
        onConfirm={handleRemovePeer}
        title="Remove Peer"
        message="Are you sure you want to remove this peer from the network?"
        confirmLabel="Remove"
        variant="danger"
      />
    </div>
  )
}
