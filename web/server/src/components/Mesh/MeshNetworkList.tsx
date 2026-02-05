import type { MeshNetwork } from '../../api/types'

interface MeshNetworkListProps {
  networks?: MeshNetwork[]
  selectedNetworkId?: string
  isLoading: boolean
  onSelect: (networkId: string) => void
  onDelete: (networkId: string) => void
}

export function MeshNetworkList({
  networks,
  selectedNetworkId,
  isLoading,
  onSelect,
  onDelete,
}: MeshNetworkListProps) {
  if (isLoading && !networks) {
    return (
      <div className="space-y-2">
        {[...Array(3)].map((_, i) => (
          <div key={i} className="h-16 bg-bifrost-bg rounded animate-pulse" />
        ))}
      </div>
    )
  }

  if (!networks || networks.length === 0) {
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
            d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
          />
        </svg>
        <p className="text-bifrost-muted">No mesh networks configured</p>
        <p className="text-sm text-bifrost-muted mt-1">
          Create a network to start building your mesh
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {networks.map((network) => (
        <div
          key={network.id}
          onClick={() => onSelect(network.id)}
          className={`card cursor-pointer transition-all hover:border-bifrost-accent/50 ${
            selectedNetworkId === network.id
              ? 'border-bifrost-accent bg-bifrost-accent/5'
              : ''
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-bifrost-accent/10 flex items-center justify-center">
                <svg
                  className="w-5 h-5 text-bifrost-accent"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={1.5}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
                  />
                </svg>
              </div>
              <div>
                <h3 className="font-medium text-white">{network.name || network.id}</h3>
                <p className="text-sm text-bifrost-muted">
                  {network.cidr} &middot; {network.peer_count} peer{network.peer_count !== 1 ? 's' : ''}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="badge badge-info">{network.peer_count}</span>
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  onDelete(network.id)
                }}
                className="p-1.5 rounded hover:bg-bifrost-error/10 text-bifrost-muted hover:text-bifrost-error transition-colors"
                aria-label="Delete network"
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
                    d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                  />
                </svg>
              </button>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
