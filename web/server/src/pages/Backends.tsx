import { useBackends } from '../hooks/useStats'
import { BackendList } from '../components/Backends/BackendList'

export function Backends() {
  const { data: backends, isLoading, refetch } = useBackends()

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Backends</h2>
          <p className="text-bifrost-muted mt-1">
            View and monitor proxy backend connections
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="btn btn-secondary"
          aria-label="Refresh backends"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
            />
          </svg>
          Refresh
        </button>
      </div>

      {/* Backend Summary */}
      {backends && backends.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="card bg-gradient-to-br from-bifrost-accent/10 to-transparent">
            <p className="text-sm text-gray-400">Total Backends</p>
            <p className="text-2xl font-bold text-white mt-1">{backends.length}</p>
          </div>
          <div className="card bg-gradient-to-br from-bifrost-success/10 to-transparent">
            <p className="text-sm text-gray-400">Healthy</p>
            <p className="text-2xl font-bold text-bifrost-success mt-1">
              {backends.filter((b) => b.healthy).length}
            </p>
          </div>
          <div className="card bg-gradient-to-br from-bifrost-error/10 to-transparent">
            <p className="text-sm text-gray-400">Unhealthy</p>
            <p className="text-2xl font-bold text-bifrost-error mt-1">
              {backends.filter((b) => !b.healthy).length}
            </p>
          </div>
        </div>
      )}

      {/* Backend List */}
      <BackendList backends={backends} isLoading={isLoading} />
    </div>
  )
}
