import { useStats, useBackends } from '../hooks/useStats'
import { StatsCards } from '../components/Dashboard/StatsCards'
import { BackendHealth } from '../components/Dashboard/BackendHealth'
import { formatBytes } from '../utils'

export function Dashboard() {
  const { stats, isLoading: statsLoading, isConnected } = useStats()
  const { data: backends, isLoading: backendsLoading } = useBackends()

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Dashboard</h2>
          <p className="text-bifrost-muted mt-1">
            Monitor your proxy server performance
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${
              isConnected ? 'bg-bifrost-success' : 'bg-bifrost-warning'
            }`}
          />
          <span className="text-sm text-gray-400">
            {isConnected ? 'Live updates' : 'Polling'}
          </span>
        </div>
      </div>

      {/* Stats Cards */}
      <StatsCards stats={stats} isLoading={statsLoading} />

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Backend Health */}
        <BackendHealth backends={backends} isLoading={backendsLoading} />

        {/* Quick Stats */}
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Traffic Overview</h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Bytes Sent</span>
              <span className="text-white font-mono">
                {formatBytes(stats?.bytes_sent ?? 0)}
              </span>
            </div>
            <div className="h-2 bg-bifrost-bg rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-bifrost-accent to-cyan-400 transition-all duration-500"
                style={{
                  width: `${Math.min(
                    ((stats?.bytes_sent ?? 0) /
                      ((stats?.bytes_sent ?? 0) + (stats?.bytes_received ?? 0) || 1)) *
                      100,
                    100
                  )}%`,
                }}
              />
            </div>
            <div className="flex justify-between items-center">
              <span className="text-gray-400">Bytes Received</span>
              <span className="text-white font-mono">
                {formatBytes(stats?.bytes_received ?? 0)}
              </span>
            </div>
            <div className="h-2 bg-bifrost-bg rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 transition-all duration-500"
                style={{
                  width: `${Math.min(
                    ((stats?.bytes_received ?? 0) /
                      ((stats?.bytes_sent ?? 0) + (stats?.bytes_received ?? 0) || 1)) *
                      100,
                    100
                  )}%`,
                }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
