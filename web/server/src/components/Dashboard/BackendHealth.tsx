import type { Backend } from '../../api/types'

interface BackendHealthProps {
  backends: Backend[] | undefined
  isLoading: boolean
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function BackendHealth({ backends, isLoading }: BackendHealthProps) {
  if (isLoading) {
    return (
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Backend Status</h3>
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="animate-pulse flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-bifrost-border" />
              <div className="h-4 bg-bifrost-border rounded w-32" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (!backends || backends.length === 0) {
    return (
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Backend Status</h3>
        <p className="text-bifrost-muted">No backends configured</p>
      </div>
    )
  }

  return (
    <div className="card">
      <h3 className="text-lg font-semibold text-white mb-4">Backend Status</h3>
      <div className="space-y-3">
        {backends.map((backend, index) => (
          <div
            key={backend.name}
            className="flex items-center justify-between p-3 rounded-lg bg-bifrost-bg/50 animate-slide-up"
            style={{ animationDelay: `${index * 50}ms` }}
          >
            <div className="flex items-center gap-3">
              <div
                className={`w-3 h-3 rounded-full ${
                  backend.healthy
                    ? 'bg-bifrost-success animate-pulse-subtle'
                    : 'bg-bifrost-error'
                }`}
              />
              <div>
                <p className="font-medium text-white">{backend.name}</p>
                <p className="text-xs text-bifrost-muted">{backend.type}</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-sm text-gray-300">
                {backend.stats.active_connections} active
              </p>
              <p className="text-xs text-bifrost-muted">
                {formatBytes(backend.stats.bytes_sent + backend.stats.bytes_received)}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
