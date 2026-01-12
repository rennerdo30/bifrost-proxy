import { useVersion, useHealth } from '../../hooks/useStats'

export function Header() {
  const { data: version } = useVersion()
  const { data: health } = useHealth()

  const isHealthy = health?.status === 'healthy'

  return (
    <header className="bg-bifrost-card border-b border-bifrost-border">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Title */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-bifrost-accent to-cyan-500 flex items-center justify-center shadow-lg">
              <svg
                className="w-6 h-6 text-white"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M13 10V3L4 14h7v7l9-11h-7z"
                />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Bifrost</h1>
              <p className="text-xs text-bifrost-muted">Proxy Server Dashboard</p>
            </div>
          </div>

          {/* Status and Version */}
          <div className="flex items-center gap-4">
            {/* Connection Status */}
            <div className="flex items-center gap-2">
              <div
                className={`w-2 h-2 rounded-full ${
                  isHealthy ? 'bg-bifrost-success animate-pulse-subtle' : 'bg-bifrost-error'
                }`}
              />
              <span className="text-sm text-gray-400">
                {isHealthy ? 'Connected' : 'Disconnected'}
              </span>
            </div>

            {/* Version Badge */}
            {version && (
              <span className="badge badge-info">
                v{version.version}
              </span>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}
