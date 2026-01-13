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

            {/* Documentation Link */}
            <a
              href="https://rennerdo30.github.io/bifrost-proxy/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-ghost"
              title="Documentation"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" />
              </svg>
            </a>
          </div>
        </div>
      </div>
    </header>
  )
}
