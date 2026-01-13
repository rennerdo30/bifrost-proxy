import { useStatus, useVersion } from '../../hooks/useStatus'
import { useQueryClient } from '@tanstack/react-query'

export function Header() {
  const { data: status } = useStatus()
  const { data: version } = useVersion()
  const queryClient = useQueryClient()

  const handleRefresh = () => {
    queryClient.invalidateQueries()
  }

  const isConnected = status?.server_status === 'connected'

  return (
    <header className="border-b border-bifrost-border bg-bifrost-card/50 backdrop-blur-sm sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-bifrost-accent to-cyan-500 flex items-center justify-center shadow-lg">
              <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">Bifrost Client</h1>
              <p className="text-sm text-bifrost-muted">
                {version ? `v${version.version}` : 'Loading...'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className={`badge ${isConnected ? 'badge-success' : 'badge-error'}`}>
              <span className={`w-2 h-2 rounded-full mr-2 ${isConnected ? 'bg-bifrost-success' : 'bg-bifrost-error'}`} />
              {isConnected ? 'Server Connected' : 'Server Disconnected'}
            </div>

            <button
              onClick={handleRefresh}
              className="btn btn-ghost"
              title="Refresh data"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>

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
