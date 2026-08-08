import { useVersion, useHealth } from '../../hooks/useStats'
import { ThemeToggle } from '../ThemeToggle'

export function Header() {
  const { data: version } = useVersion()
  const { data: health } = useHealth()

  const isHealthy = health?.status === 'healthy'

  return (
    <header className="bg-bifrost-card border-b border-bifrost-border">
      <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 py-3 sm:h-16 sm:py-0">
          {/* Logo and Title */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 shrink-0 rounded-xl bg-gradient-to-br from-bifrost-accent to-cyan-500 flex items-center justify-center shadow-lg" aria-hidden="true">
              <svg
                className="w-6 h-6 text-bifrost-on-accent"
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
              <h1 className="text-lg font-bold tracking-tight text-bifrost-heading sm:text-xl">Bifrost</h1>
              <p className="text-xs text-bifrost-muted">Proxy Server Dashboard</p>
            </div>
          </div>

          {/* Status and Version */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Connection Status */}
            <div className="flex items-center gap-2" role="status">
              <div
                className={`w-2 h-2 rounded-full ${
                  isHealthy ? 'bg-bifrost-success animate-pulse-subtle' : 'bg-bifrost-error'
                }`}
                aria-hidden="true"
              />
              <span className="text-sm text-bifrost-subtle">
                {isHealthy ? 'Connected' : 'Disconnected'}
              </span>
            </div>

            {/* Version Badge */}
            {version && (
              <span className="badge badge-info">
                v{version.version}
              </span>
            )}

            <ThemeToggle />

            {/* GitHub Repository Link */}
            <a
              href="https://github.com/rennerdo30/bifrost-proxy"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-ghost"
              title="GitHub Repository"
              aria-label="View source on GitHub"
            >
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
              </svg>
            </a>

            {/* Documentation Link */}
            <a
              href="https://rennerdo30.github.io/bifrost-proxy/"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-ghost"
              title="Documentation"
              aria-label="View documentation"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
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
