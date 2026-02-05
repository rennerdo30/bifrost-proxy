import { Component, ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
  /** Optional section name for more specific error messages */
  section?: string
  /** Callback when an error is caught */
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: React.ErrorInfo | null
}

// Error logging function - logs to console and could be extended to send to external service
function logError(error: Error, errorInfo: React.ErrorInfo, section?: string) {
  const errorData = {
    timestamp: new Date().toISOString(),
    section: section || 'unknown',
    message: error.message,
    stack: error.stack,
    componentStack: errorInfo.componentStack,
    userAgent: navigator.userAgent,
    url: window.location.href,
  }

  // Always log errors for debugging
  console.error('[ErrorBoundary] Error caught:', errorData)

  // In production, you could send to an error tracking service here
  // e.g., Sentry, LogRocket, etc.
}

// Generate GitHub issue URL with pre-filled error details
function generateIssueUrl(error: Error, section?: string): string {
  const title = encodeURIComponent(`[Bug] UI Error${section ? ` in ${section}` : ''}: ${error.message.slice(0, 50)}`)
  const body = encodeURIComponent(
    `## Error Description
An error occurred in the Bifrost Proxy Client UI${section ? ` (${section} section)` : ''}.

## Error Details
\`\`\`
${error.message}
\`\`\`

## Stack Trace
\`\`\`
${error.stack || 'No stack trace available'}
\`\`\`

## Environment
- URL: ${window.location.href}
- User Agent: ${navigator.userAgent}
- Timestamp: ${new Date().toISOString()}

## Steps to Reproduce
1.
2.
3.

## Expected Behavior
<!-- What should have happened? -->

## Additional Context
<!-- Add any other context about the problem here -->
`
  )
  return `https://github.com/rennerdo30/bifrost-proxy/issues/new?title=${title}&body=${body}&labels=bug,ui`
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({ errorInfo })

    // Log error for debugging
    logError(error, errorInfo, this.props.section)

    // Call optional error callback
    this.props.onError?.(error, errorInfo)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback
      }

      const { error } = this.state
      const { section } = this.props
      const issueUrl = error ? generateIssueUrl(error, section) : '#'

      return (
        <div className="flex items-center justify-center min-h-[400px] p-8">
          <div className="text-center max-w-md">
            <div className="text-bifrost-error text-4xl mb-4">⚠</div>
            <h2 className="text-xl font-semibold text-bifrost-text mb-2">
              Something went wrong
              {section && <span className="text-bifrost-muted font-normal"> in {section}</span>}
            </h2>
            <p className="text-bifrost-muted mb-4">
              An unexpected error occurred. Please try again or refresh the page.
              If the problem persists, please report this issue.
            </p>
            {import.meta.env.DEV && error && (
              <pre className="text-left text-xs bg-bifrost-card border border-bifrost-border p-3 rounded mb-4 overflow-auto max-h-32 text-bifrost-text">
                {error.message}
              </pre>
            )}
            <div className="flex gap-3 justify-center">
              <button
                onClick={this.handleRetry}
                className="px-4 py-2 bg-bifrost-accent text-white rounded-md hover:bg-bifrost-accent/90 transition-colors"
                aria-label="Try again"
              >
                Try Again
              </button>
              <a
                href={issueUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 bg-bifrost-card border border-bifrost-border text-bifrost-text rounded-md hover:bg-bifrost-card-hover transition-colors inline-flex items-center gap-2"
                aria-label="Report issue on GitHub"
              >
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
                </svg>
                Report Issue
              </a>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

/** Compact error boundary for smaller sections with inline error display */
interface SectionErrorFallbackProps {
  error: Error | null
  section: string
  onRetry: () => void
}

function SectionErrorFallback({ error, section, onRetry }: SectionErrorFallbackProps) {
  const issueUrl = error ? generateIssueUrl(error, section) : '#'

  return (
    <div className="card p-6">
      <div className="flex items-start gap-4">
        <div className="text-bifrost-error text-2xl flex-shrink-0">⚠</div>
        <div className="flex-1 min-w-0">
          <h3 className="text-lg font-medium text-bifrost-text mb-1">
            Error loading {section}
          </h3>
          <p className="text-sm text-bifrost-muted mb-3">
            This section encountered an error. Other parts of the app should still work.
          </p>
          {import.meta.env.DEV && error && (
            <pre className="text-xs bg-bifrost-bg border border-bifrost-border p-2 rounded mb-3 overflow-auto max-h-24 text-bifrost-text">
              {error.message}
            </pre>
          )}
          <div className="flex gap-2">
            <button
              onClick={onRetry}
              className="text-sm px-3 py-1.5 bg-bifrost-accent text-white rounded hover:bg-bifrost-accent/90 transition-colors"
              aria-label={`Retry loading ${section}`}
            >
              Retry
            </button>
            <a
              href={issueUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm px-3 py-1.5 text-bifrost-muted hover:text-bifrost-text transition-colors"
              aria-label="Report issue on GitHub"
            >
              Report Issue
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}

/** Error boundary specifically designed for page sections with compact fallback UI */
export class SectionErrorBoundary extends Component<
  { children: ReactNode; section: string; onError?: (error: Error, errorInfo: React.ErrorInfo) => void },
  State
> {
  constructor(props: { children: ReactNode; section: string; onError?: (error: Error, errorInfo: React.ErrorInfo) => void }) {
    super(props)
    this.state = { hasError: false, error: null, errorInfo: null }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({ errorInfo })
    logError(error, errorInfo, this.props.section)
    this.props.onError?.(error, errorInfo)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null, errorInfo: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <SectionErrorFallback
          error={this.state.error}
          section={this.props.section}
          onRetry={this.handleRetry}
        />
      )
    }
    return this.props.children
  }
}
