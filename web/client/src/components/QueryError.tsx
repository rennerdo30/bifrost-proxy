interface QueryErrorProps {
  /** What failed to load, e.g. "backends". */
  what: string
  error: unknown
  onRetry?: () => void
}

// QueryError is the standard failed-query state (the pattern Clients.tsx
// established): what failed, the actual error message, and a retry button.
export function QueryError({ what, error, onRetry }: QueryErrorProps) {
  return (
    <div className="p-8 text-center" role="alert">
      <svg
        className="w-12 h-12 mx-auto mb-4 text-bifrost-error opacity-70"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={1.5}
          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
        />
      </svg>
      <p className="text-bifrost-error font-medium">Failed to load {what}</p>
      <p className="text-sm text-bifrost-muted mt-2">
        {error instanceof Error ? error.message : 'An unexpected error occurred'}
      </p>
      {onRetry && (
        <button onClick={onRetry} className="btn btn-secondary mt-4">
          Try Again
        </button>
      )}
    </div>
  )
}
