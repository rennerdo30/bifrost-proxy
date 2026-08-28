import { useState, useEffect } from 'react'
import { useModalA11y } from '../../hooks/useModalA11y'

interface PurgeDomainDialogProps {
  isOpen: boolean
  onClose: () => void
  onPurge: (domain: string) => Promise<void>
  initialDomain?: string
}

export function PurgeDomainDialog({
  isOpen,
  onClose,
  onPurge,
  initialDomain = '',
}: PurgeDomainDialogProps) {
  const [domain, setDomain] = useState(initialDomain)
  const [isPurging, setIsPurging] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Update domain when initialDomain changes
  useEffect(() => {
    if (isOpen) {
      setDomain(initialDomain)
      setError(null)
    }
  }, [isOpen, initialDomain])

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    if (isOpen) {
      document.addEventListener('keydown', handleEscape)
      document.body.style.overflow = 'hidden'
    }
    return () => {
      document.removeEventListener('keydown', handleEscape)
      document.body.style.overflow = ''
    }
  }, [isOpen, onClose])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    const trimmedDomain = domain.trim()
    if (!trimmedDomain) {
      setError('Domain is required')
      return
    }

    setIsPurging(true)
    try {
      await onPurge(trimmedDomain)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to purge domain')
    } finally {
      setIsPurging(false)
    }
  }

  const modalRef = useModalA11y(isOpen, onClose)

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="presentation">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-bifrost-overlay backdrop-blur-sm" onClick={onClose} aria-hidden="true" />

      {/* Modal */}
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="purge-domain-title"
        className="relative w-full max-w-md bg-bifrost-card border border-bifrost-border rounded-xl shadow-2xl animate-slide-up">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-bifrost-border">
          <h2 id="purge-domain-title" className="text-xl font-semibold text-bifrost-heading">Purge Domain Cache</h2>
          <button
            onClick={onClose}
            className="p-1 text-bifrost-muted hover:text-bifrost-heading transition-colors"
            aria-label="Close dialog"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          {/* Content */}
          <div className="px-6 py-4 space-y-4">
            {error && (
              <div className="p-3 bg-bifrost-error/10 border border-bifrost-error/50 rounded-lg text-bifrost-error text-sm">
                {error}
              </div>
            )}

            <p className="text-bifrost-text text-sm">
              This will delete all cached entries for the specified domain.
            </p>

            <div>
              <label className="block text-sm font-medium text-bifrost-text mb-1">
                Domain
              </label>
              <input
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="input w-full"
                placeholder="example.com"
                autoFocus
              />
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-bifrost-border">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button
              type="submit"
              className="btn bg-bifrost-warning hover:bg-bifrost-warning/80 text-bifrost-on-warning"
              disabled={isPurging}
            >
              {isPurging ? 'Purging...' : 'Purge Domain'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
