import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { getApiToken, setApiToken, clearApiToken } from '../../api/client'
import { useToast } from '../Toast'

/**
 * ApiTokenDialog lets the operator supply the browser-side API token required
 * when the client daemon is started with `api.token` set. Without it every REST
 * call and the log SSE stream return 401 and the dashboard is unusable. The
 * dialog is reachable at any time from the header key button, and also opens
 * automatically when a request is rejected with 401 (via the
 * `bifrost:unauthorized` window event dispatched by the API client), so a
 * bricked dashboard can recover itself.
 */
export function ApiTokenDialog() {
  const [isOpen, setIsOpen] = useState(false)
  const [value, setValue] = useState('')
  const [reveal, setReveal] = useState(false)
  const queryClient = useQueryClient()
  const { showToast } = useToast()

  // Open automatically on the first 401 so the operator is prompted to
  // authenticate rather than staring at a silently broken dashboard.
  useEffect(() => {
    const onUnauthorized = () => {
      setValue(getApiToken() ?? '')
      setIsOpen(true)
    }
    window.addEventListener('bifrost:unauthorized', onUnauthorized)
    return () => window.removeEventListener('bifrost:unauthorized', onUnauthorized)
  }, [])

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setIsOpen(false)
    }
    if (isOpen) {
      document.addEventListener('keydown', handleEscape)
      document.body.style.overflow = 'hidden'
    }
    return () => {
      document.removeEventListener('keydown', handleEscape)
      document.body.style.overflow = ''
    }
  }, [isOpen])

  const open = () => {
    setValue(getApiToken() ?? '')
    setIsOpen(true)
  }

  const handleSave = () => {
    const trimmed = value.trim()
    if (trimmed) {
      setApiToken(trimmed)
      showToast('API token saved', 'success')
    } else {
      clearApiToken()
      showToast('API token cleared', 'info')
    }
    setIsOpen(false)
    // Re-run every query now that the Authorization header will be sent.
    queryClient.invalidateQueries()
  }

  const hasToken = !!getApiToken()

  return (
    <>
      <button
        onClick={open}
        className="btn btn-ghost"
        title={hasToken ? 'API token configured' : 'Set API token'}
        aria-label="Set API token"
      >
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
        {hasToken && (
          <span className="ml-1 w-2 h-2 rounded-full bg-bifrost-success" aria-hidden="true" />
        )}
      </button>

      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setIsOpen(false)} />

          <div className="relative w-full max-w-md bg-bifrost-card border border-bifrost-border rounded-xl shadow-2xl animate-slide-up">
            <div className="flex items-center justify-between px-6 py-4 border-b border-bifrost-border">
              <h2 className="text-xl font-semibold text-bifrost-text">API Token</h2>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1 text-bifrost-muted hover:text-bifrost-text transition-colors"
                aria-label="Close dialog"
              >
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="px-6 py-4 space-y-3">
              <p className="text-sm text-bifrost-text/80">
                Enter the API token configured with <code className="font-mono text-bifrost-accent">api.token</code> on
                the client daemon. It is stored in this browser and sent as an
                <code className="font-mono text-bifrost-accent"> Authorization: Bearer</code> header. Leave empty if the
                daemon has no token configured.
              </p>
              <div className="relative">
                <input
                  type={reveal ? 'text' : 'password'}
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleSave()
                  }}
                  placeholder="Paste API token"
                  autoComplete="off"
                  className="input pr-20"
                  aria-label="API token"
                />
                <button
                  type="button"
                  onClick={() => setReveal((r) => !r)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-bifrost-muted hover:text-bifrost-text"
                  aria-label={reveal ? 'Hide token' : 'Show token'}
                >
                  {reveal ? 'Hide' : 'Show'}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-bifrost-border">
              <button onClick={() => setIsOpen(false)} className="btn btn-secondary">
                Cancel
              </button>
              <button onClick={handleSave} className="btn btn-primary">
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
