import { useEffect, useState } from 'react'
import { Modal } from '../Config/Modal'
import {
  APIError,
  UNAUTHORIZED_EVENT,
  clearApiToken,
  getApiToken,
  hasSession,
  login,
  logout,
} from '../../api/client'

// ApiTokenButton takes the API token the server configures as `api.token` and,
// where the server has a `session:` store, exchanges it for an HttpOnly session
// cookie so the token itself is never persisted where script can read it. On a
// server without sessions it falls back to storing the token and sending
// `Authorization: Bearer`.
export function ApiTokenButton() {
  const [isOpen, setIsOpen] = useState(false)
  const [value, setValue] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const sessionActive = hasSession()
  const tokenStored = !!getApiToken()
  const authenticated = sessionActive || tokenStored

  const open = () => {
    // Never pre-fill: with a session there is no token to show, and echoing a
    // stored one back into the DOM serves no purpose.
    setValue('')
    setError(null)
    setIsOpen(true)
  }

  // A rejected credential (expired session, rotated token) opens this dialog
  // instead of leaving every page showing an unactionable error.
  useEffect(() => {
    const handler = () => {
      setValue('')
      setError('Your session is no longer valid. Sign in again with the API token.')
      setIsOpen(true)
    }
    window.addEventListener(UNAUTHORIZED_EVENT, handler)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handler)
  }, [])

  const save = async () => {
    const trimmed = value.trim()
    if (!trimmed) {
      setError('Enter a token, or use Sign out to clear the current credential.')
      return
    }

    setBusy(true)
    setError(null)
    try {
      await login(trimmed)
      setIsOpen(false)
      // Reload so React Query refetches and the WebSocket reconnects with the
      // new credential.
      window.location.reload()
    } catch (err) {
      const message =
        err instanceof APIError && err.status === 401
          ? 'The server rejected that token.'
          : err instanceof Error
            ? err.message
            : 'Login failed'
      setError(message)
    } finally {
      setBusy(false)
    }
  }

  const signOut = async () => {
    setBusy(true)
    try {
      await logout()
    } finally {
      clearApiToken()
      setValue('')
      setIsOpen(false)
      window.location.reload()
    }
  }

  return (
    <>
      <button
        onClick={open}
        className="btn btn-ghost"
        title={
          sessionActive
            ? 'Signed in with a session cookie — click to manage'
            : tokenStored
              ? 'API token stored in this browser — click to manage'
              : 'Sign in with the API token'
        }
        aria-label={authenticated ? 'Manage API credential' : 'Sign in with the API token'}
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
          />
        </svg>
        {authenticated && (
          <span
            className={`w-2 h-2 rounded-full ml-1 ${sessionActive ? 'bg-bifrost-success' : 'bg-bifrost-warning'}`}
            aria-hidden="true"
          />
        )}
      </button>

      <Modal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        title="API Credential"
        onSave={save}
        saveLabel={busy ? 'Signing in…' : 'Sign in'}
        isSaving={busy}
        size="md"
      >
        <div className="space-y-4">
          <p className="text-sm text-bifrost-text">
            When the server is configured with an API token (<code className="font-mono">api.token</code>),
            the dashboard must authenticate before it can load data. Paste the
            token below; it is exchanged for a session and{' '}
            <strong>not kept in this browser</strong>.
          </p>

          {sessionActive && (
            <div className="p-3 rounded-lg bg-bifrost-success/10 border border-bifrost-success/30 text-xs text-bifrost-success">
              Signed in with an HttpOnly session cookie. The API token is not stored in this browser.
            </div>
          )}

          {!sessionActive && tokenStored && (
            <div className="p-3 rounded-lg bg-bifrost-warning/10 border border-bifrost-warning/30 text-xs text-bifrost-warning" role="note">
              This server has no <code className="font-mono">session:</code> store configured, so the
              dashboard is falling back to keeping the API token in this browser&apos;s local storage
              and sending it as a bearer credential. Configure a session store to have the token
              exchanged for an HttpOnly cookie instead.
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-bifrost-error/10 border border-bifrost-error/30 text-xs text-bifrost-error" role="alert">
              {error}
            </div>
          )}
          <div>
            <label htmlFor="api-token-input" className="block text-sm font-medium text-bifrost-text mb-1">
              Token
            </label>
            <div className="relative">
              <input
                id="api-token-input"
                type={show ? 'text' : 'password'}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder="Paste API token"
                autoComplete="off"
                className="input pr-10"
              />
              <button
                type="button"
                onClick={() => setShow(!show)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-bifrost-heading"
                aria-label={show ? 'Hide token' : 'Show token'}
              >
                {show ? (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                )}
              </button>
            </div>
            <p className="text-xs text-bifrost-muted mt-1">
              The token is sent once to <code className="font-mono">/api/v1/login</code>.
            </p>
          </div>
          {authenticated && (
            <button onClick={signOut} disabled={busy} className="btn btn-secondary text-sm">
              Sign out
            </button>
          )}
        </div>
      </Modal>
    </>
  )
}
