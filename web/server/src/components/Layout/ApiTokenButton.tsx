import { useState } from 'react'
import { Modal } from '../Config/Modal'
import { getApiToken, setApiToken, clearApiToken } from '../../api/client'

// ApiTokenButton lets an operator supply the API token the dashboard sends as
// `Authorization: Bearer <token>` (and as `?token=` on WebSocket handshakes).
// This is required whenever the server has `api.token` configured; without it
// every /api/v1/* call returns 401 and the dashboard cannot load data.
export function ApiTokenButton() {
  const [isOpen, setIsOpen] = useState(false)
  const [value, setValue] = useState('')
  const [show, setShow] = useState(false)
  const hasToken = !!getApiToken()

  const open = () => {
    setValue(getApiToken() || '')
    setIsOpen(true)
  }

  const save = () => {
    const trimmed = value.trim()
    if (trimmed) {
      setApiToken(trimmed)
    } else {
      clearApiToken()
    }
    setIsOpen(false)
    // Reload so React Query refetches and WebSockets reconnect with the new
    // credentials (the token is read at request time from localStorage).
    window.location.reload()
  }

  const clear = () => {
    clearApiToken()
    setValue('')
    setIsOpen(false)
    window.location.reload()
  }

  return (
    <>
      <button
        onClick={open}
        className="btn btn-ghost"
        title={hasToken ? 'API token set — click to change' : 'Set API token'}
        aria-label={hasToken ? 'Change API token' : 'Set API token'}
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
          />
        </svg>
        {hasToken && <span className="w-2 h-2 rounded-full bg-bifrost-success ml-1" aria-hidden="true" />}
      </button>

      <Modal
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        title="API Token"
        onSave={save}
        saveLabel="Save & Reload"
        size="md"
      >
        <div className="space-y-4">
          <p className="text-sm text-gray-300">
            When the server is configured with an API token (<code className="font-mono">api.token</code>),
            the dashboard must send it with every request. Paste the token below;
            it is stored in this browser&apos;s local storage only.
          </p>
          <div>
            <label htmlFor="api-token-input" className="block text-sm font-medium text-gray-300 mb-1">
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
                className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-white"
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
              Leave empty and save to remove the stored token.
            </p>
          </div>
          {hasToken && (
            <button onClick={clear} className="btn btn-secondary text-sm">
              Clear stored token
            </button>
          )}
        </div>
      </Modal>
    </>
  )
}
