import { useState } from 'react'
import { Modal } from '../Config/Modal'
import type { TestBackendResponse } from '../../api/types'
import { api } from '../../api/client'

interface TestBackendDialogProps {
  isOpen: boolean
  onClose: () => void
  backendName: string
}

export function TestBackendDialog({ isOpen, onClose, backendName }: TestBackendDialogProps) {
  const [target, setTarget] = useState('https://www.google.com')
  const [timeout, setTimeout] = useState('10s')
  const [isTesting, setIsTesting] = useState(false)
  const [result, setResult] = useState<TestBackendResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleTest = async () => {
    setIsTesting(true)
    setResult(null)
    setError(null)

    try {
      const response = await api.testBackend(backendName, {
        target: target || undefined,
        timeout: timeout || undefined,
      })
      setResult(response)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Test failed')
    } finally {
      setIsTesting(false)
    }
  }

  const handleClose = () => {
    setResult(null)
    setError(null)
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title={`Test Backend: ${backendName}`}
      size="md"
    >
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Target URL</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://www.google.com"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">URL to test connectivity to</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Timeout</label>
          <input
            type="text"
            value={timeout}
            onChange={(e) => setTimeout(e.target.value)}
            placeholder="10s"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">Go duration format (e.g., 10s, 1m)</p>
        </div>

        <button
          onClick={handleTest}
          disabled={isTesting}
          className="btn btn-primary w-full"
        >
          {isTesting ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Testing...
            </>
          ) : (
            <>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              Run Test
            </>
          )}
        </button>

        {error && (
          <div className="p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-bifrost-error text-sm">
            {error}
          </div>
        )}

        {result && (
          <div
            className={`p-4 rounded-lg border ${
              result.status === 'success'
                ? 'bg-bifrost-success/10 border-bifrost-success/30'
                : 'bg-bifrost-error/10 border-bifrost-error/30'
            }`}
          >
            <div className="flex items-center gap-2 mb-3">
              {result.status === 'success' ? (
                <svg className="w-5 h-5 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              ) : (
                <svg className="w-5 h-5 text-bifrost-error" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              )}
              <span
                className={`font-semibold ${
                  result.status === 'success' ? 'text-bifrost-success' : 'text-bifrost-error'
                }`}
              >
                {result.status === 'success' ? 'Test Passed' : 'Test Failed'}
              </span>
            </div>

            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Backend:</span>
                <span className="text-white font-mono">{result.backend}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Target:</span>
                <span className="text-white font-mono truncate max-w-[200px]">{result.target}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Duration:</span>
                <span className="text-white font-mono">{result.duration}</span>
              </div>
              {result.healthy !== undefined && (
                <div className="flex justify-between">
                  <span className="text-gray-400">Healthy:</span>
                  <span className={result.healthy ? 'text-bifrost-success' : 'text-bifrost-error'}>
                    {result.healthy ? 'Yes' : 'No'}
                  </span>
                </div>
              )}
              {result.error && (
                <div className="mt-2 pt-2 border-t border-bifrost-border">
                  <span className="text-gray-400 block mb-1">Error:</span>
                  <span className="text-bifrost-error text-xs font-mono break-all">{result.error}</span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </Modal>
  )
}
