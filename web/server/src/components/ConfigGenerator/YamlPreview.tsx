import { useState } from 'react'

interface YamlPreviewProps {
  yaml: string
}

type NotificationType = 'success' | 'error' | null

export function YamlPreview({ yaml }: YamlPreviewProps) {
  const [copied, setCopied] = useState(false)
  const [notification, setNotification] = useState<{ message: string; type: NotificationType }>({ message: '', type: null })

  const showNotification = (message: string, type: NotificationType) => {
    setNotification({ message, type })
    setTimeout(() => setNotification({ message: '', type: null }), 3000)
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(yaml)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy to clipboard:', err)
      showNotification('Failed to copy to clipboard. Please try selecting and copying manually.', 'error')
    }
  }

  const handleDownload = () => {
    try {
      const blob = new Blob([yaml], { type: 'text/yaml' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'bifrost-client.yaml'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      showNotification('Configuration downloaded successfully.', 'success')
    } catch (err) {
      console.error('Failed to download configuration:', err)
      showNotification('Failed to download configuration. Please try copying the content instead.', 'error')
    }
  }

  return (
    <div className="card h-full flex flex-col">
      {/* Notification Banner */}
      {notification.type && (
        <div
          className={`mb-4 px-4 py-3 rounded-lg flex items-center gap-2 ${
            notification.type === 'error'
              ? 'bg-bifrost-error/10 border border-bifrost-error/30 text-bifrost-error'
              : 'bg-bifrost-success/10 border border-bifrost-success/30 text-bifrost-success'
          }`}
        >
          {notification.type === 'error' ? (
            <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          ) : (
            <svg className="w-5 h-5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          )}
          <span className="text-sm">{notification.message}</span>
        </div>
      )}

      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white">Generated Config</h3>
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="btn btn-secondary text-sm"
          >
            {copied ? (
              <>
                <svg className="w-4 h-4 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                Copied!
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
                Copy
              </>
            )}
          </button>
          <button
            onClick={handleDownload}
            className="btn btn-primary text-sm"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Download
          </button>
        </div>
      </div>

      <div className="code-block flex-1 overflow-auto">
        <pre className="text-gray-300 whitespace-pre-wrap">{yaml}</pre>
      </div>

      <div className="mt-4 p-3 bg-bifrost-bg rounded-lg">
        <p className="text-xs text-bifrost-muted">
          Save this file as <code className="text-bifrost-accent">bifrost-client.yaml</code> and run:
        </p>
        <code className="block mt-2 text-sm text-gray-300">
          bifrost-client -c bifrost-client.yaml
        </code>
      </div>
    </div>
  )
}
