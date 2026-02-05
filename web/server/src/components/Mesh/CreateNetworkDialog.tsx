import { useState, useCallback } from 'react'
import type { CreateMeshNetworkRequest } from '../../api/types'

interface CreateNetworkDialogProps {
  isOpen: boolean
  onClose: () => void
  onSave: (request: CreateMeshNetworkRequest) => Promise<void>
  existingIds: string[]
}

export function CreateNetworkDialog({
  isOpen,
  onClose,
  onSave,
  existingIds,
}: CreateNetworkDialogProps) {
  const [id, setId] = useState('')
  const [name, setName] = useState('')
  const [cidr, setCidr] = useState('10.100.0.0/16')
  const [error, setError] = useState('')
  const [isSaving, setIsSaving] = useState(false)

  const handleClose = useCallback(() => {
    setId('')
    setName('')
    setCidr('10.100.0.0/16')
    setError('')
    onClose()
  }, [onClose])

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    // Validation
    if (!id.trim()) {
      setError('Network ID is required')
      return
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
      setError('Network ID can only contain letters, numbers, hyphens, and underscores')
      return
    }

    if (existingIds.includes(id)) {
      setError('A network with this ID already exists')
      return
    }

    // Basic CIDR validation
    if (cidr && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(cidr)) {
      setError('Invalid CIDR format (e.g., 10.100.0.0/16)')
      return
    }

    setIsSaving(true)
    try {
      await onSave({
        id: id.trim(),
        name: name.trim() || id.trim(),
        cidr: cidr || undefined,
      })
      handleClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create network')
    } finally {
      setIsSaving(false)
    }
  }, [id, name, cidr, existingIds, onSave, handleClose])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={handleClose}
      />

      {/* Dialog */}
      <div className="relative w-full max-w-md bg-bifrost-card border border-bifrost-border rounded-lg shadow-xl">
        <form onSubmit={handleSubmit}>
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-bifrost-border">
            <h3 className="text-lg font-semibold text-white">Create Mesh Network</h3>
            <button
              type="button"
              onClick={handleClose}
              className="p-1.5 rounded hover:bg-bifrost-bg text-bifrost-muted hover:text-white transition-colors"
              aria-label="Close"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Content */}
          <div className="px-6 py-4 space-y-4">
            {error && (
              <div className="p-3 rounded bg-bifrost-error/10 border border-bifrost-error/50 text-bifrost-error text-sm">
                {error}
              </div>
            )}

            <div>
              <label htmlFor="network-id" className="block text-sm font-medium text-bifrost-muted mb-1">
                Network ID <span className="text-bifrost-error">*</span>
              </label>
              <input
                id="network-id"
                type="text"
                value={id}
                onChange={(e) => setId(e.target.value)}
                placeholder="my-mesh-network"
                className="input w-full"
                autoFocus
              />
              <p className="text-xs text-bifrost-muted mt-1">
                Unique identifier for this network
              </p>
            </div>

            <div>
              <label htmlFor="network-name" className="block text-sm font-medium text-bifrost-muted mb-1">
                Display Name
              </label>
              <input
                id="network-name"
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="My Mesh Network"
                className="input w-full"
              />
              <p className="text-xs text-bifrost-muted mt-1">
                Human-readable name (defaults to ID)
              </p>
            </div>

            <div>
              <label htmlFor="network-cidr" className="block text-sm font-medium text-bifrost-muted mb-1">
                CIDR Range
              </label>
              <input
                id="network-cidr"
                type="text"
                value={cidr}
                onChange={(e) => setCidr(e.target.value)}
                placeholder="10.100.0.0/16"
                className="input w-full font-mono"
              />
              <p className="text-xs text-bifrost-muted mt-1">
                IP address range for virtual IPs
              </p>
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-bifrost-border bg-bifrost-bg/50">
            <button
              type="button"
              onClick={handleClose}
              className="btn btn-secondary"
              disabled={isSaving}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isSaving}
            >
              {isSaving ? (
                <>
                  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Creating...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                  </svg>
                  Create Network
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
