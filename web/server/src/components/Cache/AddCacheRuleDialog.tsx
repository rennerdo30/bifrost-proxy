import { useState, useEffect } from 'react'
import type { AddCacheRuleRequest } from '../../api/types'

interface AddCacheRuleDialogProps {
  isOpen: boolean
  onClose: () => void
  onSave: (rule: AddCacheRuleRequest) => Promise<void>
  existingNames: string[]
}

export function AddCacheRuleDialog({
  isOpen,
  onClose,
  onSave,
  existingNames,
}: AddCacheRuleDialogProps) {
  const [name, setName] = useState('')
  const [domains, setDomains] = useState('')
  const [ttl, setTtl] = useState('24h')
  const [priority, setPriority] = useState(10)
  const [enabled, setEnabled] = useState(true)
  const [ignoreQuery, setIgnoreQuery] = useState(false)
  const [respectCacheControl, setRespectCacheControl] = useState(true)
  const [maxSize, setMaxSize] = useState('')
  const [contentTypes, setContentTypes] = useState('')
  const [isSaving, setIsSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Reset form when dialog opens
  useEffect(() => {
    if (isOpen) {
      setName('')
      setDomains('')
      setTtl('24h')
      setPriority(10)
      setEnabled(true)
      setIgnoreQuery(false)
      setRespectCacheControl(true)
      setMaxSize('')
      setContentTypes('')
      setError(null)
    }
  }, [isOpen])

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

    // Validation
    if (!name.trim()) {
      setError('Rule name is required')
      return
    }

    if (existingNames.includes(name.trim())) {
      setError('A rule with this name already exists')
      return
    }

    const domainList = domains
      .split(/[,\n]/)
      .map((d) => d.trim())
      .filter(Boolean)

    if (domainList.length === 0) {
      setError('At least one domain is required')
      return
    }

    if (!ttl.trim()) {
      setError('TTL is required')
      return
    }

    const rule: AddCacheRuleRequest = {
      name: name.trim(),
      domains: domainList,
      ttl: ttl.trim(),
      priority,
      enabled,
      ignore_query: ignoreQuery,
      respect_cache_control: respectCacheControl,
    }

    if (maxSize.trim()) {
      rule.max_size = maxSize.trim()
    }

    const contentTypeList = contentTypes
      .split(/[,\n]/)
      .map((c) => c.trim())
      .filter(Boolean)

    if (contentTypeList.length > 0) {
      rule.content_types = contentTypeList
    }

    setIsSaving(true)
    try {
      await onSave(rule)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save rule')
    } finally {
      setIsSaving(false)
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className="relative w-full max-w-lg bg-bifrost-card border border-bifrost-border rounded-xl shadow-2xl animate-slide-up max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-bifrost-card flex items-center justify-between px-6 py-4 border-b border-bifrost-border">
          <h2 className="text-xl font-semibold text-white">Add Cache Rule</h2>
          <button
            onClick={onClose}
            className="p-1 text-bifrost-muted hover:text-white transition-colors"
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

            {/* Name */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Rule Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="input w-full"
                placeholder="my-cache-rule"
              />
            </div>

            {/* Domains */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Domains
              </label>
              <textarea
                value={domains}
                onChange={(e) => setDomains(e.target.value)}
                className="input w-full h-20 resize-none"
                placeholder="*.example.com&#10;api.example.com"
              />
              <p className="text-xs text-bifrost-muted mt-1">
                One domain per line or comma-separated. Supports wildcards (*)
              </p>
            </div>

            {/* TTL and Priority */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  TTL
                </label>
                <input
                  type="text"
                  value={ttl}
                  onChange={(e) => setTtl(e.target.value)}
                  className="input w-full"
                  placeholder="24h"
                />
                <p className="text-xs text-bifrost-muted mt-1">e.g., 1h, 30m, 7d</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Priority
                </label>
                <input
                  type="number"
                  value={priority}
                  onChange={(e) => setPriority(parseInt(e.target.value) || 0)}
                  className="input w-full"
                  min={0}
                  max={100}
                />
                <p className="text-xs text-bifrost-muted mt-1">Higher = checked first</p>
              </div>
            </div>

            {/* Max Size */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Max Size (optional)
              </label>
              <input
                type="text"
                value={maxSize}
                onChange={(e) => setMaxSize(e.target.value)}
                className="input w-full"
                placeholder="100MB"
              />
              <p className="text-xs text-bifrost-muted mt-1">
                Maximum file size to cache (e.g., 10MB, 1GB)
              </p>
            </div>

            {/* Content Types */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Content Types (optional)
              </label>
              <input
                type="text"
                value={contentTypes}
                onChange={(e) => setContentTypes(e.target.value)}
                className="input w-full"
                placeholder="application/json, text/html"
              />
              <p className="text-xs text-bifrost-muted mt-1">
                Comma-separated list of MIME types to cache
              </p>
            </div>

            {/* Toggles */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-300">Enabled</p>
                  <p className="text-xs text-bifrost-muted">Rule is active</p>
                </div>
                <button
                  type="button"
                  onClick={() => setEnabled(!enabled)}
                  className={`w-10 h-5 rounded-full relative transition-colors ${
                    enabled ? 'bg-bifrost-success' : 'bg-bifrost-border'
                  }`}
                >
                  <span
                    className={`absolute w-4 h-4 rounded-full bg-white top-0.5 transition-transform ${
                      enabled ? 'translate-x-5' : 'translate-x-0.5'
                    }`}
                  />
                </button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-300">Ignore Query String</p>
                  <p className="text-xs text-bifrost-muted">Cache regardless of query params</p>
                </div>
                <button
                  type="button"
                  onClick={() => setIgnoreQuery(!ignoreQuery)}
                  className={`w-10 h-5 rounded-full relative transition-colors ${
                    ignoreQuery ? 'bg-bifrost-success' : 'bg-bifrost-border'
                  }`}
                >
                  <span
                    className={`absolute w-4 h-4 rounded-full bg-white top-0.5 transition-transform ${
                      ignoreQuery ? 'translate-x-5' : 'translate-x-0.5'
                    }`}
                  />
                </button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-gray-300">Respect Cache-Control</p>
                  <p className="text-xs text-bifrost-muted">Honor upstream cache headers</p>
                </div>
                <button
                  type="button"
                  onClick={() => setRespectCacheControl(!respectCacheControl)}
                  className={`w-10 h-5 rounded-full relative transition-colors ${
                    respectCacheControl ? 'bg-bifrost-success' : 'bg-bifrost-border'
                  }`}
                >
                  <span
                    className={`absolute w-4 h-4 rounded-full bg-white top-0.5 transition-transform ${
                      respectCacheControl ? 'translate-x-5' : 'translate-x-0.5'
                    }`}
                  />
                </button>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="sticky bottom-0 bg-bifrost-card flex items-center justify-end gap-3 px-6 py-4 border-t border-bifrost-border">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={isSaving}>
              {isSaving ? 'Saving...' : 'Add Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
