import { useState, useEffect, useCallback } from 'react'
import { Modal } from '../Modal'
import { ArrayInput } from '../ArrayInput'
import type { RouteConfig } from '../../../api/types'

interface RouteFormProps {
  route?: RouteConfig
  availableBackends: string[]
  onSave: (route: RouteConfig) => void
  onCancel: () => void
}

const loadBalanceOptions = [
  { value: 'round_robin', label: 'Round Robin' },
  { value: 'least_conn', label: 'Least Connections' },
  { value: 'ip_hash', label: 'IP Hash' },
  { value: 'weighted', label: 'Weighted' },
]

export function RouteForm({ route, availableBackends, onSave, onCancel }: RouteFormProps) {
  const isEdit = !!route
  const [form, setForm] = useState<RouteConfig>({
    domains: [''],
    priority: 100,
  })
  const [useMultipleBackends, setUseMultipleBackends] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (route) {
      setForm(route)
      setUseMultipleBackends(!!route.backends && route.backends.length > 0)
    }
  }, [route])

  const handleSave = useCallback(() => {
    // Validation
    const validDomains = form.domains.filter((d) => d.trim())
    if (validDomains.length === 0) {
      setError('At least one domain pattern is required')
      return
    }
    if (!useMultipleBackends && !form.backend) {
      setError('Please select a backend')
      return
    }
    if (useMultipleBackends && (!form.backends || form.backends.length === 0)) {
      setError('Please select at least one backend')
      return
    }

    setError(null)

    const savedRoute: RouteConfig = {
      ...form,
      domains: validDomains,
    }

    // Clean up based on mode
    if (useMultipleBackends) {
      delete savedRoute.backend
    } else {
      delete savedRoute.backends
      delete savedRoute.load_balance
    }

    onSave(savedRoute)
  }, [form, useMultipleBackends, onSave])

  const updateForm = useCallback((field: string, value: unknown) => {
    setForm((prev) => ({ ...prev, [field]: value }))
    setError(null)
  }, [])

  const toggleBackend = useCallback((backendName: string) => {
    setForm((prev) => {
      const current = prev.backends || []
      const updated = current.includes(backendName)
        ? current.filter((b) => b !== backendName)
        : [...current, backendName]
      return { ...prev, backends: updated }
    })
    setError(null)
  }, [])

  return (
    <Modal
      isOpen={true}
      onClose={onCancel}
      title={isEdit ? 'Edit Route' : 'Add Route'}
      onSave={handleSave}
      saveLabel={isEdit ? 'Save Changes' : 'Add Route'}
      size="lg"
    >
      <div className="space-y-6">
        {error && (
          <div className="p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-bifrost-error text-sm">
            {error}
          </div>
        )}

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Route Name</label>
          <input
            type="text"
            value={form.name || ''}
            onChange={(e) => updateForm('name', e.target.value)}
            placeholder="Optional descriptive name"
            className="input"
          />
        </div>

        <div>
          <ArrayInput
            label="Domain Patterns"
            values={form.domains}
            onChange={(domains) => updateForm('domains', domains)}
            placeholder="*.example.com or example.com"
          />
          <p className="text-xs text-bifrost-muted mt-1">
            Use * as wildcard (e.g., *.google.com). Use * alone for catch-all.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Priority</label>
          <input
            type="number"
            value={form.priority}
            onChange={(e) => updateForm('priority', parseInt(e.target.value) || 0)}
            className="input max-w-xs"
          />
          <p className="text-xs text-bifrost-muted mt-1">Higher priority routes are evaluated first</p>
        </div>

        <div className="pt-4 border-t border-bifrost-border">
          <div className="flex items-center gap-4 mb-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                checked={!useMultipleBackends}
                onChange={() => setUseMultipleBackends(false)}
                className="w-4 h-4 border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
              />
              <span className="text-sm text-gray-300">Single Backend</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="radio"
                checked={useMultipleBackends}
                onChange={() => setUseMultipleBackends(true)}
                className="w-4 h-4 border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
              />
              <span className="text-sm text-gray-300">Load Balance (Multiple)</span>
            </label>
          </div>

          {!useMultipleBackends ? (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Backend</label>
              <select
                value={form.backend || ''}
                onChange={(e) => updateForm('backend', e.target.value)}
                className="input"
              >
                <option value="">Select a backend...</option>
                {availableBackends.map((b) => (
                  <option key={b} value={b}>
                    {b}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Backends</label>
                <div className="space-y-2">
                  {availableBackends.map((b) => (
                    <label key={b} className="flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={form.backends?.includes(b) || false}
                        onChange={() => toggleBackend(b)}
                        className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                      />
                      <span className="text-sm text-gray-300">{b}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Load Balance Strategy</label>
                <select
                  value={form.load_balance || 'round_robin'}
                  onChange={(e) => updateForm('load_balance', e.target.value)}
                  className="input max-w-xs"
                >
                  {loadBalanceOptions.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          )}
        </div>
      </div>
    </Modal>
  )
}
