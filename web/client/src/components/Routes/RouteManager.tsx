import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../../api/client'
import type { Route, RouteTestResult } from '../../api/types'
import { useToast } from '../Toast'
import { ConfirmModal } from '../ConfirmModal'

interface RouteFormData {
  name: string
  patterns: string[]
  action: 'server' | 'direct'
  priority: number
}

interface AddRouteModalProps {
  isOpen: boolean
  onClose: () => void
  onAdd: (route: RouteFormData) => void
  existingNames: string[]
}

function AddRouteModal({ isOpen, onClose, onAdd, existingNames }: AddRouteModalProps) {
  const [name, setName] = useState('')
  const [patterns, setPatterns] = useState('')
  const [action, setAction] = useState<'server' | 'direct'>('server')
  const [priority, setPriority] = useState(100)
  const [error, setError] = useState('')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!name.trim()) {
      setError('Route name is required')
      return
    }

    if (existingNames.includes(name.trim())) {
      setError('A route with this name already exists')
      return
    }

    const patternList = patterns.split('\n').map(p => p.trim()).filter(p => p)
    if (patternList.length === 0) {
      setError('At least one domain pattern is required')
      return
    }

    onAdd({
      name: name.trim(),
      patterns: patternList,
      action,
      priority,
    })

    // Reset form
    setName('')
    setPatterns('')
    setAction('server')
    setPriority(100)
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg bg-bifrost-card border border-bifrost-border rounded-xl shadow-2xl animate-slide-up">
        <div className="flex items-center justify-between px-6 py-4 border-b border-bifrost-border">
          <h2 className="text-xl font-semibold text-bifrost-text">Add Route</h2>
          <button
            onClick={onClose}
            className="p-1 text-bifrost-muted hover:text-bifrost-text transition-colors"
            aria-label="Close dialog"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-4 space-y-4">
          {error && (
            <div className="p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-sm text-bifrost-error">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., social-media"
              className="input w-full"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">
              Domain Patterns
              <span className="text-bifrost-muted font-normal ml-1">(one per line)</span>
            </label>
            <textarea
              value={patterns}
              onChange={(e) => setPatterns(e.target.value)}
              placeholder="*.facebook.com&#10;*.twitter.com&#10;instagram.com"
              rows={4}
              className="input w-full font-mono text-sm"
            />
            <p className="text-xs text-bifrost-muted mt-1">
              Use * as wildcard. Example: *.example.com matches all subdomains.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-bifrost-text mb-1">Action</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value as 'server' | 'direct')}
                className="input w-full"
              >
                <option value="server">Server (Proxy)</option>
                <option value="direct">Direct</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-bifrost-text mb-1">Priority</label>
              <input
                type="number"
                value={priority}
                onChange={(e) => setPriority(parseInt(e.target.value) || 0)}
                min={0}
                max={1000}
                className="input w-full"
              />
              <p className="text-xs text-bifrost-muted mt-1">Higher = checked first</p>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-bifrost-border">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Add Route
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

interface EditRouteModalProps {
  isOpen: boolean
  onClose: () => void
  onSave: (route: RouteFormData) => void
  route: Route | null
  existingNames: string[]
}

function EditRouteModal({ isOpen, onClose, onSave, route, existingNames }: EditRouteModalProps) {
  const [name, setName] = useState(route?.name || '')
  const [patterns, setPatterns] = useState(route?.patterns.join('\n') || '')
  const [action, setAction] = useState<'server' | 'direct'>(route?.action || 'server')
  const [priority, setPriority] = useState(route?.priority || 100)
  const [error, setError] = useState('')

  // Update form when route changes
  useState(() => {
    if (route) {
      setName(route.name)
      setPatterns(route.patterns.join('\n'))
      setAction(route.action)
      setPriority(route.priority)
    }
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    if (!name.trim()) {
      setError('Route name is required')
      return
    }

    // Check for duplicate names (excluding current route)
    if (route && name.trim() !== route.name && existingNames.includes(name.trim())) {
      setError('A route with this name already exists')
      return
    }

    const patternList = patterns.split('\n').map(p => p.trim()).filter(p => p)
    if (patternList.length === 0) {
      setError('At least one domain pattern is required')
      return
    }

    onSave({
      name: name.trim(),
      patterns: patternList,
      action,
      priority,
    })
  }

  if (!isOpen || !route) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg bg-bifrost-card border border-bifrost-border rounded-xl shadow-2xl animate-slide-up">
        <div className="flex items-center justify-between px-6 py-4 border-b border-bifrost-border">
          <h2 className="text-xl font-semibold text-bifrost-text">Edit Route</h2>
          <button
            onClick={onClose}
            className="p-1 text-bifrost-muted hover:text-bifrost-text transition-colors"
            aria-label="Close dialog"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-4 space-y-4">
          {error && (
            <div className="p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-sm text-bifrost-error">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., social-media"
              className="input w-full"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-bifrost-text mb-1">
              Domain Patterns
              <span className="text-bifrost-muted font-normal ml-1">(one per line)</span>
            </label>
            <textarea
              value={patterns}
              onChange={(e) => setPatterns(e.target.value)}
              placeholder="*.facebook.com&#10;*.twitter.com&#10;instagram.com"
              rows={4}
              className="input w-full font-mono text-sm"
            />
            <p className="text-xs text-bifrost-muted mt-1">
              Use * as wildcard. Example: *.example.com matches all subdomains.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-bifrost-text mb-1">Action</label>
              <select
                value={action}
                onChange={(e) => setAction(e.target.value as 'server' | 'direct')}
                className="input w-full"
              >
                <option value="server">Server (Proxy)</option>
                <option value="direct">Direct</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-bifrost-text mb-1">Priority</label>
              <input
                type="number"
                value={priority}
                onChange={(e) => setPriority(parseInt(e.target.value) || 0)}
                min={0}
                max={1000}
                className="input w-full"
              />
              <p className="text-xs text-bifrost-muted mt-1">Higher = checked first</p>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-bifrost-border">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Save Changes
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export function RouteManager() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const [showAddModal, setShowAddModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [selectedRoute, setSelectedRoute] = useState<Route | null>(null)
  const [testDomain, setTestDomain] = useState('')
  const [testResult, setTestResult] = useState<RouteTestResult | null>(null)

  const { data: routes = [], isLoading, isError } = useQuery({
    queryKey: ['routes'],
    queryFn: api.getRoutes,
  })

  const addMutation = useMutation({
    mutationFn: (route: RouteFormData) => api.addRoute({
      name: route.name,
      domains: route.patterns,
      action: route.action,
      priority: route.priority,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['routes'] })
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setShowAddModal(false)
      showToast('Route added successfully', 'success')
    },
    onError: (err: Error) => {
      showToast(`Failed to add route: ${err.message}`, 'error')
    },
  })

  const removeMutation = useMutation({
    mutationFn: (name: string) => api.removeRoute(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['routes'] })
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setShowDeleteConfirm(false)
      setSelectedRoute(null)
      showToast('Route removed successfully', 'success')
    },
    onError: (err: Error) => {
      showToast(`Failed to remove route: ${err.message}`, 'error')
    },
  })

  const editMutation = useMutation({
    mutationFn: async (route: RouteFormData) => {
      // Edit = delete old + add new (since backend doesn't have update endpoint)
      if (selectedRoute) {
        await api.removeRoute(selectedRoute.name)
      }
      return api.addRoute({
        name: route.name,
        domains: route.patterns,
        action: route.action,
        priority: route.priority,
      })
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['routes'] })
      queryClient.invalidateQueries({ queryKey: ['config'] })
      setShowEditModal(false)
      setSelectedRoute(null)
      showToast('Route updated successfully', 'success')
    },
    onError: (err: Error) => {
      showToast(`Failed to update route: ${err.message}`, 'error')
    },
  })

  const testMutation = useMutation({
    mutationFn: api.testRoute,
    onSuccess: (data) => setTestResult(data),
    onError: (err: Error) => {
      showToast(`Failed to test route: ${err.message}`, 'error')
    },
  })

  const handleTest = (e: React.FormEvent) => {
    e.preventDefault()
    if (testDomain.trim()) {
      testMutation.mutate(testDomain.trim())
    }
  }

  const handleExport = async (format: 'json' | 'yaml') => {
    try {
      const blob = await api.exportRoutes(format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `bifrost-routes.${format}`
      a.click()
      URL.revokeObjectURL(url)
      showToast('Routes exported successfully', 'success')
    } catch (err) {
      showToast(`Failed to export routes: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
    }
  }

  const handleImport = () => {
    fileInputRef.current?.click()
  }

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    try {
      const content = await file.text()
      let importedRoutes: Route[]

      if (file.name.endsWith('.json')) {
        importedRoutes = JSON.parse(content)
      } else if (file.name.endsWith('.yaml') || file.name.endsWith('.yml')) {
        // Simple YAML parsing for routes
        const lines = content.split('\n')
        importedRoutes = []
        let currentRoute: Partial<Route> | null = null

        for (const line of lines) {
          const trimmed = line.trim()
          if (trimmed.startsWith('- name:')) {
            if (currentRoute && currentRoute.name) {
              importedRoutes.push(currentRoute as Route)
            }
            currentRoute = {
              name: trimmed.replace('- name:', '').trim().replace(/"/g, ''),
              patterns: [],
              action: 'server',
              priority: 100,
            }
          } else if (currentRoute) {
            if (trimmed.startsWith('- "') || trimmed.startsWith("- '")) {
              currentRoute.patterns = currentRoute.patterns || []
              currentRoute.patterns.push(trimmed.slice(3, -1))
            } else if (trimmed.startsWith('action:')) {
              currentRoute.action = trimmed.replace('action:', '').trim().replace(/"/g, '') as 'server' | 'direct'
            } else if (trimmed.startsWith('priority:')) {
              currentRoute.priority = parseInt(trimmed.replace('priority:', '').trim()) || 100
            }
          }
        }
        if (currentRoute && currentRoute.name) {
          importedRoutes.push(currentRoute as Route)
        }
      } else {
        showToast('Unsupported file format. Use JSON or YAML.', 'error')
        return
      }

      if (!Array.isArray(importedRoutes) || importedRoutes.length === 0) {
        showToast('No valid routes found in file', 'error')
        return
      }

      const results = await api.importRoutes(importedRoutes)
      const successCount = results.filter(r => r.success).length
      const failCount = results.filter(r => !r.success).length

      queryClient.invalidateQueries({ queryKey: ['routes'] })
      queryClient.invalidateQueries({ queryKey: ['config'] })

      if (failCount === 0) {
        showToast(`Successfully imported ${successCount} route(s)`, 'success')
      } else {
        showToast(`Imported ${successCount} route(s), ${failCount} failed`, 'warning')
      }
    } catch (err) {
      showToast(`Failed to import routes: ${err instanceof Error ? err.message : 'Unknown error'}`, 'error')
    }

    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const existingNames = routes.map(r => r.name)

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="animate-spin w-6 h-6 border-2 border-bifrost-accent border-t-transparent rounded-full" />
      </div>
    )
  }

  if (isError) {
    return (
      <div className="p-4 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-sm text-bifrost-error">
        Failed to load routes. Please try again.
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Route Tester */}
      <div className="p-4 bg-bifrost-bg/50 rounded-lg border border-bifrost-border">
        <h4 className="text-sm font-medium text-bifrost-text mb-3">Test Domain Routing</h4>
        <form onSubmit={handleTest} className="flex gap-2">
          <input
            type="text"
            placeholder="Enter domain (e.g., google.com)"
            value={testDomain}
            onChange={(e) => setTestDomain(e.target.value)}
            className="input flex-1"
          />
          <button
            type="submit"
            disabled={!testDomain.trim() || testMutation.isPending}
            className="btn btn-primary"
          >
            {testMutation.isPending ? 'Testing...' : 'Test'}
          </button>
        </form>
        {testResult && (
          <div className="mt-3 p-3 bg-bifrost-card rounded border border-bifrost-border">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-bifrost-text">{testResult.domain}</span>
              <span className={`badge ${testResult.action === 'server' ? 'badge-server' : 'badge-direct'}`}>
                {testResult.action}
              </span>
            </div>
            {testResult.matched_route && (
              <p className="text-xs text-bifrost-muted mt-1">Matched: {testResult.matched_route}</p>
            )}
          </div>
        )}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm text-bifrost-muted">
          {routes.length} route{routes.length !== 1 ? 's' : ''} configured
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={handleImport} className="btn btn-secondary text-sm">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            Import
          </button>
          <button onClick={() => handleExport('json')} className="btn btn-secondary text-sm">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Export
          </button>
          <button onClick={() => setShowAddModal(true)} className="btn btn-primary text-sm">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add Route
          </button>
        </div>
      </div>

      {/* Hidden file input for import */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".json,.yaml,.yml"
        onChange={handleFileSelect}
        className="hidden"
      />

      {/* Routes Table */}
      {routes.length === 0 ? (
        <div className="text-center py-8 text-bifrost-muted">
          <svg className="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
          </svg>
          <p>No routes configured</p>
          <p className="text-sm mt-1">Add a route to control how traffic is routed.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-bifrost-border">
          <table className="w-full text-sm">
            <thead className="bg-bifrost-bg/50 border-b border-bifrost-border">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-bifrost-muted">Priority</th>
                <th className="px-4 py-3 text-left font-medium text-bifrost-muted">Name</th>
                <th className="px-4 py-3 text-left font-medium text-bifrost-muted">Patterns</th>
                <th className="px-4 py-3 text-left font-medium text-bifrost-muted">Action</th>
                <th className="px-4 py-3 text-right font-medium text-bifrost-muted">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-bifrost-border">
              {routes
                .sort((a, b) => b.priority - a.priority)
                .map((route) => (
                  <tr key={route.name} className="hover:bg-bifrost-card-hover transition-colors">
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center justify-center w-8 h-6 text-xs font-medium bg-bifrost-bg rounded">
                        {route.priority}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-medium text-bifrost-text">{route.name}</td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {route.patterns.slice(0, 3).map((pattern, idx) => (
                          <code key={idx} className="px-2 py-0.5 text-xs bg-bifrost-bg rounded font-mono text-bifrost-muted">
                            {pattern}
                          </code>
                        ))}
                        {route.patterns.length > 3 && (
                          <span className="text-xs text-bifrost-muted">+{route.patterns.length - 3} more</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`badge ${route.action === 'server' ? 'badge-server' : 'badge-direct'}`}>
                        {route.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex justify-end gap-1">
                        <button
                          onClick={() => {
                            setSelectedRoute(route)
                            setShowEditModal(true)
                          }}
                          className="p-1.5 text-bifrost-muted hover:text-bifrost-accent transition-colors"
                          aria-label="Edit route"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                        </button>
                        <button
                          onClick={() => {
                            setSelectedRoute(route)
                            setShowDeleteConfirm(true)
                          }}
                          className="p-1.5 text-bifrost-muted hover:text-bifrost-error transition-colors"
                          aria-label="Delete route"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modals */}
      <AddRouteModal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onAdd={(route) => addMutation.mutate(route)}
        existingNames={existingNames}
      />

      <EditRouteModal
        isOpen={showEditModal}
        onClose={() => {
          setShowEditModal(false)
          setSelectedRoute(null)
        }}
        onSave={(route) => editMutation.mutate(route)}
        route={selectedRoute}
        existingNames={existingNames}
      />

      <ConfirmModal
        isOpen={showDeleteConfirm}
        onClose={() => {
          setShowDeleteConfirm(false)
          setSelectedRoute(null)
        }}
        onConfirm={() => selectedRoute && removeMutation.mutate(selectedRoute.name)}
        title="Delete Route"
        message={`Are you sure you want to delete the route "${selectedRoute?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </div>
  )
}
