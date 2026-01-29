import { useState } from 'react'
import { Section } from '../Section'
import { RouteForm } from '../forms/RouteForm'
import { ConfirmModal } from '../ConfirmModal'
import type { RouteConfig } from '../../../api/types'

interface RoutesSectionProps {
  routes: RouteConfig[]
  availableBackends: string[]
  onChange: (routes: RouteConfig[]) => void
}

export function RoutesSection({ routes, availableBackends, onChange }: RoutesSectionProps) {
  const [editingRoute, setEditingRoute] = useState<{ route: RouteConfig; index: number } | null>(null)
  const [isAdding, setIsAdding] = useState(false)
  const [deletingRouteIndex, setDeletingRouteIndex] = useState<number | null>(null)

  const handleSave = (route: RouteConfig) => {
    if (editingRoute) {
      // Edit existing
      const updated = [...routes]
      updated[editingRoute.index] = route
      onChange(updated)
    } else {
      // Add new
      onChange([...routes, route])
    }
    setEditingRoute(null)
    setIsAdding(false)
  }

  const handleDelete = (index: number) => {
    onChange(routes.filter((_, i) => i !== index))
  }

  const getRouteName = (index: number) => {
    const route = routes[index]
    return route?.name || route?.domains.join(', ') || 'this route'
  }

  const moveRoute = (index: number, direction: 'up' | 'down') => {
    const newIndex = direction === 'up' ? index - 1 : index + 1
    if (newIndex < 0 || newIndex >= routes.length) return

    const updated = [...routes]
    const [removed] = updated.splice(index, 1)
    updated.splice(newIndex, 0, removed)
    onChange(updated)
  }

  // Sort by priority for display
  const sortedRoutes = [...routes].sort((a, b) => (b.priority || 0) - (a.priority || 0))

  return (
    <Section title="Routes" badge="hot-reload">
      <div className="space-y-4">
        {routes.length === 0 ? (
          <div className="text-center py-8 text-bifrost-muted">
            <p>No routes configured</p>
            <p className="text-sm mt-1">Add routes to direct traffic to specific backends</p>
          </div>
        ) : (
          <div className="space-y-2">
            {sortedRoutes.map((route, displayIndex) => {
              const actualIndex = routes.indexOf(route)
              return (
                <div
                  key={actualIndex}
                  className="flex items-center justify-between p-4 bg-bifrost-bg rounded-lg"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      {route.name && (
                        <span className="font-medium text-white">{route.name}</span>
                      )}
                      <span className="badge badge-info text-xs">Priority: {route.priority || 0}</span>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {route.domains.slice(0, 3).map((domain, i) => (
                        <code key={i} className="px-2 py-0.5 bg-bifrost-card rounded text-xs font-mono text-bifrost-muted">
                          {domain}
                        </code>
                      ))}
                      {route.domains.length > 3 && (
                        <span className="text-xs text-bifrost-muted">+{route.domains.length - 3} more</span>
                      )}
                    </div>
                    <div className="text-xs text-bifrost-muted mt-1">
                      {route.backend ? (
                        <>
                          Backend: <span className="text-white">{route.backend}</span>
                        </>
                      ) : route.backends ? (
                        <>
                          Backends: <span className="text-white">{route.backends.join(', ')}</span>
                          {route.load_balance && (
                            <> • {route.load_balance.replace('_', ' ')}</>
                          )}
                        </>
                      ) : (
                        <span className="text-bifrost-warning">No backend specified</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 ml-4">
                    <button
                      onClick={() => moveRoute(actualIndex, 'up')}
                      disabled={displayIndex === 0}
                      className="btn btn-ghost text-sm disabled:opacity-30"
                      title="Move up (higher priority)"
                      aria-label="Move route up"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                      </svg>
                    </button>
                    <button
                      onClick={() => moveRoute(actualIndex, 'down')}
                      disabled={displayIndex === sortedRoutes.length - 1}
                      className="btn btn-ghost text-sm disabled:opacity-30"
                      title="Move down (lower priority)"
                      aria-label="Move route down"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>
                    <button
                      onClick={() => setEditingRoute({ route, index: actualIndex })}
                      className="btn btn-ghost text-sm"
                      aria-label="Edit route"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                      </svg>
                    </button>
                    <button
                      onClick={() => setDeletingRouteIndex(actualIndex)}
                      className="btn btn-ghost text-sm text-bifrost-error hover:bg-bifrost-error/10"
                      aria-label="Delete route"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}

        <button onClick={() => setIsAdding(true)} className="btn btn-secondary">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Route
        </button>
      </div>

      {(isAdding || editingRoute) && (
        <RouteForm
          route={editingRoute?.route}
          availableBackends={availableBackends}
          onSave={handleSave}
          onCancel={() => {
            setIsAdding(false)
            setEditingRoute(null)
          }}
        />
      )}

      <ConfirmModal
        isOpen={deletingRouteIndex !== null}
        onClose={() => setDeletingRouteIndex(null)}
        onConfirm={() => deletingRouteIndex !== null && handleDelete(deletingRouteIndex)}
        title="Delete Route"
        message={`Are you sure you want to delete "${deletingRouteIndex !== null ? getRouteName(deletingRouteIndex) : ''}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </Section>
  )
}
