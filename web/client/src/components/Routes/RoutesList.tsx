import type { Route } from '../../api/types'

interface RoutesListProps {
  routes: Route[]
}

export function RoutesList({ routes }: RoutesListProps) {
  if (routes.length === 0) {
    return (
      <div className="card text-center py-12">
        <svg className="w-12 h-12 mx-auto text-bifrost-muted mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
        </svg>
        <p className="text-bifrost-muted">No routing rules configured</p>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden p-0">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-bifrost-bg/50 border-b border-bifrost-border">
            <tr>
              <th className="table-header">Priority</th>
              <th className="table-header">Name</th>
              <th className="table-header">Patterns</th>
              <th className="table-header">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-bifrost-border">
            {routes.map((route, idx) => (
              <tr key={`${route.name}-${route.priority}-${idx}`} className="hover:bg-bifrost-card-hover transition-colors">
                <td className="table-cell">
                  <span className="badge badge-info">{route.priority}</span>
                </td>
                <td className="table-cell font-medium text-white">
                  {route.name}
                </td>
                <td className="table-cell">
                  <div className="flex flex-wrap gap-1">
                    {route.patterns.slice(0, 3).map((pattern, pIdx) => (
                      <code key={pIdx} className="px-2 py-0.5 bg-bifrost-bg rounded text-xs font-mono text-bifrost-muted">
                        {pattern}
                      </code>
                    ))}
                    {route.patterns.length > 3 && (
                      <span className="text-xs text-bifrost-muted">+{route.patterns.length - 3} more</span>
                    )}
                  </div>
                </td>
                <td className="table-cell">
                  <span className={`badge ${route.action === 'server' ? 'badge-server' : 'badge-direct'}`}>
                    {route.action}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
