import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { RoutesList } from '../components/Routes/RoutesList'
import { RouteTester } from '../components/Routes/RouteTester'

export function RoutesPage() {
  const { data: routes = [], isLoading, isError, error } = useQuery({
    queryKey: ['routes'],
    queryFn: api.getRoutes,
  })

  return (
    <div className="space-y-6">
      <RouteTester />

      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Routing Rules</h2>
        {isError ? (
          <div className="card text-center py-12 border-bifrost-error/30">
            <svg className="w-12 h-12 mx-auto text-bifrost-error mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <p className="text-bifrost-error">Failed to load routes</p>
            <p className="text-sm text-bifrost-muted mt-1">{error instanceof Error ? error.message : 'Unknown error'}</p>
          </div>
        ) : isLoading ? (
          <div className="card text-center py-12">
            <div className="animate-spin w-8 h-8 border-2 border-bifrost-accent border-t-transparent rounded-full mx-auto" />
            <p className="text-bifrost-muted mt-4">Loading routes...</p>
          </div>
        ) : (
          <RoutesList routes={routes} />
        )}
      </div>
    </div>
  )
}
