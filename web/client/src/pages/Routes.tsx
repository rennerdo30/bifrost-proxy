import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { RoutesList } from '../components/Routes/RoutesList'
import { RouteTester } from '../components/Routes/RouteTester'

export function RoutesPage() {
  const { data: routes = [], isLoading } = useQuery({
    queryKey: ['routes'],
    queryFn: api.getRoutes,
  })

  return (
    <div className="space-y-6">
      <RouteTester />

      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Routing Rules</h2>
        {isLoading ? (
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
