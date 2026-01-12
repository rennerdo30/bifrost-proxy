import type { ServerStats } from '../../api/types'

interface StatsCardsProps {
  stats: ServerStats | undefined
  isLoading: boolean
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

interface StatCardProps {
  label: string
  value: string | number
  icon: React.ReactNode
  trend?: 'up' | 'down' | 'neutral'
  color?: 'default' | 'success' | 'warning' | 'error'
  delay?: number
}

function StatCard({ label, value, icon, color = 'default', delay = 0 }: StatCardProps) {
  const colorClasses = {
    default: 'from-bifrost-accent/20 to-transparent',
    success: 'from-bifrost-success/20 to-transparent',
    warning: 'from-bifrost-warning/20 to-transparent',
    error: 'from-bifrost-error/20 to-transparent',
  }

  const iconColorClasses = {
    default: 'text-bifrost-accent',
    success: 'text-bifrost-success',
    warning: 'text-bifrost-warning',
    error: 'text-bifrost-error',
  }

  return (
    <div
      className="card card-hover animate-slide-up relative overflow-hidden"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className={`absolute inset-0 bg-gradient-to-br ${colorClasses[color]} pointer-events-none`} />
      <div className="relative">
        <div className="flex items-start justify-between">
          <div>
            <p className="stat-label">{label}</p>
            <p className="stat-value mt-1">{value}</p>
          </div>
          <div className={`p-2 rounded-lg bg-bifrost-bg/50 ${iconColorClasses[color]}`}>
            {icon}
          </div>
        </div>
      </div>
    </div>
  )
}

export function StatsCards({ stats, isLoading }: StatsCardsProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="card animate-pulse">
            <div className="h-4 bg-bifrost-border rounded w-24 mb-3" />
            <div className="h-8 bg-bifrost-border rounded w-16" />
          </div>
        ))}
      </div>
    )
  }

  const healthyBackends = stats?.backends.healthy ?? 0
  const totalBackends = stats?.backends.total ?? 0
  const backendHealth = totalBackends > 0 ? healthyBackends / totalBackends : 0

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        label="Active Connections"
        value={stats?.active_connections ?? 0}
        delay={50}
        color="default"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.19 8.688a4.5 4.5 0 011.242 7.244l-4.5 4.5a4.5 4.5 0 01-6.364-6.364l1.757-1.757m13.35-.622l1.757-1.757a4.5 4.5 0 00-6.364-6.364l-4.5 4.5a4.5 4.5 0 001.242 7.244" />
          </svg>
        }
      />
      <StatCard
        label="Total Connections"
        value={(stats?.total_connections ?? 0).toLocaleString()}
        delay={100}
        color="default"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
          </svg>
        }
      />
      <StatCard
        label="Data Transferred"
        value={formatBytes((stats?.bytes_sent ?? 0) + (stats?.bytes_received ?? 0))}
        delay={150}
        color="default"
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 7.5L7.5 3m0 0L12 7.5M7.5 3v13.5m13.5 0L16.5 21m0 0L12 16.5m4.5 4.5V7.5" />
          </svg>
        }
      />
      <StatCard
        label="Healthy Backends"
        value={`${healthyBackends}/${totalBackends}`}
        delay={200}
        color={backendHealth === 1 ? 'success' : backendHealth >= 0.5 ? 'warning' : 'error'}
        icon={
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        }
      />
    </div>
  )
}
