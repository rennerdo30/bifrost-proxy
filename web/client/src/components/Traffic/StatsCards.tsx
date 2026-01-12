import type { DebugEntry } from '../../api/types'

interface StatsCardsProps {
  entries: DebugEntry[]
}

interface StatCardProps {
  label: string
  value: number | string
  color: 'blue' | 'green' | 'purple' | 'red'
  delay: number
}

const colorClasses = {
  blue: 'from-bifrost-accent/20 to-transparent',
  green: 'from-bifrost-success/20 to-transparent',
  purple: 'from-purple-500/20 to-transparent',
  red: 'from-bifrost-error/20 to-transparent',
}

function StatCard({ label, value, color, delay }: StatCardProps) {
  return (
    <div
      className="card card-hover animate-slide-up relative overflow-hidden"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div className={`absolute inset-0 bg-gradient-to-br ${colorClasses[color]} pointer-events-none`} />
      <div className="relative">
        <p className="stat-label">{label}</p>
        <p className="stat-value mt-1">{value}</p>
      </div>
    </div>
  )
}

export function StatsCards({ entries }: StatsCardsProps) {
  const total = entries.length
  const viaServer = entries.filter(e => e.route === 'server').length
  const direct = entries.filter(e => e.route === 'direct').length
  const errors = entries.filter(e => e.error || (e.status_code >= 400)).length

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard label="Total Requests" value={total} color="blue" delay={0} />
      <StatCard label="Via Server" value={viaServer} color="purple" delay={50} />
      <StatCard label="Direct" value={direct} color="green" delay={100} />
      <StatCard label="Errors" value={errors} color="red" delay={150} />
    </div>
  )
}
