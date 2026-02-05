import type { CacheStats } from '../../api/types'

interface CacheStatsProps {
  stats: CacheStats
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}

function formatNumber(num: number): string {
  return num.toLocaleString()
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`
}

export function CacheStats({ stats }: CacheStatsProps) {
  const statCards = [
    {
      label: 'Status',
      value: stats.enabled ? 'Enabled' : 'Disabled',
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M12 5l7 7-7 7" />
        </svg>
      ),
      color: stats.enabled ? 'text-emerald-400' : 'text-bifrost-muted',
    },
    {
      label: 'Storage Type',
      value: stats.storage_type.charAt(0).toUpperCase() + stats.storage_type.slice(1),
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
        </svg>
      ),
      color: 'text-cyan-400',
    },
    {
      label: 'Entries',
      value: formatNumber(stats.entries),
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
        </svg>
      ),
      color: 'text-violet-400',
    },
    {
      label: 'Total Size',
      value: formatBytes(stats.total_size_bytes),
      subtext: `of ${formatBytes(stats.max_size_bytes)}`,
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
        </svg>
      ),
      color: 'text-amber-400',
    },
    {
      label: 'Used',
      value: formatPercent(stats.used_percent / 100),
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 3.055A9.001 9.001 0 1020.945 13H11V3.055z" />
        </svg>
      ),
      color: stats.used_percent > 90 ? 'text-red-400' : stats.used_percent > 70 ? 'text-amber-400' : 'text-emerald-400',
    },
    {
      label: 'Hit Rate',
      value: formatPercent(stats.hit_rate),
      subtext: `${formatNumber(stats.hit_count)} hits / ${formatNumber(stats.miss_count)} misses`,
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
        </svg>
      ),
      color: stats.hit_rate > 0.8 ? 'text-emerald-400' : stats.hit_rate > 0.5 ? 'text-amber-400' : 'text-red-400',
    },
    {
      label: 'Evictions',
      value: formatNumber(stats.eviction_count),
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
        </svg>
      ),
      color: 'text-bifrost-muted',
    },
    {
      label: 'Rules',
      value: `${stats.rules_count} total`,
      subtext: `${stats.presets_count} presets, ${stats.custom_rules_count} custom`,
      icon: (
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
        </svg>
      ),
      color: 'text-cyan-400',
    },
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      {statCards.map((card) => (
        <div key={card.label} className="card p-4">
          <div className="flex items-center gap-3">
            <div className={`${card.color}`}>{card.icon}</div>
            <div>
              <p className="text-xs text-bifrost-muted">{card.label}</p>
              <p className={`text-lg font-semibold ${card.color}`}>{card.value}</p>
              {card.subtext && <p className="text-xs text-bifrost-muted">{card.subtext}</p>}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
