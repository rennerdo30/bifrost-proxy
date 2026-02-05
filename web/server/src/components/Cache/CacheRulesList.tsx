import type { CacheRule } from '../../api/types'

interface CacheRulesListProps {
  rules: CacheRule[] | undefined
  isLoading: boolean
  onToggle: (name: string, enabled: boolean) => void
  onDelete: (name: string) => void
}

export function CacheRulesList({
  rules,
  isLoading,
  onToggle,
  onDelete,
}: CacheRulesListProps) {
  if (isLoading) {
    return (
      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-bifrost-border">
                <th className="table-header">Name</th>
                <th className="table-header">Domains</th>
                <th className="table-header">TTL</th>
                <th className="table-header text-right">Priority</th>
                <th className="table-header text-center">Enabled</th>
                <th className="table-header text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {[...Array(3)].map((_, i) => (
                <tr key={i} className="border-b border-bifrost-border/50">
                  {[...Array(6)].map((__, j) => (
                    <td key={j} className="table-cell">
                      <div className="h-4 bg-bifrost-border rounded w-20 animate-pulse" />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  if (!rules || rules.length === 0) {
    return (
      <div className="card text-center py-12">
        <svg
          className="w-12 h-12 mx-auto text-bifrost-muted mb-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={1.5}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z"
          />
          <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
        <p className="text-gray-400">No cache rules configured</p>
        <p className="text-sm text-bifrost-muted mt-1">
          Add rules to control caching behavior for specific domains
        </p>
      </div>
    )
  }

  return (
    <div className="card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-bifrost-border">
              <th className="table-header">Name</th>
              <th className="table-header">Domains</th>
              <th className="table-header">TTL</th>
              <th className="table-header text-right">Priority</th>
              <th className="table-header text-center">Enabled</th>
              <th className="table-header text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, index) => (
              <tr
                key={rule.name}
                className="border-b border-bifrost-border/50 hover:bg-bifrost-card-hover transition-colors animate-slide-up"
                style={{ animationDelay: `${index * 20}ms` }}
              >
                <td className="table-cell">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">{rule.name}</span>
                    {rule.preset && (
                      <span className="badge badge-info text-xs">Preset</span>
                    )}
                  </div>
                </td>
                <td className="table-cell">
                  <div className="flex flex-wrap gap-1 max-w-[250px]">
                    {rule.domains.slice(0, 3).map((domain) => (
                      <span key={domain} className="text-xs font-mono text-bifrost-muted bg-bifrost-bg px-1.5 py-0.5 rounded">
                        {domain}
                      </span>
                    ))}
                    {rule.domains.length > 3 && (
                      <span className="text-xs text-bifrost-muted">
                        +{rule.domains.length - 3} more
                      </span>
                    )}
                  </div>
                </td>
                <td className="table-cell font-mono text-sm text-bifrost-muted">
                  {rule.ttl}
                </td>
                <td className="table-cell text-right font-mono text-sm">
                  {rule.priority}
                </td>
                <td className="table-cell text-center">
                  <button
                    onClick={() => onToggle(rule.name, !rule.enabled)}
                    className={`w-10 h-5 rounded-full relative transition-colors ${
                      rule.enabled ? 'bg-bifrost-success' : 'bg-bifrost-border'
                    }`}
                    aria-label={rule.enabled ? 'Disable rule' : 'Enable rule'}
                  >
                    <span
                      className={`absolute w-4 h-4 rounded-full bg-white top-0.5 transition-transform ${
                        rule.enabled ? 'translate-x-5' : 'translate-x-0.5'
                      }`}
                    />
                  </button>
                </td>
                <td className="table-cell text-right">
                  <button
                    onClick={() => onDelete(rule.name)}
                    className="p-1 text-bifrost-muted hover:text-bifrost-error transition-colors"
                    aria-label="Delete rule"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
