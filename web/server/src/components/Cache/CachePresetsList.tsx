import type { CachePreset } from '../../api/types'

interface CachePresetsListProps {
  presets: CachePreset[] | undefined
  isLoading: boolean
  onToggle: (name: string, enable: boolean) => void
}

export function CachePresetsList({
  presets,
  isLoading,
  onToggle,
}: CachePresetsListProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="card animate-pulse">
            <div className="h-5 bg-bifrost-border rounded w-24 mb-2" />
            <div className="h-4 bg-bifrost-border rounded w-full mb-3" />
            <div className="h-4 bg-bifrost-border rounded w-16" />
          </div>
        ))}
      </div>
    )
  }

  if (!presets || presets.length === 0) {
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
            d="M20.25 7.5l-.625 10.632a2.25 2.25 0 01-2.247 2.118H6.622a2.25 2.25 0 01-2.247-2.118L3.75 7.5M10 11.25h4M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125z"
          />
        </svg>
        <p className="text-gray-400">No presets available</p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {presets.map((preset) => (
        <div
          key={preset.name}
          className={`card border transition-colors ${
            preset.enabled
              ? 'border-bifrost-success/50 bg-bifrost-success/5'
              : 'border-bifrost-border'
          }`}
        >
          <div className="flex items-start justify-between mb-2">
            <div className="flex items-center gap-2">
              <h4 className="font-medium text-white">{preset.name}</h4>
              {preset.enabled && (
                <span className="badge badge-success text-xs">Active</span>
              )}
            </div>
            <button
              onClick={() => onToggle(preset.name, !preset.enabled)}
              className={`w-10 h-5 rounded-full relative transition-colors ${
                preset.enabled ? 'bg-bifrost-success' : 'bg-bifrost-border'
              }`}
              aria-label={preset.enabled ? 'Disable preset' : 'Enable preset'}
            >
              <span
                className={`absolute w-4 h-4 rounded-full bg-white top-0.5 transition-transform ${
                  preset.enabled ? 'translate-x-5' : 'translate-x-0.5'
                }`}
              />
            </button>
          </div>
          <p className="text-sm text-bifrost-muted mb-3">{preset.description}</p>
          <div className="flex items-center justify-between text-xs">
            <span className="text-bifrost-muted">
              {preset.domains.length} domain{preset.domains.length !== 1 ? 's' : ''}
            </span>
            <span className="font-mono text-bifrost-muted">TTL: {preset.ttl}</span>
          </div>
        </div>
      ))}
    </div>
  )
}
