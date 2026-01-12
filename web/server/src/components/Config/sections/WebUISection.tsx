import { Section } from '../Section'
import type { WebUIConfig } from '../../../api/types'

interface WebUISectionProps {
  config: WebUIConfig
  onChange: (config: WebUIConfig) => void
}

export function WebUISection({ config, onChange }: WebUISectionProps) {
  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <Section title="Web UI" badge="restart-required">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable Web UI</span>
        </label>

        {config.enabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Listen Address</label>
              <input
                type="text"
                value={config.listen || ''}
                onChange={(e) => update('listen', e.target.value)}
                placeholder=":8081"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Base Path</label>
              <input
                type="text"
                value={config.base_path || ''}
                onChange={(e) => update('base_path', e.target.value)}
                placeholder="/"
                className="input"
              />
              <p className="text-xs text-bifrost-muted mt-1">URL path prefix for the Web UI</p>
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
