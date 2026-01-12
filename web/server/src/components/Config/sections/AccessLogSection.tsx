import { Section } from '../Section'
import type { AccessLogConfig } from '../../../api/types'

interface AccessLogSectionProps {
  config: AccessLogConfig
  onChange: (config: AccessLogConfig) => void
}

export function AccessLogSection({ config, onChange }: AccessLogSectionProps) {
  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <Section title="Access Logging" badge="restart-required">
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable Access Logging</span>
        </label>

        {config.enabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Format</label>
              <select
                value={config.format || 'json'}
                onChange={(e) => update('format', e.target.value)}
                className="input"
              >
                <option value="json">JSON</option>
                <option value="apache">Apache (Combined)</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Output</label>
              <input
                type="text"
                value={config.output || ''}
                onChange={(e) => update('output', e.target.value)}
                placeholder="stdout, stderr, or file path"
                className="input"
              />
              <p className="text-xs text-bifrost-muted mt-1">Use stdout, stderr, or a file path</p>
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
