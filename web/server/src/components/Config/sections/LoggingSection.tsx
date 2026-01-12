import { Section } from '../Section'
import type { LoggingConfig } from '../../../api/types'

interface LoggingSectionProps {
  config: LoggingConfig
  onChange: (config: LoggingConfig) => void
}

export function LoggingSection({ config, onChange }: LoggingSectionProps) {
  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <Section title="Application Logging" badge="restart-required">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Log Level</label>
          <select
            value={config.level || 'info'}
            onChange={(e) => update('level', e.target.value)}
            className="input"
          >
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warn">Warning</option>
            <option value="error">Error</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Format</label>
          <select
            value={config.format || 'text'}
            onChange={(e) => update('format', e.target.value)}
            className="input"
          >
            <option value="text">Text</option>
            <option value="json">JSON</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Output</label>
          <input
            type="text"
            value={config.output || ''}
            onChange={(e) => update('output', e.target.value)}
            placeholder="stdout"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">stdout, stderr, or file path</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Time Format</label>
          <input
            type="text"
            value={config.time_format || ''}
            onChange={(e) => update('time_format', e.target.value)}
            placeholder="2006-01-02T15:04:05.000Z07:00"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">Go time format string (optional)</p>
        </div>
      </div>
    </Section>
  )
}
