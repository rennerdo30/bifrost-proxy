import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
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
    <Section sectionKey="logging" title="Application Logging">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ValidatedSelect
          label="Log Level"
          value={config.level || 'info'}
          onChange={(e) => update('level', e.target.value)}
          helpText="Minimum severity level to log"
        >
          <option value="debug">Debug</option>
          <option value="info">Info</option>
          <option value="warn">Warning</option>
          <option value="error">Error</option>
        </ValidatedSelect>
        <ValidatedSelect
          label="Format"
          value={config.format || 'text'}
          onChange={(e) => update('format', e.target.value)}
          helpText="Log output format"
        >
          <option value="text">Text</option>
          <option value="json">JSON</option>
        </ValidatedSelect>
        <ValidatedInput
          label="Output"
          value={config.output || ''}
          onChange={(e) => update('output', e.target.value)}
          placeholder="stdout"
          helpText="stdout, stderr, or file path"
        />
        <ValidatedInput
          label="Time Format"
          value={config.time_format || ''}
          onChange={(e) => update('time_format', e.target.value)}
          placeholder="2006-01-02T15:04:05.000Z07:00"
          helpText="Go time format string (optional)"
        />
        <ValidatedInput
          label="Max File Size (MB)"
          type="number"
          value={config.max_size_mb ?? 0}
          onChange={(e) => update('max_size_mb', parseInt(e.target.value) || 0)}
          helpText="Rotate the log file when it exceeds this size. 0 disables rotation. Only used when Output is a file path"
        />
        <ValidatedInput
          label="Rotated Files to Keep"
          type="number"
          value={config.max_backups ?? 0}
          onChange={(e) => update('max_backups', parseInt(e.target.value) || 0)}
          helpText="Number of rotated log files to retain. 0 keeps all"
        />
      </div>
    </Section>
  )
}
