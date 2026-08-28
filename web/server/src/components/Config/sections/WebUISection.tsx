import { Section } from '../Section'
import { ValidatedInput } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { WebUIConfig } from '../../../api/types'

interface WebUISectionProps {
  config: WebUIConfig
  onChange: (config: WebUIConfig) => void
}

type WebUIValidationKeys = {
  listen: string
  base_path: string
}

export function WebUISection({ config, onChange }: WebUISectionProps) {
  const { errors, handleFieldChange } = useValidation<WebUIValidationKeys>({
    listen: [validators.listenAddress()],
    base_path: [validators.pattern(/^\//, 'Path must start with /')],
  })

  const update = (field: string, value: unknown) => {
    if (field === 'listen' || field === 'base_path') {
      handleFieldChange(field as keyof WebUIValidationKeys, value as never)
    }
    onChange({ ...config, [field]: value })
  }

  return (
    <Section sectionKey="web_ui" title="Web UI">
      <div className="space-y-4">
        <div className="p-3 bg-bifrost-warning/10 border border-bifrost-warning/30 rounded-lg text-xs text-bifrost-warning" role="note">
          This dashboard is currently always served on the <strong>API listener</strong> (the{' '}
          <code className="font-mono">api.listen</code> address). The fields below are stored in the config
          but are not honored by the server yet: there is no separate Web UI listener, and no base-path
          rewriting. They exist so a future release can serve the UI separately without a config migration.
        </div>
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-bifrost-text">Enable Web UI</span>
        </label>

        {config.enabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <ValidatedInput
              label="Listen Address"
              value={config.listen || ''}
              onChange={(e) => update('listen', e.target.value)}
              placeholder=":8081"
              error={errors.listen}
              helpText="Format: :port or host:port"
            />
            <ValidatedInput
              label="Base Path"
              value={config.base_path || ''}
              onChange={(e) => update('base_path', e.target.value)}
              placeholder="/"
              error={errors.base_path}
              helpText="URL path prefix for the Web UI"
            />
          </div>
        )}
      </div>
    </Section>
  )
}
