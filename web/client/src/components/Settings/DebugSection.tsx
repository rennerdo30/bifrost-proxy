import {
  FormNumber,
  FormToggle,
  FormTagInput,
  ConfigSection,
} from '../form'
import { DebugIcon } from '../icons'
import { useSettings } from './SettingsContext'

export function DebugSection() {
  const { getValue, updateField } = useSettings()

  return (
    <ConfigSection
      title="Debug Settings"
      icon={<DebugIcon />}
      description="Traffic debugging and capture settings"
    >
      <div className="space-y-4">
        <FormToggle
          label="Enable Debugging"
          description="Capture and display traffic for debugging"
          checked={getValue('debug', 'enabled', true) as boolean}
          onChange={(v) => updateField('debug', 'enabled', v)}
        />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormNumber
            label="Max Entries"
            description="Maximum number of debug entries to keep"
            value={getValue('debug', 'max_entries', 1000) as number}
            onChange={(v) => updateField('debug', 'max_entries', v)}
            min={100}
            max={10000}
          />
          <FormNumber
            label="Max Body Size"
            description="Maximum body size to capture (bytes)"
            value={getValue('debug', 'max_body_size', 65536) as number}
            onChange={(v) => updateField('debug', 'max_body_size', v)}
            min={0}
            max={1048576}
          />
        </div>
        <FormToggle
          label="Capture Body"
          description="Capture request/response body content"
          checked={getValue('debug', 'capture_body', false) as boolean}
          onChange={(v) => updateField('debug', 'capture_body', v)}
        />
        <FormTagInput
          label="Filter Domains"
          description="Only capture traffic for these domains (leave empty for all)"
          value={(getValue('debug', 'filter_domains', []) as string[]) || []}
          onChange={(v) => updateField('debug', 'filter_domains', v)}
          placeholder="e.g., example.com"
        />
      </div>
    </ConfigSection>
  )
}
