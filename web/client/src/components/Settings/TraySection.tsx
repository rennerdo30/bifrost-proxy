import {
  FormToggle,
  ConfigSection,
} from '../form'
import { TrayIcon } from '../icons'
import { useSettings } from './SettingsContext'

export function TraySection() {
  const { getValue, updateField } = useSettings()

  return (
    <ConfigSection
      title="System Tray"
      icon={<TrayIcon />}
      description="System tray and quick access settings"
      defaultOpen={false}
    >
      <div className="space-y-4">
        <FormToggle
          label="Enable System Tray"
          description="Show icon in system tray"
          checked={getValue('tray', 'enabled', true) as boolean}
          onChange={(v) => updateField('tray', 'enabled', v)}
        />
        <FormToggle
          label="Start Minimized"
          description="Start in system tray on launch"
          checked={getValue('tray', 'start_minimized', false) as boolean}
          onChange={(v) => updateField('tray', 'start_minimized', v)}
        />
        <FormToggle
          label="Show Quick GUI"
          description="Show quick access window on tray click"
          checked={getValue('tray', 'show_quick_gui', true) as boolean}
          onChange={(v) => updateField('tray', 'show_quick_gui', v)}
        />
        <FormToggle
          label="Auto-Connect"
          description="Connect to server on startup"
          checked={getValue('tray', 'auto_connect', false) as boolean}
          onChange={(v) => updateField('tray', 'auto_connect', v)}
        />
        <FormToggle
          label="Show Notifications"
          description="Show connection notifications"
          checked={getValue('tray', 'show_notifications', true) as boolean}
          onChange={(v) => updateField('tray', 'show_notifications', v)}
        />
      </div>
    </ConfigSection>
  )
}
