import { ArrayInput } from '../ArrayInput'
import type { SystemAuth } from '../../../api/types'

interface SystemAuthFormProps {
  config: SystemAuth
  onChange: (config: SystemAuth) => void
}

export function SystemAuthForm({ config, onChange }: SystemAuthFormProps) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Authenticate users against the system (PAM). Restrict access to specific users or groups.
      </p>

      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">PAM Service</label>
        <input
          type="text"
          value={config.service || ''}
          onChange={(e) => onChange({ ...config, service: e.target.value })}
          placeholder="login"
          className="input max-w-xs"
        />
        <p className="text-xs text-bifrost-muted mt-1">PAM service name (default: login)</p>
      </div>

      <div>
        <ArrayInput
          label="Allowed Users"
          values={config.allowed_users || []}
          onChange={(users) => onChange({ ...config, allowed_users: users })}
          placeholder="username"
        />
        <p className="text-xs text-bifrost-muted mt-1">Leave empty to allow all authenticated users</p>
      </div>

      <div>
        <ArrayInput
          label="Allowed Groups"
          values={config.allowed_groups || []}
          onChange={(groups) => onChange({ ...config, allowed_groups: groups })}
          placeholder="groupname"
        />
        <p className="text-xs text-bifrost-muted mt-1">Users must be members of at least one group</p>
      </div>
    </div>
  )
}
