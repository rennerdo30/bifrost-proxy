import { ArrayInput } from '../ArrayInput'

interface OpenVPNBackendFormProps {
  config: Record<string, unknown>
  onChange: (config: Record<string, unknown>) => void
}

export function OpenVPNBackendForm({ config, onChange }: OpenVPNBackendFormProps) {
  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Route traffic through an OpenVPN tunnel.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-300 mb-1">Config File</label>
          <input
            type="text"
            value={(config.config_file as string) || ''}
            onChange={(e) => update('config_file', e.target.value)}
            placeholder="/path/to/client.ovpn"
            className="input"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Auth File</label>
          <input
            type="text"
            value={(config.auth_file as string) || ''}
            onChange={(e) => update('auth_file', e.target.value)}
            placeholder="/path/to/auth.txt (optional)"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">File containing username and password</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">OpenVPN Binary</label>
          <input
            type="text"
            value={(config.binary as string) || ''}
            onChange={(e) => update('binary', e.target.value)}
            placeholder="openvpn (default)"
            className="input"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Management Address</label>
          <input
            type="text"
            value={(config.management_addr as string) || ''}
            onChange={(e) => update('management_addr', e.target.value)}
            placeholder="127.0.0.1"
            className="input"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Management Port</label>
          <input
            type="number"
            value={(config.management_port as number) || ''}
            onChange={(e) => update('management_port', parseInt(e.target.value) || undefined)}
            placeholder="7505"
            className="input"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Connect Timeout</label>
          <input
            type="text"
            value={(config.connect_timeout as string) || ''}
            onChange={(e) => update('connect_timeout', e.target.value)}
            placeholder="30s"
            className="input"
          />
        </div>
        <div className="md:col-span-2">
          <ArrayInput
            label="Extra Arguments"
            values={(config.extra_args as string[]) || []}
            onChange={(args) => update('extra_args', args)}
            placeholder="--verb 3"
          />
        </div>
      </div>
    </div>
  )
}
