import { useState, useRef } from 'react'
import { ArrayInput } from '../ArrayInput'

interface OpenVPNBackendFormProps {
  config: Record<string, unknown>
  onChange: (config: Record<string, unknown>) => void
}

export function OpenVPNBackendForm({ config, onChange }: OpenVPNBackendFormProps) {
  const [showImport, setShowImport] = useState(false)
  const [configText, setConfigText] = useState('')
  const [authMethod, setAuthMethod] = useState<'file' | 'inline'>(
    (config.username as string) ? 'inline' : 'file'
  )
  const fileInputRef = useRef<HTMLInputElement>(null)

  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result as string
      setConfigText(content)
    }
    reader.readAsText(file)
  }

  const applyConfig = () => {
    if (!configText.trim()) return

    // Store the config content directly
    onChange({
      ...config,
      config_content: configText,
      config_file: '', // Clear file path when using inline config
    })

    setShowImport(false)
    setConfigText('')
  }

  const handleAuthMethodChange = (method: 'file' | 'inline') => {
    setAuthMethod(method)
    if (method === 'file') {
      // Clear inline credentials
      onChange({
        ...config,
        username: undefined,
        password: undefined,
      })
    } else {
      // Clear auth file
      onChange({
        ...config,
        auth_file: undefined,
      })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-bifrost-muted">
          Route traffic through an OpenVPN tunnel.
        </p>
        <button
          type="button"
          onClick={() => setShowImport(!showImport)}
          className="btn btn-secondary text-sm"
        >
          {showImport ? 'Hide Import' : 'Import Config'}
        </button>
      </div>

      {/* Import Section */}
      {showImport && (
        <div className="bg-bifrost-bg-tertiary rounded-lg p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold text-white">Import OpenVPN Configuration</h4>
            <input
              type="file"
              ref={fileInputRef}
              accept=".ovpn,.conf,.txt"
              onChange={handleFileUpload}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="btn btn-secondary text-sm"
            >
              Upload File
            </button>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Or paste your OpenVPN config below:
            </label>
            <textarea
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              placeholder={`client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca [inline]
cert [inline]
key [inline]
...`}
              rows={12}
              className="input font-mono text-xs"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                setShowImport(false)
                setConfigText('')
              }}
              className="btn btn-secondary text-sm"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={applyConfig}
              disabled={!configText.trim()}
              className="btn btn-primary text-sm"
            >
              Apply Config
            </button>
          </div>
        </div>
      )}

      {/* Config Content Display */}
      {(config.config_content as string) && (
        <div className="bg-bifrost-bg-tertiary rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-semibold text-white">Embedded Configuration</h4>
            <button
              type="button"
              onClick={() => update('config_content', undefined)}
              className="text-sm text-red-400 hover:text-red-300"
            >
              Clear
            </button>
          </div>
          <pre className="text-xs text-bifrost-muted font-mono bg-bifrost-bg rounded p-2 max-h-32 overflow-auto">
            {(config.config_content as string).slice(0, 500)}
            {(config.config_content as string).length > 500 && '...'}
          </pre>
        </div>
      )}

      {/* Config File Path (alternative to embedded) */}
      {!(config.config_content as string) && (
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Config File Path</label>
          <input
            type="text"
            value={(config.config_file as string) || ''}
            onChange={(e) => update('config_file', e.target.value)}
            placeholder="/path/to/client.ovpn"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">
            Path to OpenVPN config file on the server, or use Import Config above
          </p>
        </div>
      )}

      {/* Authentication */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Authentication</h4>

        {/* Auth Method Toggle */}
        <div className="flex gap-4 mb-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="authMethod"
              checked={authMethod === 'file'}
              onChange={() => handleAuthMethodChange('file')}
              className="form-radio text-bifrost-purple"
            />
            <span className="text-sm text-gray-300">Auth File</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="authMethod"
              checked={authMethod === 'inline'}
              onChange={() => handleAuthMethodChange('inline')}
              className="form-radio text-bifrost-purple"
            />
            <span className="text-sm text-gray-300">Username/Password</span>
          </label>
        </div>

        {authMethod === 'file' ? (
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Auth File</label>
            <input
              type="text"
              value={(config.auth_file as string) || ''}
              onChange={(e) => update('auth_file', e.target.value)}
              placeholder="/path/to/auth.txt"
              className="input"
            />
            <p className="text-xs text-bifrost-muted mt-1">
              File containing username on first line, password on second line
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
              <input
                type="text"
                value={(config.username as string) || ''}
                onChange={(e) => update('username', e.target.value)}
                placeholder="VPN username"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
              <input
                type="password"
                value={(config.password as string) || ''}
                onChange={(e) => update('password', e.target.value)}
                placeholder="VPN password"
                className="input"
              />
            </div>
          </div>
        )}
      </div>

      {/* Advanced Settings */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Advanced Settings</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
            <label className="block text-sm font-medium text-gray-300 mb-1">Connect Timeout</label>
            <input
              type="text"
              value={(config.connect_timeout as string) || ''}
              onChange={(e) => update('connect_timeout', e.target.value)}
              placeholder="30s"
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
    </div>
  )
}
