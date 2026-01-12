import { useState, useEffect } from 'react'
import { Modal } from '../Modal'
import { HealthCheckForm } from './HealthCheckForm'
import { DirectBackendForm } from '../backend-forms/DirectBackendForm'
import { HTTPProxyBackendForm } from '../backend-forms/HTTPProxyBackendForm'
import { SOCKS5ProxyBackendForm } from '../backend-forms/SOCKS5ProxyBackendForm'
import { WireGuardBackendForm } from '../backend-forms/WireGuardBackendForm'
import { OpenVPNBackendForm } from '../backend-forms/OpenVPNBackendForm'
import type { BackendConfig } from '../../../api/types'

interface BackendFormProps {
  backend?: BackendConfig
  existingNames: string[]
  onSave: (backend: BackendConfig) => void
  onCancel: () => void
}

const backendTypes = [
  { value: 'direct', label: 'Direct', description: 'Direct internet connection' },
  { value: 'http_proxy', label: 'HTTP Proxy', description: 'Route through HTTP proxy' },
  { value: 'socks5_proxy', label: 'SOCKS5 Proxy', description: 'Route through SOCKS5 proxy' },
  { value: 'wireguard', label: 'WireGuard', description: 'Route through WireGuard VPN' },
  { value: 'openvpn', label: 'OpenVPN', description: 'Route through OpenVPN tunnel' },
]

export function BackendForm({ backend, existingNames, onSave, onCancel }: BackendFormProps) {
  const isEdit = !!backend
  const [form, setForm] = useState<BackendConfig>({
    name: '',
    type: 'direct',
    enabled: true,
    priority: 10,
    weight: 1,
    config: {},
  })
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (backend) {
      setForm(backend)
    }
  }, [backend])

  const handleSave = () => {
    // Validation
    if (!form.name.trim()) {
      setError('Backend name is required')
      return
    }
    if (!isEdit && existingNames.includes(form.name)) {
      setError('A backend with this name already exists')
      return
    }
    if (!form.type) {
      setError('Backend type is required')
      return
    }

    setError(null)
    onSave(form)
  }

  const updateForm = (field: string, value: unknown) => {
    setForm((prev) => ({ ...prev, [field]: value }))
    setError(null)
  }

  const renderTypeForm = () => {
    const props = {
      config: form.config || {},
      onChange: (config: Record<string, unknown>) => updateForm('config', config),
    }

    switch (form.type) {
      case 'direct':
        return <DirectBackendForm {...props} />
      case 'http_proxy':
        return <HTTPProxyBackendForm {...props} />
      case 'socks5_proxy':
        return <SOCKS5ProxyBackendForm {...props} />
      case 'wireguard':
        return <WireGuardBackendForm {...props} />
      case 'openvpn':
        return <OpenVPNBackendForm {...props} />
      default:
        return null
    }
  }

  return (
    <Modal
      isOpen={true}
      onClose={onCancel}
      title={isEdit ? `Edit Backend: ${backend.name}` : 'Add Backend'}
      onSave={handleSave}
      saveLabel={isEdit ? 'Save Changes' : 'Add Backend'}
      size="xl"
    >
      <div className="space-y-6">
        {error && (
          <div className="p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg text-bifrost-error text-sm">
            {error}
          </div>
        )}

        {/* Common Fields */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => updateForm('name', e.target.value)}
              placeholder="my-backend"
              className="input"
              disabled={isEdit}
            />
            {isEdit && <p className="text-xs text-bifrost-muted mt-1">Name cannot be changed</p>}
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
            <select
              value={form.type}
              onChange={(e) => {
                updateForm('type', e.target.value)
                updateForm('config', {}) // Reset config when type changes
              }}
              className="input"
            >
              {backendTypes.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Priority</label>
            <input
              type="number"
              value={form.priority}
              onChange={(e) => updateForm('priority', parseInt(e.target.value) || 0)}
              className="input"
            />
            <p className="text-xs text-bifrost-muted mt-1">Higher = more preferred</p>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Weight</label>
            <input
              type="number"
              value={form.weight}
              onChange={(e) => updateForm('weight', parseInt(e.target.value) || 1)}
              className="input"
            />
            <p className="text-xs text-bifrost-muted mt-1">For load balancing</p>
          </div>
          <div className="md:col-span-2">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => updateForm('enabled', e.target.checked)}
                className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
              />
              <span className="text-sm font-medium text-gray-300">Enabled</span>
            </label>
          </div>
        </div>

        {/* Type-specific config */}
        <div className="pt-4 border-t border-bifrost-border">
          <h4 className="text-sm font-semibold text-white mb-3">
            {backendTypes.find((t) => t.value === form.type)?.label} Configuration
          </h4>
          {renderTypeForm()}
        </div>

        {/* Health Check */}
        <div className="pt-4 border-t border-bifrost-border">
          <h4 className="text-sm font-semibold text-white mb-3">Health Check</h4>
          <HealthCheckForm
            config={form.health_check}
            onChange={(health_check) => updateForm('health_check', health_check)}
            optional={true}
          />
        </div>
      </div>
    </Modal>
  )
}
