import { useState } from 'react'
import { Section } from '../Section'
import { BackendForm } from '../forms/BackendForm'
import { ConfirmModal } from '../ConfirmModal'
import type { BackendConfig } from '../../../api/types'

interface BackendsSectionProps {
  backends: BackendConfig[]
  onChange: (backends: BackendConfig[]) => void
}

const typeLabels: Record<string, string> = {
  direct: 'Direct',
  http_proxy: 'HTTP Proxy',
  socks5_proxy: 'SOCKS5 Proxy',
  wireguard: 'WireGuard',
  openvpn: 'OpenVPN',
  nordvpn: 'NordVPN',
  mullvad: 'Mullvad',
  pia: 'PIA',
  protonvpn: 'ProtonVPN',
}

const typeBadgeColors: Record<string, string> = {
  direct: 'badge-success',
  http_proxy: 'badge-info',
  socks5_proxy: 'badge-info',
  wireguard: 'bg-purple-500/20 text-purple-400',
  openvpn: 'bg-orange-500/20 text-orange-400',
  nordvpn: 'bg-blue-500/20 text-blue-400',
  mullvad: 'bg-yellow-500/20 text-yellow-400',
  pia: 'bg-green-500/20 text-green-400',
  protonvpn: 'bg-violet-500/20 text-violet-400',
}

export function BackendsSection({ backends, onChange }: BackendsSectionProps) {
  const [editingBackend, setEditingBackend] = useState<BackendConfig | null>(null)
  const [isAdding, setIsAdding] = useState(false)
  const [deletingBackend, setDeletingBackend] = useState<string | null>(null)

  const handleSave = (backend: BackendConfig) => {
    if (editingBackend) {
      // Edit existing
      onChange(backends.map((b) => (b.name === editingBackend.name ? backend : b)))
    } else {
      // Add new
      onChange([...backends, backend])
    }
    setEditingBackend(null)
    setIsAdding(false)
  }

  const handleDelete = (name: string) => {
    onChange(backends.filter((b) => b.name !== name))
  }

  const existingNames = backends.map((b) => b.name)

  return (
    <Section title="Backends" badge="restart-required">
      <div className="space-y-4">
        <p className="text-xs text-bifrost-muted">
          Backends configured here are persisted to the config file and survive restarts.
        </p>
        {backends.length === 0 ? (
          <div className="text-center py-8 text-bifrost-muted">
            <p>No backends configured</p>
            <p className="text-sm mt-1">Add at least one backend to route traffic through</p>
          </div>
        ) : (
          <div className="space-y-2">
            {backends.map((backend) => (
              <div
                key={backend.name}
                className="flex items-center justify-between p-4 bg-bifrost-bg rounded-lg"
              >
                <div className="flex items-center gap-4">
                  <div className={`w-2 h-2 rounded-full ${backend.enabled ? 'bg-bifrost-success' : 'bg-bifrost-muted'}`} />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">{backend.name}</span>
                      <span className={`badge text-xs ${typeBadgeColors[backend.type] || 'badge-info'}`}>
                        {typeLabels[backend.type] || backend.type}
                      </span>
                      {!backend.enabled && (
                        <span className="badge badge-warning text-xs">Disabled</span>
                      )}
                    </div>
                    <div className="text-xs text-bifrost-muted mt-0.5">
                      Priority: {backend.priority} • Weight: {backend.weight}
                      {backend.health_check && ' • Custom health check'}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setEditingBackend(backend)}
                    className="btn btn-ghost text-sm"
                    aria-label={`Edit backend ${backend.name}`}
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                    </svg>
                  </button>
                  <button
                    onClick={() => setDeletingBackend(backend.name)}
                    className="btn btn-ghost text-sm text-bifrost-error hover:bg-bifrost-error/10"
                    aria-label={`Delete backend ${backend.name}`}
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <button onClick={() => setIsAdding(true)} className="btn btn-secondary">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Backend
        </button>
      </div>

      {(isAdding || editingBackend) && (
        <BackendForm
          backend={editingBackend || undefined}
          existingNames={editingBackend ? existingNames.filter((n) => n !== editingBackend.name) : existingNames}
          onSave={handleSave}
          onCancel={() => {
            setIsAdding(false)
            setEditingBackend(null)
          }}
        />
      )}

      <ConfirmModal
        isOpen={deletingBackend !== null}
        onClose={() => setDeletingBackend(null)}
        onConfirm={() => deletingBackend && handleDelete(deletingBackend)}
        title="Delete Backend"
        message={`Are you sure you want to delete the backend "${deletingBackend}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </Section>
  )
}
