import { useState } from 'react'
import { Section } from '../Section'
import { NativeAuthForm } from '../auth-forms/NativeAuthForm'
import { SystemAuthForm } from '../auth-forms/SystemAuthForm'
import { LDAPAuthForm } from '../auth-forms/LDAPAuthForm'
import { OAuthForm } from '../auth-forms/OAuthForm'
import type { AuthConfig, AuthProvider } from '../../../api/types'

interface AuthSectionProps {
  config: AuthConfig
  onChange: (config: AuthConfig) => void
}

const authTypes = [
  { value: 'native', label: 'Native', description: 'Built-in user database with bcrypt passwords' },
  { value: 'system', label: 'System (PAM)', description: 'Authenticate against OS users via PAM' },
  { value: 'ldap', label: 'LDAP', description: 'Authenticate against LDAP/Active Directory' },
  { value: 'oauth', label: 'OAuth/OIDC', description: 'Authenticate via OAuth 2.0 / OpenID Connect' },
]

function getDefaultProviderConfig(type: string): Partial<AuthProvider> {
  switch (type) {
    case 'native':
      return { native: { users: [] } }
    case 'system':
      return { system: {} }
    case 'ldap':
      return {
        ldap: {
          url: '',
          base_dn: '',
          bind_dn: '',
          bind_password: '',
          user_filter: '(uid=%s)',
          tls: false,
          insecure_skip_verify: false,
        },
      }
    case 'oauth':
      return {
        oauth: {
          provider: '',
          client_id: '',
          client_secret: '',
          issuer_url: '',
          redirect_url: '',
          scopes: ['openid', 'profile', 'email'],
        },
      }
    default:
      return {}
  }
}

export function AuthSection({ config, onChange }: AuthSectionProps) {
  const [editingProvider, setEditingProvider] = useState<number | null>(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [newProviderType, setNewProviderType] = useState<string>('native')
  const [newProviderName, setNewProviderName] = useState('')

  // Get providers array (use providers if exists, otherwise convert legacy mode)
  const providers = config.providers || []
  const hasProviders = providers.length > 0

  // Check if using legacy mode (no providers but has mode set)
  const isLegacyMode = !hasProviders && config.mode && config.mode !== 'none'

  const handleEnableMultiProvider = () => {
    // Convert legacy config to providers format
    if (isLegacyMode && config.mode) {
      const legacyProvider: AuthProvider = {
        name: `${config.mode}-1`,
        type: config.mode,
        enabled: true,
        priority: 0,
        native: config.native,
        system: config.system,
        ldap: config.ldap,
        oauth: config.oauth,
      }
      onChange({
        providers: [legacyProvider],
      })
    } else {
      onChange({
        providers: [],
      })
    }
  }

  const handleUseLegacyMode = () => {
    // Convert back to legacy single-mode
    if (providers.length > 0) {
      const firstEnabled = providers.find((p) => p.enabled) || providers[0]
      onChange({
        mode: firstEnabled.type,
        native: firstEnabled.native,
        system: firstEnabled.system,
        ldap: firstEnabled.ldap,
        oauth: firstEnabled.oauth,
      })
    } else {
      onChange({ mode: 'none' })
    }
  }

  const handleAddProvider = () => {
    if (!newProviderName.trim()) return

    const newProvider: AuthProvider = {
      name: newProviderName.trim(),
      type: newProviderType as AuthProvider['type'],
      enabled: true,
      priority: providers.length,
      ...getDefaultProviderConfig(newProviderType),
    }

    onChange({
      providers: [...providers, newProvider],
    })

    setNewProviderName('')
    setShowAddForm(false)
    setEditingProvider(providers.length)
  }

  const handleRemoveProvider = (index: number) => {
    const newProviders = providers.filter((_, i) => i !== index)
    onChange({ providers: newProviders })
    if (editingProvider === index) {
      setEditingProvider(null)
    }
  }

  const handleToggleProvider = (index: number) => {
    const newProviders = [...providers]
    newProviders[index] = { ...newProviders[index], enabled: !newProviders[index].enabled }
    onChange({ providers: newProviders })
  }

  const handleUpdateProvider = (index: number, updates: Partial<AuthProvider>) => {
    const newProviders = [...providers]
    newProviders[index] = { ...newProviders[index], ...updates }
    onChange({ providers: newProviders })
  }

  const handleMoveProvider = (index: number, direction: 'up' | 'down') => {
    const newIndex = direction === 'up' ? index - 1 : index + 1
    if (newIndex < 0 || newIndex >= providers.length) return

    const newProviders = [...providers]
    ;[newProviders[index], newProviders[newIndex]] = [newProviders[newIndex], newProviders[index]]
    // Update priorities
    newProviders.forEach((p, i) => (p.priority = i))
    onChange({ providers: newProviders })

    if (editingProvider === index) {
      setEditingProvider(newIndex)
    } else if (editingProvider === newIndex) {
      setEditingProvider(index)
    }
  }

  // Legacy mode UI (single provider dropdown)
  if (!hasProviders && !showAddForm) {
    return (
      <Section title="Authentication" badge="restart-required">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Authentication Mode</label>
            <select
              value={config.mode || 'none'}
              onChange={(e) => {
                const mode = e.target.value as AuthConfig['mode']
                const newConfig: AuthConfig = { mode }
                if (mode && mode !== 'none') {
                  Object.assign(newConfig, getDefaultProviderConfig(mode))
                }
                onChange(newConfig)
              }}
              className="input max-w-xs"
            >
              <option value="none">None (No authentication)</option>
              {authTypes.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>

          {config.mode === 'native' && config.native && (
            <div className="mt-4 pt-4 border-t border-bifrost-border">
              <NativeAuthForm config={config.native} onChange={(native) => onChange({ ...config, native })} />
            </div>
          )}

          {config.mode === 'system' && config.system && (
            <div className="mt-4 pt-4 border-t border-bifrost-border">
              <SystemAuthForm config={config.system} onChange={(system) => onChange({ ...config, system })} />
            </div>
          )}

          {config.mode === 'ldap' && config.ldap && (
            <div className="mt-4 pt-4 border-t border-bifrost-border">
              <LDAPAuthForm config={config.ldap} onChange={(ldap) => onChange({ ...config, ldap })} />
            </div>
          )}

          {config.mode === 'oauth' && config.oauth && (
            <div className="mt-4 pt-4 border-t border-bifrost-border">
              <OAuthForm config={config.oauth} onChange={(oauth) => onChange({ ...config, oauth })} />
            </div>
          )}

          <div className="mt-6 pt-4 border-t border-bifrost-border">
            <button onClick={handleEnableMultiProvider} className="btn btn-ghost text-sm">
              <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
              </svg>
              Enable Multiple Auth Providers
            </button>
            <p className="text-xs text-bifrost-muted mt-1">
              Configure multiple authentication backends that are tried in order
            </p>
          </div>
        </div>
      </Section>
    )
  }

  // Multi-provider UI
  return (
    <Section title="Authentication" badge="restart-required">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-300">
            {providers.length === 0
              ? 'No authentication required'
              : `${providers.filter((p) => p.enabled).length} of ${providers.length} providers enabled`}
          </p>
          <button onClick={handleUseLegacyMode} className="btn btn-ghost text-xs">
            Switch to Single Mode
          </button>
        </div>

        {/* Provider List */}
        <div className="space-y-2">
          {providers.map((provider, index) => (
            <div
              key={`${provider.name}-${index}`}
              className={`bg-bifrost-bg rounded-lg border ${
                editingProvider === index ? 'border-bifrost-accent' : 'border-bifrost-border'
              }`}
            >
              {/* Provider Header */}
              <div className="flex items-center justify-between p-3">
                <div className="flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={provider.enabled}
                    onChange={() => handleToggleProvider(index)}
                    className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className={`font-medium ${provider.enabled ? 'text-white' : 'text-gray-500'}`}>
                        {provider.name}
                      </span>
                      <span className="badge badge-info text-xs">{provider.type}</span>
                      <span className="text-xs text-bifrost-muted">Priority: {provider.priority}</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1">
                  <button
                    onClick={() => handleMoveProvider(index, 'up')}
                    disabled={index === 0}
                    className="btn btn-ghost btn-sm p-1 disabled:opacity-30"
                    title="Move up (higher priority)"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                    </svg>
                  </button>
                  <button
                    onClick={() => handleMoveProvider(index, 'down')}
                    disabled={index === providers.length - 1}
                    className="btn btn-ghost btn-sm p-1 disabled:opacity-30"
                    title="Move down (lower priority)"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>
                  <button
                    onClick={() => setEditingProvider(editingProvider === index ? null : index)}
                    className="btn btn-ghost btn-sm p-1"
                    title="Edit"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                      />
                    </svg>
                  </button>
                  <button
                    onClick={() => handleRemoveProvider(index)}
                    className="btn btn-ghost btn-sm p-1 text-bifrost-error hover:bg-bifrost-error/10"
                    title="Remove"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                      />
                    </svg>
                  </button>
                </div>
              </div>

              {/* Provider Edit Form */}
              {editingProvider === index && (
                <div className="border-t border-bifrost-border p-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-1">Provider Name</label>
                      <input
                        type="text"
                        value={provider.name}
                        onChange={(e) => handleUpdateProvider(index, { name: e.target.value })}
                        className="input"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
                      <select
                        value={provider.type}
                        onChange={(e) => {
                          const newType = e.target.value as AuthProvider['type']
                          handleUpdateProvider(index, {
                            type: newType,
                            ...getDefaultProviderConfig(newType),
                          })
                        }}
                        className="input"
                      >
                        {authTypes.map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {provider.type === 'native' && (
                    <NativeAuthForm
                      config={provider.native || { users: [] }}
                      onChange={(native) => handleUpdateProvider(index, { native })}
                    />
                  )}

                  {provider.type === 'system' && (
                    <SystemAuthForm
                      config={provider.system || {}}
                      onChange={(system) => handleUpdateProvider(index, { system })}
                    />
                  )}

                  {provider.type === 'ldap' && (
                    <LDAPAuthForm
                      config={
                        provider.ldap || {
                          url: '',
                          base_dn: '',
                          bind_dn: '',
                          bind_password: '',
                          user_filter: '',
                          tls: false,
                          insecure_skip_verify: false,
                        }
                      }
                      onChange={(ldap) => handleUpdateProvider(index, { ldap })}
                    />
                  )}

                  {provider.type === 'oauth' && (
                    <OAuthForm
                      config={
                        provider.oauth || {
                          provider: '',
                          client_id: '',
                          client_secret: '',
                          issuer_url: '',
                          redirect_url: '',
                          scopes: [],
                        }
                      }
                      onChange={(oauth) => handleUpdateProvider(index, { oauth })}
                    />
                  )}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Add Provider Form */}
        {showAddForm ? (
          <div className="bg-bifrost-bg rounded-lg border border-bifrost-accent p-4">
            <h4 className="text-sm font-medium text-white mb-3">Add Authentication Provider</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Provider Name</label>
                <input
                  type="text"
                  value={newProviderName}
                  onChange={(e) => setNewProviderName(e.target.value)}
                  placeholder="e.g., corporate-ldap"
                  className="input"
                  autoFocus
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">Type</label>
                <select
                  value={newProviderType}
                  onChange={(e) => setNewProviderType(e.target.value)}
                  className="input"
                >
                  {authTypes.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button onClick={() => setShowAddForm(false)} className="btn btn-ghost">
                Cancel
              </button>
              <button onClick={handleAddProvider} disabled={!newProviderName.trim()} className="btn btn-primary">
                Add Provider
              </button>
            </div>
          </div>
        ) : (
          <button onClick={() => setShowAddForm(true)} className="btn btn-ghost w-full border-dashed border-2 border-bifrost-border hover:border-bifrost-accent">
            <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            Add Authentication Provider
          </button>
        )}

        <p className="text-xs text-bifrost-muted">
          Providers are tried in priority order (lowest first). Authentication succeeds when any enabled provider accepts the credentials.
        </p>
      </div>
    </Section>
  )
}
