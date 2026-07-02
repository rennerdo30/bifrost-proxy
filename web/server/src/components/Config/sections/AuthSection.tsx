import { useState, useCallback, useMemo } from 'react'
import { Section } from '../Section'
import { NativeUsersForm } from '../auth-forms/NativeUsersForm'
import { ApiKeysForm } from '../auth-forms/ApiKeysForm'
import { AuthProviderConfigForm } from '../auth-forms/AuthProviderConfigForm'
import { NegotiateForm } from '../auth-forms/NegotiateForm'
import type { AuthConfig, AuthProvider, AuthProviderConfig, AuthProviderType } from '../../../api/types'

interface AuthSectionProps {
  config: AuthConfig
  onChange: (config: AuthConfig) => void
}

interface AuthTypeOption {
  value: AuthProviderType
  label: string
  description: string
  // warning marks provider types that are known not to authenticate in the
  // default/Docker server build so operators are not misled into relying on
  // them. The type is still selectable (it may work in a custom build).
  warning?: string
}

// All registered auth plugin types (see internal/auth/plugin).
const authTypes: AuthTypeOption[] = [
  { value: 'none', label: 'None', description: 'Allow all requests (no authentication)' },
  { value: 'native', label: 'Native', description: 'Built-in user database with bcrypt passwords' },
  {
    value: 'system',
    label: 'System (PAM)',
    description: 'Authenticate against OS users via PAM',
    warning:
      'PAM is compiled out of the default and Docker builds and fails closed (rejects all logins). It only works in a build made with the "pam" tag on Linux with cgo enabled.',
  },
  { value: 'ldap', label: 'LDAP', description: 'Authenticate against LDAP/Active Directory' },
  { value: 'oauth', label: 'OAuth/OIDC', description: 'Authenticate via OAuth 2.0 / OpenID Connect' },
  { value: 'jwt', label: 'JWT', description: 'Verify JWT bearer tokens via JWKS or a static key' },
  { value: 'apikey', label: 'API Key', description: 'Authenticate via API keys in a request header' },
  { value: 'mtls', label: 'mTLS', description: 'Authenticate via client TLS certificates' },
  { value: 'kerberos', label: 'Kerberos (SPNEGO)', description: 'Negotiate authentication via Kerberos' },
  {
    value: 'ntlm',
    label: 'NTLM',
    description: 'Negotiate authentication via NTLM',
    warning:
      'NTLM Type 3 validation is not implemented on the server and fails closed (rejects every client). Selecting it will block all requests routed through it.',
  },
  { value: 'hotp', label: 'HOTP (counter-based OTP)', description: 'One-time passwords using an HMAC counter' },
  { value: 'totp', label: 'TOTP (time-based OTP)', description: 'One-time passwords using a time counter (authenticator apps)' },
]

// Sensible starting config map per plugin type. Empty maps are fine for
// types whose required fields the user must fill in.
function getDefaultProviderConfig(type: AuthProviderType): AuthProviderConfig {
  switch (type) {
    case 'native':
      return { users: [] }
    case 'apikey':
      return { header_name: 'X-API-Key', keys: [] }
    case 'ldap':
      return { user_filter: '(uid=%s)' }
    case 'oauth':
      return { scopes: ['openid', 'profile', 'email'] }
    case 'totp':
      return { issuer: 'Bifrost Proxy', digits: 6, period: 30, algorithm: 'SHA1', skew: 1 }
    case 'hotp':
      return { digits: 6, algorithm: 'SHA1', look_ahead: 10 }
    default:
      return {}
  }
}

function AuthTypeWarning({ type }: { type: AuthProviderType }) {
  const warning = authTypes.find((t) => t.value === type)?.warning
  if (!warning) return null
  return (
    <div className="mt-3 p-3 bg-bifrost-warning/10 border border-bifrost-warning/30 rounded-lg text-xs text-bifrost-warning">
      <strong>Not functional in this build:</strong> {warning}
    </div>
  )
}

function ProviderConfigEditor({
  type,
  config,
  onChange,
}: {
  type: AuthProviderType
  config: AuthProviderConfig
  onChange: (config: AuthProviderConfig) => void
}) {
  if (type === 'none') {
    return <p className="text-sm text-bifrost-muted">This provider accepts all requests without authentication.</p>
  }
  if (type === 'native') {
    return <NativeUsersForm config={config} onChange={onChange} />
  }
  if (type === 'apikey') {
    return <ApiKeysForm config={config} onChange={onChange} />
  }
  return <AuthProviderConfigForm type={type} config={config} onChange={onChange} />
}

export function AuthSection({ config, onChange }: AuthSectionProps) {
  const [editingProvider, setEditingProvider] = useState<number | null>(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [newProviderType, setNewProviderType] = useState<AuthProviderType>('native')
  const [newProviderName, setNewProviderName] = useState('')

  const providers = useMemo(() => config.providers || [], [config.providers])

  const handleAddProvider = useCallback(() => {
    if (!newProviderName.trim()) return

    const newProvider: AuthProvider = {
      name: newProviderName.trim(),
      type: newProviderType,
      enabled: true,
      priority: providers.length,
      config: getDefaultProviderConfig(newProviderType),
    }

    onChange({ providers: [...providers, newProvider] })

    setNewProviderName('')
    setShowAddForm(false)
    setEditingProvider(providers.length)
  }, [newProviderName, newProviderType, providers, onChange])

  const handleRemoveProvider = useCallback(
    (index: number) => {
      onChange({ providers: providers.filter((_, i) => i !== index) })
      setEditingProvider((current) => (current === index ? null : current))
    },
    [providers, onChange]
  )

  const handleToggleProvider = useCallback(
    (index: number) => {
      const next = [...providers]
      next[index] = { ...next[index], enabled: !next[index].enabled }
      onChange({ providers: next })
    },
    [providers, onChange]
  )

  const handleUpdateProvider = useCallback(
    (index: number, updates: Partial<AuthProvider>) => {
      const next = [...providers]
      next[index] = { ...next[index], ...updates }
      onChange({ providers: next })
    },
    [providers, onChange]
  )

  const handleMoveProvider = useCallback(
    (index: number, direction: 'up' | 'down') => {
      const newIndex = direction === 'up' ? index - 1 : index + 1
      if (newIndex < 0 || newIndex >= providers.length) return

      const next = [...providers]
      ;[next[index], next[newIndex]] = [next[newIndex], next[index]]
      next.forEach((p, i) => (p.priority = i))
      onChange({ providers: next })

      setEditingProvider((current) => {
        if (current === index) return newIndex
        if (current === newIndex) return index
        return current
      })
    },
    [providers, onChange]
  )

  return (
    <Section title="Authentication" badge="restart-required">
      <div className="space-y-4">
        <p className="text-sm text-gray-300">
          {providers.length === 0
            ? 'No authentication required'
            : `${providers.filter((p) => p.enabled).length} of ${providers.length} providers enabled`}
        </p>

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
                    aria-label={`Enable ${provider.name}`}
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
                    aria-label={`Move ${provider.name} up`}
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
                    </svg>
                  </button>
                  <button
                    onClick={() => handleMoveProvider(index, 'down')}
                    disabled={index === providers.length - 1}
                    className="btn btn-ghost btn-sm p-1 disabled:opacity-30"
                    title="Move down (lower priority)"
                    aria-label={`Move ${provider.name} down`}
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                  </button>
                  <button
                    onClick={() => setEditingProvider(editingProvider === index ? null : index)}
                    className="btn btn-ghost btn-sm p-1"
                    title="Edit"
                    aria-label={`Edit ${provider.name}`}
                    aria-expanded={editingProvider === index}
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
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
                    aria-label={`Remove ${provider.name}`}
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
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
                          const newType = e.target.value as AuthProviderType
                          handleUpdateProvider(index, {
                            type: newType,
                            config: getDefaultProviderConfig(newType),
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
                      <p className="text-xs text-bifrost-muted mt-1">
                        {authTypes.find((t) => t.value === provider.type)?.description}
                      </p>
                    </div>
                  </div>

                  <AuthTypeWarning type={provider.type} />

                  <ProviderConfigEditor
                    type={provider.type}
                    config={provider.config || {}}
                    onChange={(cfg) => handleUpdateProvider(index, { config: cfg })}
                  />
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
                  onChange={(e) => setNewProviderType(e.target.value as AuthProviderType)}
                  className="input"
                >
                  {authTypes.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-bifrost-muted mt-1">
                  {authTypes.find((t) => t.value === newProviderType)?.description}
                </p>
              </div>
            </div>
            <AuthTypeWarning type={newProviderType} />
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
          <button
            onClick={() => setShowAddForm(true)}
            className="btn btn-ghost w-full border-dashed border-2 border-bifrost-border hover:border-bifrost-accent"
          >
            <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            Add Authentication Provider
          </button>
        )}

        <p className="text-xs text-bifrost-muted">
          Providers are tried in priority order (lowest first). Authentication succeeds when any enabled provider accepts
          the credentials.
        </p>

        <div className="pt-4 border-t border-bifrost-border">
          <NegotiateForm
            config={config.negotiate}
            providers={providers}
            onChange={(negotiate) => onChange({ ...config, negotiate })}
          />
        </div>
      </div>
    </Section>
  )
}
