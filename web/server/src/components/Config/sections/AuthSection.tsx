import { useState, useCallback, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Section } from '../Section'
import { NativeUsersForm } from '../auth-forms/NativeUsersForm'
import { ApiKeysForm } from '../auth-forms/ApiKeysForm'
import { AuthProviderConfigForm } from '../auth-forms/AuthProviderConfigForm'
import { NegotiateForm } from '../auth-forms/NegotiateForm'
import { api } from '../../../api/client'
import type {
  AuthConfig,
  AuthProvider,
  AuthProviderConfig,
  AuthProviderType,
  AuthPluginAvailability,
} from '../../../api/types'

interface AuthSectionProps {
  config: AuthConfig
  onChange: (config: AuthConfig) => void
}

interface AuthTypeOption {
  value: AuthProviderType
  label: string
  description: string
}

// Display metadata for the registered auth plugin types (see
// internal/auth/plugin). Whether a type actually WORKS is deliberately not
// listed here — it is fetched from the server, because it can depend on how the
// binary was built (`system` needs `-tags pam`) and this list has drifted from
// the code before.
const authTypes: AuthTypeOption[] = [
  { value: 'none', label: 'None', description: 'Allow all requests (no authentication)' },
  { value: 'native', label: 'Native', description: 'Built-in user database with bcrypt passwords' },
  { value: 'system', label: 'System (PAM)', description: 'Authenticate against OS users via PAM' },
  { value: 'ldap', label: 'LDAP', description: 'Authenticate against LDAP/Active Directory' },
  { value: 'oauth', label: 'OAuth/OIDC', description: 'Authenticate via OAuth 2.0 / OpenID Connect' },
  { value: 'jwt', label: 'JWT', description: 'Verify JWT bearer tokens via JWKS, a static key, or an HMAC secret' },
  { value: 'apikey', label: 'API Key', description: 'Authenticate via API keys in a request header' },
  { value: 'mtls', label: 'mTLS', description: 'Authenticate via client TLS certificates' },
  { value: 'kerberos', label: 'Kerberos (SPNEGO)', description: 'Negotiate authentication via Kerberos' },
  { value: 'ntlm', label: 'NTLM', description: 'Negotiate authentication via NTLM' },
  { value: 'hotp', label: 'HOTP (counter-based OTP)', description: 'One-time passwords using an HMAC counter' },
  { value: 'totp', label: 'TOTP (time-based OTP)', description: 'One-time passwords using a time counter (authenticator apps)' },
  {
    value: 'mfa_wrapper',
    label: 'MFA Wrapper',
    description: 'Combine a primary provider with TOTP/HOTP as a second factor',
  },
]

// How long the plugin availability list is considered fresh. It only changes
// when the server binary changes, so it does not need frequent refetching.
const AUTH_PLUGINS_STALE_MS = 5 * 60 * 1000

// useAuthPluginAvailability reports, per provider type, whether the connected
// server can actually authenticate with it.
//
// Returns an empty map while loading or if the endpoint is unavailable (an older
// server), in which case nothing is flagged — the UI must not invent warnings it
// cannot substantiate, and the server still refuses unusable providers on save.
function useAuthPluginAvailability(): Record<string, AuthPluginAvailability> {
  const { data } = useQuery({
    queryKey: ['auth-plugins'],
    queryFn: () => api.getAuthPlugins(),
    staleTime: AUTH_PLUGINS_STALE_MS,
    retry: false,
  })

  return useMemo(() => {
    const byType: Record<string, AuthPluginAvailability> = {}
    for (const plugin of data?.plugins ?? []) {
      byType[plugin.name] = plugin.availability
    }
    return byType
  }, [data])
}

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
    case 'mfa_wrapper':
      // Only the inline primary/secondary block format works; the server refuses
      // the by-name (primary_provider/mfa_provider) format outright.
      return {
        primary: { mode: 'native', config: { users: [] } },
        secondary: { mode: 'totp', config: { secrets: {} } },
        mfa_required: 'always',
        password_format: 'separated',
        separator: ':',
        mfa_code_length: 6,
      }
    default:
      return {}
  }
}

// AuthTypeWarning states plainly that a provider cannot authenticate, using the
// server's own reason. A provider that rejects every login used to be offered
// with a full config form and no indication that it was a dead end.
function AuthTypeWarning({ availability }: { availability?: AuthPluginAvailability }) {
  if (!availability || availability.state === 'available') return null

  const unimplemented = availability.state === 'unimplemented'
  // 'unimplemented' is an error: the server refuses to save it at all.
  // 'build_disabled' is a warning: the config is valid, this build just cannot
  // honour it.
  const tone = unimplemented
    ? 'bg-bifrost-error/10 border-bifrost-error/30 text-bifrost-error'
    : 'bg-bifrost-warning/10 border-bifrost-warning/30 text-bifrost-warning'

  return (
    <div className={`mt-3 p-3 border rounded-lg text-xs ${tone}`} role="alert">
      <strong>
        {unimplemented
          ? 'Not functional — the server will refuse this configuration:'
          : 'Not functional in this server build:'}
      </strong>{' '}
      {availability.reason}
    </div>
  )
}

// AvailabilityBadge marks a provider in the collapsed list. The full reason is
// rendered as visually-hidden text rather than living only in a `title`
// attribute, which never reaches keyboard or screen-reader users.
function AvailabilityBadge({ availability }: { availability?: AuthPluginAvailability }) {
  if (!availability || availability.state === 'available') return null

  const unimplemented = availability.state === 'unimplemented'
  return (
    <span
      className={`badge text-xs ${unimplemented ? 'badge-error' : 'badge-warning'}`}
      title={availability.reason}
    >
      {unimplemented ? 'Not functional' : 'Unavailable in this build'}
      {availability.reason && <span className="sr-only">: {availability.reason}</span>}
    </span>
  )
}

// typeOptionLabel appends the availability state to the dropdown label so the
// list itself is honest, not just the panel below it.
function typeOptionLabel(option: AuthTypeOption, availability?: AuthPluginAvailability): string {
  switch (availability?.state) {
    case 'unimplemented':
      return `${option.label} — not functional`
    case 'build_disabled':
      return `${option.label} — unavailable in this build`
    default:
      return option.label
  }
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
  const availabilityByType = useAuthPluginAvailability()

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
    <Section sectionKey="auth" title="Authentication">
      <div className="space-y-4">
        <p className="text-sm text-bifrost-text">
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
                      <span className={`font-medium ${provider.enabled ? 'text-bifrost-heading' : 'text-bifrost-muted'}`}>
                        {provider.name}
                      </span>
                      <span className="badge badge-info text-xs">{provider.type}</span>
                      {/* Flag a dead-end provider in the collapsed row too, so it
                          is visible without expanding the form. The reason is in
                          the markup rather than only in a title attribute, which
                          a keyboard or screen-reader user never sees. */}
                      <AvailabilityBadge availability={availabilityByType[provider.type]} />
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
                      <label className="block text-sm font-medium text-bifrost-text mb-1">Provider Name</label>
                      <input
                        type="text"
                        value={provider.name}
                        onChange={(e) => handleUpdateProvider(index, { name: e.target.value })}
                        className="input"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-bifrost-text mb-1">Type</label>
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
                          <option
                            key={t.value}
                            value={t.value}
                            // A type that can never authenticate must not be
                            // selectable. The provider's CURRENT type stays
                            // selectable so an existing bad config still renders
                            // (and can be disabled or removed) instead of being
                            // silently rewritten to something else.
                            disabled={
                              availabilityByType[t.value]?.state === 'unimplemented' && t.value !== provider.type
                            }
                          >
                            {typeOptionLabel(t, availabilityByType[t.value])}
                          </option>
                        ))}
                      </select>
                      <p className="text-xs text-bifrost-muted mt-1">
                        {authTypes.find((t) => t.value === provider.type)?.description}
                      </p>
                    </div>
                  </div>

                  <AuthTypeWarning availability={availabilityByType[provider.type]} />

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
            <h4 className="text-sm font-medium text-bifrost-heading mb-3">Add Authentication Provider</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-bifrost-text mb-1">Provider Name</label>
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
                <label className="block text-sm font-medium text-bifrost-text mb-1">Type</label>
                <select
                  value={newProviderType}
                  onChange={(e) => setNewProviderType(e.target.value as AuthProviderType)}
                  className="input"
                >
                  {authTypes.map((t) => (
                    <option
                      key={t.value}
                      value={t.value}
                      // Adding a provider that rejects every login is never what
                      // the operator wants, and the server would refuse to save
                      // it anyway — so it cannot be picked here.
                      disabled={availabilityByType[t.value]?.state === 'unimplemented'}
                    >
                      {typeOptionLabel(t, availabilityByType[t.value])}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-bifrost-muted mt-1">
                  {authTypes.find((t) => t.value === newProviderType)?.description}
                </p>
              </div>
            </div>
            <AuthTypeWarning availability={availabilityByType[newProviderType]} />
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
