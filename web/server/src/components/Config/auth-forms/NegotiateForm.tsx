import type { AuthProvider, NegotiateConfig } from '../../../api/types'

interface NegotiateFormProps {
  config?: NegotiateConfig
  providers: AuthProvider[]
  onChange: (config: NegotiateConfig | undefined) => void
}

// HTTP Negotiate (SPNEGO/Kerberos with optional NTLM fallback) middleware.
// It delegates credential validation to named kerberos/ntlm auth providers,
// so the selectors are populated from the configured providers list.
export function NegotiateForm({ config, providers, onChange }: NegotiateFormProps) {
  const enabled = config?.enabled ?? false
  const kerberosProviders = providers.filter((p) => p.type === 'kerberos')
  const ntlmProviders = providers.filter((p) => p.type === 'ntlm')

  const update = (field: keyof NegotiateConfig, value: unknown) => {
    onChange({ ...(config || { enabled: true }), enabled: true, [field]: value })
  }

  const toggle = (enable: boolean) => {
    if (enable) {
      onChange({ prefer_kerberos: true, ...(config || {}), enabled: true })
    } else {
      onChange(undefined)
    }
  }

  return (
    <div className="bg-bifrost-bg rounded-lg border border-bifrost-border p-4 space-y-4">
      <div>
        <h4 className="text-sm font-semibold text-white">Negotiate (SPNEGO / Windows SSO)</h4>
        <p className="text-xs text-bifrost-muted mt-0.5">
          Drives the browser challenge/response handshake for Windows-domain
          single sign-on. Validation is delegated to a Kerberos provider (and an
          optional NTLM provider). NTLM validation currently fails closed on the
          server, so leave NTLM fallback off unless you know it is supported.
        </p>
      </div>

      <label className="flex items-center gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => toggle(e.target.checked)}
          className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
        />
        <span className="text-sm font-medium text-gray-300">Enable Negotiate Authentication</span>
      </label>

      {enabled && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Kerberos Provider</label>
            <select
              value={config?.kerberos_provider || ''}
              onChange={(e) => update('kerberos_provider', e.target.value)}
              className="input"
            >
              <option value="">Select a Kerberos provider...</option>
              {kerberosProviders.map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
            <p className="text-xs text-bifrost-muted mt-1">
              Required. Add a provider of type &quot;kerberos&quot; above.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Realm</label>
            <input
              type="text"
              value={config?.realm || ''}
              onChange={(e) => update('realm', e.target.value)}
              placeholder="EXAMPLE.COM"
              className="input"
            />
          </div>

          <label className="flex items-center gap-2 cursor-pointer md:col-span-2">
            <input
              type="checkbox"
              checked={config?.prefer_kerberos ?? true}
              onChange={(e) => update('prefer_kerberos', e.target.checked)}
              className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
            />
            <span className="text-sm text-gray-300">Prefer Kerberos over NTLM (default)</span>
          </label>

          <label className="flex items-center gap-2 cursor-pointer md:col-span-2">
            <input
              type="checkbox"
              checked={config?.allow_ntlm ?? false}
              onChange={(e) => update('allow_ntlm', e.target.checked)}
              className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
            />
            <span className="text-sm text-gray-300">Allow NTLM fallback</span>
            <span className="badge badge-warning text-xs">Fails closed on server</span>
          </label>

          {config?.allow_ntlm && (
            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-300 mb-1">NTLM Provider</label>
              <select
                value={config?.ntlm_provider || ''}
                onChange={(e) => update('ntlm_provider', e.target.value)}
                className="input"
              >
                <option value="">Select an NTLM provider...</option>
                {ntlmProviders.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name}
                  </option>
                ))}
              </select>
              <p className="text-xs text-bifrost-warning mt-1">
                NTLM Type 3 validation is not implemented on the server and
                rejects all clients; enable only if this changes.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
