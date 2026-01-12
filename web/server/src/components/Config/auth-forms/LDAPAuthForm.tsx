import { useState } from 'react'
import type { LDAPAuth } from '../../../api/types'

interface LDAPAuthFormProps {
  config: LDAPAuth
  onChange: (config: LDAPAuth) => void
}

export function LDAPAuthForm({ config, onChange }: LDAPAuthFormProps) {
  const [showPassword, setShowPassword] = useState(false)

  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Authenticate users against LDAP or Active Directory.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-300 mb-1">LDAP URL</label>
          <input
            type="text"
            value={config.url || ''}
            onChange={(e) => update('url', e.target.value)}
            placeholder="ldap://ldap.example.com:389"
            className="input"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Base DN</label>
          <input
            type="text"
            value={config.base_dn || ''}
            onChange={(e) => update('base_dn', e.target.value)}
            placeholder="dc=example,dc=com"
            className="input"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Bind DN</label>
          <input
            type="text"
            value={config.bind_dn || ''}
            onChange={(e) => update('bind_dn', e.target.value)}
            placeholder="cn=admin,dc=example,dc=com"
            className="input"
          />
        </div>

        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-300 mb-1">Bind Password</label>
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              value={config.bind_password || ''}
              onChange={(e) => update('bind_password', e.target.value)}
              placeholder="LDAP bind password"
              className="input pr-10"
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-white"
            >
              {showPassword ? (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>
              )}
            </button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">User Filter</label>
          <input
            type="text"
            value={config.user_filter || ''}
            onChange={(e) => update('user_filter', e.target.value)}
            placeholder="(uid=%s)"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">%s will be replaced with username</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Group Filter</label>
          <input
            type="text"
            value={config.group_filter || ''}
            onChange={(e) => update('group_filter', e.target.value)}
            placeholder="(cn=%s)"
            className="input"
          />
        </div>

        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-300 mb-1">Required Group</label>
          <input
            type="text"
            value={config.require_group || ''}
            onChange={(e) => update('require_group', e.target.value)}
            placeholder="proxy-users"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">Users must be members of this group (optional)</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-6 pt-2">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.tls}
            onChange={(e) => update('tls', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm text-gray-300">Use TLS (LDAPS)</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={config.insecure_skip_verify}
            onChange={(e) => update('insecure_skip_verify', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm text-gray-300">Skip TLS Verification</span>
          {config.insecure_skip_verify && (
            <span className="badge badge-warning text-xs">Insecure</span>
          )}
        </label>
      </div>
    </div>
  )
}
