import { useState } from 'react'
import { ArrayInput } from '../ArrayInput'
import type { OAuthAuth } from '../../../api/types'

interface OAuthFormProps {
  config: OAuthAuth
  onChange: (config: OAuthAuth) => void
}

export function OAuthForm({ config, onChange }: OAuthFormProps) {
  const [showSecret, setShowSecret] = useState(false)

  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Authenticate users via OAuth 2.0 / OpenID Connect.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Provider Name</label>
          <input
            type="text"
            value={config.provider || ''}
            onChange={(e) => update('provider', e.target.value)}
            placeholder="google, github, okta..."
            className="input"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Issuer URL</label>
          <input
            type="text"
            value={config.issuer_url || ''}
            onChange={(e) => update('issuer_url', e.target.value)}
            placeholder="https://accounts.google.com"
            className="input"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Client ID</label>
          <input
            type="text"
            value={config.client_id || ''}
            onChange={(e) => update('client_id', e.target.value)}
            placeholder="your-client-id"
            className="input"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Client Secret</label>
          <div className="relative">
            <input
              type={showSecret ? 'text' : 'password'}
              value={config.client_secret || ''}
              onChange={(e) => update('client_secret', e.target.value)}
              placeholder="your-client-secret"
              className="input pr-10"
            />
            <button
              type="button"
              onClick={() => setShowSecret(!showSecret)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-white"
            >
              {showSecret ? (
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

        <div className="md:col-span-2">
          <label className="block text-sm font-medium text-gray-300 mb-1">Redirect URL</label>
          <input
            type="text"
            value={config.redirect_url || ''}
            onChange={(e) => update('redirect_url', e.target.value)}
            placeholder="http://localhost:8080/auth/callback"
            className="input"
          />
          <p className="text-xs text-bifrost-muted mt-1">Must match the callback URL configured in your OAuth provider</p>
        </div>

        <div className="md:col-span-2">
          <ArrayInput
            label="Scopes"
            values={config.scopes || ['openid', 'profile', 'email']}
            onChange={(scopes) => update('scopes', scopes)}
            placeholder="openid, profile, email..."
          />
        </div>
      </div>
    </div>
  )
}
