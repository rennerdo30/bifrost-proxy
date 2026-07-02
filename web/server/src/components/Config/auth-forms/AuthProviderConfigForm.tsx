import { useState } from 'react'
import type { AuthProviderConfig, AuthProviderType } from '../../../api/types'

interface AuthProviderConfigFormProps {
  type: AuthProviderType
  config: AuthProviderConfig
  onChange: (config: AuthProviderConfig) => void
}

type FieldKind = 'text' | 'password' | 'number' | 'bool' | 'textarea' | 'stringlist'

interface FieldSchema {
  key: string
  label: string
  kind: FieldKind
  placeholder?: string
  help?: string
  insecure?: boolean
}

// Field schemas keyed by plugin type. Field keys map 1:1 to the server's
// config map keys (see internal/auth/plugin/*). The server expects an
// `auth.providers[].config` map, never the legacy typed fields.
const FIELD_SCHEMAS: Record<string, FieldSchema[]> = {
  system: [
    { key: 'service', label: 'PAM Service', kind: 'text', placeholder: 'login' },
    { key: 'allowed_users', label: 'Allowed Users', kind: 'stringlist', help: 'Comma-separated usernames (optional)' },
    { key: 'allowed_groups', label: 'Allowed Groups', kind: 'stringlist', help: 'Comma-separated groups (optional)' },
  ],
  ldap: [
    { key: 'url', label: 'LDAP URL', kind: 'text', placeholder: 'ldap://ldap.example.com:389' },
    { key: 'base_dn', label: 'Base DN', kind: 'text', placeholder: 'dc=example,dc=com' },
    { key: 'bind_dn', label: 'Bind DN', kind: 'text', placeholder: 'cn=admin,dc=example,dc=com' },
    { key: 'bind_password', label: 'Bind Password', kind: 'password', placeholder: 'LDAP bind password' },
    { key: 'user_filter', label: 'User Filter', kind: 'text', placeholder: '(uid=%s)', help: '%s is replaced with the username' },
    { key: 'group_filter', label: 'Group Filter', kind: 'text', placeholder: '(cn=%s)' },
    { key: 'require_group', label: 'Required Group', kind: 'text', placeholder: 'proxy-users', help: 'Users must be members of this group (optional)' },
    { key: 'tls', label: 'Use TLS (LDAPS)', kind: 'bool' },
    { key: 'insecure_skip_verify', label: 'Skip TLS Verification', kind: 'bool', insecure: true },
  ],
  oauth: [
    { key: 'provider', label: 'Provider', kind: 'text', placeholder: 'google, github, generic' },
    { key: 'client_id', label: 'Client ID', kind: 'text' },
    { key: 'client_secret', label: 'Client Secret', kind: 'password' },
    { key: 'issuer_url', label: 'Issuer URL', kind: 'text', placeholder: 'https://accounts.google.com' },
    { key: 'introspect_url', label: 'Introspection URL', kind: 'text', help: 'OAuth2 token introspection endpoint (optional)' },
    { key: 'userinfo_url', label: 'UserInfo URL', kind: 'text', help: 'OIDC userinfo endpoint (optional)' },
    { key: 'scopes', label: 'Scopes', kind: 'stringlist', placeholder: 'openid, profile, email' },
    { key: 'required_claims', label: 'Required Claims', kind: 'stringlist', help: 'Comma-separated claim names (optional)' },
  ],
  jwt: [
    { key: 'jwks_url', label: 'JWKS URL', kind: 'text', placeholder: 'https://issuer/.well-known/jwks.json' },
    { key: 'public_key_pem', label: 'Public Key (PEM)', kind: 'textarea', help: 'Static verification key (alternative to JWKS URL)' },
    { key: 'issuer', label: 'Issuer', kind: 'text' },
    { key: 'audience', label: 'Audience', kind: 'text' },
    { key: 'algorithms', label: 'Algorithms', kind: 'stringlist', placeholder: 'RS256, ES256' },
    { key: 'username_claim', label: 'Username Claim', kind: 'text', placeholder: 'sub' },
    { key: 'groups_claim', label: 'Groups Claim', kind: 'text', placeholder: 'groups' },
    { key: 'email_claim', label: 'Email Claim', kind: 'text', placeholder: 'email' },
    { key: 'leeway_seconds', label: 'Leeway (seconds)', kind: 'number' },
    { key: 'jwks_refresh_interval', label: 'JWKS Refresh Interval', kind: 'text', placeholder: '15m' },
  ],
  mtls: [
    { key: 'ca_cert_file', label: 'CA Cert File', kind: 'text', placeholder: '/path/to/ca.pem' },
    { key: 'ca_cert_pem', label: 'CA Cert (PEM)', kind: 'textarea', help: 'Inline CA certificate (alternative to file)' },
    { key: 'require_client_cert', label: 'Require Client Certificate', kind: 'bool' },
    { key: 'verify_time', label: 'Verify Certificate Validity Period', kind: 'bool' },
    { key: 'crl_file', label: 'CRL File', kind: 'text', help: 'Certificate revocation list (optional)' },
    { key: 'allowed_subjects', label: 'Allowed Subjects', kind: 'stringlist', help: 'Comma-separated subject DNs (optional)' },
    { key: 'allowed_issuers', label: 'Allowed Issuers', kind: 'stringlist', help: 'Comma-separated issuer DNs (optional)' },
  ],
  kerberos: [
    { key: 'keytab_file', label: 'Keytab File', kind: 'text', placeholder: '/etc/krb5.keytab' },
    { key: 'keytab_base64', label: 'Keytab (Base64)', kind: 'textarea', help: 'Inline keytab (alternative to file)' },
    { key: 'service_principal', label: 'Service Principal', kind: 'text', placeholder: 'HTTP/proxy.example.com' },
    { key: 'realm', label: 'Realm', kind: 'text', placeholder: 'EXAMPLE.COM' },
    { key: 'krb5_config_file', label: 'krb5.conf File', kind: 'text', placeholder: '/etc/krb5.conf' },
    { key: 'krb5_config', label: 'krb5.conf (inline)', kind: 'textarea' },
    { key: 'kdc_servers', label: 'KDC Servers', kind: 'stringlist', help: 'Comma-separated KDC addresses (optional)' },
    { key: 'strip_realm', label: 'Strip Realm From Username', kind: 'bool' },
    { key: 'username_to_lowercase', label: 'Lowercase Username', kind: 'bool' },
  ],
  ntlm: [
    { key: 'domain', label: 'Domain', kind: 'text', placeholder: 'EXAMPLE' },
    { key: 'allowed_domains', label: 'Allowed Domains', kind: 'stringlist', help: 'Comma-separated domains (optional)' },
    { key: 'strip_domain', label: 'Strip Domain From Username', kind: 'bool' },
    { key: 'username_to_lowercase', label: 'Lowercase Username', kind: 'bool' },
    { key: 'server_challenge_secret', label: 'Server Challenge Secret', kind: 'password', help: 'Optional deterministic challenge secret' },
  ],
  totp: [
    { key: 'issuer', label: 'Issuer', kind: 'text', placeholder: 'Bifrost Proxy', help: 'Name shown in authenticator apps' },
    { key: 'digits', label: 'Digits', kind: 'number', placeholder: '6', help: '6 or 8' },
    { key: 'period', label: 'Period (seconds)', kind: 'number', placeholder: '30' },
    { key: 'algorithm', label: 'Algorithm', kind: 'text', placeholder: 'SHA1', help: 'SHA1, SHA256, or SHA512' },
    { key: 'skew', label: 'Clock Skew', kind: 'number', placeholder: '1', help: 'Number of periods to allow for clock drift' },
    { key: 'secrets_file', label: 'Secrets File', kind: 'text', placeholder: '/etc/bifrost/totp-secrets.yaml', help: 'YAML file of per-user secrets' },
  ],
  hotp: [
    { key: 'digits', label: 'Digits', kind: 'number', placeholder: '6', help: '6 or 8' },
    { key: 'algorithm', label: 'Algorithm', kind: 'text', placeholder: 'SHA1', help: 'SHA1, SHA256, or SHA512' },
    { key: 'look_ahead', label: 'Look-Ahead Window', kind: 'number', placeholder: '10', help: 'Counters to look ahead for resync' },
    { key: 'secrets_file', label: 'Secrets File', kind: 'text', placeholder: '/etc/bifrost/hotp-secrets.yaml', help: 'YAML file of per-user secrets' },
  ],
}

function toStringList(value: unknown): string {
  if (Array.isArray(value)) return value.join(', ')
  return ''
}

function parseStringList(text: string): string[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

function PasswordField({
  value,
  onChange,
  placeholder,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  const [show, setShow] = useState(false)
  return (
    <div className="relative">
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="input pr-10"
      />
      <button
        type="button"
        onClick={() => setShow(!show)}
        aria-label={show ? 'Hide value' : 'Show value'}
        className="absolute right-2 top-1/2 -translate-y-1/2 text-bifrost-muted hover:text-white"
      >
        {show ? (
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
          </svg>
        ) : (
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
          </svg>
        )}
      </button>
    </div>
  )
}

export function AuthProviderConfigForm({ type, config, onChange }: AuthProviderConfigFormProps) {
  const schema = FIELD_SCHEMAS[type]

  if (!schema) {
    return null
  }

  const update = (key: string, value: unknown) => {
    const next = { ...config }
    if (value === '' || value === undefined || (Array.isArray(value) && value.length === 0)) {
      delete next[key]
    } else {
      next[key] = value
    }
    onChange(next)
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {schema.map((field) => {
          const id = `auth-${type}-${field.key}`
          const raw = config[field.key]

          if (field.kind === 'bool') {
            return (
              <label key={field.key} className="flex items-center gap-2 cursor-pointer md:col-span-2">
                <input
                  id={id}
                  type="checkbox"
                  checked={raw === true}
                  onChange={(e) => update(field.key, e.target.checked)}
                  className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                />
                <span className="text-sm text-gray-300">{field.label}</span>
                {field.insecure && raw === true && <span className="badge badge-warning text-xs">Insecure</span>}
              </label>
            )
          }

          const colSpan = field.kind === 'textarea' ? 'md:col-span-2' : ''
          return (
            <div key={field.key} className={colSpan}>
              <label htmlFor={id} className="block text-sm font-medium text-gray-300 mb-1">
                {field.label}
              </label>
              {field.kind === 'textarea' ? (
                <textarea
                  id={id}
                  value={typeof raw === 'string' ? raw : ''}
                  onChange={(e) => update(field.key, e.target.value)}
                  placeholder={field.placeholder}
                  rows={4}
                  className="input font-mono text-xs"
                />
              ) : field.kind === 'password' ? (
                <PasswordField
                  value={typeof raw === 'string' ? raw : ''}
                  onChange={(v) => update(field.key, v)}
                  placeholder={field.placeholder}
                />
              ) : field.kind === 'number' ? (
                <input
                  id={id}
                  type="number"
                  value={typeof raw === 'number' ? raw : ''}
                  onChange={(e) => update(field.key, e.target.value === '' ? '' : Number(e.target.value))}
                  placeholder={field.placeholder}
                  className="input"
                />
              ) : field.kind === 'stringlist' ? (
                <input
                  id={id}
                  type="text"
                  value={toStringList(raw)}
                  onChange={(e) => update(field.key, parseStringList(e.target.value))}
                  placeholder={field.placeholder}
                  className="input"
                />
              ) : (
                <input
                  id={id}
                  type="text"
                  value={typeof raw === 'string' ? raw : ''}
                  onChange={(e) => update(field.key, e.target.value)}
                  placeholder={field.placeholder}
                  className="input"
                />
              )}
              {field.help && <p className="text-xs text-bifrost-muted mt-1">{field.help}</p>}
            </div>
          )
        })}
      </div>
    </div>
  )
}
