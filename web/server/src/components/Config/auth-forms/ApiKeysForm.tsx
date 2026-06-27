import type { AuthProviderConfig } from '../../../api/types'

interface ApiKeysFormProps {
  config: AuthProviderConfig
  onChange: (config: AuthProviderConfig) => void
}

interface ApiKeyEntry {
  name: string
  key_hash: string
  key_plain: string
  groups: string[]
}

function readKeys(config: AuthProviderConfig): ApiKeyEntry[] {
  const raw = config.keys
  if (!Array.isArray(raw)) return []
  return raw.map((k) => {
    const obj = (k ?? {}) as Record<string, unknown>
    return {
      name: typeof obj.name === 'string' ? obj.name : '',
      key_hash: typeof obj.key_hash === 'string' ? obj.key_hash : '',
      key_plain: typeof obj.key_plain === 'string' ? obj.key_plain : '',
      groups: Array.isArray(obj.groups) ? (obj.groups as unknown[]).map(String) : [],
    }
  })
}

// Strip empty optional fields so the emitted config map stays clean.
function serializeKey(k: ApiKeyEntry): Record<string, unknown> {
  const out: Record<string, unknown> = { name: k.name }
  if (k.key_hash) out.key_hash = k.key_hash
  if (k.key_plain) out.key_plain = k.key_plain
  if (k.groups.length > 0) out.groups = k.groups
  return out
}

export function ApiKeysForm({ config, onChange }: ApiKeysFormProps) {
  const keys = readKeys(config)
  const headerName = typeof config.header_name === 'string' ? config.header_name : ''

  const commit = (next: ApiKeyEntry[]) => {
    onChange({ ...config, keys: next.map(serializeKey) })
  }

  const setHeaderName = (value: string) => {
    const next = { ...config }
    if (value) next.header_name = value
    else delete next.header_name
    onChange(next)
  }

  const addKey = () => commit([...keys, { name: '', key_hash: '', key_plain: '', groups: [] }])

  const updateKey = (index: number, key: ApiKeyEntry) => {
    const next = [...keys]
    next[index] = key
    commit(next)
  }

  const removeKey = (index: number) => commit(keys.filter((_, i) => i !== index))

  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Authenticate requests with API keys sent in a header. Provide either a bcrypt hash (recommended) or a plaintext
        key per entry.
      </p>

      <div className="max-w-xs">
        <label className="block text-sm font-medium text-gray-300 mb-1">Header Name</label>
        <input
          type="text"
          value={headerName}
          onChange={(e) => setHeaderName(e.target.value)}
          placeholder="X-API-Key"
          className="input"
        />
      </div>

      {keys.map((key, index) => (
        <div key={index} className="p-4 bg-bifrost-bg rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-white">Key {index + 1}</span>
            <button
              type="button"
              onClick={() => removeKey(index)}
              aria-label={`Remove key ${index + 1}`}
              className="text-bifrost-error hover:text-red-400"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Name</label>
              <input
                type="text"
                value={key.name}
                onChange={(e) => updateKey(index, { ...key, name: e.target.value })}
                placeholder="ci-pipeline"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Groups</label>
              <input
                type="text"
                value={key.groups.join(', ')}
                onChange={(e) =>
                  updateKey(index, {
                    ...key,
                    groups: e.target.value
                      .split(',')
                      .map((s) => s.trim())
                      .filter((s) => s.length > 0),
                  })
                }
                placeholder="admins, users"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Key Hash (bcrypt)</label>
              <input
                type="text"
                value={key.key_hash}
                onChange={(e) => updateKey(index, { ...key, key_hash: e.target.value })}
                placeholder="$2a$10$..."
                className="input font-mono text-xs"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Key (plaintext)</label>
              <input
                type="text"
                value={key.key_plain}
                onChange={(e) => updateKey(index, { ...key, key_plain: e.target.value })}
                placeholder="(only if not using a hash)"
                className="input font-mono text-xs"
              />
            </div>
          </div>
        </div>
      ))}

      <button type="button" onClick={addKey} className="btn btn-secondary">
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
        </svg>
        Add API Key
      </button>
    </div>
  )
}
