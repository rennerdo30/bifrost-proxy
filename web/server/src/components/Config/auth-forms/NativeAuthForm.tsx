import type { NativeAuth, NativeUser } from '../../../api/types'

interface NativeAuthFormProps {
  config: NativeAuth
  onChange: (config: NativeAuth) => void
}

export function NativeAuthForm({ config, onChange }: NativeAuthFormProps) {
  const users = config.users || []

  const addUser = () => {
    onChange({
      ...config,
      users: [...users, { username: '', password_hash: '' }],
    })
  }

  const updateUser = (index: number, user: NativeUser) => {
    const updated = [...users]
    updated[index] = user
    onChange({ ...config, users: updated })
  }

  const removeUser = (index: number) => {
    onChange({
      ...config,
      users: users.filter((_, i) => i !== index),
    })
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-bifrost-muted">
        Configure users with bcrypt password hashes. Use <code className="text-xs bg-bifrost-bg px-1 py-0.5 rounded">htpasswd -nB username</code> to generate hashes.
      </p>

      {users.map((user, index) => (
        <div key={index} className="p-4 bg-bifrost-bg rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-white">User {index + 1}</span>
            <button
              type="button"
              onClick={() => removeUser(index)}
              className="text-bifrost-error hover:text-red-400"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
              <input
                type="text"
                value={user.username}
                onChange={(e) => updateUser(index, { ...user, username: e.target.value })}
                placeholder="username"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Password Hash (bcrypt)</label>
              <input
                type="text"
                value={user.password_hash}
                onChange={(e) => updateUser(index, { ...user, password_hash: e.target.value })}
                placeholder="$2a$10$..."
                className="input font-mono text-xs"
              />
            </div>
          </div>
        </div>
      ))}

      <button type="button" onClick={addUser} className="btn btn-secondary">
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
        </svg>
        Add User
      </button>
    </div>
  )
}
