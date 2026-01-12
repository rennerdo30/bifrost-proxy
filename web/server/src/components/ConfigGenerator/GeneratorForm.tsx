import { useState } from 'react'
import yaml from 'js-yaml'

interface ClientConfig {
  server: {
    address: string
    protocol: 'http' | 'socks5'
  }
  local: {
    http_listen: string
    socks5_listen: string
  }
  routes: Array<{
    pattern: string
    action: 'proxy' | 'direct'
  }>
  auth?: {
    username: string
    password: string
  }
}

interface GeneratorFormProps {
  onConfigChange: (yaml: string) => void
}

const defaultConfig: ClientConfig = {
  server: {
    address: 'localhost:8080',
    protocol: 'http',
  },
  local: {
    http_listen: ':8080',
    socks5_listen: ':1080',
  },
  routes: [
    { pattern: '*.local', action: 'direct' },
    { pattern: 'localhost', action: 'direct' },
    { pattern: '*', action: 'proxy' },
  ],
}

export function GeneratorForm({ onConfigChange }: GeneratorFormProps) {
  const [config, setConfig] = useState<ClientConfig>(defaultConfig)
  const [useAuth, setUseAuth] = useState(false)

  const updateConfig = (updates: Partial<ClientConfig>) => {
    const newConfig = { ...config, ...updates }
    setConfig(newConfig)

    // Generate YAML
    const yamlConfig: Record<string, unknown> = {
      server: {
        address: newConfig.server.address,
        protocol: newConfig.server.protocol,
      },
      local: {
        http_listen: newConfig.local.http_listen,
        socks5_listen: newConfig.local.socks5_listen,
      },
      routes: newConfig.routes.map((r) => ({
        pattern: r.pattern,
        action: r.action,
      })),
    }

    if (useAuth && newConfig.auth?.username) {
      yamlConfig.auth = {
        username: newConfig.auth.username,
        password: newConfig.auth.password || '',
      }
    }

    onConfigChange(yaml.dump(yamlConfig, { indent: 2, lineWidth: -1 }))
  }

  const addRoute = () => {
    updateConfig({
      routes: [...config.routes, { pattern: '', action: 'proxy' }],
    })
  }

  const removeRoute = (index: number) => {
    updateConfig({
      routes: config.routes.filter((_, i) => i !== index),
    })
  }

  const updateRoute = (index: number, updates: Partial<ClientConfig['routes'][0]>) => {
    const newRoutes = [...config.routes]
    newRoutes[index] = { ...newRoutes[index], ...updates }
    updateConfig({ routes: newRoutes })
  }

  return (
    <div className="space-y-6">
      {/* Server Connection */}
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Server Connection</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="label">Server Address</label>
            <input
              type="text"
              className="input"
              value={config.server.address}
              onChange={(e) =>
                updateConfig({
                  server: { ...config.server, address: e.target.value },
                })
              }
              placeholder="proxy.example.com:8080"
            />
            <p className="text-xs text-bifrost-muted mt-1">
              The address of your Bifrost server
            </p>
          </div>
          <div>
            <label className="label">Protocol</label>
            <select
              className="select"
              value={config.server.protocol}
              onChange={(e) =>
                updateConfig({
                  server: { ...config.server, protocol: e.target.value as 'http' | 'socks5' },
                })
              }
            >
              <option value="http">HTTP Proxy</option>
              <option value="socks5">SOCKS5</option>
            </select>
          </div>
        </div>
      </div>

      {/* Local Proxy Settings */}
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Local Proxy Settings</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="label">HTTP Listen Address</label>
            <input
              type="text"
              className="input"
              value={config.local.http_listen}
              onChange={(e) =>
                updateConfig({
                  local: { ...config.local, http_listen: e.target.value },
                })
              }
              placeholder=":8080"
            />
          </div>
          <div>
            <label className="label">SOCKS5 Listen Address</label>
            <input
              type="text"
              className="input"
              value={config.local.socks5_listen}
              onChange={(e) =>
                updateConfig({
                  local: { ...config.local, socks5_listen: e.target.value },
                })
              }
              placeholder=":1080"
            />
          </div>
        </div>
      </div>

      {/* Authentication */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Authentication</h3>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={useAuth}
              onChange={(e) => {
                setUseAuth(e.target.checked)
                if (!e.target.checked) {
                  updateConfig({ auth: undefined })
                } else {
                  updateConfig({ auth: { username: '', password: '' } })
                }
              }}
              className="rounded border-bifrost-border bg-bifrost-bg"
            />
            <span className="text-sm text-gray-300">Enable</span>
          </label>
        </div>
        {useAuth && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="label">Username</label>
              <input
                type="text"
                className="input"
                value={config.auth?.username || ''}
                onChange={(e) =>
                  updateConfig({
                    auth: { ...config.auth!, username: e.target.value },
                  })
                }
                placeholder="username"
              />
            </div>
            <div>
              <label className="label">Password</label>
              <input
                type="password"
                className="input"
                value={config.auth?.password || ''}
                onChange={(e) =>
                  updateConfig({
                    auth: { ...config.auth!, password: e.target.value },
                  })
                }
                placeholder="password"
              />
            </div>
          </div>
        )}
      </div>

      {/* Routing Rules */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">Routing Rules</h3>
          <button onClick={addRoute} className="btn btn-secondary text-sm">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Rule
          </button>
        </div>
        <div className="space-y-3">
          {config.routes.map((route, index) => (
            <div
              key={index}
              className="flex items-center gap-3 p-3 bg-bifrost-bg rounded-lg animate-slide-up"
              style={{ animationDelay: `${index * 30}ms` }}
            >
              <input
                type="text"
                className="input flex-1"
                value={route.pattern}
                onChange={(e) => updateRoute(index, { pattern: e.target.value })}
                placeholder="*.example.com"
              />
              <select
                className="select w-32"
                value={route.action}
                onChange={(e) =>
                  updateRoute(index, { action: e.target.value as 'proxy' | 'direct' })
                }
              >
                <option value="proxy">Proxy</option>
                <option value="direct">Direct</option>
              </select>
              <button
                onClick={() => removeRoute(index)}
                className="btn btn-ghost text-bifrost-error p-2"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}
        </div>
        <p className="text-xs text-bifrost-muted mt-3">
          Use * for wildcard matching. Rules are evaluated in order.
        </p>
      </div>
    </div>
  )
}
