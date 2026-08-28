import { useEffect, useState } from 'react'
import * as yaml from 'js-yaml'

// This form emits the client's real schema (internal/config/client.go):
// `server.address/protocol/username/password`, `proxy.http.listen` /
// `proxy.socks5.listen`, and `routes[].domains` (a list) with action
// `server` | `direct`. An earlier version invented `local.*`,
// `routes[].pattern` and `action: proxy` — output that failed
// `bifrost-client validate` as written.

interface GeneratorRoute {
  /** Comma-separated domain patterns; emitted as the `domains` list. */
  domains: string
  action: 'server' | 'direct'
}

interface GeneratorState {
  serverAddress: string
  serverProtocol: 'http' | 'socks5'
  useAuth: boolean
  username: string
  password: string
  httpListen: string
  socks5Listen: string
  routes: GeneratorRoute[]
}

interface GeneratorFormProps {
  onConfigChange: (yaml: string) => void
}

const DEFAULT_STATE: GeneratorState = {
  serverAddress: 'proxy.example.com:7080',
  serverProtocol: 'http',
  useAuth: false,
  username: '',
  password: '',
  httpListen: '127.0.0.1:7380',
  socks5Listen: '127.0.0.1:7381',
  routes: [
    { domains: '*.local, localhost', action: 'direct' },
    { domains: '*', action: 'server' },
  ],
}

function parseDomains(text: string): string[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

function buildYaml(state: GeneratorState): string {
  const server: Record<string, unknown> = {
    address: state.serverAddress,
    protocol: state.serverProtocol,
  }
  if (state.useAuth && state.username) {
    server.username = state.username
    server.password = state.password || ''
  }

  const doc: Record<string, unknown> = {
    server,
    proxy: {
      http: { listen: state.httpListen },
      socks5: { listen: state.socks5Listen },
    },
    routes: state.routes
      .map((r) => ({ domains: parseDomains(r.domains), action: r.action }))
      .filter((r) => r.domains.length > 0),
    logging: { level: 'info', format: 'text' },
  }

  return yaml.dump(doc, { indent: 2, lineWidth: -1 })
}

export function GeneratorForm({ onConfigChange }: GeneratorFormProps) {
  const [state, setState] = useState<GeneratorState>(DEFAULT_STATE)

  // Regenerate from the committed state, never from a stale closure: the
  // auth toggle previously read the pre-toggle value and only took effect
  // on the next keystroke.
  useEffect(() => {
    onConfigChange(buildYaml(state))
  }, [state, onConfigChange])

  const update = (updates: Partial<GeneratorState>) => {
    setState((prev) => ({ ...prev, ...updates }))
  }

  const updateRoute = (index: number, updates: Partial<GeneratorRoute>) => {
    setState((prev) => ({
      ...prev,
      routes: prev.routes.map((r, i) => (i === index ? { ...r, ...updates } : r)),
    }))
  }

  const addRoute = () => {
    setState((prev) => ({ ...prev, routes: [...prev.routes, { domains: '', action: 'server' }] }))
  }

  const removeRoute = (index: number) => {
    setState((prev) => ({ ...prev, routes: prev.routes.filter((_, i) => i !== index) }))
  }

  return (
    <div className="space-y-6">
      {/* Server Connection */}
      <div className="card">
        <h3 className="text-lg font-semibold text-bifrost-heading mb-4">Server Connection</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="label" htmlFor="gen-server-address">Server Address</label>
            <input
              id="gen-server-address"
              type="text"
              className="input"
              value={state.serverAddress}
              onChange={(e) => update({ serverAddress: e.target.value })}
              placeholder="proxy.example.com:7080"
            />
            <p className="text-xs text-bifrost-muted mt-1">
              The address of your Bifrost server
            </p>
          </div>
          <div>
            <label className="label" htmlFor="gen-server-protocol">Protocol</label>
            <select
              id="gen-server-protocol"
              className="select"
              value={state.serverProtocol}
              onChange={(e) => update({ serverProtocol: e.target.value as 'http' | 'socks5' })}
            >
              <option value="http">HTTP Proxy</option>
              <option value="socks5">SOCKS5</option>
            </select>
          </div>
        </div>
      </div>

      {/* Local Proxy Settings */}
      <div className="card">
        <h3 className="text-lg font-semibold text-bifrost-heading mb-4">Local Proxy Listeners</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="label" htmlFor="gen-http-listen">HTTP Listen Address</label>
            <input
              id="gen-http-listen"
              type="text"
              className="input"
              value={state.httpListen}
              onChange={(e) => update({ httpListen: e.target.value })}
              placeholder="127.0.0.1:7380"
            />
          </div>
          <div>
            <label className="label" htmlFor="gen-socks5-listen">SOCKS5 Listen Address</label>
            <input
              id="gen-socks5-listen"
              type="text"
              className="input"
              value={state.socks5Listen}
              onChange={(e) => update({ socks5Listen: e.target.value })}
              placeholder="127.0.0.1:7381"
            />
          </div>
        </div>
      </div>

      {/* Authentication */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-bifrost-heading">Authentication</h3>
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={state.useAuth}
              onChange={(e) => update({ useAuth: e.target.checked })}
              className="rounded border-bifrost-border bg-bifrost-bg"
            />
            <span className="text-sm text-bifrost-text">Enable</span>
          </label>
        </div>
        {state.useAuth && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="label" htmlFor="gen-username">Username</label>
              <input
                id="gen-username"
                type="text"
                className="input"
                value={state.username}
                onChange={(e) => update({ username: e.target.value })}
                placeholder="username"
              />
            </div>
            <div>
              <label className="label" htmlFor="gen-password">Password</label>
              <input
                id="gen-password"
                type="password"
                className="input"
                autoComplete="current-password"
                value={state.password}
                onChange={(e) => update({ password: e.target.value })}
                placeholder="password"
              />
            </div>
          </div>
        )}
      </div>

      {/* Routes */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-bifrost-heading">Routes</h3>
          <button onClick={addRoute} className="btn btn-secondary text-sm">
            Add Route
          </button>
        </div>
        <p className="text-xs text-bifrost-muted mb-3">
          Domain patterns are matched top to bottom. <code className="font-mono">server</code> sends the
          traffic through the Bifrost server, <code className="font-mono">direct</code> bypasses it.
        </p>
        <div className="space-y-2">
          {state.routes.map((route, i) => (
            <div key={i} className="grid grid-cols-[2fr_1fr_auto] gap-2 items-center">
              <input
                type="text"
                className="input"
                value={route.domains}
                onChange={(e) => updateRoute(i, { domains: e.target.value })}
                placeholder="*.example.com, example.com"
                aria-label={`Route ${i + 1} domain patterns`}
              />
              <select
                className="select"
                value={route.action}
                onChange={(e) => updateRoute(i, { action: e.target.value as 'server' | 'direct' })}
                aria-label={`Route ${i + 1} action`}
              >
                <option value="server">Via Server</option>
                <option value="direct">Direct</option>
              </select>
              <button
                onClick={() => removeRoute(i)}
                className="btn btn-secondary text-bifrost-error"
                aria-label={`Remove route ${i + 1}`}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
