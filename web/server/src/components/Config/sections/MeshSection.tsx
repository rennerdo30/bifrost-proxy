import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
import type {
  MeshConfig,
  MeshConnectionConfig,
  MeshDeviceConfig,
  MeshDiscoveryConfig,
  MeshSecurityConfig,
  MeshSTUNConfig,
  MeshTURNServer,
} from '../../../api/types'

interface MeshSectionProps {
  config?: MeshConfig
  onChange: (config: MeshConfig) => void
}

const NS_PER_SECOND = 1_000_000_000

// Mesh durations are Go time.Duration values: integer nanoseconds in JSON.
// The form edits them in seconds.
function nsToSeconds(ns: number | undefined, fallback: number): number {
  if (ns === undefined || ns === null) return fallback
  return Math.round(ns / NS_PER_SECOND)
}

function secondsToNs(seconds: number): number {
  return Math.max(0, Math.round(seconds)) * NS_PER_SECOND
}

function toCommaList(value: string[] | undefined): string {
  return (value || []).join(', ')
}

function parseCommaList(text: string): string[] {
  return text
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
}

export function MeshSection({ config, onChange }: MeshSectionProps) {
  const cfg: MeshConfig = config ?? { enabled: false }

  const update = (field: keyof MeshConfig, value: unknown) => {
    onChange({ ...cfg, [field]: value })
  }

  const updateDevice = (field: keyof MeshDeviceConfig, value: unknown) => {
    onChange({ ...cfg, device: { ...(cfg.device || {}), [field]: value } })
  }

  const updateDiscovery = (field: keyof MeshDiscoveryConfig, value: unknown) => {
    onChange({ ...cfg, discovery: { ...(cfg.discovery || {}), [field]: value } })
  }

  const updateSTUN = (field: keyof MeshSTUNConfig, value: unknown) => {
    onChange({ ...cfg, stun: { ...(cfg.stun || {}), [field]: value } })
  }

  const updateConnection = (field: keyof MeshConnectionConfig, value: unknown) => {
    onChange({ ...cfg, connection: { ...(cfg.connection || {}), [field]: value } })
  }

  const updateSecurity = (field: keyof MeshSecurityConfig, value: unknown) => {
    onChange({ ...cfg, security: { ...(cfg.security || {}), [field]: value } })
  }

  const turnServers = cfg.turn?.servers || []

  const updateTURNServer = (index: number, field: keyof MeshTURNServer, value: string) => {
    const next = turnServers.map((server, i) =>
      i === index ? { ...server, [field]: value } : server
    )
    onChange({ ...cfg, turn: { ...(cfg.turn || {}), servers: next } })
  }

  const addTURNServer = () => {
    onChange({ ...cfg, turn: { ...(cfg.turn || {}), servers: [...turnServers, { url: '' }] } })
  }

  const removeTURNServer = (index: number) => {
    onChange({
      ...cfg,
      turn: { ...(cfg.turn || {}), servers: turnServers.filter((_, i) => i !== index) },
    })
  }

  return (
    <Section
      sectionKey="mesh"
      title="Mesh Networking"
      description="P2P mesh coordinator and peer settings"
    >
      <div className="space-y-4">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={cfg.enabled}
            onChange={(e) => update('enabled', e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-bifrost-text">Enable Mesh Networking</span>
        </label>

        {cfg.enabled && (
          <div className="space-y-6 pl-7">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ValidatedInput
                label="Network ID"
                value={cfg.network_id || ''}
                onChange={(e) => update('network_id', e.target.value)}
                placeholder="my-mesh"
                helpText="Identifier of the mesh network to join"
              />
              <ValidatedInput
                label="Network CIDR"
                value={cfg.network_cidr || ''}
                onChange={(e) => update('network_cidr', e.target.value)}
                placeholder="10.42.0.0/16"
                helpText="Virtual IP range for mesh peers"
              />
              <ValidatedInput
                label="Peer Name"
                value={cfg.peer_name || ''}
                onChange={(e) => update('peer_name', e.target.value)}
                placeholder="hostname"
                helpText="How this peer identifies itself (defaults to the hostname)"
              />
            </div>

            <div>
              <h4 className="text-sm font-medium text-bifrost-heading mb-3">Device</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <ValidatedSelect
                  label="Type"
                  value={cfg.device?.type || 'tun'}
                  onChange={(e) => updateDevice('type', e.target.value)}
                >
                  <option value="tun">TUN (layer 3)</option>
                  <option value="tap">TAP (layer 2)</option>
                </ValidatedSelect>
                <ValidatedInput
                  label="Interface Name"
                  value={cfg.device?.name || ''}
                  onChange={(e) => updateDevice('name', e.target.value)}
                  placeholder="bifrost-mesh"
                />
                <ValidatedInput
                  label="MTU"
                  type="number"
                  value={cfg.device?.mtu ?? 1400}
                  onChange={(e) => updateDevice('mtu', parseInt(e.target.value) || 0)}
                />
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-bifrost-heading mb-3">Discovery</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <ValidatedInput
                  label="Coordinator Server"
                  value={cfg.discovery?.server || ''}
                  onChange={(e) => updateDiscovery('server', e.target.value)}
                  placeholder="wss://coordinator.example.com"
                />
                <ValidatedInput
                  label="Discovery Token"
                  type="password"
                  value={cfg.discovery?.token || ''}
                  onChange={(e) => updateDiscovery('token', e.target.value)}
                  placeholder="Optional"
                  helpText="Shared secret the coordinator requires to join"
                />
                <ValidatedInput
                  label="Heartbeat Interval (seconds)"
                  type="number"
                  value={nsToSeconds(cfg.discovery?.heartbeat_interval, 30)}
                  onChange={(e) =>
                    updateDiscovery('heartbeat_interval', secondsToNs(parseInt(e.target.value) || 0))
                  }
                />
                <ValidatedInput
                  label="Peer Timeout (seconds)"
                  type="number"
                  value={nsToSeconds(cfg.discovery?.peer_timeout, 90)}
                  onChange={(e) =>
                    updateDiscovery('peer_timeout', secondsToNs(parseInt(e.target.value) || 0))
                  }
                />
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-bifrost-heading mb-3">NAT Traversal</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <ValidatedInput
                  label="STUN Servers"
                  value={toCommaList(cfg.stun?.servers)}
                  onChange={(e) => updateSTUN('servers', parseCommaList(e.target.value))}
                  placeholder="stun.l.google.com:19302"
                  helpText="Comma-separated host:port list"
                />
                <ValidatedInput
                  label="STUN Timeout (seconds)"
                  type="number"
                  value={nsToSeconds(cfg.stun?.timeout, 5)}
                  onChange={(e) => updateSTUN('timeout', secondsToNs(parseInt(e.target.value) || 0))}
                />
              </div>

              <div className="mt-4 space-y-3">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cfg.turn?.enabled === true}
                    onChange={(e) => onChange({ ...cfg, turn: { ...(cfg.turn || {}), enabled: e.target.checked } })}
                    className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                  />
                  <span className="text-sm text-bifrost-text">Enable TURN relay fallback</span>
                </label>

                {cfg.turn?.enabled && (
                  <div className="space-y-2 pl-7">
                    {turnServers.map((server, i) => (
                      <div key={i} className="grid grid-cols-1 md:grid-cols-[2fr_1fr_1fr_auto] gap-2 items-end">
                        <ValidatedInput
                          label={i === 0 ? 'TURN URL' : ''}
                          value={server.url}
                          onChange={(e) => updateTURNServer(i, 'url', e.target.value)}
                          placeholder="turn:turn.example.com:3478"
                        />
                        <ValidatedInput
                          label={i === 0 ? 'Username' : ''}
                          value={server.username || ''}
                          onChange={(e) => updateTURNServer(i, 'username', e.target.value)}
                          placeholder="Optional"
                        />
                        <ValidatedInput
                          label={i === 0 ? 'Password' : ''}
                          type="password"
                          value={server.password || ''}
                          onChange={(e) => updateTURNServer(i, 'password', e.target.value)}
                          placeholder="Optional"
                        />
                        <button
                          type="button"
                          onClick={() => removeTURNServer(i)}
                          aria-label={`Remove TURN server ${server.url || i + 1}`}
                          className="btn btn-secondary text-bifrost-error mb-0.5"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                    <button type="button" onClick={addTURNServer} className="btn btn-secondary text-sm">
                      Add TURN Server
                    </button>
                  </div>
                )}
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-bifrost-heading mb-3">Connections</h4>
              <div className="space-y-3">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cfg.connection?.direct_connect !== false}
                    onChange={(e) => updateConnection('direct_connect', e.target.checked)}
                    className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                  />
                  <span className="text-sm text-bifrost-text">Attempt direct P2P connections</span>
                </label>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cfg.connection?.relay_enabled === true}
                    onChange={(e) => updateConnection('relay_enabled', e.target.checked)}
                    className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                  />
                  <span className="text-sm text-bifrost-text">Fall back to TURN relays</span>
                </label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <ValidatedInput
                    label="Connect Timeout (seconds)"
                    type="number"
                    value={nsToSeconds(cfg.connection?.connect_timeout, 30)}
                    onChange={(e) =>
                      updateConnection('connect_timeout', secondsToNs(parseInt(e.target.value) || 0))
                    }
                  />
                  <ValidatedInput
                    label="Keep-Alive Interval (seconds)"
                    type="number"
                    value={nsToSeconds(cfg.connection?.keep_alive_interval, 25)}
                    onChange={(e) =>
                      updateConnection('keep_alive_interval', secondsToNs(parseInt(e.target.value) || 0))
                    }
                  />
                </div>
              </div>
            </div>

            <div>
              <h4 className="text-sm font-medium text-bifrost-heading mb-3">Security</h4>
              <div className="space-y-3">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cfg.security?.require_encryption !== false}
                    onChange={(e) => updateSecurity('require_encryption', e.target.checked)}
                    className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                  />
                  <span className="text-sm text-bifrost-text">Require encrypted peer connections</span>
                </label>
                <ValidatedInput
                  label="Allowed Peers"
                  value={toCommaList(cfg.security?.allowed_peers)}
                  onChange={(e) => updateSecurity('allowed_peers', parseCommaList(e.target.value))}
                  placeholder="Optional, comma-separated peer IDs"
                  helpText="Empty allows any peer the coordinator admits"
                />
              </div>
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
