import { useState, useRef } from 'react'
import { ArrayInput } from '../ArrayInput'
import { WireGuardBackendConfig, WireGuardPeerConfig } from '../../../api/types'

interface WireGuardBackendFormProps {
  config: WireGuardBackendConfig
  onChange: (config: WireGuardBackendConfig) => void
}

// Internal type for parsing WireGuard config files
interface ParsedWireGuardConfig {
  privateKey: string
  address: string[]
  dns: string[]
  mtu?: number
  peer: {
    publicKey: string
    presharedKey?: string
    endpoint: string
    allowedIPs: string[]
    persistentKeepalive?: number
  }
}

// Parse WireGuard config file format
function parseWireGuardConfig(content: string): ParsedWireGuardConfig | null {
  const config: ParsedWireGuardConfig = {
    privateKey: '',
    address: [],
    dns: [],
    peer: {
      publicKey: '',
      endpoint: '',
      allowedIPs: [],
    },
  }

  let currentSection = ''
  const lines = content.split('\n')

  for (const rawLine of lines) {
    const line = rawLine.trim()

    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue

    // Check for section headers
    if (line.startsWith('[') && line.endsWith(']')) {
      currentSection = line.slice(1, -1).toLowerCase()
      continue
    }

    // Parse key = value
    const eqIndex = line.indexOf('=')
    if (eqIndex === -1) continue

    const key = line.slice(0, eqIndex).trim().toLowerCase()
    const value = line.slice(eqIndex + 1).trim()

    if (currentSection === 'interface') {
      switch (key) {
        case 'privatekey':
          config.privateKey = value
          break
        case 'address':
          config.address = value.split(',').map((s) => s.trim())
          break
        case 'dns':
          config.dns = value.split(',').map((s) => s.trim())
          break
        case 'mtu':
          config.mtu = parseInt(value, 10) || undefined
          break
      }
    } else if (currentSection === 'peer') {
      switch (key) {
        case 'publickey':
          config.peer.publicKey = value
          break
        case 'presharedkey':
          config.peer.presharedKey = value
          break
        case 'endpoint':
          config.peer.endpoint = value
          break
        case 'allowedips':
          config.peer.allowedIPs = value.split(',').map((s) => s.trim())
          break
        case 'persistentkeepalive':
          config.peer.persistentKeepalive = parseInt(value, 10) || undefined
          break
      }
    }
  }

  // Validate required fields
  if (!config.privateKey || !config.peer.publicKey) {
    return null
  }

  return config
}

// Helper type for peer with all fields guaranteed
interface PeerWithDefaults {
  public_key: string
  endpoint: string
  allowed_ips: string[]
  preshared_key?: string
  persistent_keepalive?: number
}

// Helper to ensure peer object has required fields with defaults
function ensurePeer(peer: Partial<WireGuardPeerConfig> | undefined): PeerWithDefaults {
  return {
    public_key: peer?.public_key ?? '',
    endpoint: peer?.endpoint ?? '',
    allowed_ips: peer?.allowed_ips ?? [],
    preshared_key: peer?.preshared_key,
    persistent_keepalive: peer?.persistent_keepalive,
  }
}

export function WireGuardBackendForm({ config, onChange }: WireGuardBackendFormProps) {
  const [showImport, setShowImport] = useState(false)
  const [configText, setConfigText] = useState('')
  const [parseError, setParseError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const peer = ensurePeer(config.peer)

  const update = <K extends keyof WireGuardBackendConfig>(field: K, value: WireGuardBackendConfig[K]) => {
    onChange({ ...config, [field]: value })
  }

  const updatePeer = <K extends keyof PeerWithDefaults>(field: K, value: PeerWithDefaults[K]) => {
    onChange({ ...config, peer: { ...peer, [field]: value } })
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result as string
      setConfigText(content)
      applyConfig(content)
    }
    reader.readAsText(file)
  }

  const applyConfig = (content: string) => {
    setParseError(null)
    const parsed = parseWireGuardConfig(content)

    if (!parsed) {
      setParseError('Invalid WireGuard configuration. Make sure it contains [Interface] and [Peer] sections with required fields.')
      return
    }

    // Apply parsed config to form
    onChange({
      ...config,
      private_key: parsed.privateKey,
      address: parsed.address.join(', '),
      dns: parsed.dns,
      mtu: parsed.mtu,
      peer: {
        public_key: parsed.peer.publicKey,
        preshared_key: parsed.peer.presharedKey,
        endpoint: parsed.peer.endpoint,
        allowed_ips: parsed.peer.allowedIPs,
        persistent_keepalive: parsed.peer.persistentKeepalive,
      },
    })

    setShowImport(false)
    setConfigText('')
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-sm text-bifrost-muted">
          Route traffic through a WireGuard VPN tunnel.
        </p>
        <button
          type="button"
          onClick={() => setShowImport(!showImport)}
          className="btn btn-secondary text-sm"
        >
          {showImport ? 'Hide Import' : 'Import Config'}
        </button>
      </div>

      {/* Import Section */}
      {showImport && (
        <div className="bg-bifrost-bg-tertiary rounded-lg p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-semibold text-white">Import WireGuard Configuration</h4>
            <input
              type="file"
              ref={fileInputRef}
              accept=".conf,.txt"
              onChange={handleFileUpload}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="btn btn-secondary text-sm"
            >
              Upload File
            </button>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">
              Or paste your WireGuard config below:
            </label>
            <textarea
              value={configText}
              onChange={(e) => setConfigText(e.target.value)}
              placeholder={`[Interface]
PrivateKey = your_private_key_here
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = server_public_key_here
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0`}
              rows={10}
              className="input font-mono text-xs"
            />
          </div>
          {parseError && (
            <p className="text-sm text-red-400">{parseError}</p>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                setShowImport(false)
                setConfigText('')
                setParseError(null)
              }}
              className="btn btn-secondary text-sm"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => applyConfig(configText)}
              disabled={!configText.trim()}
              className="btn btn-primary text-sm"
            >
              Apply Config
            </button>
          </div>
        </div>
      )}

      {/* Interface Settings */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Interface</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-300 mb-1">Private Key</label>
            <textarea
              value={config.private_key || ''}
              onChange={(e) => update('private_key', e.target.value)}
              placeholder="Base64-encoded private key"
              rows={2}
              className="input font-mono text-xs"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Address</label>
            <input
              type="text"
              value={config.address || ''}
              onChange={(e) => update('address', e.target.value)}
              placeholder="10.0.0.2/24"
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">MTU</label>
            <input
              type="number"
              value={config.mtu ?? ''}
              onChange={(e) => update('mtu', parseInt(e.target.value) || undefined)}
              placeholder="1420"
              className="input"
            />
          </div>
          <div className="md:col-span-2">
            <ArrayInput
              label="DNS Servers"
              values={config.dns ?? []}
              onChange={(dns) => update('dns', dns)}
              placeholder="1.1.1.1"
            />
          </div>
        </div>
      </div>

      {/* Peer Settings */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Peer</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-300 mb-1">Public Key</label>
            <input
              type="text"
              value={peer.public_key || ''}
              onChange={(e) => updatePeer('public_key', e.target.value)}
              placeholder="Base64-encoded public key"
              className="input font-mono text-xs"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Endpoint</label>
            <input
              type="text"
              value={peer.endpoint || ''}
              onChange={(e) => updatePeer('endpoint', e.target.value)}
              placeholder="vpn.example.com:51820"
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Persistent Keepalive</label>
            <input
              type="number"
              value={peer.persistent_keepalive ?? ''}
              onChange={(e) => updatePeer('persistent_keepalive', parseInt(e.target.value) || undefined)}
              placeholder="25"
              className="input"
            />
            <p className="text-xs text-bifrost-muted mt-1">Seconds (0 to disable)</p>
          </div>
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-300 mb-1">Preshared Key</label>
            <input
              type="text"
              value={peer.preshared_key || ''}
              onChange={(e) => updatePeer('preshared_key', e.target.value)}
              placeholder="Optional: base64-encoded preshared key"
              className="input font-mono text-xs"
            />
          </div>
          <div className="md:col-span-2">
            <ArrayInput
              label="Allowed IPs"
              values={peer.allowed_ips?.length ? peer.allowed_ips : ['0.0.0.0/0']}
              onChange={(ips) => updatePeer('allowed_ips', ips)}
              placeholder="0.0.0.0/0"
            />
          </div>
        </div>
      </div>
    </div>
  )
}
