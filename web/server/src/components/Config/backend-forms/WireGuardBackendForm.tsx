import { ArrayInput } from '../ArrayInput'

interface WireGuardBackendFormProps {
  config: Record<string, unknown>
  onChange: (config: Record<string, unknown>) => void
}

export function WireGuardBackendForm({ config, onChange }: WireGuardBackendFormProps) {
  const peer = (config.peer as Record<string, unknown>) || {}

  const update = (field: string, value: unknown) => {
    onChange({ ...config, [field]: value })
  }

  const updatePeer = (field: string, value: unknown) => {
    onChange({ ...config, peer: { ...peer, [field]: value } })
  }

  return (
    <div className="space-y-6">
      <p className="text-sm text-bifrost-muted">
        Route traffic through a WireGuard VPN tunnel.
      </p>

      {/* Interface Settings */}
      <div>
        <h4 className="text-sm font-semibold text-white mb-3">Interface</h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-300 mb-1">Private Key</label>
            <textarea
              value={(config.private_key as string) || ''}
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
              value={(config.address as string) || ''}
              onChange={(e) => update('address', e.target.value)}
              placeholder="10.0.0.2/24"
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">MTU</label>
            <input
              type="number"
              value={(config.mtu as number) || ''}
              onChange={(e) => update('mtu', parseInt(e.target.value) || undefined)}
              placeholder="1420"
              className="input"
            />
          </div>
          <div className="md:col-span-2">
            <ArrayInput
              label="DNS Servers"
              values={(config.dns as string[]) || []}
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
              value={(peer.public_key as string) || ''}
              onChange={(e) => updatePeer('public_key', e.target.value)}
              placeholder="Base64-encoded public key"
              className="input font-mono text-xs"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Endpoint</label>
            <input
              type="text"
              value={(peer.endpoint as string) || ''}
              onChange={(e) => updatePeer('endpoint', e.target.value)}
              placeholder="vpn.example.com:51820"
              className="input"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Persistent Keepalive</label>
            <input
              type="number"
              value={(peer.persistent_keepalive as number) || ''}
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
              value={(peer.preshared_key as string) || ''}
              onChange={(e) => updatePeer('preshared_key', e.target.value)}
              placeholder="Optional: base64-encoded preshared key"
              className="input font-mono text-xs"
            />
          </div>
          <div className="md:col-span-2">
            <ArrayInput
              label="Allowed IPs"
              values={(peer.allowed_ips as string[]) || ['0.0.0.0/0']}
              onChange={(ips) => updatePeer('allowed_ips', ips)}
              placeholder="0.0.0.0/0"
            />
          </div>
        </div>
      </div>
    </div>
  )
}
