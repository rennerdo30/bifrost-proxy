import {
  FormInput,
  FormNumber,
  FormSelect,
  FormToggle,
  FormDuration,
  FormTagInput,
  ConfigSection,
} from '../form'
import { MeshIcon } from '../icons'
import { useSettings } from './SettingsContext'
import type { MeshDeviceConfig, MeshDiscoveryConfig, STUNConfig, MeshConnectionConfig, MeshSecurityConfig } from '../../api/client'

export function MeshSection() {
  const { getValue, updateField } = useSettings()

  const meshDevice = getValue('mesh', 'device', {}) as MeshDeviceConfig
  const meshDiscovery = getValue('mesh', 'discovery', {}) as MeshDiscoveryConfig
  const meshStun = getValue('mesh', 'stun', {}) as STUNConfig
  const meshConnection = getValue('mesh', 'connection', {}) as MeshConnectionConfig
  const meshSecurity = getValue('mesh', 'security', {}) as MeshSecurityConfig

  return (
    <ConfigSection
      title="Mesh Networking"
      icon={<MeshIcon />}
      description="P2P mesh network settings (Advanced)"
      restartRequired
      defaultOpen={false}
    >
      <div className="space-y-6">
        <FormToggle
          label="Enable Mesh Networking"
          description="Connect to other Bifrost peers directly"
          checked={getValue('mesh', 'enabled', false) as boolean}
          onChange={(v) => updateField('mesh', 'enabled', v)}
        />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormInput
            label="Network ID"
            description="Unique identifier for your mesh network"
            placeholder="my-mesh-network"
            value={getValue('mesh', 'network_id', '') as string}
            onChange={(v) => updateField('mesh', 'network_id', v)}
          />
          <FormInput
            label="Network CIDR"
            description="IP range for mesh network"
            placeholder="10.254.0.0/16"
            value={getValue('mesh', 'network_cidr', '') as string}
            onChange={(v) => updateField('mesh', 'network_cidr', v)}
          />
          <FormInput
            label="Peer Name"
            description="This device's name in the mesh"
            placeholder="my-device"
            value={getValue('mesh', 'peer_name', '') as string}
            onChange={(v) => updateField('mesh', 'peer_name', v)}
          />
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Discovery</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormInput
              label="Discovery Server"
              placeholder="https://discovery.bifrost.com"
              value={meshDiscovery.server || ''}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, server: v })}
            />
            <FormInput
              label="Discovery Token"
              placeholder="Optional"
              type="password"
              autoComplete="off"
              value={meshDiscovery.token || ''}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, token: v })}
            />
            <FormDuration
              label="Heartbeat Interval"
              value={meshDiscovery.heartbeat_interval || '30s'}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, heartbeat_interval: v })}
            />
            <FormDuration
              label="Peer Timeout"
              value={meshDiscovery.peer_timeout || '120s'}
              onChange={(v) => updateField('mesh', 'discovery', { ...meshDiscovery, peer_timeout: v })}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Common Settings</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormToggle
              label="Require Encryption"
              checked={meshSecurity.require_encryption !== false}
              onChange={(v) => updateField('mesh', 'security', { ...meshSecurity, require_encryption: v })}
            />
            <FormSelect
              label="Device Type"
              value={meshDevice.type || 'tun'}
              onChange={(v) => updateField('mesh', 'device', { ...meshDevice, type: v })}
              options={[
                { value: 'tun', label: 'TUN' },
                { value: 'tap', label: 'TAP' },
              ]}
            />
            <FormNumber
              label="Device MTU"
              value={meshDevice.mtu || 1350}
              onChange={(v) => updateField('mesh', 'device', { ...meshDevice, mtu: v })}
              min={576}
              max={9000}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Connection</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormToggle
              label="Allow Relay"
              checked={meshConnection.relay_enabled !== false}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, relay_enabled: v })}
            />
            <FormToggle
              label="Direct Connect"
              checked={meshConnection.direct_connect !== false}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, direct_connect: v })}
            />
            <FormDuration
              label="Keepalive"
              value={meshConnection.keepalive_interval || '15s'}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, keepalive_interval: v })}
            />
            <FormDuration
              label="Connect Timeout"
              value={meshConnection.connect_timeout || '10s'}
              onChange={(v) => updateField('mesh', 'connection', { ...meshConnection, connect_timeout: v })}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">STUN Servers</h4>
          <FormTagInput
            label="STUN Server URLs"
            description="STUN servers for NAT traversal"
            value={meshStun.servers || []}
            onChange={(v) => updateField('mesh', 'stun', { ...meshStun, servers: v })}
            placeholder="e.g., stun:stun.l.google.com:19302"
          />
        </div>
      </div>
    </ConfigSection>
  )
}
