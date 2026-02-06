import {
  FormInput,
  FormNumber,
  FormSelect,
  FormToggle,
  FormDuration,
  FormTagInput,
  ConfigSection,
} from '../form'
import { VPNIcon } from '../icons'
import { useSettings } from './SettingsContext'
import { validateDomain, validateIP, validateDomainOrIP } from '../../utils/validation'
import type { TunConfig, DNSSettings } from '../../api/client'

export function VPNSection() {
  const { getValue, getNestedValue, updateField, updateNestedField } = useSettings()

  const tunConfig = getValue('vpn', 'tun', {}) as TunConfig
  const vpnDns = getValue('vpn', 'dns', {}) as DNSSettings

  return (
    <ConfigSection
      title="VPN Mode"
      icon={<VPNIcon />}
      description="TUN device and split tunneling"
      restartRequired
      defaultOpen={false}
    >
      <div className="space-y-6">
        <FormToggle
          label="Enable VPN Mode"
          description="Route traffic through TUN device"
          checked={getValue('vpn', 'enabled', false) as boolean}
          onChange={(v) => updateField('vpn', 'enabled', v)}
        />

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">TUN Device</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <FormInput
              label="Device Name"
              placeholder="bifrost0"
              value={tunConfig.name || ''}
              onChange={(v) => updateField('vpn', 'tun', { ...tunConfig, name: v })}
            />
            <FormInput
              label="Address"
              placeholder="10.255.0.2/24"
              value={tunConfig.address || ''}
              onChange={(v) => updateField('vpn', 'tun', { ...tunConfig, address: v })}
            />
            <FormNumber
              label="MTU"
              value={tunConfig.mtu || 1500}
              onChange={(v) => updateField('vpn', 'tun', { ...tunConfig, mtu: v })}
              min={576}
              max={9000}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">Split Tunnel</h4>
          <div className="space-y-4">
            <FormSelect
              label="Mode"
              value={getNestedValue('vpn', ['split_tunnel', 'mode'], 'exclude') as string}
              onChange={(v) => updateNestedField('vpn', ['split_tunnel', 'mode'], v)}
              options={[
                { value: 'exclude', label: 'Exclude (bypass specified)' },
                { value: 'include', label: 'Include (only specified)' },
              ]}
            />
            <FormTagInput
              label="Split Tunnel Domains"
              description="Domains to include/exclude based on mode"
              value={getNestedValue('vpn', ['split_tunnel', 'domains'], []) as string[]}
              onChange={(v) => updateNestedField('vpn', ['split_tunnel', 'domains'], v)}
              placeholder="e.g., internal.example.com"
              validate={validateDomain}
            />
            <FormTagInput
              label="Split Tunnel IPs"
              description="IPs/CIDRs to include/exclude based on mode"
              value={getNestedValue('vpn', ['split_tunnel', 'ips'], []) as string[]}
              onChange={(v) => updateNestedField('vpn', ['split_tunnel', 'ips'], v)}
              placeholder="e.g., 10.0.0.0/8"
              validate={validateIP}
            />
            <FormTagInput
              label="Always Bypass"
              description="Destinations that ALWAYS bypass VPN (regardless of mode)"
              value={getNestedValue('vpn', ['split_tunnel', 'always_bypass'], []) as string[]}
              onChange={(v) => updateNestedField('vpn', ['split_tunnel', 'always_bypass'], v)}
              placeholder="e.g., 8.8.8.8"
              validate={validateDomainOrIP}
            />
          </div>
        </div>

        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">DNS</h4>
          <div className="space-y-4">
            <FormToggle
              label="Enable DNS Interception"
              checked={vpnDns.enabled !== false}
              onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, enabled: v })}
            />
            <FormTagInput
              label="Upstream DNS Servers"
              value={vpnDns.upstream || []}
              onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, upstream: v })}
              placeholder="e.g., 8.8.8.8"
            />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormInput
                label="Listen Address"
                placeholder="10.255.0.1:53"
                value={vpnDns.listen || ''}
                onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, listen: v })}
              />
              <FormDuration
                label="Cache TTL"
                value={vpnDns.cache_ttl || '5m'}
                onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, cache_ttl: v })}
              />
              <FormSelect
                label="Intercept Mode"
                value={vpnDns.intercept_mode || 'all'}
                onChange={(v) => updateField('vpn', 'dns', { ...vpnDns, intercept_mode: v })}
                options={[
                  { value: 'all', label: 'All Queries' },
                  { value: 'tunnel_only', label: 'Tunnel Only' },
                ]}
              />
            </div>
          </div>
        </div>
      </div>
    </ConfigSection>
  )
}
