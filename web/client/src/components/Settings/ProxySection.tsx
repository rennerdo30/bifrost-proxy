import {
  FormInput,
  FormNumber,
  FormDuration,
  ConfigSection,
} from '../form'
import { ProxyIcon } from '../icons'
import { useSettings } from './SettingsContext'
import type { ListenerConfig } from '../../api/client'

export function ProxySection() {
  const { getValue, updateField } = useSettings()

  const httpProxy = getValue('proxy', 'http', {}) as ListenerConfig
  const socks5Proxy = getValue('proxy', 'socks5', {}) as ListenerConfig

  return (
    <ConfigSection
      title="Local Proxy"
      icon={<ProxyIcon />}
      description="Local ports that apps on this device connect to"
      restartRequired
    >
      <div className="space-y-6">
        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">HTTP Proxy</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormInput
              label="Listen Address"
              placeholder="127.0.0.1:3128"
              value={httpProxy.listen || ''}
              onChange={(v) => updateField('proxy', 'http', { ...httpProxy, listen: v })}
            />
            <FormDuration
              label="Read Timeout"
              value={httpProxy.read_timeout || '30s'}
              onChange={(v) => updateField('proxy', 'http', { ...httpProxy, read_timeout: v })}
            />
            <FormDuration
              label="Write Timeout"
              value={httpProxy.write_timeout || '30s'}
              onChange={(v) => updateField('proxy', 'http', { ...httpProxy, write_timeout: v })}
            />
            <FormDuration
              label="Idle Timeout"
              value={httpProxy.idle_timeout || '60s'}
              onChange={(v) => updateField('proxy', 'http', { ...httpProxy, idle_timeout: v })}
            />
          </div>
        </div>
        <div>
          <h4 className="text-sm font-medium text-bifrost-text mb-3">SOCKS5 Proxy</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormInput
              label="Listen Address"
              placeholder="127.0.0.1:1081"
              value={socks5Proxy.listen || ''}
              onChange={(v) => updateField('proxy', 'socks5', { ...socks5Proxy, listen: v })}
            />
            <FormDuration
              label="Read Timeout"
              value={socks5Proxy.read_timeout || '30s'}
              onChange={(v) => updateField('proxy', 'socks5', { ...socks5Proxy, read_timeout: v })}
            />
            <FormNumber
              label="Max Connections"
              value={socks5Proxy.max_connections || 0}
              onChange={(v) => updateField('proxy', 'socks5', { ...socks5Proxy, max_connections: v })}
              min={0}
            />
          </div>
        </div>
      </div>
    </ConfigSection>
  )
}
