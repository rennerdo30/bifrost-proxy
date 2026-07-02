import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { NetworkConfig } from '../../../api/types'

interface NetworkSectionProps {
  config?: NetworkConfig
  onChange: (config: NetworkConfig | undefined) => void
}

type NetworkValidationKeys = {
  keepalive: string
  dial_timeout: string
  max_connections: number
}

// Address-family select value derived from the tri-state ipv6 pointer:
//   undefined / null / true -> dual-stack (default)
//   false                   -> IPv4 only
function familyValue(ipv6: NetworkConfig['ipv6']): 'dual' | 'ipv4' {
  return ipv6 === false ? 'ipv4' : 'dual'
}

export function NetworkSection({ config, onChange }: NetworkSectionProps) {
  const cfg = config ?? {}

  const { errors, handleFieldChange } = useValidation<NetworkValidationKeys>({
    keepalive: [validators.duration()],
    dial_timeout: [validators.duration()],
    max_connections: [validators.positiveInteger()],
  })

  const update = (field: keyof NetworkConfig, value: unknown) => {
    if (field === 'keepalive' || field === 'dial_timeout' || field === 'max_connections') {
      handleFieldChange(field as keyof NetworkValidationKeys, value as never)
    }
    onChange({ ...cfg, [field]: value })
  }

  return (
    <Section
      title="Network"
      badge="restart-required"
      description="Outbound dial tuning applied to backend connections"
    >
      <div className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <ValidatedSelect
            label="Address Family"
            value={familyValue(cfg.ipv6)}
            onChange={(e) =>
              // Dual-stack is the historical default and is represented by
              // leaving ipv6 unset (undefined); only IPv4-only sets it false.
              update('ipv6', e.target.value === 'ipv4' ? false : undefined)
            }
            helpText="Dual-stack is the default; IPv4 only restricts outbound dials"
          >
            <option value="dual">Dual-stack (default)</option>
            <option value="ipv4">IPv4 only</option>
          </ValidatedSelect>

          <label className="flex items-center gap-3 cursor-pointer mt-7">
            <input
              type="checkbox"
              checked={cfg.prefer_ipv6 ?? false}
              onChange={(e) => update('prefer_ipv6', e.target.checked)}
              className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
            />
            <span className="text-sm font-medium text-gray-300">Prefer IPv6</span>
          </label>

          <ValidatedInput
            label="Keep-Alive"
            value={cfg.keepalive || ''}
            onChange={(e) => update('keepalive', e.target.value)}
            placeholder="30s"
            error={errors.keepalive}
            helpText="TCP keep-alive period for outbound dials (empty = Go default)"
          />
          <ValidatedInput
            label="Dial Timeout"
            value={cfg.dial_timeout || ''}
            onChange={(e) => update('dial_timeout', e.target.value)}
            placeholder="10s"
            error={errors.dial_timeout}
            helpText="Default outbound connection timeout"
          />
          <ValidatedInput
            label="Max Connections"
            type="number"
            value={cfg.max_connections ?? 0}
            onChange={(e) => update('max_connections', parseInt(e.target.value) || 0)}
            placeholder="0 (unlimited)"
            error={errors.max_connections}
            helpText="Process-wide ceiling on concurrent proxied connections"
          />
        </div>
      </div>
    </Section>
  )
}
