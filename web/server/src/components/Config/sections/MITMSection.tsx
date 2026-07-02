import { Section } from '../Section'
import { ValidatedInput } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { MITMConfig } from '../../../api/types'

interface MITMSectionProps {
  config?: MITMConfig
  onChange: (config: MITMConfig | undefined) => void
}

type MITMValidationKeys = {
  ca_cert_file: string
  ca_key_file: string
  leaf_ttl: string
  max_cached_certs: number
}

export function MITMSection({ config, onChange }: MITMSectionProps) {
  const enabled = config?.enabled ?? false

  const { errors, handleFieldChange, clearErrors } = useValidation<MITMValidationKeys>({
    ca_cert_file: [validators.filePath()],
    ca_key_file: [validators.filePath()],
    leaf_ttl: [validators.duration()],
    max_cached_certs: [validators.positiveInteger()],
  })

  const toggleEnabled = (enable: boolean) => {
    clearErrors()
    if (enable) {
      onChange({ ...(config || {}), enabled: true })
    } else {
      // Preserve any entered paths but mark disabled so the server fails
      // closed (interception off) unless explicitly re-enabled.
      onChange({ ...(config || {}), enabled: false })
    }
  }

  const update = (field: keyof MITMConfig, value: unknown) => {
    if (field === 'ca_cert_file' || field === 'ca_key_file' || field === 'leaf_ttl' || field === 'max_cached_certs') {
      handleFieldChange(field as keyof MITMValidationKeys, value as never)
    }
    onChange({ ...(config || { enabled: true }), enabled: true, [field]: value })
  }

  return (
    <Section
      title="HTTPS Interception (MITM)"
      badge="restart-required"
      description="Opt-in TLS interception for traffic debugging"
    >
      <div className="space-y-4">
        <div className="p-3 bg-bifrost-warning/10 border border-bifrost-warning/30 rounded-lg text-sm text-bifrost-warning">
          <strong>Security warning:</strong> when enabled, the proxy decrypts TLS
          traffic by minting leaf certificates signed by the configured CA. The
          CA private key can impersonate any site to trusting clients. Use only
          in controlled debugging environments with a dedicated throwaway CA;
          never reuse a production CA.
        </div>

        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => toggleEnabled(e.target.checked)}
            className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
          />
          <span className="text-sm font-medium text-gray-300">Enable HTTPS Interception</span>
        </label>

        {enabled && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <ValidatedInput
              label="CA Certificate File"
              value={config?.ca_cert_file || ''}
              onChange={(e) => update('ca_cert_file', e.target.value)}
              placeholder="/etc/bifrost/mitm-ca.pem"
              error={errors.ca_cert_file}
              helpText="Required when enabled"
            />
            <ValidatedInput
              label="CA Key File"
              value={config?.ca_key_file || ''}
              onChange={(e) => update('ca_key_file', e.target.value)}
              placeholder="/etc/bifrost/mitm-ca-key.pem"
              error={errors.ca_key_file}
              helpText="Required when enabled"
            />
            <ValidatedInput
              label="Leaf Certificate TTL"
              value={config?.leaf_ttl || ''}
              onChange={(e) => update('leaf_ttl', e.target.value)}
              placeholder="24h"
              error={errors.leaf_ttl}
              helpText="Validity period of minted leaf certs (empty = 24h)"
            />
            <ValidatedInput
              label="Max Cached Certs"
              type="number"
              value={config?.max_cached_certs ?? 0}
              onChange={(e) => update('max_cached_certs', parseInt(e.target.value) || 0)}
              placeholder="0 (default)"
              error={errors.max_cached_certs}
              helpText="In-memory leaf certificate cache size"
            />
          </div>
        )}
      </div>
    </Section>
  )
}
