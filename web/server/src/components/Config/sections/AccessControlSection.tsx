import { Section } from '../Section'
import { ArrayInput } from '../ArrayInput'
import type { AccessControlConfig } from '../../../api/types'

interface AccessControlSectionProps {
  config: AccessControlConfig
  onChange: (config: AccessControlConfig) => void
}

export function AccessControlSection({ config, onChange }: AccessControlSectionProps) {
  const hasWhitelist = config.whitelist.length > 0
  const hasBlacklist = config.blacklist.length > 0
  const hasBothWarning = hasWhitelist && hasBlacklist

  return (
    <Section
      title="Access Control"
      badge="hot-reload"
      id="section-access-control"
      description="IP-based whitelist and blacklist for connection filtering"
    >
      <div className="space-y-6">
        {hasBothWarning && (
          <div className="p-3 bg-bifrost-warning/10 border border-bifrost-warning/30 rounded-lg">
            <div className="flex items-start gap-2">
              <svg className="w-5 h-5 text-bifrost-warning mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <p className="text-sm text-bifrost-warning">
                Both whitelist and blacklist are configured. When both are set, only whitelisted IPs are allowed, and blacklisted IPs within the whitelist are denied.
              </p>
            </div>
          </div>
        )}

        <div>
          <div className="flex items-center gap-2 mb-2">
            <h4 className="text-sm font-medium text-gray-300">IP Whitelist</h4>
            {hasWhitelist && (
              <span className="badge badge-success text-xs">{config.whitelist.length} entries</span>
            )}
          </div>
          <p className="text-xs text-bifrost-muted mb-3">
            Only allow connections from these IPs. Leave empty to allow all.
          </p>
          <ArrayInput
            values={config.whitelist}
            onChange={(whitelist) => onChange({ ...config, whitelist })}
            placeholder="e.g., 192.168.1.0/24 or 10.0.0.1"
          />
        </div>

        <div>
          <div className="flex items-center gap-2 mb-2">
            <h4 className="text-sm font-medium text-gray-300">IP Blacklist</h4>
            {hasBlacklist && (
              <span className="badge badge-error text-xs">{config.blacklist.length} entries</span>
            )}
          </div>
          <p className="text-xs text-bifrost-muted mb-3">
            Block connections from these IPs.
          </p>
          <ArrayInput
            values={config.blacklist}
            onChange={(blacklist) => onChange({ ...config, blacklist })}
            placeholder="e.g., 203.0.113.0/24 or 198.51.100.1"
          />
        </div>
      </div>
    </Section>
  )
}
