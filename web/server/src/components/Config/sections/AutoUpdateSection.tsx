import { Section } from '../Section'
import type { AutoUpdateConfig } from '../../../api/types'

interface AutoUpdateSectionProps {
    config: AutoUpdateConfig
    onChange: (config: AutoUpdateConfig) => void
}

export function AutoUpdateSection({ config, onChange }: AutoUpdateSectionProps) {
    const update = (field: string, value: unknown) => {
        onChange({ ...config, [field]: value })
    }

    return (
        <Section title="Auto Update" badge="restart-required">
            <div className="space-y-4">
                <label className="flex items-center gap-3 cursor-pointer">
                    <input
                        type="checkbox"
                        checked={config.enabled}
                        onChange={(e) => update('enabled', e.target.checked)}
                        className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                    />
                    <span className="text-sm font-medium text-gray-300">Enable Auto Update</span>
                </label>

                {config.enabled && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
                        <div>
                            <label className="block text-sm font-medium text-gray-300 mb-1">Check Interval</label>
                            <input
                                type="text"
                                value={config.check_interval || ''}
                                onChange={(e) => update('check_interval', e.target.value)}
                                placeholder="24h"
                                className="input"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-gray-300 mb-1">Channel</label>
                            <select
                                value={config.channel || 'stable'}
                                onChange={(e) => update('channel', e.target.value)}
                                className="input"
                            >
                                <option value="stable">Stable</option>
                                <option value="prerelease">Pre-release</option>
                            </select>
                        </div>
                    </div>
                )}
            </div>
        </Section>
    )
}
