import { Section } from '../Section'
import type { CacheConfig, CacheStorageConfig } from '../../../api/types'

interface CacheSectionProps {
    config: CacheConfig
    onChange: (config: CacheConfig) => void
}

export function CacheSection({ config, onChange }: CacheSectionProps) {
    const update = (field: string, value: unknown) => {
        onChange({ ...config, [field]: value })
    }

    const updateStorage = (type: CacheStorageConfig['type']) => {
        const storage: CacheStorageConfig = { ...config.storage, type }

        // Initialize defaults for new type if missing
        if (type === 'memory' && !storage.memory) {
            storage.memory = {
                max_size: '2GB',
                max_entries: 50000,
                evict_policy: 'lru',
            }
        } else if (type === 'disk' && !storage.disk) {
            storage.disk = {
                path: '/var/cache/bifrost',
                max_size: '500GB',
                cleanup_interval: '1h',
                shard_count: 256,
            }
        } else if (type === 'tiered') {
            if (!storage.tiered) {
                storage.tiered = { memory_threshold: '10MB' }
            }
            if (!storage.memory) {
                storage.memory = {
                    max_size: '2GB',
                    max_entries: 50000,
                    evict_policy: 'lru',
                }
            }
            if (!storage.disk) {
                storage.disk = {
                    path: '/var/cache/bifrost',
                    max_size: '500GB',
                    cleanup_interval: '1h',
                    shard_count: 256,
                }
            }
        }

        onChange({ ...config, storage })
    }

    const updateMemoryConfig = (field: string, value: unknown) => {
        onChange({
            ...config,
            storage: {
                ...config.storage,
                memory: { ...(config.storage.memory || { max_size: '2GB', max_entries: 50000, evict_policy: 'lru' }), [field]: value },
            }
        })
    }

    const updateDiskConfig = (field: string, value: unknown) => {
        onChange({
            ...config,
            storage: {
                ...config.storage,
                disk: { ...(config.storage.disk || { path: '/var/cache/bifrost', max_size: '500GB', cleanup_interval: '1h', shard_count: 256 }), [field]: value },
            }
        })
    }

    const updateTieredConfig = (field: string, value: unknown) => {
        onChange({
            ...config,
            storage: {
                ...config.storage,
                tiered: { ...(config.storage.tiered || { memory_threshold: '10MB' }), [field]: value },
            }
        })
    }

    return (
        <Section title="Cache" badge="restart-required">
            <div className="space-y-4">
                <label className="flex items-center gap-3 cursor-pointer">
                    <input
                        type="checkbox"
                        checked={config.enabled}
                        onChange={(e) => update('enabled', e.target.checked)}
                        className="w-4 h-4 rounded border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                    />
                    <span className="text-sm font-medium text-gray-300">Enable Caching</span>
                </label>

                {config.enabled && (
                    <div className="space-y-6 pl-7">
                        {/* General Settings */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-1">Default TTL</label>
                                <input
                                    type="text"
                                    value={config.default_ttl || ''}
                                    onChange={(e) => update('default_ttl', e.target.value)}
                                    placeholder="30d"
                                    className="input"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-1">Max File Size</label>
                                <input
                                    type="text"
                                    value={config.max_file_size || ''}
                                    onChange={(e) => update('max_file_size', e.target.value)}
                                    placeholder="50GB"
                                    className="input"
                                />
                            </div>
                        </div>

                        {/* Storage Configuration */}
                        <div className="bg-bifrost-bg rounded-lg p-4 space-y-4">
                            <h4 className="text-sm font-semibold text-white">Storage Backend</h4>

                            <div>
                                <label className="block text-sm font-medium text-gray-300 mb-2">Storage Type</label>
                                <div className="flex gap-4">
                                    {(['memory', 'disk', 'tiered'] as const).map((type) => (
                                        <label key={type} className="flex items-center gap-2 cursor-pointer">
                                            <input
                                                type="radio"
                                                name="storage_type"
                                                checked={config.storage.type === type}
                                                onChange={() => updateStorage(type)}
                                                className="w-4 h-4 border-bifrost-border bg-bifrost-bg text-bifrost-accent focus:ring-bifrost-accent"
                                            />
                                            <span className="text-sm text-gray-300 capitalize">{type}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>

                            {/* Memory Settings */}
                            {(config.storage.type === 'memory' || config.storage.type === 'tiered') && (
                                <div className="space-y-4 border-t border-bifrost-border pt-4">
                                    <h5 className="text-xs font-semibold text-bifrost-muted uppercase tracking-wider">Memory Configuration</h5>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-1">Max Size</label>
                                            <input
                                                type="text"
                                                value={config.storage.memory?.max_size || ''}
                                                onChange={(e) => updateMemoryConfig('max_size', e.target.value)}
                                                className="input"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-1">Max Entries</label>
                                            <input
                                                type="number"
                                                value={config.storage.memory?.max_entries || 0}
                                                onChange={(e) => updateMemoryConfig('max_entries', parseInt(e.target.value))}
                                                className="input"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-1">Eviction Policy</label>
                                            <select
                                                value={config.storage.memory?.evict_policy || 'lru'}
                                                onChange={(e) => updateMemoryConfig('evict_policy', e.target.value)}
                                                className="input"
                                            >
                                                <option value="lru">LRU</option>
                                                <option value="lfu">LFU</option>
                                                <option value="fifo">FIFO</option>
                                            </select>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Disk Settings */}
                            {(config.storage.type === 'disk' || config.storage.type === 'tiered') && (
                                <div className="space-y-4 border-t border-bifrost-border pt-4">
                                    <h5 className="text-xs font-semibold text-bifrost-muted uppercase tracking-wider">Disk Configuration</h5>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div className="md:col-span-2">
                                            <label className="block text-sm font-medium text-gray-300 mb-1">Cache Path</label>
                                            <input
                                                type="text"
                                                value={config.storage.disk?.path || ''}
                                                onChange={(e) => updateDiskConfig('path', e.target.value)}
                                                className="input"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-1">Max Size</label>
                                            <input
                                                type="text"
                                                value={config.storage.disk?.max_size || ''}
                                                onChange={(e) => updateDiskConfig('max_size', e.target.value)}
                                                className="input"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-300 mb-1">Cleanup Interval</label>
                                            <input
                                                type="text"
                                                value={config.storage.disk?.cleanup_interval || ''}
                                                onChange={(e) => updateDiskConfig('cleanup_interval', e.target.value)}
                                                className="input"
                                            />
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* Tiered Settings */}
                            {config.storage.type === 'tiered' && (
                                <div className="space-y-4 border-t border-bifrost-border pt-4">
                                    <h5 className="text-xs font-semibold text-bifrost-muted uppercase tracking-wider">Tiered Configuration</h5>
                                    <div>
                                        <label className="block text-sm font-medium text-gray-300 mb-1">Memory Threshold</label>
                                        <input
                                            type="text"
                                            value={config.storage.tiered?.memory_threshold || ''}
                                            onChange={(e) => updateTieredConfig('memory_threshold', e.target.value)}
                                            placeholder="10MB"
                                            className="input"
                                        />
                                        <p className="text-xs text-bifrost-muted mt-1">Files smaller than this stay in memory</p>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>
        </Section>
    )
}
