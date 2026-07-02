import { Section } from '../Section'
import { ValidatedInput, ValidatedSelect } from '../../ui/ValidatedInput'
import { useValidation } from '../../../hooks/useValidation'
import { validators } from '../../../utils/validation'
import type { SessionConfig, RedisSessionConfig } from '../../../api/types'

interface SessionSectionProps {
  config?: SessionConfig
  onChange: (config: SessionConfig | undefined) => void
}

type SessionValidationKeys = {
  duration: string
  cleanup_interval: string
  max_sessions_per_user: number
  'redis.addr': string
  'redis.op_timeout': string
  'redis.db': number
}

export function SessionSection({ config, onChange }: SessionSectionProps) {
  const cfg: SessionConfig = config ?? { store: 'memory' }
  const isRedis = cfg.store === 'redis'

  const { errors, handleFieldChange } = useValidation<SessionValidationKeys>({
    duration: [validators.duration()],
    cleanup_interval: [validators.duration()],
    max_sessions_per_user: [validators.positiveInteger()],
    'redis.addr': [validators.pattern(/^[\w.-]+:\d+$/, 'Format: host:port')],
    'redis.op_timeout': [validators.duration()],
    'redis.db': [validators.positiveInteger()],
  })

  const update = (field: keyof SessionConfig, value: unknown) => {
    if (field === 'duration' || field === 'cleanup_interval' || field === 'max_sessions_per_user') {
      handleFieldChange(field as keyof SessionValidationKeys, value as never)
    }
    onChange({ ...cfg, [field]: value })
  }

  const updateRedis = (field: keyof RedisSessionConfig, value: unknown) => {
    const key = `redis.${field}` as keyof SessionValidationKeys
    if (field === 'addr' || field === 'op_timeout' || field === 'db') {
      handleFieldChange(key, value as never)
    }
    onChange({ ...cfg, redis: { ...(cfg.redis || { addr: '' }), [field]: value } })
  }

  return (
    <Section
      title="Session Storage"
      badge="restart-required"
      description="Where authenticated Web UI / API sessions are stored"
    >
      <div className="space-y-4">
        <ValidatedSelect
          label="Store"
          value={cfg.store || 'memory'}
          onChange={(e) => update('store', e.target.value)}
          className="max-w-xs"
          helpText="Redis is required to share sessions across replicas"
        >
          <option value="memory">Memory (default, not shared)</option>
          <option value="redis">Redis (shared, persistent)</option>
        </ValidatedSelect>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <ValidatedInput
            label="Session Duration"
            value={cfg.duration || ''}
            onChange={(e) => update('duration', e.target.value)}
            placeholder="8h"
            error={errors.duration}
            helpText="Default session lifetime (empty = 8h)"
          />
          <ValidatedInput
            label="Max Sessions Per User"
            type="number"
            value={cfg.max_sessions_per_user ?? 0}
            onChange={(e) => update('max_sessions_per_user', parseInt(e.target.value) || 0)}
            placeholder="0 (unlimited)"
            error={errors.max_sessions_per_user}
          />
          {!isRedis && (
            <ValidatedInput
              label="Cleanup Interval"
              value={cfg.cleanup_interval || ''}
              onChange={(e) => update('cleanup_interval', e.target.value)}
              placeholder="5m"
              error={errors.cleanup_interval}
              helpText="How often the memory store reaps expired sessions"
            />
          )}
        </div>

        {isRedis && (
          <div className="p-4 bg-bifrost-bg rounded-lg space-y-4">
            <h4 className="text-sm font-semibold text-white">Redis Connection</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ValidatedInput
                label="Address"
                value={cfg.redis?.addr || ''}
                onChange={(e) => updateRedis('addr', e.target.value)}
                placeholder="127.0.0.1:6379"
                error={errors['redis.addr']}
                helpText="Required when store is Redis"
              />
              <ValidatedInput
                label="Password"
                type="password"
                value={cfg.redis?.password || ''}
                onChange={(e) => updateRedis('password', e.target.value)}
                placeholder="Optional AUTH password"
                autoComplete="off"
              />
              <ValidatedInput
                label="Database"
                type="number"
                value={cfg.redis?.db ?? 0}
                onChange={(e) => updateRedis('db', parseInt(e.target.value) || 0)}
                error={errors['redis.db']}
                helpText="Logical database index"
              />
              <ValidatedInput
                label="Key Prefix"
                value={cfg.redis?.key_prefix || ''}
                onChange={(e) => updateRedis('key_prefix', e.target.value)}
                placeholder="bifrost:session:"
              />
              <ValidatedInput
                label="Operation Timeout"
                value={cfg.redis?.op_timeout || ''}
                onChange={(e) => updateRedis('op_timeout', e.target.value)}
                placeholder="5s"
                error={errors['redis.op_timeout']}
                helpText="Per-operation timeout (empty = 5s)"
              />
            </div>
          </div>
        )}
      </div>
    </Section>
  )
}
