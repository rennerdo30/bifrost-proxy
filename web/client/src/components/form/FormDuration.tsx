import { useState, useEffect } from 'react'

interface FormDurationProps {
  label: string
  description?: string
  error?: string
  value: string // e.g., "30s", "5m", "1h"
  onChange: (value: string) => void
  disabled?: boolean
}

const UNITS = [
  { value: 'ms', label: 'ms' },
  { value: 's', label: 'sec' },
  { value: 'm', label: 'min' },
  { value: 'h', label: 'hour' },
]

function parseDuration(duration: string): { value: number; unit: string } {
  if (!duration) return { value: 0, unit: 's' }

  const match = duration.match(/^(\d+)(ms|s|m|h)$/)
  if (match) {
    return { value: parseInt(match[1], 10), unit: match[2] }
  }

  // Try to parse as nanoseconds (Go default)
  const ns = parseInt(duration, 10)
  if (!isNaN(ns)) {
    if (ns >= 3600000000000) return { value: Math.round(ns / 3600000000000), unit: 'h' }
    if (ns >= 60000000000) return { value: Math.round(ns / 60000000000), unit: 'm' }
    if (ns >= 1000000000) return { value: Math.round(ns / 1000000000), unit: 's' }
    if (ns >= 1000000) return { value: Math.round(ns / 1000000), unit: 'ms' }
  }

  return { value: 0, unit: 's' }
}

export function FormDuration({
  label,
  description,
  error,
  value,
  onChange,
  disabled = false,
}: FormDurationProps) {
  const parsed = parseDuration(value)
  const [numValue, setNumValue] = useState(parsed.value)
  const [unit, setUnit] = useState(parsed.unit)

  useEffect(() => {
    const parsed = parseDuration(value)
    setNumValue(parsed.value)
    setUnit(parsed.unit)
  }, [value])

  const handleChange = (newNum: number, newUnit: string) => {
    setNumValue(newNum)
    setUnit(newUnit)
    onChange(`${newNum}${newUnit}`)
  }

  return (
    <div className="space-y-1">
      <label className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <div className="flex gap-2">
        <input
          type="number"
          value={numValue}
          onChange={(e) => {
            const val = parseInt(e.target.value, 10)
            if (!isNaN(val) && val >= 0) {
              handleChange(val, unit)
            }
          }}
          min={0}
          disabled={disabled}
          className={`input flex-1 ${error ? 'border-bifrost-error focus:ring-bifrost-error' : ''}`}
        />
        <select
          value={unit}
          onChange={(e) => handleChange(numValue, e.target.value)}
          disabled={disabled}
          className="input w-20"
        >
          {UNITS.map((u) => (
            <option key={u.value} value={u.value}>
              {u.label}
            </option>
          ))}
        </select>
      </div>
      {error && (
        <p className="text-xs text-bifrost-error">{error}</p>
      )}
    </div>
  )
}
