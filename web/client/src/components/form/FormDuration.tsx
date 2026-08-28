import { useState, useEffect, useId } from 'react'

interface FormDurationProps {
  label: string
  description?: string
  error?: string
  value: string // Go duration syntax, e.g. "30s", "5m0s", "1h30m"
  onChange: (value: string) => void
  disabled?: boolean
}

const UNITS = [
  { value: 'ms', label: 'ms' },
  { value: 's', label: 'sec' },
  { value: 'm', label: 'min' },
  { value: 'h', label: 'hour' },
]

const MS_PER_UNIT: Record<string, number> = {
  ns: 1e-6,
  us: 1e-3,
  'µs': 1e-3,
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
}

const NS_PER_MS = 1_000_000

/**
 * Parse a Go duration string into a single value/unit pair for the inputs.
 *
 * The Go API emits composite canonical forms — `time.Duration.String()` turns
 * five minutes into "5m0s" and ninety seconds into "1m30s" — so a parser that
 * only accepts one component silently rendered every such value as 0 sec.
 * A bare number is accepted as legacy nanoseconds. Returns null when the
 * string is not a duration at all, so callers can surface the problem instead
 * of coercing it to zero.
 */
function parseDuration(duration: string): { value: number; unit: string } | null {
  if (!duration) return { value: 0, unit: 's' }

  const trimmed = duration.trim()

  // Bare number: legacy nanosecond count from the untagged time.Duration era.
  if (/^\d+$/.test(trimmed)) {
    return msToDisplay(parseInt(trimmed, 10) / NS_PER_MS)
  }

  // Composite Go syntax: one or more number+unit components, e.g. "1h30m0s".
  const componentRe = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g
  let totalMs = 0
  let consumed = ''
  for (const match of trimmed.matchAll(componentRe)) {
    consumed += match[0]
    totalMs += parseFloat(match[1]) * MS_PER_UNIT[match[2]]
  }
  if (consumed !== trimmed || consumed === '') {
    return null
  }
  return msToDisplay(totalMs)
}

/** Pick the largest unit that represents the duration exactly. */
function msToDisplay(totalMs: number): { value: number; unit: string } {
  const ms = Math.round(totalMs)
  if (ms >= 3_600_000 && ms % 3_600_000 === 0) return { value: ms / 3_600_000, unit: 'h' }
  if (ms >= 60_000 && ms % 60_000 === 0) return { value: ms / 60_000, unit: 'm' }
  if (ms >= 1_000 && ms % 1_000 === 0) return { value: ms / 1_000, unit: 's' }
  return { value: ms, unit: 'ms' }
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
  const [numValue, setNumValue] = useState(parsed?.value ?? 0)
  const [unit, setUnit] = useState(parsed?.unit ?? 's')
  const [parseError, setParseError] = useState<string | null>(null)

  useEffect(() => {
    const next = parseDuration(value)
    if (next === null) {
      // Keep the inputs as they are rather than silently showing 0 for a
      // value we could not read; the message below names the raw value.
      setParseError(`Unrecognized duration "${value}"`)
      return
    }
    setParseError(null)
    setNumValue(next.value)
    setUnit(next.unit)
  }, [value])

  const handleChange = (newNum: number, newUnit: string) => {
    setNumValue(newNum)
    setUnit(newUnit)
    setParseError(null)
    onChange(`${newNum}${newUnit}`)
  }

  const shownError = error ?? parseError ?? undefined
  const inputId = useId()

  return (
    <div className="space-y-1">
      <label htmlFor={inputId} className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <div className="flex gap-2">
        <input
          id={inputId}
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
          className={`input flex-1 ${shownError ? 'border-bifrost-error focus:ring-bifrost-error' : ''}`}
        />
        <select
          aria-label={`${label} unit`}
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
      {shownError && (
        <p className="text-xs text-bifrost-error">{shownError}</p>
      )}
    </div>
  )
}
