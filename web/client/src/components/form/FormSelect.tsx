import { SelectHTMLAttributes, useId } from 'react'

interface Option {
  value: string
  label: string
}

interface FormSelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'onChange' | 'value'> {
  label: string
  description?: string
  error?: string
  value: string
  onChange: (value: string) => void
  options: Option[]
}

export function FormSelect({
  label,
  description,
  error,
  value,
  onChange,
  options,
  className = '',
  id: providedId,
  ...props
}: FormSelectProps) {
  const generatedId = useId()
  const selectId = providedId || generatedId
  const descriptionId = description ? `${selectId}-description` : undefined
  const errorId = error ? `${selectId}-error` : undefined

  return (
    <div className="space-y-1">
      <label htmlFor={selectId} className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p id={descriptionId} className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <select
        id={selectId}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-describedby={[descriptionId, errorId].filter(Boolean).join(' ') || undefined}
        aria-invalid={error ? 'true' : undefined}
        className={`input ${error ? 'border-bifrost-error focus:ring-bifrost-error' : ''} ${className}`}
        {...props}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      {error && (
        <p id={errorId} className="text-xs text-bifrost-error" role="alert">{error}</p>
      )}
    </div>
  )
}
