import { InputHTMLAttributes, useId } from 'react'

interface FormNumberProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange' | 'value' | 'type'> {
  label: string
  description?: string
  error?: string
  value: number
  onChange: (value: number) => void
}

export function FormNumber({
  label,
  description,
  error,
  value,
  onChange,
  min,
  max,
  className = '',
  id: providedId,
  ...props
}: FormNumberProps) {
  const generatedId = useId()
  const inputId = providedId || generatedId
  const descriptionId = description ? `${inputId}-description` : undefined
  const errorId = error ? `${inputId}-error` : undefined

  return (
    <div className="space-y-1">
      <label htmlFor={inputId} className="block text-sm font-medium text-bifrost-muted">{label}</label>
      {description && (
        <p id={descriptionId} className="text-xs text-bifrost-muted/70">{description}</p>
      )}
      <input
        id={inputId}
        type="number"
        value={value}
        onChange={(e) => {
          const val = parseInt(e.target.value, 10)
          if (!isNaN(val)) {
            onChange(val)
          }
        }}
        min={min}
        max={max}
        aria-describedby={[descriptionId, errorId].filter(Boolean).join(' ') || undefined}
        aria-invalid={error ? 'true' : undefined}
        className={`input ${error ? 'border-bifrost-error focus:ring-bifrost-error' : ''} ${className}`}
        {...props}
      />
      {error && (
        <p id={errorId} className="text-xs text-bifrost-error" role="alert">{error}</p>
      )}
    </div>
  )
}
