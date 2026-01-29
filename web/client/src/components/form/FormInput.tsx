import { InputHTMLAttributes, useId } from 'react'

interface FormInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'onChange'> {
  label: string
  description?: string
  error?: string
  value: string
  onChange: (value: string) => void
}

export function FormInput({
  label,
  description,
  error,
  value,
  onChange,
  className = '',
  id: providedId,
  ...props
}: FormInputProps) {
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
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
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
